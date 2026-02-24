"""Critical journey flow checker with hardened network and structured outputs."""

from __future__ import annotations

import csv
import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from loom.tools.registry import Tool, ToolContext, ToolResult

_DEFAULT_USER_AGENT = "loom-a11y-flow-check/1.0"
_DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_TRANSIENT_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):  # type: ignore[override]
        return None


_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


@dataclass(frozen=True)
class _NetworkConfig:
    timeout_seconds: int
    max_redirects: int
    max_retries: int
    backoff_base_seconds: float
    backoff_max_seconds: float
    request_delay_seconds: float
    max_fetch_bytes: int
    user_agent: str
    accept: str
    accept_language: str


@dataclass(frozen=True)
class _FetchResult:
    requested_url: str
    final_url: str
    status_code: int
    content_type: str
    body: str
    truncated: bool


@dataclass(frozen=True)
class _StepSpec:
    name: str
    url: str
    expected_text: tuple[str, ...]


class _SignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_html_lang = False
        self._in_title = 0
        self.title_parts: list[str] = []
        self.has_main = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        if tag_name == "html" and attr_map.get("lang", "").strip():
            self.has_html_lang = True
        if tag_name == "title":
            self._in_title += 1
        if tag_name == "main" or attr_map.get("role", "").strip().lower() == "main":
            self.has_main = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title > 0:
            self._in_title -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title > 0:
            self.title_parts.append(data)


def _clamp_int(value: Any, minimum: int, maximum: int) -> int:
    return max(minimum, min(int(value), maximum))


def _clamp_float(value: Any, minimum: float, maximum: float) -> float:
    return max(minimum, min(float(value), maximum))


def _ensure_url(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    return text


def _normalize_url(raw: Any, *, keep_query: bool = True) -> str | None:
    candidate = _ensure_url(raw)
    if not candidate:
        return None

    try:
        parts = urllib.parse.urlsplit(candidate)
    except ValueError:
        return None

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return None

    host = (parts.hostname or "").strip().lower()
    if not host:
        return None

    try:
        port = parts.port
    except ValueError:
        return None

    if port is None:
        netloc = host
    elif (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    else:
        netloc = f"{host}:{port}"

    path = parts.path or "/"
    path = urllib.parse.urljoin("/", path)
    query = parts.query if keep_query else ""

    return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))


def _host_from_url(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").strip().lower()


def _is_blocked_ip(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def _validate_public_host(host: str) -> None:
    if not host:
        raise ValueError("URL host is empty")

    if host.lower() == "localhost":
        raise ValueError("Host 'localhost' is not allowed")

    try:
        resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as err:
        raise ValueError(f"DNS resolution failed for '{host}': {err}") from err

    seen_ips: set[str] = set()
    for _family, _socktype, _proto, _canonname, sockaddr in resolved:
        ip_str = str(sockaddr[0])
        if ip_str in seen_ips:
            continue
        seen_ips.add(ip_str)
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError as err:
            raise ValueError(
                f"Host '{host}' resolved to invalid IP '{ip_str}'"
            ) from err
        if _is_blocked_ip(ip):
            raise ValueError(f"Host '{host}' resolved to blocked address '{ip_str}'")


def _parse_retry_after(value: str) -> float | None:
    token = value.strip()
    if not token:
        return None

    if token.isdigit():
        return max(0.0, float(token))

    try:
        parsed = parsedate_to_datetime(token)
    except (TypeError, ValueError):
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    seconds = (parsed - datetime.now(timezone.utc)).total_seconds()
    return max(0.0, seconds)


def _compute_backoff_delay(
    *,
    attempt: int,
    cfg: _NetworkConfig,
    retry_after_header: str = "",
) -> float:
    retry_after_seconds = _parse_retry_after(retry_after_header)
    if retry_after_seconds is not None:
        return min(cfg.backoff_max_seconds, retry_after_seconds)
    return min(cfg.backoff_max_seconds, cfg.backoff_base_seconds * (2**attempt))


def _pace_request(
    host: str, cfg: _NetworkConfig, last_request_by_host: dict[str, float]
) -> None:
    if cfg.request_delay_seconds <= 0:
        return

    now = time.monotonic()
    previous = last_request_by_host.get(host)
    if previous is not None:
        wait_for = cfg.request_delay_seconds - (now - previous)
        if wait_for > 0:
            time.sleep(wait_for)
    last_request_by_host[host] = time.monotonic()


def _new_warning(code: str, url: str, message: str) -> dict[str, str]:
    return {"code": code, "url": url, "message": message}


def _fetch_url(
    url: str,
    *,
    cfg: _NetworkConfig,
    last_request_by_host: dict[str, float],
    warnings: list[dict[str, str]],
) -> _FetchResult:
    current = url

    for _ in range(cfg.max_redirects + 1):
        host = _host_from_url(current)
        _validate_public_host(host)

        for attempt in range(cfg.max_retries + 1):
            _pace_request(host, cfg, last_request_by_host)
            request = urllib.request.Request(
                current,
                headers={
                    "User-Agent": cfg.user_agent,
                    "Accept": cfg.accept,
                    "Accept-Language": cfg.accept_language,
                },
            )

            try:
                with _NO_REDIRECT_OPENER.open(
                    request, timeout=cfg.timeout_seconds
                ) as response:
                    status_code = int(response.getcode() or 200)
                    headers = {k.lower(): v for k, v in response.headers.items()}
                    payload = response.read(cfg.max_fetch_bytes + 1)
                    truncated = len(payload) > cfg.max_fetch_bytes
                    body = payload[: cfg.max_fetch_bytes].decode(
                        "utf-8", errors="replace"
                    )

                    if truncated:
                        warnings.append(
                            _new_warning(
                                "response_truncated",
                                current,
                                f"Response body exceeded {cfg.max_fetch_bytes} bytes and was truncated.",
                            ),
                        )

                    if (
                        status_code in _TRANSIENT_STATUS_CODES
                        and attempt < cfg.max_retries
                    ):
                        delay_seconds = _compute_backoff_delay(
                            attempt=attempt,
                            cfg=cfg,
                            retry_after_header=(
                                headers.get("retry-after", "")
                                if status_code in {429, 503}
                                else ""
                            ),
                        )
                        warnings.append(
                            _new_warning(
                                "transient_retry",
                                current,
                                f"HTTP {status_code}; retrying in {delay_seconds:.2f}s.",
                            ),
                        )
                        time.sleep(delay_seconds)
                        continue

                    return _FetchResult(
                        requested_url=url,
                        final_url=current,
                        status_code=status_code,
                        content_type=str(headers.get("content-type", "")).lower(),
                        body=body,
                        truncated=truncated,
                    )

            except urllib.error.HTTPError as err:
                status_code = int(err.code)
                err_headers = {
                    k.lower(): v
                    for k, v in (err.headers.items() if err.headers else [])
                }

                if status_code in _REDIRECT_STATUS_CODES:
                    location = str(err_headers.get("location", "")).strip()
                    if not location:
                        raise ValueError(
                            f"Redirect from '{current}' missing Location header"
                        )
                    redirected = urllib.parse.urljoin(current, location)
                    normalized = _normalize_url(redirected, keep_query=True)
                    if not normalized:
                        raise ValueError(f"Redirect target '{redirected}' is invalid")
                    _validate_public_host(_host_from_url(normalized))
                    current = normalized
                    break

                payload = err.read(cfg.max_fetch_bytes + 1)
                truncated = len(payload) > cfg.max_fetch_bytes
                body = payload[: cfg.max_fetch_bytes].decode("utf-8", errors="replace")
                if truncated:
                    warnings.append(
                        _new_warning(
                            "response_truncated",
                            current,
                            f"Error response body exceeded {cfg.max_fetch_bytes} bytes and was truncated.",
                        ),
                    )

                if status_code in _TRANSIENT_STATUS_CODES and attempt < cfg.max_retries:
                    delay_seconds = _compute_backoff_delay(
                        attempt=attempt,
                        cfg=cfg,
                        retry_after_header=(
                            err_headers.get("retry-after", "")
                            if status_code in {429, 503}
                            else ""
                        ),
                    )
                    warnings.append(
                        _new_warning(
                            "transient_retry",
                            current,
                            f"HTTP {status_code}; retrying in {delay_seconds:.2f}s.",
                        ),
                    )
                    time.sleep(delay_seconds)
                    continue

                return _FetchResult(
                    requested_url=url,
                    final_url=current,
                    status_code=status_code,
                    content_type=str(err_headers.get("content-type", "")).lower(),
                    body=body,
                    truncated=truncated,
                )

            except (
                urllib.error.URLError,
                TimeoutError,
                socket.timeout,
                OSError,
            ) as err:
                if attempt < cfg.max_retries:
                    delay_seconds = _compute_backoff_delay(attempt=attempt, cfg=cfg)
                    warnings.append(
                        _new_warning(
                            "network_retry",
                            current,
                            f"Transient network error '{err}'; retrying in {delay_seconds:.2f}s.",
                        ),
                    )
                    time.sleep(delay_seconds)
                    continue
                raise RuntimeError(f"Failed to fetch '{current}': {err}") from err
        else:
            continue

        continue

    raise ValueError(f"Too many redirects while fetching '{url}'")


def _parse_expected_text(raw: Any) -> tuple[str, ...]:
    if raw is None:
        return ()
    if isinstance(raw, str):
        value = raw.strip()
        return (value,) if value else ()
    if isinstance(raw, list):
        items = [str(item).strip() for item in raw if str(item).strip()]
        return tuple(items)
    value = str(raw).strip()
    return (value,) if value else ()


def _parse_step(step_raw: Any, index: int) -> _StepSpec | None:
    if isinstance(step_raw, str):
        normalized = _normalize_url(step_raw, keep_query=True)
        if not normalized:
            return None
        return _StepSpec(name=f"step-{index}", url=normalized, expected_text=())

    if not isinstance(step_raw, dict):
        return None

    raw_url = step_raw.get("url")
    normalized = _normalize_url(raw_url, keep_query=True)
    if not normalized:
        return None

    raw_name = str(step_raw.get("name", "")).strip()
    expected = _parse_expected_text(step_raw.get("expected_text"))
    if not expected:
        expected = _parse_expected_text(step_raw.get("assert_text"))

    return _StepSpec(
        name=raw_name or f"step-{index}",
        url=normalized,
        expected_text=expected,
    )


def _inspect_html_signals(body: str) -> tuple[dict[str, bool], list[str]]:
    parser = _SignalParser()
    parser.feed(body)
    parser.close()

    has_title = bool("".join(parser.title_parts).strip())
    has_html_lang = parser.has_html_lang
    has_main = parser.has_main

    notes: list[str] = []
    if not has_title:
        notes.append("Missing or empty page title.")
    if not has_html_lang:
        notes.append("Missing html lang attribute.")
    if not has_main:
        notes.append("Missing main landmark.")

    return {
        "has_title": has_title,
        "has_html_lang": has_html_lang,
        "has_main_landmark": has_main,
    }, notes


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "flow_name",
        "flow_status",
        "step_index",
        "step_name",
        "url",
        "final_url",
        "step_status",
        "status_code",
        "content_type",
        "expected_text",
        "missing_text",
        "notes",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2, sort_keys=True)
        handle.write("\n")


class A11yFlowCheckTool(Tool):
    """Checks critical journey flows and returns structured health signals."""

    @property
    def name(self) -> str:
        return "a11y_flow_check"

    @property
    def description(self) -> str:
        return (
            "Validate critical journey flow steps with SSRF-safe fetches, "
            "health signals, and optional text assertions."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "flows": {
                    "type": "array",
                    "description": "List of flow objects with {name, steps}.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "steps": {
                                "type": "array",
                                "description": "Ordered step URLs or step objects.",
                                "items": {
                                    "anyOf": [
                                        {"type": "string"},
                                        {
                                            "type": "object",
                                            "properties": {
                                                "name": {"type": "string"},
                                                "url": {"type": "string"},
                                                "expected_text": {
                                                    "anyOf": [
                                                        {"type": "string"},
                                                        {
                                                            "type": "array",
                                                            "items": {"type": "string"},
                                                        },
                                                    ],
                                                },
                                                "assert_text": {
                                                    "anyOf": [
                                                        {"type": "string"},
                                                        {
                                                            "type": "array",
                                                            "items": {"type": "string"},
                                                        },
                                                    ],
                                                },
                                            },
                                            "required": ["url"],
                                        },
                                    ],
                                },
                            },
                        },
                        "required": ["name", "steps"],
                    },
                },
                "max_flows": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20,
                    "description": "Maximum number of flows processed.",
                },
                "max_steps_per_flow": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 25,
                    "description": "Maximum steps processed per flow.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60,
                    "default": 12,
                    "description": "Per-request timeout in seconds.",
                },
                "require_https": {
                    "type": "boolean",
                    "default": True,
                    "description": "Flag flow steps that are not HTTPS.",
                },
                "max_redirects": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 10,
                    "default": 5,
                    "description": "Maximum redirect hops per request.",
                },
                "max_retries": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 5,
                    "default": 2,
                    "description": "Retries for transient network/HTTP failures.",
                },
                "backoff_base_seconds": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 10,
                    "default": 0.5,
                    "description": "Base exponential backoff delay in seconds.",
                },
                "backoff_max_seconds": {
                    "type": "number",
                    "minimum": 0.2,
                    "maximum": 30,
                    "default": 6,
                    "description": "Upper bound for backoff delay in seconds.",
                },
                "request_delay_seconds": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 5,
                    "default": 0.3,
                    "description": "Minimum delay between requests to the same host.",
                },
                "max_fetch_bytes": {
                    "type": "integer",
                    "minimum": 20000,
                    "maximum": 5000000,
                    "default": 1500000,
                    "description": "Maximum bytes read from each response body.",
                },
                "user_agent": {
                    "type": "string",
                    "description": "Optional User-Agent override.",
                },
                "output_flow_csv": {
                    "type": "string",
                    "description": "Optional workspace-relative CSV report path.",
                },
                "output_flow_json": {
                    "type": "string",
                    "description": "Optional workspace-relative JSON report path.",
                },
            },
            "required": ["flows"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw_flows = args.get("flows")
        if not isinstance(raw_flows, list) or not raw_flows:
            return ToolResult.fail("'flows' must be a non-empty list")

        try:
            max_flows = _clamp_int(args.get("max_flows", 20), 1, 100)
            max_steps_per_flow = _clamp_int(args.get("max_steps_per_flow", 25), 1, 100)
            timeout_seconds = _clamp_int(args.get("timeout_seconds", 12), 1, 60)
            max_redirects = _clamp_int(args.get("max_redirects", 5), 0, 10)
            max_retries = _clamp_int(args.get("max_retries", 2), 0, 5)
            backoff_base_seconds = _clamp_float(
                args.get("backoff_base_seconds", 0.5), 0.1, 10.0
            )
            backoff_max_seconds = _clamp_float(
                args.get("backoff_max_seconds", 6.0), 0.2, 30.0
            )
            request_delay_seconds = _clamp_float(
                args.get("request_delay_seconds", 0.3), 0.0, 5.0
            )
            max_fetch_bytes = _clamp_int(
                args.get("max_fetch_bytes", 1_500_000), 20_000, 5_000_000
            )
        except (TypeError, ValueError):
            return ToolResult.fail("Invalid numeric argument value")

        require_https = bool(args.get("require_https", True))

        user_agent_raw = str(args.get("user_agent", "")).strip()
        user_agent = user_agent_raw or _DEFAULT_USER_AGENT

        cfg = _NetworkConfig(
            timeout_seconds=timeout_seconds,
            max_redirects=max_redirects,
            max_retries=max_retries,
            backoff_base_seconds=backoff_base_seconds,
            backoff_max_seconds=backoff_max_seconds,
            request_delay_seconds=request_delay_seconds,
            max_fetch_bytes=max_fetch_bytes,
            user_agent=user_agent,
            accept=_DEFAULT_ACCEPT,
            accept_language=_DEFAULT_ACCEPT_LANGUAGE,
        )

        warnings: list[dict[str, str]] = []
        warning_keys: set[tuple[str, str, str]] = set()

        def add_warning(code: str, url: str, message: str) -> None:
            key = (code, url, message)
            if key in warning_keys:
                return
            warning_keys.add(key)
            warnings.append(_new_warning(code, url, message))

        flow_results: list[dict[str, Any]] = []
        step_report_rows: list[dict[str, Any]] = []

        last_request_by_host: dict[str, float] = {}
        blocked_flow_count = 0

        manual_checklist = [
            "Keyboard-only traversal completes without trap across the entire flow.",
            "Visible focus indicator remains clear on every interactive control.",
            "Screen reader announces titles, landmarks, and controls in expected order.",
            "Validation errors are programmatically associated and announced.",
            "Status changes (loading, confirmations, errors) are announced accessibly.",
        ]

        for raw_flow in raw_flows[:max_flows]:
            if not isinstance(raw_flow, dict):
                continue

            flow_name = str(raw_flow.get("name", "")).strip() or "unnamed-flow"
            raw_steps = raw_flow.get("steps", [])

            if not isinstance(raw_steps, list) or not raw_steps:
                flow_results.append(
                    {
                        "name": flow_name,
                        "status": "needs-attention",
                        "blockers": ["Flow has no steps."],
                        "steps": [],
                        "notes": ["Define at least one step URL for this flow."],
                    },
                )
                blocked_flow_count += 1
                continue

            step_specs: list[_StepSpec] = []
            blockers: list[str] = []
            for index, raw_step in enumerate(raw_steps[:max_steps_per_flow], start=1):
                step = _parse_step(raw_step, index)
                if step is None:
                    blockers.append(f"Step {index}: invalid step definition or URL.")
                    continue
                step_specs.append(step)

            step_results: list[dict[str, Any]] = []

            for step_index, spec in enumerate(step_specs, start=1):
                step_notes: list[str] = []
                step_status = "ok"
                status_code: int | None = None
                content_type = ""
                final_url = spec.url
                signals = {
                    "has_title": False,
                    "has_html_lang": False,
                    "has_main_landmark": False,
                }
                missing_text: list[str] = []

                if (
                    require_https
                    and urllib.parse.urlsplit(spec.url).scheme.lower() != "https"
                ):
                    blockers.append(
                        f"Step {step_index}: URL is not HTTPS ({spec.url})."
                    )

                try:
                    fetched = _fetch_url(
                        spec.url,
                        cfg=cfg,
                        last_request_by_host=last_request_by_host,
                        warnings=warnings,
                    )
                    status_code = fetched.status_code
                    content_type = fetched.content_type
                    final_url = fetched.final_url

                    if fetched.status_code >= 400:
                        step_status = "http-error"
                        blockers.append(
                            f"Step {step_index}: HTTP {fetched.status_code} for {spec.url}.",
                        )
                    elif "html" not in fetched.content_type:
                        step_status = "non-html"
                        step_notes.append(
                            "Non-HTML response; semantic signals are limited."
                        )
                    else:
                        signals, signal_notes = _inspect_html_signals(fetched.body)
                        step_notes.extend(signal_notes)

                    if spec.expected_text:
                        body_for_match = fetched.body.casefold()
                        for expected in spec.expected_text:
                            if expected.casefold() not in body_for_match:
                                missing_text.append(expected)
                        if missing_text:
                            step_status = "assertion-failed"
                            blockers.append(
                                f"Step {step_index}: expected text not found ({', '.join(missing_text)}).",
                            )

                except Exception as err:
                    step_status = "fetch-failed"
                    blockers.append(
                        f"Step {step_index}: failed to fetch {spec.url} ({err})."
                    )
                    add_warning("fetch_failed", spec.url, str(err))
                    step_notes.append(str(err))

                step_payload = {
                    "step": step_index,
                    "name": spec.name,
                    "url": spec.url,
                    "final_url": final_url,
                    "status": step_status,
                    "status_code": status_code,
                    "content_type": content_type,
                    "signals": signals,
                    "assertions": {
                        "expected_text": list(spec.expected_text),
                        "missing_text": missing_text,
                        "passed": not missing_text,
                    },
                    "notes": step_notes,
                }
                step_results.append(step_payload)

                step_report_rows.append(
                    {
                        "flow_name": flow_name,
                        "flow_status": "",
                        "step_index": step_index,
                        "step_name": spec.name,
                        "url": spec.url,
                        "final_url": final_url,
                        "step_status": step_status,
                        "status_code": "" if status_code is None else status_code,
                        "content_type": content_type,
                        "expected_text": " | ".join(spec.expected_text),
                        "missing_text": " | ".join(missing_text),
                        "notes": " | ".join(step_notes),
                    },
                )

            flow_status = "pass" if not blockers else "needs-attention"
            if blockers:
                blocked_flow_count += 1

            for row in step_report_rows:
                if row["flow_name"] == flow_name and not row["flow_status"]:
                    row["flow_status"] = flow_status

            flow_results.append(
                {
                    "name": flow_name,
                    "status": flow_status,
                    "blockers": blockers,
                    "steps": step_results,
                    "notes": (
                        ["Flow has blocking issues."]
                        if blockers
                        else ["No blocking fetch/assertion failures detected."]
                    ),
                },
            )

        files_changed: list[str] = []
        output_flow_csv = str(args.get("output_flow_csv", "")).strip()
        if output_flow_csv:
            if ctx.workspace is None:
                return ToolResult.fail("'output_flow_csv' requires an active workspace")
            csv_path = self._resolve_path(output_flow_csv, ctx.workspace)
            _write_csv(csv_path, step_report_rows)
            files_changed.append(str(csv_path))

        output_flow_json = str(args.get("output_flow_json", "")).strip()
        output_payload = {
            "summary": {
                "flows_checked": len(flow_results),
                "flows_needing_attention": blocked_flow_count,
                "warning_count": len(warnings),
            },
            "flows": flow_results,
            "manual_checklist": manual_checklist,
            "warnings": warnings,
        }
        if output_flow_json:
            if ctx.workspace is None:
                return ToolResult.fail(
                    "'output_flow_json' requires an active workspace"
                )
            json_path = self._resolve_path(output_flow_json, ctx.workspace)
            _write_json(json_path, output_payload)
            files_changed.append(str(json_path))

        output_lines = [
            f"Flows checked: {len(flow_results)}",
            f"Flows needing attention: {blocked_flow_count}",
            f"Operational warnings: {len(warnings)}",
            "Manual checks required for each flow:",
        ]
        output_lines.extend([f"  - {item}" for item in manual_checklist])

        return ToolResult.ok(
            "\n".join(output_lines),
            data=output_payload,
            files_changed=files_changed,
        )
