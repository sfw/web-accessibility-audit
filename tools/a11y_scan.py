"""Heuristic accessibility scanner with hardened network fetching."""

from __future__ import annotations

import csv
import hashlib
import ipaddress
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from loom.tools.registry import Tool, ToolContext, ToolResult

_DEFAULT_USER_AGENT = "loom-a11y-scan/1.0"
_DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_TRANSIENT_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}


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


class _A11yParser(HTMLParser):
    """Collects lightweight accessibility signals from HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_html_lang = False
        self._in_title_depth = 0
        self.title_parts: list[str] = []
        self.has_viewport = False

        self.images: list[dict[str, Any]] = []
        self._nameable_stack: list[dict[str, Any]] = []
        self.nameable_elements: list[dict[str, Any]] = []

        self.labels_for: set[str] = set()
        self.controls: list[dict[str, Any]] = []
        self._in_label_depth = 0

        self.heading_levels: list[int] = []
        self.h1_count = 0

        self.landmarks: set[str] = set()

        self.id_counts: dict[str, int] = defaultdict(int)
        self.iframes: list[dict[str, Any]] = []

        self._table_stack: list[dict[str, Any]] = []
        self.tables: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        element_id = attr_map.get("id", "").strip()
        if element_id:
            self.id_counts[element_id] += 1

        if tag_name == "html" and attr_map.get("lang", "").strip():
            self.has_html_lang = True

        if tag_name == "title":
            self._in_title_depth += 1

        if (
            tag_name == "meta"
            and attr_map.get("name", "").strip().lower() == "viewport"
            and attr_map.get("content", "").strip()
        ):
            self.has_viewport = True

        if tag_name == "img":
            self.images.append(
                {
                    "index": len(self.images) + 1,
                    "has_alt": "alt" in attr_map,
                    "alt_text": attr_map.get("alt", ""),
                },
            )

        if tag_name in {"a", "button"}:
            self._nameable_stack.append(
                {
                    "tag": tag_name,
                    "index": len(self.nameable_elements)
                    + len(self._nameable_stack)
                    + 1,
                    "attrs": attr_map,
                    "text_parts": [],
                },
            )

        if tag_name == "label":
            self._in_label_depth += 1
            label_for = attr_map.get("for", "").strip()
            if label_for:
                self.labels_for.add(label_for)

        if tag_name in {"input", "select", "textarea"}:
            self.controls.append(
                {
                    "tag": tag_name,
                    "index": len(self.controls) + 1,
                    "attrs": attr_map,
                    "wrapped_by_label": self._in_label_depth > 0,
                },
            )

        if tag_name.startswith("h") and len(tag_name) == 2 and tag_name[1].isdigit():
            level = int(tag_name[1])
            if 1 <= level <= 6:
                self.heading_levels.append(level)
                if level == 1:
                    self.h1_count += 1

        if tag_name in {"main", "nav", "header", "footer", "aside", "form"}:
            self.landmarks.add(tag_name)
        role_value = attr_map.get("role", "").strip().lower()
        if role_value:
            self.landmarks.add(f"role:{role_value}")

        if tag_name == "iframe":
            self.iframes.append(
                {
                    "index": len(self.iframes) + 1,
                    "has_title": bool(attr_map.get("title", "").strip()),
                },
            )

        if tag_name == "table":
            table_role = attr_map.get("role", "").strip().lower()
            self._table_stack.append(
                {
                    "index": len(self.tables) + len(self._table_stack) + 1,
                    "th_count": 0,
                    "td_count": 0,
                    "has_headers_attr": False,
                    "is_layout": table_role in {"presentation", "none"},
                },
            )

        if self._table_stack:
            if tag_name == "th":
                self._table_stack[-1]["th_count"] += 1
            elif tag_name == "td":
                self._table_stack[-1]["td_count"] += 1
                if attr_map.get("headers", "").strip():
                    self._table_stack[-1]["has_headers_attr"] = True

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()

        if tag_name == "title" and self._in_title_depth > 0:
            self._in_title_depth -= 1

        if tag_name in {"a", "button"} and self._nameable_stack:
            self.nameable_elements.append(self._nameable_stack.pop())

        if tag_name == "label" and self._in_label_depth > 0:
            self._in_label_depth -= 1

        if tag_name == "table" and self._table_stack:
            self.tables.append(self._table_stack.pop())

    def handle_data(self, data: str) -> None:
        if self._in_title_depth > 0:
            self.title_parts.append(data)

        if self._nameable_stack:
            self._nameable_stack[-1]["text_parts"].append(data)


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

    for redirect_index in range(cfg.max_redirects + 1):
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


def _finding(
    *,
    url: str,
    rule_id: str,
    wcag_sc: str,
    severity: str,
    impact: str,
    confidence: float,
    message: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    token = f"{url}|{rule_id}|{message}|{evidence}|{remediation}"
    finding_id = f"a11y-{hashlib.sha1(token.encode('utf-8')).hexdigest()[:12]}"
    return {
        "finding_id": finding_id,
        "url": url,
        "rule_id": rule_id,
        "wcag_sc": wcag_sc,
        "severity": severity,
        "impact": impact,
        "confidence": round(confidence, 2),
        "message": message,
        "evidence": evidence,
        "remediation": remediation,
    }


def _has_accessible_name(attrs: dict[str, str], text_content: str) -> bool:
    if text_content.strip():
        return True
    for key in ("aria-label", "aria-labelledby", "title"):
        if attrs.get(key, "").strip():
            return True
    return False


def _scan_html(url: str, html_text: str) -> list[dict[str, Any]]:
    parser = _A11yParser()
    parser.feed(html_text)
    parser.close()

    findings: list[dict[str, Any]] = []

    if not parser.has_html_lang:
        findings.append(
            _finding(
                url=url,
                rule_id="html-lang-missing",
                wcag_sc="3.1.1",
                severity="error",
                impact="high",
                confidence=0.98,
                message="Missing or empty `lang` attribute on the `<html>` element.",
                evidence="`<html>` did not include a non-empty lang attribute.",
                remediation="Set a valid language code on `<html lang='...'>` for the page locale.",
            ),
        )

    title_text = "".join(parser.title_parts).strip()
    if not title_text:
        findings.append(
            _finding(
                url=url,
                rule_id="page-title-missing",
                wcag_sc="2.4.2",
                severity="error",
                impact="high",
                confidence=0.98,
                message="Missing or empty page title.",
                evidence="No non-empty `<title>` element was detected.",
                remediation="Provide a unique, descriptive `<title>` element for the page.",
            ),
        )

    if not parser.has_viewport:
        findings.append(
            _finding(
                url=url,
                rule_id="viewport-meta-missing",
                wcag_sc="1.4.10",
                severity="warning",
                impact="medium",
                confidence=0.9,
                message="Missing viewport meta tag.",
                evidence="No `<meta name='viewport'>` element detected.",
                remediation=(
                    "Add `<meta name='viewport' content='width=device-width, initial-scale=1'>` "
                    "or equivalent responsive viewport settings."
                ),
            ),
        )

    for image in parser.images:
        if not image["has_alt"]:
            findings.append(
                _finding(
                    url=url,
                    rule_id="image-alt-missing",
                    wcag_sc="1.1.1",
                    severity="error",
                    impact="high",
                    confidence=0.97,
                    message="Image element missing `alt` attribute.",
                    evidence=f"Image #{image['index']} is missing `alt`.",
                    remediation="Provide meaningful alt text or `alt=''` for decorative images.",
                ),
            )

    for element in parser.nameable_elements:
        tag_name = str(element["tag"])
        attrs = dict(element["attrs"])
        text_content = "".join(element["text_parts"])
        if _has_accessible_name(attrs, text_content):
            continue

        if tag_name == "a":
            findings.append(
                _finding(
                    url=url,
                    rule_id="link-name-missing",
                    wcag_sc="2.4.4",
                    severity="error",
                    impact="high",
                    confidence=0.95,
                    message="Link has no accessible name.",
                    evidence=(
                        f"Anchor #{element['index']} has no text content, aria-label, "
                        "aria-labelledby, or title."
                    ),
                    remediation="Provide visible link text or an explicit accessible name.",
                ),
            )
        elif tag_name == "button":
            findings.append(
                _finding(
                    url=url,
                    rule_id="button-name-missing",
                    wcag_sc="4.1.2",
                    severity="error",
                    impact="high",
                    confidence=0.95,
                    message="Button has no accessible name.",
                    evidence=(
                        f"Button #{element['index']} has no text content, aria-label, "
                        "aria-labelledby, or title."
                    ),
                    remediation="Provide visible button text or an explicit accessible name.",
                ),
            )

    for control in parser.controls:
        attrs = dict(control["attrs"])
        tag_name = str(control["tag"])
        if tag_name == "input":
            input_type = attrs.get("type", "text").strip().lower()
            if input_type in {"hidden", "submit", "reset", "button", "image"}:
                continue

        control_id = attrs.get("id", "").strip()
        has_aria = bool(
            attrs.get("aria-label", "").strip()
            or attrs.get("aria-labelledby", "").strip()
        )
        has_label_for = bool(control_id and control_id in parser.labels_for)
        wrapped_by_label = bool(control.get("wrapped_by_label", False))

        if not has_aria and not has_label_for and not wrapped_by_label:
            findings.append(
                _finding(
                    url=url,
                    rule_id="form-control-label-missing",
                    wcag_sc="1.3.1",
                    severity="error",
                    impact="high",
                    confidence=0.95,
                    message="Form control missing associated label.",
                    evidence=f"Control #{control['index']} (`{tag_name}`) has no detectable label association.",
                    remediation=(
                        "Associate each control with `<label for=...>`, wrap control in `<label>`, "
                        "or provide `aria-label`/`aria-labelledby`."
                    ),
                ),
            )

    duplicates = sorted(key for key, count in parser.id_counts.items() if count > 1)
    for duplicate in duplicates:
        findings.append(
            _finding(
                url=url,
                rule_id="duplicate-id",
                wcag_sc="4.1.1",
                severity="error",
                impact="medium",
                confidence=0.99,
                message="Duplicate element ID detected.",
                evidence=f"`id='{duplicate}'` appears {parser.id_counts[duplicate]} times.",
                remediation="Ensure every `id` value is unique within the document.",
            ),
        )

    for iframe in parser.iframes:
        if not iframe["has_title"]:
            findings.append(
                _finding(
                    url=url,
                    rule_id="iframe-title-missing",
                    wcag_sc="4.1.2",
                    severity="warning",
                    impact="medium",
                    confidence=0.93,
                    message="Iframe missing descriptive title.",
                    evidence=f"Iframe #{iframe['index']} has no non-empty `title`.",
                    remediation="Add a concise `title` attribute describing iframe purpose.",
                ),
            )

    if parser.h1_count == 0:
        findings.append(
            _finding(
                url=url,
                rule_id="h1-missing",
                wcag_sc="1.3.1",
                severity="warning",
                impact="medium",
                confidence=0.9,
                message="No `<h1>` heading detected.",
                evidence="Document contains headings but no h1, or no headings at all.",
                remediation="Include a meaningful h1 that describes the page purpose.",
            ),
        )

    previous_level = 0
    for level in parser.heading_levels:
        if previous_level and level > previous_level + 1:
            findings.append(
                _finding(
                    url=url,
                    rule_id="heading-level-skip",
                    wcag_sc="1.3.1",
                    severity="warning",
                    impact="low",
                    confidence=0.88,
                    message="Heading level skip detected.",
                    evidence=f"Heading jumped from h{previous_level} to h{level}.",
                    remediation="Use sequential heading levels to preserve document structure.",
                ),
            )
            break
        previous_level = level

    if "main" not in parser.landmarks and "role:main" not in parser.landmarks:
        findings.append(
            _finding(
                url=url,
                rule_id="main-landmark-missing",
                wcag_sc="1.3.1",
                severity="warning",
                impact="medium",
                confidence=0.9,
                message="Main landmark not detected.",
                evidence="Neither `<main>` nor `role='main'` was found.",
                remediation="Add a single main landmark to identify primary page content.",
            ),
        )

    for table in parser.tables:
        if table["is_layout"]:
            continue
        if int(table["td_count"]) == 0:
            continue
        if int(table["th_count"]) > 0 or bool(table["has_headers_attr"]):
            continue
        findings.append(
            _finding(
                url=url,
                rule_id="table-header-missing",
                wcag_sc="1.3.1",
                severity="warning",
                impact="medium",
                confidence=0.84,
                message="Data table appears to be missing header associations.",
                evidence=(
                    f"Table #{table['index']} contains {table['td_count']} td elements but "
                    "no th or headers attributes."
                ),
                remediation="Add `<th>` cells with scope or explicit headers/id associations.",
            ),
        )

    return findings


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for finding in findings:
        key = (
            str(finding.get("url", "")),
            str(finding.get("rule_id", "")),
            str(finding.get("message", "")),
            str(finding.get("evidence", "")),
            str(finding.get("remediation", "")),
        )
        if key not in deduped:
            deduped[key] = finding

    ordered = sorted(
        deduped.values(),
        key=lambda item: (
            str(item.get("url", "")),
            _SEVERITY_RANK.get(str(item.get("severity", "warning")), 99),
            str(item.get("rule_id", "")),
            str(item.get("evidence", "")),
        ),
    )
    return ordered


def _limit_findings_per_url(
    findings: list[dict[str, Any]],
    *,
    max_findings_per_url: int,
) -> list[dict[str, Any]]:
    per_url_counts: dict[str, int] = defaultdict(int)
    selected: list[dict[str, Any]] = []

    for finding in findings:
        url = str(finding.get("url", ""))
        if per_url_counts[url] >= max_findings_per_url:
            continue
        selected.append(finding)
        per_url_counts[url] += 1

    return selected


def _write_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "finding_id",
        "url",
        "rule_id",
        "wcag_sc",
        "severity",
        "impact",
        "confidence",
        "message",
        "evidence",
        "remediation",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow({field: finding.get(field, "") for field in fieldnames})


class A11yScanTool(Tool):
    """Runs baseline heuristic accessibility checks for URLs."""

    @property
    def name(self) -> str:
        return "a11y_scan"

    @property
    def description(self) -> str:
        return (
            "Run deterministic heuristic accessibility checks on target URLs "
            "with hardened network safety and normalized finding output."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "urls": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "URLs to scan.",
                },
                "max_urls": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 500,
                    "default": 25,
                    "description": "Maximum number of URLs to scan.",
                },
                "max_findings_per_url": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 50,
                    "description": "Maximum findings returned per URL after deduplication.",
                },
                "include_warnings": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include warning-severity findings in output.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 60,
                    "default": 12,
                    "description": "Per-request timeout in seconds.",
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
                    "default": 2000000,
                    "description": "Maximum bytes read from each response body.",
                },
                "user_agent": {
                    "type": "string",
                    "description": "Optional User-Agent override.",
                },
                "output_findings_csv": {
                    "type": "string",
                    "description": "Optional workspace-relative CSV path for findings output.",
                },
            },
            "required": ["urls"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw_urls = args.get("urls")
        if not isinstance(raw_urls, list) or not raw_urls:
            return ToolResult.fail("'urls' must be a non-empty list")

        try:
            max_urls = _clamp_int(args.get("max_urls", 25), 1, 500)
            max_findings_per_url = _clamp_int(
                args.get("max_findings_per_url", 50), 1, 200
            )
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
                args.get("max_fetch_bytes", 2_000_000), 20_000, 5_000_000
            )
        except (TypeError, ValueError):
            return ToolResult.fail("Invalid numeric argument value")

        include_warnings = bool(args.get("include_warnings", True))

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

        normalized_urls: list[str] = []
        warnings: list[dict[str, str]] = []
        warning_keys: set[tuple[str, str, str]] = set()

        def add_warning(code: str, url: str, message: str) -> None:
            key = (code, url, message)
            if key in warning_keys:
                return
            warning_keys.add(key)
            warnings.append(_new_warning(code, url, message))

        for raw in raw_urls:
            normalized = _normalize_url(raw, keep_query=True)
            raw_text = str(raw or "").strip()
            if not normalized:
                add_warning(
                    "invalid_url", raw_text, "Input URL is not a valid HTTP(S) URL."
                )
                continue
            if normalized not in normalized_urls:
                normalized_urls.append(normalized)

        selected_urls = normalized_urls[:max_urls]
        if not selected_urls:
            return ToolResult.fail("No valid HTTP(S) URLs were provided")

        findings: list[dict[str, Any]] = []
        scanned_count = 0
        last_request_by_host: dict[str, float] = {}

        for url in selected_urls:
            try:
                fetched = _fetch_url(
                    url,
                    cfg=cfg,
                    last_request_by_host=last_request_by_host,
                    warnings=warnings,
                )
            except Exception as err:
                message = str(err)
                add_warning("fetch_failed", url, message)
                findings.append(
                    _finding(
                        url=url,
                        rule_id="scan-fetch-failed",
                        wcag_sc="4.1.1",
                        severity="error",
                        impact="high",
                        confidence=0.85,
                        message="Failed to fetch URL during automated scan.",
                        evidence=message,
                        remediation=(
                            "Verify the URL is publicly reachable and retry. "
                            "If protected by auth, run manual checks in an authenticated session."
                        ),
                    ),
                )
                continue

            scanned_count += 1
            target_url = fetched.final_url or url

            if fetched.status_code >= 400:
                findings.append(
                    _finding(
                        url=target_url,
                        rule_id="http-error",
                        wcag_sc="4.1.1",
                        severity="error",
                        impact="high",
                        confidence=0.95,
                        message=f"HTTP error while fetching page (status {fetched.status_code}).",
                        evidence=f"Request returned status {fetched.status_code}.",
                        remediation="Fix the route availability before automated accessibility scanning.",
                    ),
                )
                continue

            if "html" not in fetched.content_type:
                findings.append(
                    _finding(
                        url=target_url,
                        rule_id="non-html-resource",
                        wcag_sc="4.1.1",
                        severity="warning",
                        impact="low",
                        confidence=0.92,
                        message="Resource is not HTML; checks are limited.",
                        evidence=f"Content-Type={fetched.content_type or 'unknown'}",
                        remediation=(
                            "Provide an HTML page for full automated checks or manually evaluate "
                            "downloaded/document content."
                        ),
                    ),
                )
                continue

            findings.extend(_scan_html(target_url, fetched.body))

        deduped_findings = _dedupe_findings(findings)
        if not include_warnings:
            deduped_findings = [
                f for f in deduped_findings if str(f.get("severity", "")) != "warning"
            ]

        bounded_findings = _limit_findings_per_url(
            deduped_findings,
            max_findings_per_url=max_findings_per_url,
        )

        by_severity: dict[str, int] = defaultdict(int)
        for finding in bounded_findings:
            by_severity[str(finding.get("severity", "warning"))] += 1

        files_changed: list[str] = []
        output_csv_path = str(args.get("output_findings_csv", "")).strip()
        if output_csv_path:
            if ctx.workspace is None:
                return ToolResult.fail(
                    "'output_findings_csv' requires an active workspace"
                )
            resolved = self._resolve_path(output_csv_path, ctx.workspace)
            _write_csv(resolved, bounded_findings)
            files_changed.append(str(resolved))

        output_lines = [
            f"URLs requested: {len(selected_urls)}",
            f"URLs scanned: {scanned_count}",
            f"Findings: {len(bounded_findings)}",
            f"Errors: {by_severity.get('error', 0)}",
            f"Warnings: {by_severity.get('warning', 0)}",
            f"Operational warnings: {len(warnings)}",
            "Heuristic scan complete; manual validation is still required for conformance claims.",
        ]

        return ToolResult.ok(
            "\n".join(output_lines),
            data={
                "findings": bounded_findings,
                "warnings": warnings,
                "summary": {
                    "urls_requested": len(selected_urls),
                    "urls_scanned": scanned_count,
                    "finding_count": len(bounded_findings),
                    "by_severity": dict(by_severity),
                    "warning_count": len(warnings),
                },
            },
            files_changed=files_changed,
        )
