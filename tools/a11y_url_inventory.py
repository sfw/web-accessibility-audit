"""URL inventory and sampling tool for accessibility audits.

Production-oriented capabilities:
- SSRF-safe HTTP fetches (public HTTP(S) only, private-network blocking)
- Manual redirect handling with bounded retries/backoff/pacing
- Discovery from robots.txt sitemaps, sitemap indexes, and bounded crawling
- Deterministic template clustering and representative sampling
"""

from __future__ import annotations

import csv
import ipaddress
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from loom.tools.registry import Tool, ToolContext, ToolResult

_DEFAULT_USER_AGENT = "loom-a11y-url-inventory/1.0"
_DEFAULT_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
_DEFAULT_ACCEPT_LANGUAGE = "en-US,en;q=0.9"
_REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}
_TRANSIENT_STATUS_CODES = {408, 425, 429, 500, 502, 503, 504}
_MAX_DEFAULT_FETCH_BYTES = 2_500_000


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
class _RobotsData:
    origin: str
    parser: urllib.robotparser.RobotFileParser
    sitemaps: tuple[str, ...]
    crawl_delay_seconds: float | None


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        href = attr_map.get("href", "").strip()
        if href:
            self.links.append(href)


def _clamp_int(value: Any, minimum: int, maximum: int) -> int:
    return max(minimum, min(int(value), maximum))


def _clamp_float(value: Any, minimum: float, maximum: float) -> float:
    return max(minimum, min(float(value), maximum))


def _parse_csv_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    text = str(raw).strip()
    if not text:
        return []
    return [piece.strip() for piece in text.split(",") if piece.strip()]


def _ensure_url(raw: Any) -> str:
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    return text


def _normalize_url(raw: Any, *, keep_query: bool = False) -> str | None:
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


def _origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))


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
    host: str,
    *,
    cfg: _NetworkConfig,
    last_request_by_host: dict[str, float],
    host_delay_overrides: dict[str, float],
) -> None:
    minimum_delay = max(cfg.request_delay_seconds, host_delay_overrides.get(host, 0.0))
    if minimum_delay <= 0:
        return

    now = time.monotonic()
    previous = last_request_by_host.get(host)
    if previous is not None:
        wait_for = minimum_delay - (now - previous)
        if wait_for > 0:
            time.sleep(wait_for)

    last_request_by_host[host] = time.monotonic()


def _new_warning(code: str, url: str, message: str) -> dict[str, str]:
    return {"code": code, "url": url, "message": message}


class _SafeFetcher:
    """Hardened HTTP client with SSRF protections and bounded retries."""

    def __init__(self, cfg: _NetworkConfig) -> None:
        self.cfg = cfg
        self._last_request_by_host: dict[str, float] = {}
        self._host_delay_overrides: dict[str, float] = {}

    def set_host_delay(self, host: str, delay_seconds: float) -> None:
        if delay_seconds <= 0:
            return
        current = self._host_delay_overrides.get(host, 0.0)
        self._host_delay_overrides[host] = max(current, delay_seconds)

    def fetch(
        self,
        url: str,
        *,
        max_bytes: int | None,
        warnings: list[dict[str, str]],
    ) -> _FetchResult:
        effective_max_bytes = (
            max_bytes if max_bytes is not None else self.cfg.max_fetch_bytes
        )
        effective_max_bytes = max(
            20_000, min(int(effective_max_bytes), self.cfg.max_fetch_bytes)
        )

        current = url

        for _ in range(self.cfg.max_redirects + 1):
            host = _host_from_url(current)
            _validate_public_host(host)

            for attempt in range(self.cfg.max_retries + 1):
                _pace_request(
                    host,
                    cfg=self.cfg,
                    last_request_by_host=self._last_request_by_host,
                    host_delay_overrides=self._host_delay_overrides,
                )
                request = urllib.request.Request(
                    current,
                    headers={
                        "User-Agent": self.cfg.user_agent,
                        "Accept": self.cfg.accept,
                        "Accept-Language": self.cfg.accept_language,
                    },
                )

                try:
                    with _NO_REDIRECT_OPENER.open(
                        request, timeout=self.cfg.timeout_seconds
                    ) as response:
                        status_code = int(response.getcode() or 200)
                        headers = {k.lower(): v for k, v in response.headers.items()}
                        payload = response.read(effective_max_bytes + 1)
                        truncated = len(payload) > effective_max_bytes
                        body = payload[:effective_max_bytes].decode(
                            "utf-8", errors="replace"
                        )

                        if truncated:
                            warnings.append(
                                _new_warning(
                                    "response_truncated",
                                    current,
                                    f"Response body exceeded {effective_max_bytes} bytes and was truncated.",
                                ),
                            )

                        if (
                            status_code in _TRANSIENT_STATUS_CODES
                            and attempt < self.cfg.max_retries
                        ):
                            delay_seconds = _compute_backoff_delay(
                                attempt=attempt,
                                cfg=self.cfg,
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
                            raise ValueError(
                                f"Redirect target '{redirected}' is invalid"
                            )

                        _validate_public_host(_host_from_url(normalized))
                        current = normalized
                        break

                    payload = err.read(effective_max_bytes + 1)
                    truncated = len(payload) > effective_max_bytes
                    body = payload[:effective_max_bytes].decode(
                        "utf-8", errors="replace"
                    )

                    if truncated:
                        warnings.append(
                            _new_warning(
                                "response_truncated",
                                current,
                                f"Error response body exceeded {effective_max_bytes} bytes and was truncated.",
                            ),
                        )

                    if (
                        status_code in _TRANSIENT_STATUS_CODES
                        and attempt < self.cfg.max_retries
                    ):
                        delay_seconds = _compute_backoff_delay(
                            attempt=attempt,
                            cfg=self.cfg,
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
                    if attempt < self.cfg.max_retries:
                        delay_seconds = _compute_backoff_delay(
                            attempt=attempt, cfg=self.cfg
                        )
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


def _passes_patterns(
    url: str, includes: list[re.Pattern], excludes: list[re.Pattern]
) -> bool:
    if includes and not any(pattern.search(url) for pattern in includes):
        return False
    if excludes and any(pattern.search(url) for pattern in excludes):
        return False
    return True


def _path_to_template(path: str) -> str:
    if not path or path == "/":
        return "/"

    hex_slug = re.compile(r"^[a-f0-9]{8,}$")
    uuid_like = re.compile(
        r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
    )

    segments: list[str] = []
    for segment in path.strip("/").split("/"):
        token = segment.strip().lower()
        if not token:
            continue
        if (
            token.isdigit()
            or uuid_like.match(token)
            or hex_slug.match(token)
            or (len(token) >= 16 and any(ch.isdigit() for ch in token))
        ):
            segments.append("{id}")
            continue
        segments.append(token)

    return "/" + "/".join(segments) if segments else "/"


def _classify_page_kind(path: str) -> str:
    low = (path or "/").lower()
    if low in {"", "/"}:
        return "home"

    kind_patterns = [
        ("checkout", r"/(cart|checkout|payment|order)(/|$)"),
        ("account", r"/(account|profile|settings|login|signin|signup)(/|$)"),
        ("search", r"/(search|results)(/|$)"),
        ("legal", r"/(privacy|terms|legal|compliance|accessibility)(/|$)"),
        ("help", r"/(help|support|faq|docs)(/|$)"),
        ("blog", r"/(blog|news|article)(/|$)"),
        ("form", r"/(contact|apply|request|register|subscribe)(/|$)"),
        ("api", r"/api(/|$)"),
    ]
    for name, pattern in kind_patterns:
        if re.search(pattern, low):
            return name

    if low.endswith((".pdf", ".doc", ".docx", ".ppt", ".pptx")):
        return "document"

    return "content"


def _extract_links(base_url: str, html_text: str, *, keep_query: bool) -> list[str]:
    parser = _LinkExtractor()
    parser.feed(html_text)
    parser.close()

    links: list[str] = []
    for href in parser.links:
        absolute = urllib.parse.urljoin(base_url, href)
        normalized = _normalize_url(absolute, keep_query=keep_query)
        if normalized:
            links.append(normalized)
    return links


def _parse_sitemap_document(
    xml_or_text: str, *, keep_query: bool
) -> tuple[list[str], list[str]]:
    xml_content = xml_or_text.strip()
    if not xml_content:
        return [], []

    try:
        root = ElementTree.fromstring(xml_content)
    except ElementTree.ParseError:
        urls: list[str] = []
        for line in xml_content.splitlines():
            normalized = _normalize_url(line.strip(), keep_query=keep_query)
            if normalized:
                urls.append(normalized)
        return urls, []

    tag = root.tag.lower()

    if tag.endswith("urlset"):
        urls: list[str] = []
        for node in root.findall(".//{*}loc"):
            if node.text:
                normalized = _normalize_url(node.text.strip(), keep_query=keep_query)
                if normalized:
                    urls.append(normalized)
        return urls, []

    if tag.endswith("sitemapindex"):
        sitemap_urls: list[str] = []
        for node in root.findall(".//{*}loc"):
            if node.text:
                normalized = _normalize_url(node.text.strip(), keep_query=keep_query)
                if normalized:
                    sitemap_urls.append(normalized)
        return [], sitemap_urls

    return [], []


def _is_allowed_host(
    host: str, allowed_hosts: set[str], include_subdomains: bool
) -> bool:
    if host in allowed_hosts:
        return True
    if not include_subdomains:
        return False
    return any(host.endswith(f".{allowed}") for allowed in allowed_hosts)


def _parse_robots_sitemaps(text: str, *, default_origin: str) -> list[str]:
    urls: list[str] = []
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if not stripped.lower().startswith("sitemap:"):
            continue
        _, value = stripped.split(":", 1)
        normalized = _normalize_url(value.strip(), keep_query=False)
        if normalized:
            urls.append(normalized)

    default_sitemap = _normalize_url(f"{default_origin}/sitemap.xml", keep_query=False)
    if default_sitemap:
        urls.append(default_sitemap)

    # Preserve order while deduping.
    seen: set[str] = set()
    ordered: list[str] = []
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        ordered.append(url)
    return ordered


def _load_robots_data(
    origin: str,
    *,
    fetcher: _SafeFetcher,
    warnings: list[dict[str, str]],
) -> _RobotsData | None:
    robots_url = f"{origin}/robots.txt"

    try:
        fetched = fetcher.fetch(robots_url, max_bytes=500_000, warnings=warnings)
    except Exception as err:
        warnings.append(
            _new_warning(
                "robots_fetch_failed",
                robots_url,
                f"Failed to fetch robots.txt: {err}",
            ),
        )
        return None

    if fetched.status_code >= 400:
        warnings.append(
            _new_warning(
                "robots_http_error",
                robots_url,
                f"robots.txt returned HTTP {fetched.status_code}",
            ),
        )
        return None

    parser = urllib.robotparser.RobotFileParser()
    parser.set_url(robots_url)
    parser.parse(fetched.body.splitlines())

    crawl_delay = parser.crawl_delay(fetcher.cfg.user_agent)
    if crawl_delay is None:
        crawl_delay = parser.crawl_delay("*")

    if crawl_delay is not None:
        fetcher.set_host_delay(_host_from_url(origin), float(crawl_delay))

    sitemaps = _parse_robots_sitemaps(fetched.body, default_origin=origin)

    return _RobotsData(
        origin=origin,
        parser=parser,
        sitemaps=tuple(sitemaps),
        crawl_delay_seconds=(float(crawl_delay) if crawl_delay is not None else None),
    )


def _get_robots_data(
    origin: str,
    *,
    cache: dict[str, _RobotsData | None],
    fetcher: _SafeFetcher,
    warnings: list[dict[str, str]],
) -> _RobotsData | None:
    if origin not in cache:
        cache[origin] = _load_robots_data(origin, fetcher=fetcher, warnings=warnings)
    return cache[origin]


def _discover_from_sitemaps(
    seeds: list[str],
    *,
    allowed_hosts: set[str],
    include_subdomains: bool,
    keep_query: bool,
    max_sitemap_urls: int,
    max_sitemap_files: int,
    fetcher: _SafeFetcher,
    warnings: list[dict[str, str]],
    robots_cache: dict[str, _RobotsData | None],
) -> dict[str, dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}

    root_sitemaps: set[str] = set()
    for seed in seeds:
        origin = _origin(seed)
        robots_data = _get_robots_data(
            origin,
            cache=robots_cache,
            fetcher=fetcher,
            warnings=warnings,
        )
        if robots_data:
            root_sitemaps.update(robots_data.sitemaps)
        else:
            fallback = _normalize_url(f"{origin}/sitemap.xml", keep_query=False)
            if fallback:
                root_sitemaps.add(fallback)

    to_process: deque[str] = deque(sorted(root_sitemaps))
    processed: set[str] = set()

    while (
        to_process
        and len(processed) < max_sitemap_files
        and len(discovered) < max_sitemap_urls
    ):
        sitemap_url = to_process.popleft()
        if sitemap_url in processed:
            continue
        processed.add(sitemap_url)

        host = _host_from_url(sitemap_url)
        if not _is_allowed_host(host, allowed_hosts, include_subdomains):
            continue

        try:
            fetched = fetcher.fetch(sitemap_url, max_bytes=None, warnings=warnings)
        except Exception as err:
            warnings.append(
                _new_warning(
                    "sitemap_fetch_failed",
                    sitemap_url,
                    f"Failed to fetch sitemap: {err}",
                ),
            )
            continue

        if fetched.status_code >= 400:
            warnings.append(
                _new_warning(
                    "sitemap_http_error",
                    sitemap_url,
                    f"Sitemap returned HTTP {fetched.status_code}",
                ),
            )
            continue

        urls, nested_sitemaps = _parse_sitemap_document(
            fetched.body, keep_query=keep_query
        )

        for page_url in urls:
            page_host = _host_from_url(page_url)
            if not _is_allowed_host(page_host, allowed_hosts, include_subdomains):
                continue
            discovered.setdefault(
                page_url,
                {
                    "url": page_url,
                    "source": "sitemap",
                    "depth": 0,
                    "status_code": None,
                    "content_type": "",
                    "truncated": False,
                    "blocked_by_robots": False,
                },
            )
            if len(discovered) >= max_sitemap_urls:
                break

        for nested in sorted(nested_sitemaps):
            if nested not in processed:
                to_process.append(nested)

    return discovered


def _crawl_same_origin(
    seeds: list[str],
    *,
    allowed_hosts: set[str],
    include_subdomains: bool,
    crawl_depth: int,
    max_discovered_urls: int,
    keep_query: bool,
    respect_robots: bool,
    fetcher: _SafeFetcher,
    warnings: list[dict[str, str]],
    robots_cache: dict[str, _RobotsData | None],
) -> dict[str, dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}

    queue: deque[tuple[str, int, str]] = deque()
    for seed in seeds:
        queue.append((seed, 0, "seed"))

    visited: set[str] = set()
    robots_block_reported: set[str] = set()

    while queue and len(discovered) < max_discovered_urls:
        current_url, depth, source = queue.popleft()
        if current_url in visited:
            continue
        visited.add(current_url)

        host = _host_from_url(current_url)
        if not _is_allowed_host(host, allowed_hosts, include_subdomains):
            continue

        blocked_by_robots = False
        if respect_robots:
            origin = _origin(current_url)
            robots_data = _get_robots_data(
                origin,
                cache=robots_cache,
                fetcher=fetcher,
                warnings=warnings,
            )
            if robots_data and not robots_data.parser.can_fetch(
                fetcher.cfg.user_agent, current_url
            ):
                blocked_by_robots = True
                if current_url not in robots_block_reported:
                    warnings.append(
                        _new_warning(
                            "robots_disallow",
                            current_url,
                            "URL blocked by robots.txt policy for configured user-agent.",
                        ),
                    )
                    robots_block_reported.add(current_url)

        if blocked_by_robots:
            discovered.setdefault(
                current_url,
                {
                    "url": current_url,
                    "source": source,
                    "depth": depth,
                    "status_code": None,
                    "content_type": "",
                    "truncated": False,
                    "blocked_by_robots": True,
                },
            )
            continue

        status_code: int | None = None
        content_type = ""
        body = ""
        truncated = False

        try:
            fetched = fetcher.fetch(current_url, max_bytes=None, warnings=warnings)
            status_code = fetched.status_code
            content_type = fetched.content_type
            body = fetched.body
            truncated = fetched.truncated
        except Exception as err:
            warnings.append(
                _new_warning(
                    "crawl_fetch_failed",
                    current_url,
                    f"Failed to fetch URL during crawl: {err}",
                ),
            )

        discovered.setdefault(
            current_url,
            {
                "url": current_url,
                "source": source,
                "depth": depth,
                "status_code": status_code,
                "content_type": content_type,
                "truncated": truncated,
                "blocked_by_robots": False,
            },
        )

        if depth >= crawl_depth:
            continue

        if status_code is None or status_code >= 400 or "html" not in content_type:
            continue

        for next_url in sorted(
            _extract_links(current_url, body, keep_query=keep_query)
        ):
            next_host = _host_from_url(next_url)
            if not _is_allowed_host(next_host, allowed_hosts, include_subdomains):
                continue
            if next_url in visited:
                continue
            if len(discovered) + len(queue) >= max_discovered_urls:
                break
            queue.append((next_url, depth + 1, "crawl"))

    return discovered


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({name: row.get(name, "") for name in fieldnames})


class A11yUrlInventoryTool(Tool):
    """Discovers candidate URLs and proposes a deterministic representative sample."""

    @property
    def name(self) -> str:
        return "a11y_url_inventory"

    @property
    def description(self) -> str:
        return (
            "Build URL inventory and representative sample for accessibility audits. "
            "Includes robots/sitemap discovery and bounded same-origin crawling."
        )

    @property
    def parameters(self) -> dict:
        return {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Seed URLs or domains to inventory.",
                },
                "max_urls": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1000,
                    "default": 75,
                    "description": "Maximum representative sample size.",
                },
                "max_discovered_urls": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 10000,
                    "default": 1500,
                    "description": "Upper bound on discovered URLs before sampling.",
                },
                "max_sitemap_urls": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 10000,
                    "default": 3000,
                    "description": "Upper bound on URLs sourced from sitemap documents.",
                },
                "max_sitemap_files": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 200,
                    "default": 40,
                    "description": "Maximum sitemap/index files parsed.",
                },
                "crawl_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 4,
                    "default": 1,
                    "description": "Same-origin crawl depth from known URLs.",
                },
                "include_sitemap": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable robots/sitemap discovery.",
                },
                "respect_robots": {
                    "type": "boolean",
                    "default": True,
                    "description": "Respect robots.txt allow/disallow rules during crawl discovery.",
                },
                "include_subdomains": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow hosts under seed domains.",
                },
                "keep_query_params": {
                    "type": "boolean",
                    "default": False,
                    "description": "Preserve URL query strings during normalization.",
                },
                "include_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regex patterns URLs must match.",
                },
                "exclude_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regex patterns URLs must not match.",
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
                    "default": 2500000,
                    "description": "Maximum bytes read from each response body.",
                },
                "user_agent": {
                    "type": "string",
                    "description": "Optional User-Agent override.",
                },
                "output_inventory_csv": {
                    "type": "string",
                    "description": "Optional workspace-relative CSV path for full inventory.",
                },
                "output_sample_csv": {
                    "type": "string",
                    "description": "Optional workspace-relative CSV path for representative sample.",
                },
                "output_templates_csv": {
                    "type": "string",
                    "description": "Optional workspace-relative CSV path for template summary.",
                },
            },
            "required": ["targets"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        raw_targets = _parse_csv_list(args.get("targets"))
        if not raw_targets:
            return ToolResult.fail("'targets' must be a non-empty list")

        keep_query = bool(args.get("keep_query_params", False))

        try:
            max_urls = _clamp_int(args.get("max_urls", 75), 1, 1000)
            max_discovered_urls = _clamp_int(
                args.get("max_discovered_urls", 1500), max_urls, 10_000
            )
            max_sitemap_urls = _clamp_int(
                args.get("max_sitemap_urls", 3000), 10, 10_000
            )
            max_sitemap_files = _clamp_int(args.get("max_sitemap_files", 40), 1, 200)
            crawl_depth = _clamp_int(args.get("crawl_depth", 1), 0, 4)

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
                args.get("max_fetch_bytes", _MAX_DEFAULT_FETCH_BYTES), 20_000, 5_000_000
            )
        except (TypeError, ValueError):
            return ToolResult.fail("Invalid numeric argument value")

        include_sitemap = bool(args.get("include_sitemap", True))
        include_subdomains = bool(args.get("include_subdomains", False))
        respect_robots = bool(args.get("respect_robots", True))

        try:
            include_patterns = [
                re.compile(pattern)
                for pattern in _parse_csv_list(args.get("include_patterns"))
            ]
            exclude_patterns = [
                re.compile(pattern)
                for pattern in _parse_csv_list(args.get("exclude_patterns"))
            ]
        except re.error as err:
            return ToolResult.fail(f"Invalid include/exclude regex: {err}")

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
        fetcher = _SafeFetcher(cfg)

        warnings: list[dict[str, str]] = []
        warning_keys: set[tuple[str, str, str]] = set()

        def add_warning(code: str, url: str, message: str) -> None:
            key = (code, url, message)
            if key in warning_keys:
                return
            warning_keys.add(key)
            warnings.append(_new_warning(code, url, message))

        seeds: list[str] = []
        for target in raw_targets:
            normalized = _normalize_url(target, keep_query=keep_query)
            if not normalized:
                add_warning(
                    "invalid_target",
                    str(target),
                    "Target is not a valid HTTP(S) URL/domain.",
                )
                continue
            if normalized not in seeds:
                seeds.append(normalized)

        if not seeds:
            return ToolResult.fail("No valid HTTP(S) targets were provided")

        allowed_hosts = {_host_from_url(url) for url in seeds}
        robots_cache: dict[str, _RobotsData | None] = {}

        discovered: dict[str, dict[str, Any]] = {}
        for seed in seeds:
            discovered.setdefault(
                seed,
                {
                    "url": seed,
                    "source": "seed",
                    "depth": 0,
                    "status_code": None,
                    "content_type": "",
                    "truncated": False,
                    "blocked_by_robots": False,
                },
            )

        if include_sitemap:
            from_sitemaps = _discover_from_sitemaps(
                seeds,
                allowed_hosts=allowed_hosts,
                include_subdomains=include_subdomains,
                keep_query=keep_query,
                max_sitemap_urls=max_sitemap_urls,
                max_sitemap_files=max_sitemap_files,
                fetcher=fetcher,
                warnings=warnings,
                robots_cache=robots_cache,
            )
            for url, row in from_sitemaps.items():
                if len(discovered) >= max_discovered_urls:
                    break
                discovered.setdefault(url, row)

        from_crawl = _crawl_same_origin(
            sorted(discovered.keys()),
            allowed_hosts=allowed_hosts,
            include_subdomains=include_subdomains,
            crawl_depth=crawl_depth,
            max_discovered_urls=max_discovered_urls,
            keep_query=keep_query,
            respect_robots=respect_robots,
            fetcher=fetcher,
            warnings=warnings,
            robots_cache=robots_cache,
        )

        for url, row in from_crawl.items():
            if len(discovered) >= max_discovered_urls:
                break
            discovered.setdefault(url, row)

        inventory_rows: list[dict[str, Any]] = []
        for url, base_row in discovered.items():
            host = _host_from_url(url)
            if not _is_allowed_host(host, allowed_hosts, include_subdomains):
                continue
            if not _passes_patterns(url, include_patterns, exclude_patterns):
                continue

            path = urllib.parse.urlsplit(url).path or "/"
            template = _path_to_template(path)

            inventory_rows.append(
                {
                    "url": url,
                    "host": host,
                    "path": path,
                    "template": template,
                    "page_kind": _classify_page_kind(path),
                    "source": base_row.get("source", ""),
                    "depth": base_row.get("depth", ""),
                    "status_code": base_row.get("status_code", ""),
                    "content_type": base_row.get("content_type", ""),
                    "truncated": bool(base_row.get("truncated", False)),
                    "blocked_by_robots": bool(base_row.get("blocked_by_robots", False)),
                },
            )

        inventory_rows.sort(key=lambda row: str(row.get("url", "")))

        template_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in inventory_rows:
            template_groups[str(row["template"])].append(row)

        sample_rows: list[dict[str, Any]] = []

        # Pass 1: one representative per template to maximize template coverage.
        for template in sorted(template_groups):
            rows = sorted(template_groups[template], key=lambda item: str(item["url"]))
            selected = rows[0]
            sample_rows.append(
                {
                    "url": selected["url"],
                    "template": template,
                    "page_kind": selected["page_kind"],
                    "source": selected["source"],
                    "sample_reason": "template_coverage",
                },
            )
            if len(sample_rows) >= max_urls:
                break

        # Pass 2: round-robin through remaining URLs in each template bucket.
        if len(sample_rows) < max_urls:
            remaining: list[list[dict[str, Any]]] = []
            for template in sorted(template_groups):
                rows = sorted(
                    template_groups[template], key=lambda item: str(item["url"])
                )
                remaining.append(rows[1:])

            offset = 0
            while len(sample_rows) < max_urls:
                added = False
                for rows in remaining:
                    if offset >= len(rows):
                        continue
                    row = rows[offset]
                    sample_rows.append(
                        {
                            "url": row["url"],
                            "template": row["template"],
                            "page_kind": row["page_kind"],
                            "source": row["source"],
                            "sample_reason": "template_round_robin",
                        },
                    )
                    added = True
                    if len(sample_rows) >= max_urls:
                        break
                if not added:
                    break
                offset += 1

        template_counts = [
            {
                "template": template,
                "count": len(rows),
                "representative_url": sorted(rows, key=lambda item: str(item["url"]))[
                    0
                ]["url"],
            }
            for template, rows in sorted(
                template_groups.items(),
                key=lambda item: (-len(item[1]), item[0]),
            )
        ]

        files_changed: list[str] = []
        output_mapping = {
            "output_inventory_csv": (
                inventory_rows,
                [
                    "url",
                    "host",
                    "path",
                    "template",
                    "page_kind",
                    "source",
                    "depth",
                    "status_code",
                    "content_type",
                    "truncated",
                    "blocked_by_robots",
                ],
            ),
            "output_sample_csv": (
                sample_rows,
                ["url", "template", "page_kind", "source", "sample_reason"],
            ),
            "output_templates_csv": (
                template_counts,
                ["template", "count", "representative_url"],
            ),
        }

        for arg_key, (rows, fieldnames) in output_mapping.items():
            raw_output_path = str(args.get(arg_key, "")).strip()
            if not raw_output_path:
                continue
            if ctx.workspace is None:
                return ToolResult.fail(f"'{arg_key}' requires an active workspace")
            resolved = self._resolve_path(raw_output_path, ctx.workspace)
            _write_csv(resolved, rows, fieldnames)
            files_changed.append(str(resolved))

        output_lines = [
            f"Seeds: {len(seeds)}",
            f"Discovered URLs: {len(inventory_rows)}",
            f"Representative sample: {len(sample_rows)}",
            f"Template groups: {len(template_counts)}",
            f"Operational warnings: {len(warnings)}",
        ]

        top_templates = template_counts[:8]
        if top_templates:
            output_lines.append("Top templates:")
            for row in top_templates:
                output_lines.append(f"  {row['template']} ({row['count']})")

        return ToolResult.ok(
            "\n".join(output_lines),
            data={
                "inventory": inventory_rows,
                "sample": sample_rows,
                "template_counts": template_counts,
                "warnings": warnings,
                # Backward-compatible aliases.
                "discovered_urls": [row["url"] for row in inventory_rows],
                "sample_urls": [row["url"] for row in sample_rows],
            },
            files_changed=files_changed,
        )
