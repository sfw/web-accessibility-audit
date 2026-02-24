"""URL inventory and sampling tool for accessibility audits."""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from html.parser import HTMLParser
from xml.etree import ElementTree

from loom.tools.registry import Tool, ToolContext, ToolResult

_MAX_FETCH_BYTES = 2_000_000


class _LinkExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attr_map = {k: (v or "") for k, v in attrs}
        href = attr_map.get("href", "").strip()
        if href:
            self.links.append(href)


def _normalize_url(raw: str) -> str | None:
    try:
        parts = urllib.parse.urlsplit(raw)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        return None
    netloc = parts.netloc.lower().strip()
    if not netloc:
        return None
    path = parts.path or "/"
    return urllib.parse.urlunsplit((scheme, netloc, path, "", ""))


def _url_origin(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _path_to_template(path: str) -> str:
    if not path or path == "/":
        return "/"

    slug_like = re.compile(r"^[a-f0-9]{8,}$")
    uuid_like = re.compile(
        r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
    )

    segments = []
    for segment in path.strip("/").split("/"):
        cleaned = segment.strip()
        if not cleaned:
            continue
        lowered = cleaned.lower()
        if (
            lowered.isdigit()
            or uuid_like.match(lowered)
            or slug_like.match(lowered)
            or (len(lowered) >= 16 and any(c.isdigit() for c in lowered))
        ):
            segments.append("{id}")
        else:
            segments.append(lowered)

    return "/" + "/".join(segments) if segments else "/"


def _fetch_text(url: str, timeout_seconds: int) -> tuple[str, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "loom-a11y-url-inventory/0.1"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        content_type = str(response.headers.get("Content-Type", "")).lower()
        raw = response.read(_MAX_FETCH_BYTES)
    text = raw.decode("utf-8", errors="replace")
    return content_type, text


def _extract_sitemap_urls(seed_url: str, timeout_seconds: int) -> list[str]:
    origin = _url_origin(seed_url)
    sitemap_url = f"{origin}/sitemap.xml"
    try:
        _, xml_text = _fetch_text(sitemap_url, timeout_seconds)
    except Exception:
        return []

    try:
        root = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        return []

    urls: list[str] = []
    for node in root.findall(".//{*}loc"):
        if node.text:
            normalized = _normalize_url(node.text.strip())
            if normalized:
                urls.append(normalized)
    return urls


def _extract_links(page_url: str, html_text: str) -> list[str]:
    parser = _LinkExtractor()
    parser.feed(html_text)
    found: list[str] = []
    for href in parser.links:
        absolute = urllib.parse.urljoin(page_url, href)
        normalized = _normalize_url(absolute)
        if normalized:
            found.append(normalized)
    return found


def _passes_patterns(url: str, includes: list[re.Pattern], excludes: list[re.Pattern]) -> bool:
    if includes and not any(p.search(url) for p in includes):
        return False
    if excludes and any(p.search(url) for p in excludes):
        return False
    return True


class A11yUrlInventoryTool(Tool):
    """Discovers candidate URLs and proposes a representative sample."""

    @property
    def name(self) -> str:
        return "a11y_url_inventory"

    @property
    def description(self) -> str:
        return (
            "Build URL inventory and representative sample for accessibility audits. "
            "Can discover URLs via sitemap and limited same-origin crawling."
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
                    "default": 50,
                    "description": "Maximum representative sample size to return.",
                },
                "crawl_depth": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 2,
                    "default": 1,
                    "description": "Same-origin crawl depth from seed URLs.",
                },
                "include_sitemap": {
                    "type": "boolean",
                    "default": True,
                    "description": "Attempt to pull URLs from /sitemap.xml.",
                },
                "include_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regex patterns URLs must match (optional).",
                },
                "exclude_patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Regex patterns URLs must not match (optional).",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 10,
                    "description": "HTTP timeout for URL discovery requests.",
                },
            },
            "required": ["targets"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        targets = args.get("targets", [])
        if not isinstance(targets, list) or not targets:
            return ToolResult.fail("'targets' must be a non-empty list of URLs")

        normalized_seeds: list[str] = []
        for item in targets:
            normalized = _normalize_url(str(item).strip())
            if normalized:
                normalized_seeds.append(normalized)

        if not normalized_seeds:
            return ToolResult.fail("No valid HTTP(S) targets were provided")

        max_urls = int(args.get("max_urls", 50))
        max_urls = max(1, min(max_urls, 500))

        crawl_depth = int(args.get("crawl_depth", 1))
        crawl_depth = max(0, min(crawl_depth, 2))

        include_sitemap = bool(args.get("include_sitemap", True))

        timeout_seconds = int(args.get("timeout_seconds", 10))
        timeout_seconds = max(1, min(timeout_seconds, 30))

        include_patterns_raw = args.get("include_patterns", []) or []
        exclude_patterns_raw = args.get("exclude_patterns", []) or []

        try:
            include_patterns = [re.compile(str(p)) for p in include_patterns_raw]
            exclude_patterns = [re.compile(str(p)) for p in exclude_patterns_raw]
        except re.error as err:
            return ToolResult.fail(f"Invalid regex in include/exclude patterns: {err}")

        allowed_hosts = {urllib.parse.urlsplit(url).netloc.lower() for url in normalized_seeds}

        discovered: set[str] = set(normalized_seeds)
        queue: deque[tuple[str, int]] = deque((url, 0) for url in normalized_seeds)
        visited: set[str] = set()

        if include_sitemap:
            for seed in normalized_seeds:
                for sm_url in _extract_sitemap_urls(seed, timeout_seconds):
                    if urllib.parse.urlsplit(sm_url).netloc.lower() in allowed_hosts:
                        discovered.add(sm_url)
                        queue.append((sm_url, 0))

        crawl_cap = max(max_urls * 4, 200)

        while queue and len(discovered) < crawl_cap:
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue
            visited.add(current_url)

            if depth >= crawl_depth:
                continue

            try:
                content_type, body = _fetch_text(current_url, timeout_seconds)
            except Exception:
                continue

            if "html" not in content_type:
                continue

            for next_url in _extract_links(current_url, body):
                if urllib.parse.urlsplit(next_url).netloc.lower() not in allowed_hosts:
                    continue
                if next_url not in discovered:
                    discovered.add(next_url)
                    queue.append((next_url, depth + 1))

        filtered = [
            url
            for url in sorted(discovered)
            if _passes_patterns(url, include_patterns, exclude_patterns)
        ]

        template_groups: dict[str, list[str]] = defaultdict(list)
        for url in filtered:
            path = urllib.parse.urlsplit(url).path
            template_groups[_path_to_template(path)].append(url)

        sample: list[str] = []
        # First pass: one representative URL per template.
        for template in sorted(template_groups):
            sample.append(sorted(template_groups[template])[0])
            if len(sample) >= max_urls:
                break

        # Second pass: round-robin fill remaining slots.
        if len(sample) < max_urls:
            ordered_templates = [sorted(template_groups[t])[1:] for t in sorted(template_groups)]
            i = 0
            while len(sample) < max_urls:
                added_any = False
                for urls in ordered_templates:
                    if i < len(urls):
                        sample.append(urls[i])
                        added_any = True
                        if len(sample) >= max_urls:
                            break
                if not added_any:
                    break
                i += 1

        template_counts = [
            {"template": template, "count": len(urls)}
            for template, urls in sorted(
                template_groups.items(), key=lambda item: (-len(item[1]), item[0])
            )
        ]

        output_lines = [
            f"Discovered URLs: {len(filtered)}",
            f"Representative sample size: {len(sample)}",
            f"Templates identified: {len(template_counts)}",
        ]

        top_templates = template_counts[:10]
        if top_templates:
            output_lines.append("Top templates:")
            for row in top_templates:
                output_lines.append(f"  {row['template']} ({row['count']})")

        return ToolResult.ok(
            "\n".join(output_lines),
            data={
                "discovered_urls": filtered,
                "sample_urls": sample,
                "template_counts": template_counts,
            },
        )
