"""Heuristic accessibility scanner for sampled URLs."""

from __future__ import annotations

import urllib.request
from html.parser import HTMLParser
from typing import Any

from loom.tools.registry import Tool, ToolContext, ToolResult

_MAX_FETCH_BYTES = 2_000_000


class _A11yParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_html_lang = False
        self._in_title = 0
        self.title_parts: list[str] = []

        self.images: list[dict[str, Any]] = []
        self.anchors: list[dict[str, Any]] = []
        self._anchor_stack: list[dict[str, Any]] = []

        self.labels_for: set[str] = set()
        self.controls: list[dict[str, Any]] = []
        self._in_label_depth = 0

        self.heading_levels: list[int] = []
        self.landmarks: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {k: (v or "") for k, v in attrs}

        if tag_name == "html" and attr_map.get("lang", "").strip():
            self.has_html_lang = True

        if tag_name == "title":
            self._in_title += 1

        if tag_name == "img":
            self.images.append({"attrs": attr_map})

        if tag_name == "a":
            self._anchor_stack.append({"attrs": attr_map, "text": []})

        if tag_name == "label":
            self._in_label_depth += 1
            label_for = attr_map.get("for", "").strip()
            if label_for:
                self.labels_for.add(label_for)

        if tag_name in {"input", "select", "textarea"}:
            self.controls.append(
                {
                    "tag": tag_name,
                    "attrs": attr_map,
                    "wrapped_by_label": self._in_label_depth > 0,
                },
            )

        if tag_name.startswith("h") and len(tag_name) == 2 and tag_name[1].isdigit():
            level = int(tag_name[1])
            if 1 <= level <= 6:
                self.heading_levels.append(level)

        if tag_name in {"main", "nav", "header", "footer", "aside", "form"}:
            self.landmarks.add(tag_name)
        role_value = attr_map.get("role", "").strip().lower()
        if role_value:
            self.landmarks.add(f"role:{role_value}")

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()

        if tag_name == "title" and self._in_title > 0:
            self._in_title -= 1

        if tag_name == "a" and self._anchor_stack:
            self.anchors.append(self._anchor_stack.pop())

        if tag_name == "label" and self._in_label_depth > 0:
            self._in_label_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title > 0:
            self.title_parts.append(data)

        if self._anchor_stack:
            self._anchor_stack[-1]["text"].append(data)


def _fetch_html(url: str, timeout_seconds: int) -> tuple[int, str, str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "loom-a11y-scan/0.1"},
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status_code = int(getattr(response, "status", 200))
        content_type = str(response.headers.get("Content-Type", "")).lower()
        payload = response.read(_MAX_FETCH_BYTES)

    return status_code, content_type, payload.decode("utf-8", errors="replace")


def _new_issue(
    url: str,
    rule_id: str,
    wcag_sc: str,
    severity: str,
    message: str,
    evidence: str,
) -> dict[str, str]:
    return {
        "url": url,
        "rule_id": rule_id,
        "wcag_sc": wcag_sc,
        "severity": severity,
        "message": message,
        "evidence": evidence,
    }


def _scan_html(url: str, html_text: str) -> list[dict[str, str]]:
    parser = _A11yParser()
    parser.feed(html_text)

    issues: list[dict[str, str]] = []

    if not parser.has_html_lang:
        issues.append(
            _new_issue(
                url,
                "html-lang-missing",
                "3.1.1",
                "error",
                "Missing or empty lang attribute on html element.",
                "<html> has no valid lang attribute.",
            ),
        )

    title_text = "".join(parser.title_parts).strip()
    if not title_text:
        issues.append(
            _new_issue(
                url,
                "page-title-missing",
                "2.4.2",
                "error",
                "Missing or empty page title.",
                "No non-empty <title> element detected.",
            ),
        )

    for idx, image in enumerate(parser.images, start=1):
        alt_text = image["attrs"].get("alt", "")
        if alt_text == "":
            issues.append(
                _new_issue(
                    url,
                    "image-alt-missing",
                    "1.1.1",
                    "error",
                    "Image element missing alt text.",
                    f"Image #{idx} has no alt attribute.",
                ),
            )

    for idx, anchor in enumerate(parser.anchors, start=1):
        text_content = "".join(anchor["text"]).strip()
        attrs = anchor["attrs"]
        aria_label = attrs.get("aria-label", "").strip()
        title_attr = attrs.get("title", "").strip()
        if not text_content and not aria_label and not title_attr:
            issues.append(
                _new_issue(
                    url,
                    "link-name-missing",
                    "2.4.4",
                    "error",
                    "Link has no accessible name.",
                    f"Anchor #{idx} has no text, aria-label, or title.",
                ),
            )

    for idx, control in enumerate(parser.controls, start=1):
        attrs = control["attrs"]
        tag_name = control["tag"]

        if tag_name == "input":
            input_type = attrs.get("type", "text").strip().lower()
            if input_type in {"hidden", "submit", "reset", "button", "image"}:
                continue

        control_id = attrs.get("id", "").strip()
        has_aria = bool(
            attrs.get("aria-label", "").strip() or attrs.get("aria-labelledby", "").strip()
        )
        has_label_for = bool(control_id and control_id in parser.labels_for)
        wrapped = bool(control.get("wrapped_by_label", False))

        if not has_aria and not has_label_for and not wrapped:
            issues.append(
                _new_issue(
                    url,
                    "form-control-label-missing",
                    "1.3.1",
                    "error",
                    "Form control missing associated accessible label.",
                    f"Control #{idx} ({tag_name}) has no label association.",
                ),
            )

    previous_level = 0
    for level in parser.heading_levels:
        if previous_level and level > previous_level + 1:
            issues.append(
                _new_issue(
                    url,
                    "heading-level-skip",
                    "1.3.1",
                    "warning",
                    "Heading level skip detected.",
                    f"Heading jumped from h{previous_level} to h{level}.",
                ),
            )
            break
        previous_level = level

    if "main" not in parser.landmarks and "role:main" not in parser.landmarks:
        issues.append(
            _new_issue(
                url,
                "main-landmark-missing",
                "1.3.1",
                "warning",
                "No main landmark detected.",
                "Neither <main> nor role='main' found.",
            ),
        )

    return issues


class A11yScanTool(Tool):
    """Runs baseline heuristic accessibility checks for URLs."""

    @property
    def name(self) -> str:
        return "a11y_scan"

    @property
    def description(self) -> str:
        return (
            "Run baseline heuristic accessibility checks on target URLs and "
            "return WCAG-mapped findings."
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
                    "default": 25,
                    "description": "Max URLs to scan from input list.",
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 10,
                    "description": "HTTP timeout per URL.",
                },
            },
            "required": ["urls"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        urls = args.get("urls", [])
        if not isinstance(urls, list) or not urls:
            return ToolResult.fail("'urls' must be a non-empty list")

        max_urls = int(args.get("max_urls", 25))
        max_urls = max(1, min(max_urls, 100))

        timeout_seconds = int(args.get("timeout_seconds", 10))
        timeout_seconds = max(1, min(timeout_seconds, 30))

        selected_urls = [str(url).strip() for url in urls[:max_urls] if str(url).strip()]
        if not selected_urls:
            return ToolResult.fail("No usable URLs were provided")

        findings: list[dict[str, str]] = []
        scanned_count = 0

        for url in selected_urls:
            try:
                status_code, content_type, body = _fetch_html(url, timeout_seconds)
                scanned_count += 1
                if status_code >= 400:
                    findings.append(
                        _new_issue(
                            url,
                            "http-error",
                            "4.1.1",
                            "error",
                            f"HTTP error while fetching page (status {status_code}).",
                            "URL returned an error status during automated scan.",
                        ),
                    )
                    continue
                if "html" not in content_type:
                    findings.append(
                        _new_issue(
                            url,
                            "non-html-resource",
                            "4.1.1",
                            "warning",
                            "Resource is not HTML; limited accessibility checks applied.",
                            f"Content-Type={content_type}",
                        ),
                    )
                    continue

                findings.extend(_scan_html(url, body))
            except Exception as err:
                findings.append(
                    _new_issue(
                        url,
                        "scan-fetch-failed",
                        "4.1.1",
                        "error",
                        "Failed to fetch URL during automated scan.",
                        str(err),
                    ),
                )

        by_severity: dict[str, int] = {"error": 0, "warning": 0}
        for finding in findings:
            severity = finding.get("severity", "warning")
            by_severity[severity] = by_severity.get(severity, 0) + 1

        output_lines = [
            f"URLs scanned: {scanned_count}",
            f"Findings: {len(findings)}",
            f"Errors: {by_severity.get('error', 0)}",
            f"Warnings: {by_severity.get('warning', 0)}",
            "Note: Heuristic scanner output requires manual validation.",
        ]

        return ToolResult.ok(
            "\n".join(output_lines),
            data={
                "findings": findings,
                "summary": {
                    "urls_scanned": scanned_count,
                    "finding_count": len(findings),
                    "by_severity": by_severity,
                },
            },
        )
