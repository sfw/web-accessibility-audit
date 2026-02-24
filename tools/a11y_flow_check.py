"""Critical journey flow checker for accessibility audit runs."""

from __future__ import annotations

import urllib.parse
import urllib.request
from html.parser import HTMLParser
from typing import Any

from loom.tools.registry import Tool, ToolContext, ToolResult

_MAX_FETCH_BYTES = 1_500_000


class _SignalParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.has_html_lang = False
        self._in_title = 0
        self.title_parts: list[str] = []
        self.has_main = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_name = tag.lower()
        attr_map = {k: (v or "") for k, v in attrs}

        if tag_name == "html" and attr_map.get("lang", "").strip():
            self.has_html_lang = True
        if tag_name == "title":
            self._in_title += 1
        if tag_name == "main":
            self.has_main = True
        if attr_map.get("role", "").strip().lower() == "main":
            self.has_main = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title" and self._in_title > 0:
            self._in_title -= 1

    def handle_data(self, data: str) -> None:
        if self._in_title > 0:
            self.title_parts.append(data)


def _is_http_url(url: str) -> bool:
    try:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
    except ValueError:
        return False
    return scheme in {"http", "https"}


def _inspect_step(url: str, timeout_seconds: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "loom-a11y-flow-check/0.1"},
    )

    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        status_code = int(getattr(response, "status", 200))
        content_type = str(response.headers.get("Content-Type", "")).lower()
        payload = response.read(_MAX_FETCH_BYTES)

    result: dict[str, Any] = {
        "url": url,
        "status_code": status_code,
        "content_type": content_type,
        "has_title": False,
        "has_html_lang": False,
        "has_main_landmark": False,
        "notes": [],
    }

    if "html" not in content_type:
        result["notes"].append("Non-HTML response; limited checks.")
        return result

    parser = _SignalParser()
    parser.feed(payload.decode("utf-8", errors="replace"))

    result["has_title"] = bool("".join(parser.title_parts).strip())
    result["has_html_lang"] = parser.has_html_lang
    result["has_main_landmark"] = parser.has_main

    if not result["has_title"]:
        result["notes"].append("Missing or empty page title.")
    if not result["has_html_lang"]:
        result["notes"].append("Missing html lang attribute.")
    if not result["has_main_landmark"]:
        result["notes"].append("Missing main landmark.")

    return result


class A11yFlowCheckTool(Tool):
    """Checks critical journey steps and provides manual test hooks."""

    @property
    def name(self) -> str:
        return "a11y_flow_check"

    @property
    def description(self) -> str:
        return (
            "Validate critical journey step URLs and return automatic signals plus "
            "manual accessibility test checklist hooks."
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
                                "items": {"type": "string"},
                            },
                        },
                        "required": ["name", "steps"],
                    },
                },
                "timeout_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 30,
                    "default": 10,
                    "description": "HTTP timeout per step URL.",
                },
                "require_https": {
                    "type": "boolean",
                    "default": True,
                    "description": "Flag non-HTTPS flow URLs.",
                },
            },
            "required": ["flows"],
        }

    async def execute(self, args: dict, ctx: ToolContext) -> ToolResult:
        flows = args.get("flows", [])
        if not isinstance(flows, list) or not flows:
            return ToolResult.fail("'flows' must be a non-empty list")

        timeout_seconds = int(args.get("timeout_seconds", 10))
        timeout_seconds = max(1, min(timeout_seconds, 30))

        require_https = bool(args.get("require_https", True))

        flow_results: list[dict[str, Any]] = []
        blocker_count = 0

        manual_checklist = [
            "Keyboard-only traversal completes without trap across entire flow.",
            "Visible focus indicator remains clear on every interactive control.",
            "Screen reader announces title, landmarks, and control names correctly.",
            "Form errors are programmatically associated and announced.",
        ]

        for flow in flows:
            if not isinstance(flow, dict):
                continue

            flow_name = str(flow.get("name", "")).strip() or "unnamed-flow"
            steps = flow.get("steps", [])
            if not isinstance(steps, list) or not steps:
                flow_results.append(
                    {
                        "name": flow_name,
                        "status": "needs-attention",
                        "blockers": ["Flow has no steps."],
                        "steps": [],
                    },
                )
                blocker_count += 1
                continue

            step_results: list[dict[str, Any]] = []
            blockers: list[str] = []

            for idx, step_url_raw in enumerate(steps, start=1):
                step_url = str(step_url_raw).strip()
                if not _is_http_url(step_url):
                    blockers.append(f"Step {idx}: invalid URL '{step_url}'.")
                    step_results.append(
                        {
                            "step": idx,
                            "url": step_url,
                            "status": "invalid-url",
                        },
                    )
                    continue

                if require_https and urllib.parse.urlsplit(step_url).scheme.lower() != "https":
                    blockers.append(f"Step {idx}: URL is not HTTPS ({step_url}).")

                try:
                    inspected = _inspect_step(step_url, timeout_seconds)
                    step_payload = {
                        "step": idx,
                        "url": step_url,
                        "status": "ok" if inspected["status_code"] < 400 else "http-error",
                        "status_code": inspected["status_code"],
                        "has_title": inspected["has_title"],
                        "has_html_lang": inspected["has_html_lang"],
                        "has_main_landmark": inspected["has_main_landmark"],
                        "notes": inspected["notes"],
                    }
                    step_results.append(step_payload)

                    if inspected["status_code"] >= 400:
                        blockers.append(
                            f"Step {idx}: HTTP {inspected['status_code']} for {step_url}.",
                        )
                except Exception as err:
                    step_results.append(
                        {
                            "step": idx,
                            "url": step_url,
                            "status": "fetch-failed",
                            "error": str(err),
                        },
                    )
                    blockers.append(f"Step {idx}: failed to fetch {step_url} ({err}).")

            flow_status = "pass" if not blockers else "needs-attention"
            if blockers:
                blocker_count += 1

            flow_results.append(
                {
                    "name": flow_name,
                    "status": flow_status,
                    "blockers": blockers,
                    "steps": step_results,
                },
            )

        output_lines = [
            f"Flows checked: {len(flow_results)}",
            f"Flows needing attention: {blocker_count}",
            "Manual checks required for each flow:",
        ]
        output_lines.extend([f"  - {item}" for item in manual_checklist])

        return ToolResult.ok(
            "\n".join(output_lines),
            data={
                "flows": flow_results,
                "manual_checklist": manual_checklist,
            },
        )
