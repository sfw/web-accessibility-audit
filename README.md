# Web Accessibility Audit Process for Loom

A [Loom](https://github.com/sfw/loom) process package for structured website
accessibility audits with WCAG-mapped findings and implementation-ready
remediation planning.

## No credentials required

This package and all bundled tools run without third-party API keys or service
credentials. Scans and URL discovery rely on direct HTTP(S) requests only.

## What this process does

The `web-accessibility-audit` process runs a strict 7-phase workflow:

1. Scope and compliance profile setup
2. URL inventory and representative sampling
3. Automated accessibility checks
4. Manual accessibility checks on critical journeys
5. Finding normalization and WCAG coverage mapping
6. Prioritized remediation roadmap
7. Final conformance and risk report

## Included tools

Bundled tools are prefixed with `a11y_` and designed for repeatable artifacts:

- `a11y_url_inventory` - discovers URLs, clusters templates, and proposes a deterministic sample.
- `a11y_scan` - runs heuristic accessibility checks and emits normalized findings.
- `a11y_flow_check` - validates critical user flows and captures manual test checkpoints.

## Maintainer upgrade guide (sealed-artifact mutation protocol)

If you add or update bundled tools that can write, move, or delete workspace
files, keep them aligned with Loom's mutation contract:

1. Set `is_mutating = True` for every workspace-writing tool.
2. Return accurate workspace-relative `files_changed` on every successful write.
3. Expose `mutation_target_arg_keys` when write paths are not in `path`
   (for example: `output_findings_csv`, `output_flow_json`).
4. Resolve writes with `_resolve_path(..., ctx.workspace)` and keep targets in
   the workspace.
5. Treat `execution.sealed_artifact_post_call_guard` (`off|warn|enforce`) as
   defense-in-depth only; preflight gating should come from mutating metadata
   and path targeting, not post-call rollback behavior.

## Network safety and request behavior

All bundled URL-fetching tools apply the same hardened policy:

- HTTP(S) only; non-web schemes are rejected.
- SSRF protections block localhost, loopback, link-local, RFC1918/private,
  reserved, multicast, and unspecified address ranges after DNS resolution.
- Redirects are handled manually with bounded redirect depth; each redirect
  target is re-validated.
- Retries with exponential backoff are used for transient failures
  (`408/425/429/500/502/503/504` and connection timeouts/errors).
- `Retry-After` is honored for `429` and `503` responses when provided.
- Per-host pacing defaults to conservative delays to avoid bursty traffic.
- Requests include browser-like headers with honest default Loom user-agents,
  plus optional user-agent override parameters.
- Response bytes and request time are bounded for deterministic execution.

## Installation

From a local path:

```bash
loom install /path/to/web-accessibility-audit
```

From GitHub using full URL:

```bash
loom install https://github.com/sfw/web-accessibility-audit
```

From GitHub shorthand:

```bash
loom install sfw/web-accessibility-audit
```

Install into a specific workspace instead of global process storage:

```bash
loom install sfw/web-accessibility-audit -w /path/to/project
```

## Usage

```bash
loom cowork --process web-accessibility-audit
```

Then in chat:

```text
/run Audit https://example.com for WCAG 2.2 AA conformance and produce a prioritized remediation plan.
```

For non-interactive execution:

```bash
loom run "Audit https://example.com for WCAG 2.2 AA conformance" --workspace /tmp/a11y-audit --process web-accessibility-audit
```

## Key tool parameters

### `a11y_url_inventory`

- Core discovery: `targets`, `max_urls`, `max_discovered_urls`, `crawl_depth`.
- Discovery modes: `include_sitemap`, `respect_robots`, `include_subdomains`.
- URL filtering: `include_patterns`, `exclude_patterns`, `keep_query_params`.
- Network controls: `timeout_seconds`, `max_redirects`, `max_retries`,
  `backoff_base_seconds`, `backoff_max_seconds`, `request_delay_seconds`,
  `max_fetch_bytes`, `user_agent`.
- Optional artifacts: `output_inventory_csv`, `output_sample_csv`,
  `output_templates_csv`.

### `a11y_scan`

- Inputs and bounds: `urls`, `max_urls`, `max_findings_per_url`.
- Output controls: `include_warnings`, `output_findings_csv`.
- Network controls: `timeout_seconds`, `max_redirects`, `max_retries`,
  `backoff_base_seconds`, `backoff_max_seconds`, `request_delay_seconds`,
  `max_fetch_bytes`, `user_agent`.
- Finding schema fields: `finding_id`, `url`, `rule_id`, `wcag_sc`, `severity`,
  `impact`, `confidence`, `message`, `evidence`, `remediation`.

### `a11y_flow_check`

- Flow model: `flows` with ordered `steps` (string URL or step object with
  `url`, optional `name`, and optional `expected_text` / `assert_text`).
- Scope/bounds: `max_flows`, `max_steps_per_flow`, `require_https`.
- Network controls: `timeout_seconds`, `max_redirects`, `max_retries`,
  `backoff_base_seconds`, `backoff_max_seconds`, `request_delay_seconds`,
  `max_fetch_bytes`, `user_agent`.
- Optional artifacts: `output_flow_csv`, `output_flow_json`.

## Core deliverables

- `audit-scope.md`
- `compliance-profile.md`
- `journey-inventory.csv`
- `url-inventory.csv`
- `url-sample.csv`
- `template-map.csv`
- `automated-findings.csv`
- `automated-audit-summary.md`
- `manual-findings.csv`
- `manual-test-notes.md`
- `findings-register.csv`
- `wcag-coverage-matrix.csv`
- `remediation-backlog.csv`
- `quick-wins.md`
- `implementation-guidelines.md`
- `accessibility-audit-report.md`
- `conformance-summary.md`
- `retest-plan.md`

## Known limitations and manual validation requirements

- Heuristic checks cannot validate keyboard interaction quality, focus behavior,
  AT announcement quality, or dynamic state transitions with full fidelity.
- Authenticated flows may require pre-authenticated/manual execution context;
  blocked or inaccessible steps should be manually validated.
- JavaScript-rendered content can reduce static-parser coverage in automated
  checks; inspect rendered states manually where risk is high.
- WCAG conformance statements require manual verification for critical journeys,
  form workflows, modal/dialog behavior, and error handling.
- Treat automated outputs as evidence inputs, not final legal conclusions.
