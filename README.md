# Web Accessibility Audit Process for Loom

A [Loom](https://github.com/sfw/loom) process package for structured website
accessibility audits with WCAG-mapped findings and implementation-ready
remediation planning.

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

Bundled tools are prefixed with `a11y_` and designed to support repeatable
artifact generation:

- `a11y_url_inventory` - discover URLs, cluster templates, and propose samples
- `a11y_scan` - run baseline heuristic checks with WCAG mapping
- `a11y_flow_check` - evaluate critical journey flow health and manual test hooks

## Installation

```bash
loom install /path/to/web-accessibility-audit
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

## Notes

- Automated checks do not replace manual accessibility testing.
- Findings should be validated in context for dynamic UI and assistive tech
  behavior.
- Use this process as an audit workflow, not a legal determination.
