# GeistScope Bug Hunting Workstation Plan

Last updated: 2026-05-15

## Status

The original CLI pipeline is complete. The current product direction is a
professional TUI-based bug-hunting browser backed by a local AI harness with
scoped tool endpoints.

The Rust engine remains the foundation. The next work should layer endpoint
dispatch, richer TUI workflows, OOB testing, request corpus management, and
reporting on top of the existing file-native engagement model.

---

## Completed Engine Steps

### Step 1 - Tool integration

`subdomain-enum`, `mg-scan`, and `fingerprint` accept engagement-aware usage.
They scope-check active probes, write structured JSON, and append audit events.

### Step 2 - `mg-recon`

Resumable recon pipeline:

```
subdomain enum -> fingerprint -> port scan -> summary.json
```

### Step 3 - `ai-prioritize`

Reads `summary.json` and skill files from `~/.claude/bug-hunting-skills/`.
Writes `priorities.md` and `priorities.json`. Anthropic is primary when
configured; Ollama is fallback.

### Step 4 - `mg-crawl`

Same-origin, in-scope crawler with robots awareness and default rate limiting.
Stores HTML/JS by SHA-256 and emits page indexes, endpoints, and redacted secret
candidates.

### Step 5 - `mg-probe`

Passive and semi-active posture checks for headers, CORS, cookies, debug paths,
and stack traces. Writes `probe-report.json` and finding markdown.

### Step 6 - `mg-fuzz`

Burp Intruder-style request templating with `§marker§` positions. Supports
sniper, battering-ram, pitchfork, and cluster-bomb modes. Built-in payload sets
include SQLi, XSS, SSTI, traversal, SSRF, common passwords, HTTP methods,
usernames, and bounded number ranges.

### Step 7 - `mg-replay`

Burp Repeater-style finding verification. Extracts curl evidence from finding
markdown, replays, diffs, and writes verdict JSON.

### Step 8 - `mg-tui`

Ratatui dashboard for engagements, hosts, findings, fuzz results, logs, and
browser-like inspection. This is now the base for the professional TUI browser.

---

## Active Product Plan

### Phase 1 - Governing docs and skills

Complete:

- `docs/PRODUCT_DOCTRINE.md`
- `docs/BUG_HUNTING_METHODOLOGY.md`
- `docs/AI_TOOL_ENDPOINTS.md`
- `docs/FEATURE_ROADMAP.md`
- `docs/RESEARCH_SOURCES.md`

Purpose: make product direction, methodology, endpoint safety, and feature
priorities explicit before more AI/browser code is added.

### Phase 2 - `mg-harness`

Build a local endpoint dispatcher around the existing engine.

Status: started. The crate exists as `engine-rust/mg-harness` with a JSON
invocation CLI and library dispatcher. Implemented endpoints:

- `endpoint.registry`
- `engagement.open`
- `scope.check`
- `recon.run` with `confirmed: true`
- `finding.create`

Requirements:

- Typed endpoint request/result schemas.
- Endpoint registry with version, risk class, and description.
- Scope check before active calls.
- Redaction before model-visible output.
- Audit events for all dispatches and blocks.
- Confirmation for high-active and state-changing actions.
- Provider-neutral model adapter.

Initial endpoints:

- `engagement.open` - implemented
- `scope.check` - implemented
- `recon.run` - implemented with confirmation gate
- `finding.create` - implemented with scope gate
- `crawl.run`
- `probe.run`
- `request.replay`
- `fuzzer.plan`
- `fuzzer.run`
- `finding.create`
- `finding.replay`
- `risk.rank`

### Phase 3 - TUI browser

Promote `mg-tui` from dashboard to bug-hunting browser.

Required views/actions:

- Request corpus table and filters.
- Request/response inspector.
- Host/path/parameter inventory.
- Replay editor.
- Fuzz marker editor.
- OOB callback feed.
- Scope and risk-mode status.
- AI "next safe test" panel.
- Finding/evidence drawer.

The TUI must stay dense, keyboard-first, and useful over SSH.

### Phase 4 - OOB subsystem

Add Interactsh-compatible OOB testing.

Requirements:

- Per-engagement callback allocation.
- Callback polling.
- Evidence files under `engagements/<name>/oob/`.
- Fuzz/replay payload integration.
- TUI feed.
- Self-hosted server support for consulting privacy.

### Phase 5 - Request corpus and import

Add a durable request corpus that can be filled by:

- TUI browser traffic.
- HAR imports.
- Burp/Caido exports.
- Crawled forms and API calls.
- OpenAPI and GraphQL schema import.

Every corpus item should be reusable by replay, fuzz, reporting, and AI ranking.

### Phase 6 - Reporting and consulting workflow

Build on `mg-engagement` findings:

- Redaction review.
- CVSS/VRT/HackerOne-style severity mapping.
- Bounty report drafts.
- Client report export.
- Retest history.
- Engagement activity timeline.
- Export bundle without secrets or out-of-scope data.

---

## Current Feature Improvements

- Add richer scope types: CIDR, path, wildcard, mobile, cloud bucket, API.
- Add subdomain takeover checks.
- Add OpenAPI and GraphQL operation inventory.
- Replace JS endpoint regex-only extraction with a real parser.
- Add HTTP fallback when HTTPS is refused.
- Add shared cross-tool rate limiting.
- Add two-account diffing for BOLA/IDOR.
- Add parameter mining from traffic, crawl, forms, JS, OpenAPI, and GraphQL.
- Add ProjectDiscovery-style fuzz preconditions.
- Add semantic response diffing for JSON, HTML, and GraphQL.
- Add prompt-injection test fixtures for AI harness code.

---

## Guardrails

- Active testing requires scope.
- High-volume tests require explicit confirmation.
- DoS, destructive actions, persistence, malware, phishing, and social
  engineering are blocked unless the engagement rules explicitly authorize them.
- AI suggestions are advisory; tool endpoints enforce policy.
- Web content is untrusted data and must not alter harness instructions.

---

## Reference Docs

- `../docs/PRODUCT_DOCTRINE.md`
- `../docs/BUG_HUNTING_METHODOLOGY.md`
- `../docs/AI_TOOL_ENDPOINTS.md`
- `../docs/FEATURE_ROADMAP.md`
- `../docs/RESEARCH_SOURCES.md`
