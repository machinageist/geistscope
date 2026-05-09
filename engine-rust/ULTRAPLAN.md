# GeistScope Bug Bounty Pipeline — Plan

## Status

All original 5 steps complete. Three additional tools added based on Burp Suite gap analysis.
Active development focus: frontend layer (TUI first, then GUI).

---

## Completed steps

### Step 1 — Tool integration ✅
`subdomain-enum`, `mg-scan`, `fingerprint` each accept `--engagement`.
Scope-check before active probe → write structured JSON to `recon/<tool>.json` → audit.log entry.

### Step 2 — `mg-recon` orchestrator ✅
Four-stage resumable pipeline: subdomain enum → fingerprint → port scan → `summary.json`.
In-process (no subprocess). Each stage checks existing output file before re-running.

### Step 3 — `ai-prioritize` ✅
Reads `summary.json` + bug-hunting skill files (`~/.claude/bug-hunting-skills/`).
Ranks attack surface by payout × exploitability. Writes `priorities.md` (timestamped, appendable)
and `priorities.json`. Anthropic primary, Ollama fallback.

### Step 4 — `mg-crawl` ✅
BFS crawler: depth-limited, same-origin, in-scope, robots.txt-aware, 1 req/sec default.
Stores pages as SHA-256-named `.html` + `.js` files.
Outputs `index.json`, `endpoints.json`, `secrets.json` per host.
Secret regex catalog: AWS keys, GitHub tokens, JWTs, Slack, Stripe, Google API keys, PEM, api_key, password.

### Step 5 — `mg-probe` ✅ (added beyond original plan)
Passive + semi-active security posture checker.
Checks: missing security headers (CSP, X-Frame-Options, HSTS, etc.), CORS origin reflection,
cookie flags (Secure, HttpOnly, SameSite), exposed debug paths (Swagger, actuator, .env, console),
stack traces in crawl HTML. Writes findings/ markdown files + `probe-report.json`.

### Step 6 — `mg-fuzz` ✅ (added beyond original plan)
Burp Intruder equivalent. Reads raw HTTP request templates with `§marker§` positions.
Attack modes: sniper, battering-ram, pitchfork, cluster-bomb.
Built-in payload sets: sqli, xss, ssti, traversal, ssrf, common-passwords, http-methods, usernames, numbers:N-M.
Diffs each response against baseline (status, body hash, length delta, timing anomaly).
Writes timestamped `fuzz-<ts>.json` report.

### Step 7 — `mg-replay` ✅ (added beyond original plan)
Burp Repeater equivalent for finding verification.
Extracts curl commands from `## Evidence` section of finding markdown.
Re-executes, diffs against optional baseline in frontmatter.
Verdict: `still_vulnerable` / `appears_fixed` / `indeterminate`.
Writes `<id>-replay-<date>.json`.

---

## Active pipeline summary

```
subdomain-enum ──┐
mg-scan ─────────┤                     ┌── ai-prioritize (LLM ranking)
fingerprint ─────┴── mg-recon ─────────┤
                      (summary.json)   └── mg-crawl ──── mg-probe
                                                   └─── mg-fuzz
                                                   └─── mg-replay
```

Every tool writes to the engagement directory. Claude reads the same files.

---

## Frontend layer ✅

### Decision needed
Two complementary interfaces, not mutually exclusive:

**TUI (Ratatui)** — terminal-based interactive dashboard
- Engagement list with status indicators (recon %, findings count, last run)
- Split pane: host list + detail panel (fingerprint, ports, open findings)
- Live log tail from audit.log during active recon
- Finding browser with severity filter
- Quick-action shortcuts: run probe, fuzz from template, replay finding
- Ships first; most useful for headless/SSH environments

**GUI (planned post-TUI)** — native desktop with egui or Tauri/React
- Richer visualizations: attack surface map, finding timeline
- Template editor with §marker§ highlighting
- Side-by-side response diff viewer (mg-fuzz results)
- Export: PDF report, Markdown bundle for submission

### TUI architecture (Ratatui) ✅
Crate: `engine-rust/mg-tui/`

```
mg-tui/src/
├── main.rs        — app init, event loop, terminal setup/restore
├── app.rs         — App state machine (selected tab, cursor, refresh timer)
├── ui.rs          — top-level render: tabs + status bar
├── views/
│   ├── engagements.rs  — engagement list table
│   ├── hosts.rs        — host detail with fingerprint + ports
│   ├── findings.rs     — findings browser with severity filter
│   ├── fuzz.rs         — fuzz job status + interesting results
│   └── logs.rs         — live audit.log tail
└── loader.rs      — async file watchers: poll recon/ + findings/ for changes
```

Key dependencies: `ratatui`, `crossterm`, `tokio` (already in workspace).
Data: read from engagement JSON files — no new IPC needed.

### OOB server integration (future)
Integrate with a self-hosted `interactsh` instance for blind SSRF / blind XSS detection.
`mg-fuzz` accepts `--oob-host` flag; generates payloads with encoded callback URLs.
Polling the interactsh API for hits closes the loop without managing DNS infrastructure.

---

## Deferred items

- CIDR / port-spec / URL-path scope rules (current `*.foo.com` suffices for now)
- Real JS AST parser (oxc/swc) in mg-crawl — regex-only is current approach
- mg-replay: honor `follow_redirects` from parsed curl `-L` flag
- mg-probe: HTTP-only fallback when HTTPS connection is refused
- Rate-limit coordination across concurrent tools (currently per-tool)
- Subdomain takeover checks (DNS CNAME → unclaimed service)
- GraphQL introspection and operation fuzzing
