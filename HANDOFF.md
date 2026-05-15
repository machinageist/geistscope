# GeistScope — Feature Completion Handoff

This document is a session brief for Claude Code. Read `CLAUDE.md` first for
project orientation, coding conventions, and repo layout. This file picks up
where that document ends: it specifies every major capability gap between the
current codebase and an autonomous "just go" engagement loop, with enough
implementation detail to build each piece without further design decisions.

---

## The Goal State

When complete, the operator workflow should be:

```bash
mg-engagement init target-bounty --target target.example.com --platform hackerone
mg-engagement scope-add target-bounty "*.target.example.com"
mg-engagement scope-deny target-bounty "dev.target.example.com"
mg-engagement credentials-set target-bounty --username user@example.com --password-env MG_PASS

# Then hand off to Claude Code:
# "Run a full engagement on target-bounty and generate a report for any findings."
```

Claude Code calls `mg-harness` endpoints in a loop: observe recon output,
decide what to test, call the right tool, read the result, decide again.
No raw shell access needed. Every action is scope-checked and audit-logged.
Any confirmed finding becomes a polished, HackerOne-ready report automatically.

---

## Strategic North Star

GeistScope should become an AI-native offensive security operating system, not
just a scanner suite. The core transition is from tool outputs stored as files
to persistent operational intelligence: security graph memory, deterministic
replay, browser-native instrumentation, investigation workflows, and scoped AI
reasoning over audited evidence.

Keep the current engagement directory model as the local-first source of truth
while building adapter boundaries for graph and replay stores.

---

## What Already Exists (Do Not Rebuild)

| Binary / Crate | Status |
|---|---|
| `engagement` lib | Complete — workspace, scope, audit, findings |
| `session` lib | Started — env-backed token header resolution, session.json helpers, TUI browser use, mg-engagement CLI, and harness session endpoints; form/OAuth/crawl/fuzz integration pending |
| `http-client` lib | Complete — reqwest wrapper, UA rotation, rate limiting |
| `llm-client` lib | Complete — Anthropic + Ollama |
| `subdomain-enum` | Complete |
| `mg-scan` | Complete |
| `mg-fingerprint` | Complete |
| `mg-recon` | Complete |
| `mg-crawl` | Complete — needs auth extension (see §3) |
| `mg-probe` | Complete — passive only, needs active checks (see §4) |
| `mg-fuzz` | Complete — needs stack-aware payload selection (see §5) |
| `mg-replay` | Complete |
| `ai-prioritize` | Complete |
| `mg-tui` | Started for product UI — dashboard, harness status, browser rendering, response inspector, redacted cookies/headers, and page search exist |
| `mg-harness` | Started — endpoint registry, engagement open/status basics, scope check, confirmed recon run, and scoped finding creation exist; continue §2 |

---

## Progress Log

- 2026-05-15: Integrated the strategic productionization handoff into
  `docs/STRATEGIC_HANDOFF.md`, product doctrine, roadmap, README, and Claude
  orientation. The next implementation slice is the local-first security graph
  foundation with harness read endpoints.
- 2026-05-15: Implemented the first strategic security graph slice. New
  `security-graph` crate defines node/edge kinds, deterministic IDs, evidence
  refs, a local JSONL `FileGraphStore`, a Postgres schema sketch, and ingestion
  from `recon/summary.json`, crawl `endpoints.json`, `probe-report.json`, and
  finding frontmatter. `mg-harness` exposes `graph.ingest`, `graph.summary`,
  and `graph.neighbors`.
- 2026-05-15: Added initial `mg-harness` crate and CLI with JSON invocation/results, endpoint registry, version/risk checks, confirmation gate for `recon.run`, `engagement.open`, `scope.check`, and scoped `finding.create`. Exposed `mg-recon` as a library so harness calls recon directly instead of shelling out. Added reusable `Finding::next_id`. Updated docs and wiki for the AI harness direction.
- 2026-05-15: Completed the first `mg-tui` Harness tab slice. The TUI now has a Harness tab that reads `audit.log`, shows current/last harness endpoint activity, queue depth placeholder, endpoint registry status, and a harness-only audit tail. This completes the checklist item for a visible Harness tab while the long-running daemon queue is still pending.
- 2026-05-15: Added read-only `mg-harness` endpoints for `engagement.status` and `finding.read`. `engagement.status` summarizes key output files and counts; `finding.read` resolves a safe finding ID prefix, bounds model-visible markdown to 256 KiB, and returns evidence references.
- 2026-05-15: Started §3 session management with a new `session` library crate. The first slice writes and loads `session.json` env-var references, rejects plaintext cookie saves, resolves token auth headers from environment variables, scope-checks session test URLs, and adds `engagements/*/session.json` to `.gitignore`. Form login, OAuth refresh, encryption-at-rest for future stored cookies/tokens, CLI commands, and tool integration remain pending.
- 2026-05-15: Expanded the `mg-tui` browser slice from rendered page viewing toward the roadmap request/response inspector. The Browser tab now shows a side inspector with request method, final URL, response status, MIME type, page inventory, response headers, redacted `Set-Cookie` inventory, and in-page search (`/`, `n`, `N`) with match highlighting. This is a partial completion of the P1 browser-core request/response viewer item; request corpus import, diffing, replay/fuzz actions, and finding creation remain pending.
- 2026-05-15: Wired the `mg-tui` Browser tab into the new `session` library for selected engagements. Browser GET and form POST requests now apply env-backed auth headers from `session.json` when present, show only a redacted auth status in the inspector, and stop navigation with a visible error if a configured session cannot resolve its environment variables. This starts the tool-integration side of §3 for the TUI browser; `mg-crawl`, `mg-fuzz`, form login, OAuth refresh, and CLI credential commands remain pending.
- 2026-05-15: Added the first dashboard-to-browser pivot. Pressing Enter on a selected Hosts row now opens that host in the Browser tab, preferring HTTPS when 443 is present and falling back to HTTP for port-80-only hosts. This starts the P1 natural workflow of pivoting from host inventory into traffic/browser inspection; request corpus navigation, replay/fuzz pivots, and finding pivots remain pending.
- 2026-05-15: Implemented the §3 credential CLI and harness session endpoints. `mg-engagement credentials-set` writes token/form env-var references to `session.json`, `credentials-test` sends a scoped token-auth test request, `mg-harness session.set` stores profiles only after confirmation, and `session.get_headers` resolves auth headers while returning only redacted metadata. Form login execution, OAuth refresh, encrypted cookie/token material, and crawl/fuzz/probe header injection remain pending.
- 2026-05-15: Wired env-backed session headers into the network tools. `http-client` now accepts default headers, `mg-crawl` loads session headers before crawling, and `mg-probe`/`mg-fuzz` apply the same headers through their reqwest clients while logging only header counts. `mg-fuzz` still lets explicit template headers override the client defaults. Transparent 401 re-auth and non-token form/OAuth refresh remain pending.
- 2026-05-15: Started §4 active vulnerability checks in `mg-probe`. Added `--active`, a no-redirect active client, crawler endpoint loading, harmless reflected-marker checks, single-quote SQL error checks, and no-follow open redirect checks with request caps and per-request rate sleeps. IDOR/two-session checks, subdomain takeover, OOB SSRF, and extended debug-path active classification remain pending.
- 2026-05-15: Implemented the §5 `payload-engine` crate and wired `mg-fuzz --context-aware` into it. The new library exposes payload context/types, stack-aware payload selection for SQLi/XSS/SSTI/SSRF/traversal/IDOR/open redirect/command injection, and engagement summary inference from recon fingerprints. `mg-fuzz` now replaces built-in payload set names with context-aware variants when `--context-aware` is set or `recon/summary.json` exists; file and numeric payload specs still use the legacy loader.
- 2026-05-15: Implemented the §8 exploit-chain reasoning pass. `ai-prioritize` now makes a second LLM call after ranking, writes `recon/chain-analysis.md` and `recon/chain-analysis.json`, includes bounded `probe-report.json` evidence when present, and records the run in audit. Added read-only harness endpoint `chain.read` so Claude Code can load bounded chain artifacts.
- 2026-05-15: Implemented the §9 `mg-report` crate and harness endpoint. `mg-report generate` reads one finding, wraps evidence as untrusted model data, drafts a HackerOne-style report, computes CVSS 3.1 locally from a vector, supports deterministic `--offline` generation, and writes `<finding>-report.md`. `mg-harness report.generate` now exposes the same flow with bounded JSON output.
- 2026-05-15: Implemented the §7 `mg-crawl` JS analyzer slice. Added `js_analyzer.rs`, enriched `endpoints.json` rows with method/source/body/params/GraphQL flags, writes `internal-refs.json`, `vulnerable-libraries.json`, and `graphql-candidates.json`, and performs a bounded in-scope GraphQL introspection POST when JS signals GraphQL. Cross-host absolute URLs are kept out of active endpoint rows and retained only as reference evidence.
- 2026-05-15: Added the §10 integration harness and CI wiring. `tests/target/docker-compose.yml` starts a local Python vulnerable target with reflected input, SQL-error, open-redirect, GraphQL, internal-ref, and vulnerable-library signals. `tests/integration/pipeline-smoke.sh` initializes an engagement, writes a localhost summary, runs `mg-crawl`, `mg-probe --active`, and `mg-report --offline`, then asserts the expected artifacts and known bug signals. `.github/workflows/ci.yml` runs workspace build, tests, clippy, and the Docker smoke test. `mg-probe` now selects nonstandard HTTP ports from recon summaries so the local target is probeable.
- 2026-05-15: Updated the standalone `~/mg-server/content/pages/geistscope-tool-suite.md` wiki page and README with the new `mg-report`, `mg-harness`, chain analysis, JS analyzer, and integration-smoke-test workflow. The wiki remains a page under `content/pages`, not a blog post, and the existing header nav link points to `/wiki/geistscope-tool-suite`.
- 2026-05-15: Shipped §14 S4. New `mg-exploitgen` crate scaffolds a four-stage Rust exploit project (`scanner` / `validator` / `payload` / `cleanup` + runbook + smoke test) under `engagements/<name>/exploits/<cve>/`. Directory and `Cargo.toml` come from static `include_str!` templates; the LLM only fills guidance fields that get pasted into file-header comments and a numbered runbook. CVE id is normalized to uppercase and rejected if it contains anything outside `[A-Za-z0-9-]`; the resulting Rust crate name is derived deterministically. `runbook.md` always opens with the `> Authorized testing only.` banner. Harness exposes `exploit.scaffold` (ReadOnly). Verified the generated scaffold passes `cargo check` end to end; 6 mg-exploitgen tests + a new harness round-trip test cover the offline path and invalid-CVE rejection.
- 2026-05-15: Shipped §14 S3. Added `PayloadSet::PromptInjection` with five categories (RoleConfusion, IndirectInjection, SystemPromptLeak, ToolAbuse, PolicyBypass) and a curated 15-payload corpus in `payload-engine`. New `mg-aifuzz` crate parses `§INJECT§` templates, JSON-escapes payloads when the body is JSON, scope-checks every request, gates execution behind a per-engagement `aifuzz/CONSENT` marker, applies a regex success-signal rubric (plus optional sentinels file) and writes JSONL rows under `aifuzz/<run-id>.jsonl`. Harness now exposes `aifuzz.consent` (StateChange) and `aifuzz.run` (HighActive, confirmation-gated). 11 mg-aifuzz tests, 7 payload-engine tests, and two new harness tests cover the consent gate and out-of-scope refusal.
- 2026-05-15: Shipped §14 S2. New `mg-recopilot` crate reads `engagements/<name>/re/<binary>/raw/<func>.c`, optionally consumes `manifest.json`, and writes `<func>.md` + `<func>.json` with sections `function_purpose`, `variable_map`, `control_flow_notes`, `suspicious_logic`, `exploit_primitives`, `suggested_next_steps`. Pseudocode and manifest are wrapped as untrusted evidence in the prompt, and binary/function arguments are rejected if they contain path separators, control chars, or `..`. Added matching harness endpoints `re.analyze` and `re.read`, `Engagement::re_dir()` helper, six lib tests, and a harness round-trip test.
- 2026-05-15: Triaged `CYBERPUNK_WISHLIST.md` into the new §14 Phase 2 roadmap and shipped §14 S1. `mg-report disclose` drafts a CVE writeup (`<id>-cve.md`) using a new `disclosure.rs` prompt module, locally computes CVSS, and renders a deterministic `<id>-disclosure.eml` form letter with an `X-GeistScope-Meta` header. Vendor/contact strings reject CR/LF to prevent RFC-822 header injection. Added matching harness endpoint `report.disclose` and unit tests for both the offline path and the header-injection guard.

---

## Build Order

Implement in this sequence. Each item depends on the ones above it.

1. `mg-harness` — the agentic dispatcher (everything else calls through this)
2. Session / credential management (unlocks authenticated crawling and fuzzing)
3. Active vulnerability checks in `mg-probe`
4. Stack-aware payload crafting for `mg-fuzz`
5. OOB callback infrastructure (`mg-oob`)
6. JS static analysis extension for `mg-crawl`
7. Exploit chain reasoning in `mg-harness`
8. Report generation (`mg-report`)
9. Integration test harness (Docker Compose + CI)
10. Global rate governor (cross-tool throttle)

Strategic platform backlog, after the current tactical handoff:

1. Unified datastore and security graph (`security-graph` crate plus harness
   `graph.*` endpoints) - started with local JSONL graph storage and ingestion
2. Deterministic replay engine and action lineage
3. Proxy/browser instrumentation with request interception and websocket support
4. Investigation-centric TUI views for auth, authorization, tenants, uploads,
   replay chains, and hypotheses
5. Plugin runtime with sandboxed scanners, workflow tools, and visualization
   extensions

---

## §1 — Prerequisite: Read These First

Before writing any code, read:

```
docs/PRODUCT_DOCTRINE.md
docs/AI_TOOL_ENDPOINTS.md
docs/BUG_HUNTING_METHODOLOGY.md
docs/FEATURE_ROADMAP.md
engine-rust/ULTRAPLAN.md
```

`AI_TOOL_ENDPOINTS.md` defines the endpoint contract that `mg-harness` must
implement. Do not invent a new schema — extend what is already there.

---

## §2 — mg-harness: The Agentic Dispatcher

### What it is

A long-running local process (Unix socket or localhost HTTP) that Claude Code
calls via structured JSON requests. It is the only thing Claude Code needs to
talk to during an engagement. It never grants raw shell access. Every call is
scope-checked before execution and written to `audit.log`.

### Architecture

```
Claude Code
    │  JSON request  { "tool": "recon.run", "engagement": "acme", ... }
    ▼
mg-harness  ──── scope_check(engagement, targets) ──► scope.json
    │
    ├── calls mg-recon / mg-crawl / mg-probe / mg-fuzz / mg-replay
    │   as subprocesses or via their library crates directly
    │
    ├── writes result summary to engagement workspace
    │
    └── returns JSON response  { "status": "ok", "output_file": "recon/summary.json", ... }
```

### Endpoint registry (minimum viable set)

Implement these first. Full contract is in `docs/AI_TOOL_ENDPOINTS.md`.

| Endpoint | Input | Output |
|---|---|---|
| `endpoint.registry` | — | list of all available endpoints with schemas |
| `engagement.open` | `engagement_name` | engagement metadata |
| `engagement.status` | `engagement_name` | current state of all output files |
| `scope.check` | `engagement_name`, `target` | `{ allowed: bool, reason: str }` |
| `recon.run` | `engagement_name`, options | path to `summary.json` |
| `crawl.run` | `engagement_name`, `urls[]` | path to crawl output |
| `probe.run` | `engagement_name` | path to `probe-report.json` |
| `fuzz.run` | `engagement_name`, `template`, `payloads`, `mode` | path to fuzz output |
| `replay.run` | `engagement_name`, `finding_id` | replay verdict |
| `prioritize.run` | `engagement_name` | path to `priorities.json` |
| `finding.read` | `engagement_name`, `finding_id` | finding markdown content |
| `finding.create` | `engagement_name`, fields | new finding file path |
| `report.generate` | `engagement_name`, `finding_id` | path to report |
| `oob.get_url` | `engagement_name`, `tag` | unique callback URL |
| `oob.poll` | `engagement_name`, `tag` | list of received callbacks |
| `session.set` | `engagement_name`, credential fields | confirmation |
| `session.get_headers` | `engagement_name` | auth headers for HTTP calls |

### Risk classes

Every endpoint must declare a risk class. Enforce before execution:

- `read` — reads files only, no network. Always allowed.
- `passive` — outbound HTTP, no payloads. Allowed unless program says no scanners.
- `active` — sends payloads or auth probes. Require explicit confirmation on first
  use per engagement (write confirmation to `engagement.json`).
- `destructive` — bulk fuzzing, brute force. Require `--force` flag or explicit
  consent field in `engagement.json`.

### Audit logging

Every harness call appends to `audit.log`:

```
2026-05-14T10:23:01Z  tool=fuzz.run  engagement=acme  risk=active  targets=["api.acme.com"]  operator=claude-code
```

### mg-tui integration

Add a `Harness` tab to `mg-tui` that tails `audit.log` and shows the current
harness endpoint being executed, last result, and queue depth if applicable.

---

## §3 — Session and Credential Management

### Problem

`mg-crawl` and `mg-fuzz` currently require tokens to be manually pasted into
request templates. Tokens expire. No tool maintains an authenticated session.

### New crate: `session` (library)

Add `engine-rust/session/` as a shared library crate.

**Storage:** Credentials live in `engagements/<name>/session.json`. This file
must be in `.gitignore` by default and never written to `audit.log` in plaintext.
Encrypt at rest using a key derived from the engagement name + a machine secret
(`~/.config/geistscope/keyfile` generated on first run).

**session.json schema:**

```json
{
  "username": "user@example.com",
  "password_env": "MG_PASS",
  "login_url": "https://acme.com/login",
  "login_method": "form",
  "token_header": "Authorization",
  "token_prefix": "Bearer",
  "token_env": null,
  "session_cookie": null,
  "token_refresh_url": null,
  "valid_until": null
}
```

**Login methods to support:**

- `form` — POST username/password to login_url, extract cookie or token from
  response. Detect success by checking for redirect or absence of error text.
- `token` — Read static token from environment variable. No login request.
- `oauth_client_credentials` — POST to token URL with client_id/secret, store
  bearer token, refresh when `valid_until` is within 60 seconds.

**`session` lib public API:**

```rust
pub async fn get_auth_headers(engagement: &Engagement) -> Result<HeaderMap>
pub async fn refresh_if_needed(engagement: &Engagement) -> Result<()>
pub async fn test_session(engagement: &Engagement, test_url: &str) -> Result<bool>
```

**CLI surface (new subcommands on `mg-engagement`):**

```bash
mg-engagement credentials-set <name> --username u --password-env VAR --login-url URL
mg-engagement credentials-set <name> --token-env VAR
mg-engagement credentials-test <name> --url https://acme.com/api/me
```

**Integration with existing tools:**

- `mg-crawl`: call `session::get_auth_headers()` before each request batch.
  Re-authenticate transparently when a 401 is returned.
- `mg-fuzz`: inject auth headers into every request template automatically
  unless the template explicitly sets its own `Authorization` header.
- `mg-probe`: same as mg-crawl.

---

## §4 — Active Vulnerability Checks

### Problem

`mg-probe` checks security posture (headers, cookies, CORS config). It never
sends attack payloads. There is no tool that confirms exploitability of
discovered weaknesses.

### Approach

Extend `mg-probe` with an `--active` flag that enables a second check phase.
Keep passive and active phases cleanly separated in the code. Risk class for
active checks is `active` — harness must confirm before running.

### Check modules to implement

Each module is a self-contained async function:
`async fn check(client: &HttpClient, host: &Host, eng: &Engagement) -> Vec<Finding>`

**IDOR / Broken Object Level Authorization**

For each API endpoint in `crawl/<host>/endpoints.json` that contains a numeric
or UUID path segment:
1. Request the resource with a valid session.
2. Record the response body hash and status.
3. Substitute the ID with adjacent values (+1, -1, random UUID).
4. If a 200 is returned with a non-identical body, create a candidate finding.
5. Attempt with a second session (if credentials for a second account exist in
   `session.json` as `session_b`) to confirm cross-account access.

Write candidate findings to `findings/` with severity `medium` and verdict
`unconfirmed`. `mg-replay` can then confirm.

**Reflected XSS**

For each parameter in `crawl/<host>/endpoints.json`:
1. Send a probe value: `<geist-xss-RANDOM>` (not a real payload, just a marker).
2. If the marker appears unescaped in the response body or in a JavaScript
   string context, create a finding with the full parameter name and location.
3. Do not send JavaScript execution payloads. Flag for human follow-up.

**Open Redirect**

For each redirect-handling endpoint (detected by 301/302 responses in crawl):
1. Append `?url=https://example.com`, `?next=//example.com`,
   `?redirect_uri=https://example.com` (and common parameter variants).
2. Follow redirects. If final destination is off-origin, create a finding.

**Subdomain Takeover**

For each subdomain in `recon/subdomain-enum.json`:
1. Resolve the CNAME chain.
2. Check if the final CNAME target matches a known takeover-vulnerable service
   fingerprint list (Fastly, Heroku, GitHub Pages, S3, Shopify, etc. — embed a
   static list in the crate; update it from a known community source on first
   run if network allows).
3. HTTP GET the subdomain. If the response body matches a known unclaimed page
   pattern (e.g. "There's nothing here", "No such app", "404 Not Found" on a
   Heroku domain), create a high-severity finding.

**SQL Injection (error-based detection only)**

For each parameter in endpoints.json:
1. Send a single-quote probe: `'`.
2. If the response contains a database error string (MySQL, PostgreSQL, MSSQL,
   SQLite — embed a regex list), create a finding with severity `high`.
3. Do not send UNION or stacked query payloads. Flag for manual follow-up.

**Stack Trace / Debug Disclosure**

For a curated list of debug paths (`/.env`, `/debug`, `/console`, `/phpinfo.php`,
`/actuator`, `/actuator/env`, `/actuator/heapdump`, `/_profiler`, `/graphql` with
introspection query, `/__debug__`, `/server-status`, `/server-info`):
1. GET each path.
2. If status 200 and body contains stack trace markers or environment variable
   dumps, create a finding.

This is already partially in `mg-probe` passive mode. Move it to active and
extend the path list.

**SSRF Probe (requires OOB — see §5)**

Skip this check if `mg-oob` is not running. When it is:
1. For each URL-accepting parameter in endpoints.json, send a request
   substituting the value with the OOB callback URL for this engagement.
2. Poll OOB after 10 seconds. If a callback arrived, create a high-severity finding.

### Finding schema additions

Add these fields to the finding frontmatter:

```yaml
check_module: idor          # which check generated this
verdict: unconfirmed        # unconfirmed | confirmed | false_positive
session_used: session_a     # which session context was active
evidence_curl: "curl -s ..."
```

---

## §5 — Stack-Aware Payload Crafting

### Problem

`mg-fuzz` ships static wordlists. A target running MySQL gets the same SQLi
payloads as one running PostgreSQL. A Jinja2 app gets the same SSTI probes as
a Twig app. Context blindness reduces hit rate and wastes requests.

### Approach

Add a `payload-engine` library crate at `engine-rust/payload-engine/`.
`mg-fuzz` replaces its current hardcoded payload selection with calls to this
library. `mg-harness` can also call it directly when constructing fuzz jobs.

### payload-engine public API

```rust
pub struct PayloadContext {
    pub backend_db: Option<DbEngine>,     // from fingerprint.json
    pub framework: Option<Framework>,     // from fingerprint.json
    pub template_engine: Option<TplEngine>,
    pub content_type: Option<String>,     // request Content-Type
    pub parameter_type: ParameterType,    // path | query | body | header | cookie
    pub value_hint: ValueHint,            // numeric | uuid | email | url | freetext
}

pub enum PayloadSet {
    Sqli,
    Xss,
    Ssti,
    Ssrf,
    PathTraversal,
    Idor,
    OpenRedirect,
    CommandInjection,
}

pub fn get_payloads(set: PayloadSet, ctx: &PayloadContext) -> Vec<String>
pub fn get_payload_context_from_engagement(eng: &Engagement) -> PayloadContext
```

### Stack-specific payload tables

Implement as match arms in the library. Examples:

**SQLi:**
- Generic: `' OR '1'='1`, `'; DROP TABLE--`, `1 AND SLEEP(5)--`
- MySQL: add `LOAD_FILE('/etc/passwd')`, `INTO OUTFILE`, `/*!UNION*/`
- PostgreSQL: add `pg_sleep(5)`, `::text`, `$$`, `COPY TO`
- MSSQL: add `WAITFOR DELAY '0:0:5'`, `xp_cmdshell`, `EXEC(`
- SQLite: add `randomblob(100000000)`, `sqlite_version()`

**SSTI:**
- Generic: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- Jinja2/Twig: `{{config}}`, `{{self._TemplateReference__context.cycler.__init__.__globals__.os}}`
- Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`
- Pebble: `{{runtime.exec("id")}}`
- Velocity: `#set($x='')##$x.class.forName('java.lang.Runtime')`

**SSRF:**
- Generic: `http://169.254.169.254/`, `http://localhost/`
- AWS: `http://169.254.169.254/latest/meta-data/`
- GCP: `http://metadata.google.internal/`
- Azure: `http://169.254.169.254/metadata/instance`
- If OOB available: use `mg-oob` callback URL instead of internal targets

### Integration with mg-fuzz

Add `--context-aware` flag (default: on when `recon/fingerprint.json` exists).
When enabled, `mg-fuzz` reads fingerprint data and calls `payload-engine` to
select the appropriate payload variant list before fuzzing begins. Log the
selected context to `audit.log`.

---

## §6 — OOB Callback Infrastructure

### Problem

Blind SSRF, blind XSS, DNS rebinding, XXE, and out-of-band SQLi are invisible
without a server that logs inbound connections. These are high-value bug classes.

### New binary: mg-oob

`engine-rust/mg-oob/` — a lightweight server the operator runs locally or on a
VPS during an engagement.

**What it runs:**

- HTTP listener on a configurable port (default 8080)
- DNS listener on port 53 (requires elevated privileges or use unbound on 5353)
- SMTP listener on port 25 (optional)

**Each engagement gets a namespace:**

```
<engagement-id>.<oob-domain>
```

Unique tags are appended per probe:

```
<tag>.<engagement-id>.<oob-domain>
```

**mg-oob server stores callbacks in SQLite at `~/.geistscope/oob.db`.**

**CLI:**

```bash
mg-oob serve --domain oob.yourdomain.com --http-port 8080
mg-oob get-url acme-bounty --tag ssrf-probe-1
# returns: http://ssrf-probe-1.acme-bounty.oob.yourdomain.com
mg-oob poll acme-bounty --tag ssrf-probe-1 --wait 30
# blocks up to 30s, prints any received callbacks as JSON
mg-oob poll acme-bounty --all
# prints all callbacks for the engagement
```

**Harness endpoints:**

`oob.get_url` and `oob.poll` call `mg-oob` via its local HTTP API.
`mg-oob` runs as a separate daemon. If it is not running, harness returns
`{ "available": false }` and skips OOB-dependent checks gracefully.

**Integration with active checks:**

`mg-probe --active` calls `oob.get_url` before running SSRF probes.
`mg-fuzz` with `--payloads ssrf` automatically substitutes OOB URLs when
`mg-oob` is available.

---

## §7 — JS Static Analysis Extension

### Problem

`mg-crawl` finds JS files and scans them for secrets. It misses: API endpoints
buried in bundled/minified code, GraphQL schemas, hardcoded internal hostnames,
known-vulnerable library versions, and serialization formats that suggest
specific payload types.

### Extend mg-crawl

Add a `js-analyzer` module inside the `mg-crawl` crate.

**Endpoint extraction improvements:**

- Parse string literals and template literals for URL patterns (not just HTML)
- Detect `fetch(`, `axios.`, `$.ajax(`, `XMLHttpRequest` call patterns and
  extract the URL argument statically where possible
- Detect GraphQL: look for `gql\``, `query {`, `mutation {`, `__schema` strings.
  If found, attempt `POST /graphql` with a full introspection query and save the
  schema to `crawl/<host>/graphql-schema.json`
- Detect `JSON.parse(` and `JSON.stringify(` patterns — note these endpoints
  likely accept JSON bodies (update `endpoints.json` with `body_format: json`)
- Detect `.serialize()` (jQuery) or `new FormData()` patterns — note form-encoded

**Library fingerprinting:**

Maintain an embedded list of `(library_name, vulnerable_versions, cve_ids)`.
When a bundled library version string is detected in JS, check it against the
list and write matches to `crawl/<host>/vulnerable-libraries.json`.

Seed list (expand over time):
- jQuery < 3.5.0 — XSS (CVE-2020-11022)
- lodash < 4.17.21 — prototype pollution (CVE-2021-23337)
- moment.js < 2.29.2 — ReDoS (CVE-2022-24785)
- handlebars < 4.7.7 — prototype pollution (CVE-2021-23369)

**Internal hostname detection:**

Look for strings matching `*.internal`, `*.corp`, `*.local`, `10.x.x.x`,
`172.16-31.x.x`, `192.168.x.x`. Write to `crawl/<host>/internal-refs.json`.
These are useful for SSRF payload construction.

**Output additions to `endpoints.json`:**

```json
{
  "url": "/api/v1/users/",
  "method": "GET",
  "source": "js_fetch",
  "body_format": "json",
  "params": ["id", "page"],
  "graphql": false
}
```

---

## §8 — Exploit Chain Reasoning

### Problem

The AI gets ranked recon output but has no structured way to reason about
finding *combinations*. Classic chains (open redirect + OAuth = account takeover,
missing CSRF + state-changing endpoint = CSRF, XSS + no CSP = exfiltration) are
well-documented patterns but nothing in the codebase encodes them.

### Approach

This is not a code problem — it is a knowledge + prompt problem. Do not try to
hardcode chain logic. Instead:

**Add a chain-reasoning prompt to `ai-prioritize`:**

When `ai-prioritize` runs, in addition to the existing priority ranking call,
make a second LLM call with a different prompt:

```
System: You are a senior bug bounty researcher reviewing recon and probe output.
Your job is to identify potential exploit chains — vulnerabilities that are not
dangerous alone but become high-severity when combined.

Known chain patterns (non-exhaustive):
- Open redirect + OAuth redirect_uri → account takeover
- Reflected XSS + missing CSRF token on auth endpoint → auth bypass
- Subdomain takeover + cookie scoped to parent domain → session hijacking
- SSRF + AWS metadata endpoint accessible → credential theft
- IDOR on resource ID + predictable ID sequence → mass data enumeration
- Debug endpoint exposed + stack traces contain DB credentials → direct DB access
- GraphQL introspection enabled + no auth on mutations → unauthorized writes

Given the following findings and recon summary, identify any chains that may
apply. For each chain, name the component findings, explain the attack path,
estimate impact, and suggest the next verification step.
```

Write chain analysis output to `recon/chain-analysis.md` and
`recon/chain-analysis.json`. Add a `chains` view to `mg-tui`.

**Add `chain-analysis.json` to the harness endpoint registry** so Claude Code
can read chains and decide which to pursue next.

---

## §9 — Report Generation

### New binary: mg-report

`engine-rust/mg-report/` — reads a finding file and generates a polished,
HackerOne-ready report using the LLM client.

**Input:** `findings/<id>-<slug>.md` plus `engagement.json` for target context.

**Output:** `findings/<id>-<slug>-report.md` — a complete report ready to paste
into HackerOne's submission form.

**Report sections (required by HackerOne):**

1. **Title** — one line, vulnerability class + affected component
2. **Severity** — Critical / High / Medium / Low / Informational + CVSS score
3. **Summary** — 2–3 sentences: what the vulnerability is, where it lives,
   what an attacker can do with it
4. **Steps to Reproduce** — numbered, copy-paste ready, includes exact URLs,
   parameters, payloads, and expected vs actual behavior
5. **Impact** — what a real attacker achieves (data exfiltration, account
   takeover, privilege escalation, etc.) without overstating
6. **Proof of Concept** — the curl commands from `## Evidence` in the finding,
   formatted cleanly with comments
7. **Recommended Fix** — concrete, actionable remediation (not just "sanitize
   inputs" — specific to the tech stack if known from fingerprint data)
8. **References** — relevant CVEs, CWEs, OWASP categories, writeups

**LLM prompt structure:**

```
System: You are a professional bug bounty researcher writing a vulnerability
report for submission to a HackerOne program. Write clearly and technically.
Do not exaggerate impact. Do not use marketing language. The report will be
read by the target company's security team.

Use this finding data:
<finding_markdown>{{ finding content }}</finding_markdown>
<engagement_context>{{ engagement.json }}</engagement_context>
<fingerprint>{{ recon/fingerprint.json }}</fingerprint>

Generate a complete HackerOne report. Output only the report content.
Use Markdown. Do not include preamble or meta-commentary.
```

**CVSS scoring:**

Implement a CVSS 3.1 base score calculator in the crate (not LLM-generated —
hardcode the formula). Prompt the LLM to output CVSS vector components as JSON,
then compute the numeric score locally.

**CLI:**

```bash
mg-report generate acme-bounty 20260514-probe-001
# writes: findings/20260514-probe-001-report.md

mg-report generate acme-bounty --all-unconfirmed
# skips findings with verdict: unconfirmed
```

**Harness endpoint:** `report.generate` calls this binary.

---

## §10 — Integration Test Harness

### Problem

There are no integration tests. `cargo test --workspace` tests unit logic only.
The full pipeline has never been verified end-to-end in CI.

### Docker Compose test target

Create `tests/target/docker-compose.yml` that spins up:

- **DVWA** (Damn Vulnerable Web Application) — covers SQLi, XSS, CSRF, file
  inclusion, command injection
- **Juice Shop** (OWASP) — covers IDOR, broken auth, sensitive data exposure,
  XSS, insecure deserialization
- **A custom `test-target` container** — a minimal Rust/Axum app that has:
  - An intentionally misconfigured CORS policy
  - A missing `Secure` cookie flag
  - An open redirect endpoint
  - A reflected XSS endpoint
  - An SSRF endpoint that makes outbound requests (pointed at `mg-oob` in tests)
  - A numeric IDOR endpoint (`/api/users/{id}`)
  - An exposed `/.env` endpoint
  - Two user accounts with known credentials (for IDOR cross-account testing)

### Integration test suite

`tests/integration/` — shell scripts or a Rust integration test binary that:

1. Starts Docker Compose
2. Initializes an engagement against `localhost:8080`
3. Runs the full pipeline: recon → crawl → probe (active) → ai-prioritize
4. Asserts that specific finding IDs appear in `findings/`
5. Runs `mg-report generate` and asserts the report is non-empty and parses
6. Tears down Docker Compose

Run via `cargo test --test integration` with `--ignored` by default (requires
Docker). CI pipeline runs them explicitly.

### GitHub Actions CI

`.github/workflows/ci.yml`:

```yaml
- cargo clippy --workspace -- -D warnings
- cargo test --workspace
- cargo test --test integration   # needs Docker service in CI runner
- cargo build --workspace --release
```

---

## §11 — Global Rate Governor

### Problem

`mg-scan` has its own rate controls. `mg-crawl` has its own. `mg-fuzz` has its
own. When running a full engagement, all tools run concurrently and their
combined request rate is uncontrolled at the engagement level. Programs with
WAFs will block the engagement or flag it.

### Approach

Extend the `engagement` library crate with a `RateGovernor` struct.

```rust
pub struct RateGovernor {
    requests_per_second: f64,
    burst: usize,
    per_host: HashMap<String, TokenBucket>,
}

impl RateGovernor {
    pub async fn acquire(&mut self, host: &str) -> ()  // blocks until token available
    pub fn from_engagement(eng: &Engagement) -> Self
}
```

**Rate config in `engagement.json`:**

```json
{
  "rate_limits": {
    "global_rps": 10.0,
    "per_host_rps": 3.0,
    "burst": 5
  }
}
```

**CLI surface:**

```bash
mg-engagement rate-set acme-bounty --global-rps 10 --per-host-rps 3
```

**All network-touching tools** (`mg-crawl`, `mg-probe`, `mg-fuzz`, `mg-scan`)
must call `RateGovernor::acquire(host)` before each outbound request. Pass the
governor through the shared `engagement` library rather than each tool managing
its own.

**User-agent rotation:**

Move UA rotation out of `http-client` and into the governor so it rotates on a
per-request basis at the engagement level, not per-tool. The current UA list in
`http-client` can seed the governor's UA pool.

---

## §12 — Coding Conventions Reminder

All new files must follow the existing header format from `CLAUDE.md`:

```rust
/*******************************************************************
 * Filename:        filename.rs
 * Author:          Jeff
 * Date:            YYYY-MM-DD
 * Description:     One-line summary
 * Notes:           Non-obvious context
 *******************************************************************/
```

Every function and major code block gets a `// Verb + noun` comment above it.
No multi-line docstrings. Constants in `ALL_CAPS_SNAKE_CASE`.
Every crate must pass `cargo clippy -- -D warnings` before commit.
New crates must be added to the workspace `Cargo.toml`.
New binaries must be added to the install loop in `README.md` and the wiki.

---

## §13 — What Not to Build

- Do not integrate Nuclei directly. The goal is a native Rust pipeline, not a
  wrapper around Go tooling. Specific check modules (§4) cover the same ground
  for the bug classes that matter most in web bug bounty.
- Do not add a web UI. The TUI is the UI. The product doctrine is explicit on
  this.
- Do not add automatic bug submission to HackerOne. Report generation (§9) stops
  at producing the Markdown file. The human reviews and submits.
- Do not store plaintext credentials anywhere except the encrypted `session.json`.
  Never log credential values to `audit.log` or `findings/`.
- Do not send payloads to out-of-scope targets under any circumstances. All
  active tools must call `scope_check` before every request to a new host.

---

## Completion Checklist

- [ ] `mg-harness` serving all endpoints in §2 with scope enforcement and audit logging
- [ ] `session` lib with form, token, and OAuth credential flows
- [x] `mg-engagement credentials-set / credentials-test` subcommands
- [x] `mg-crawl` using session headers transparently
- [x] `mg-fuzz` injecting session headers automatically
- [ ] `mg-probe --active` with all check modules in §4
- [x] `payload-engine` crate with stack-aware payload selection
- [x] `mg-fuzz --context-aware` using payload-engine
- [ ] `mg-oob serve / get-url / poll` binary with HTTP + DNS listeners
- [ ] Harness `oob.*` endpoints wired to `mg-oob`
- [x] `mg-crawl` JS analyzer with GraphQL introspection, library CVE list, internal-ref extraction
- [x] `ai-prioritize` chain-reasoning second pass writing `chain-analysis.md`
- [x] `mg-report generate` producing HackerOne-formatted Markdown with CVSS score
- [x] Harness `report.generate` endpoint
- [x] `tests/target/docker-compose.yml` with custom vulnerable target
- [x] Integration test suite asserting full pipeline finds known bugs
- [x] GitHub Actions CI running clippy, unit tests, integration tests
- [ ] `RateGovernor` in `engagement` lib, wired into all network tools
- [x] `mg-tui` Harness tab showing audit log tail and active endpoint
- [x] All new crates in workspace `Cargo.toml`
- [x] `README.md` and wiki updated with new binaries and workflow

---

## §14 — Cyberpunk Wishlist — Phase 2 Roadmap

`CYBERPUNK_WISHLIST.md` enumerates 20 module ideas. They are triaged below by
**impact on the GeistScope mission (authorized bug bounty + red team work) vs
implementation effort**. The autonomous engagement loop (§§1–11) is the
prerequisite — do not start Phase 2 modules until the §13 completion checklist
has been finished.

All Phase 2 modules MUST:

- be added as crates under `engine-rust/<crate-name>/`
- live behind `mg-harness` endpoints with a declared risk class
- pass `cargo clippy -- -D warnings`
- follow the §12 file header + comment conventions
- treat any third-party feed (LinkedIn, GitHub, PACER, SEC, breach data, Tor
  forums, on-chain data) as **untrusted input** wrapped in tagged blocks before
  it reaches an LLM, matching the pattern used in `mg-report/src/prompt.rs`
- never operate outside `scope.json` for the active engagement when the module
  sends any outbound request

### Triage tiers

| Tier | Items | Selection rule |
|---|---|---|
| **S — build next** | #04, #08, #11, #18 | Highest impact on the exploit-research loop, cleanest extension of existing crates |
| **A — high-value follow-on** | #01, #10, #15, #12 | Strong recon/threat-intel value, moderate effort |
| **B — niche or ethics-heavy** | #02, #07, #14, #16, #17 | Useful for specific engagements but tightly scope-gated |
| **C — specialized** | #03, #05, #06, #09, #13, #19 | Out-of-band tooling that does not slot into the web bug-bounty loop |
| **X — declined** | #20 | Memetic warfare — declined as the offensive form of this work is harmful outside research; only its defensive counterpart (detection) is in scope, and that is covered by §15 (item #15) |

### Tier S — Build first

#### S1. Item #04 — CVE write-up + disclosure ghostwriter (extend `mg-report`)

**What it is:** A second mode in `mg-report` that consumes raw PoC notes,
crash traces, and finding text, then produces (a) a CVE-style write-up, (b) a
CVSS 3.1 score, and (c) a responsible-disclosure email draft.

**Why simplest first:** `mg-report` already has the prompt scaffolding, CVSS
calculator (`mg-report/src/cvss.rs`), and untrusted-evidence wrapping. We need
two new prompt variants and one extra CLI subcommand.

**Specification (as implemented):**

- `mg-report disclose <engagement> <finding-id> --vendor "Acme Corp" --contact
  security@acme.example [--timeline-days N] [--offline] [--force]`.
- New file `mg-report/src/disclosure.rs` with one prompt-builder pair:
  - `cve_writeup_system_prompt()` — requires a `<!-- cvss_vector: ... -->`
    first line and the sections **Affected Versions**, **Vulnerability Type**,
    **Technical Description**, **Reproduction Steps**, **Impact**, **CWE**,
    **Patch Guidance**.
  - `cve_writeup_user_prompt(finding_markdown, fingerprint_json)` — wraps both
    as untrusted `<finding_markdown>` / `<fingerprint>` blocks.
- The disclosure **email is rendered locally as a deterministic form letter**
  (vendor, contact, timeline, reported_on, CVE-writeup filename). The LLM has
  no role in the email body — fewer code paths and no surprises in an RFC-822
  artifact.
- Email metadata travels as a custom RFC-822 header
  `X-GeistScope-Meta: vendor=...; timeline_days=...; reported_on=...` so the
  `.eml` parses correctly in mail clients.
- Output files:
  - `findings/<id>-<slug>-cve.md`
  - `findings/<id>-<slug>-disclosure.eml`
- Harness endpoint `report.disclose` mirrors the CLI with bounded JSON output.
- Risk class: `read` (no network). Disclosure emails are drafts only — the
  human sends them.
- Header-injection guard: vendor and contact strings reject `\r`/`\n` so a
  malicious finding cannot smuggle extra headers into the `.eml`.

**Done.** Unit tests in `mg-report` cover the offline path and the
header-injection guard; the matching `report.disclose` harness test asserts
that both artifacts are written with the expected headers.

#### S2. Item #08 — Binary RE copilot (new crate `mg-recopilot`)

**What it is:** Operator pastes decompiled pseudocode (from Ghidra, Binary
Ninja, IDA, radare2) into a file; the tool produces (a) a function-purpose
summary, (b) reconstructed variable intent, (c) suspicious-logic flags, and
(d) candidate exploit primitives, all written into the engagement's
`re/<binary>/<func>.md`.

**Specification:**

- New crate `engine-rust/mg-recopilot/` (lib + bin).
- Inputs:
  - `re/<binary>/raw/<func>.c` — pseudocode dropped by the operator.
  - Optional `re/<binary>/manifest.json` with `{ binary_name, arch, mitigations[], notes }`.
- New engagement subdirectory: `engagements/<name>/re/`. Add to the
  engagement-layout table in `CLAUDE.md`.
- `mg-recopilot analyze <engagement> <binary> <func>` reads the pseudocode,
  builds an LLM prompt using `llm-client`, and writes:
  - `re/<binary>/<func>.md` with sections: **Function Purpose**, **Variable
    Map**, **Control Flow Notes**, **Suspicious Logic**, **Exploit Primitives**,
    **Suggested Next Steps**.
  - `re/<binary>/<func>.json` with the same fields structured for the harness.
- Pseudocode is wrapped as `<pseudocode>…</pseudocode>` untrusted data.
- The prompt must enumerate the architectural mitigations from the manifest so
  the model does not suggest impossible primitives (e.g. JIT spray on a
  W^X-enforced target).
- Harness endpoints: `re.analyze` (active risk class because it triggers an LLM
  call but no network targeting; treat as `passive` since no payloads leave the
  box — runs always, no confirmation), `re.read` (bounded read of result).

**Done when:** `mg-recopilot analyze` against a sample pseudocode fixture
produces both files and a unit test asserts the section headers exist.

#### S3. Item #11 — Adversarial prompt-injection fuzzer (new crate `mg-aifuzz`)

**What it is:** Fuzz harness for LLM-backed endpoints. Reuses `payload-engine`
patterns to ship a curated jailbreak/injection corpus, then iterates with a
mutator that scores success against rubric prompts.

**Specification:**

- New crate `engine-rust/mg-aifuzz/` (lib + bin).
- New payload set in `payload-engine`: `PayloadSet::PromptInjection` with
  sub-categories `RoleConfusion`, `IndirectInjection`, `SystemPromptLeak`,
  `ToolAbuse`, `PolicyBypass`.
- Template format (Burp-Intruder style, matches `mg-fuzz` template grammar):
  ```
  POST /chat HTTP/1.1
  Host: api.target.example
  Authorization: Bearer {{TOKEN}}
  Content-Type: application/json

  {"messages":[{"role":"user","content":"$$INJECT$$"}]}
  ```
- Output: `engagements/<name>/aifuzz/<run-id>.jsonl`, one row per attempt with
  `{ payload_category, payload_id, request_excerpt, response_excerpt, success_signal }`.
- Success-signal rubric: configurable regex list per category. Default rubric
  for `SystemPromptLeak` looks for `"system prompt"`, `"You are an AI"`,
  and any reproduction of a known system-prompt sentinel set in
  `aifuzz/sentinels.txt`.
- Harness endpoint `aifuzz.run` is `active`-class; runs only after the
  per-engagement confirmation flag in `engagement.json`.
- Honors the §11 `RateGovernor` once that lands.

**Done when:** `mg-aifuzz run` against a local LLM mock (use `cargo test
--features mock` with a small in-process HTTP server) produces the JSONL
output and at least one classified hit.

#### S4. Item #18 — Exploit-as-a-service scaffolding (new crate `mg-exploitgen`)

**What it is:** Given a CVE ID and a target-environment JSON, produces a
modular Rust exploit project skeleton with stages: `scanner/`, `validator/`,
`payload/`, `cleanup/`, plus a `runbook.md`.

**Specification:**

- New crate `engine-rust/mg-exploitgen/` (lib + bin).
- Inputs:
  - `--cve CVE-YYYY-NNNNN`
  - `--target-env <path>` — JSON file describing target stack, mitigations,
    network reachability, and constraints (no internet exfil, etc.).
- The CVE itself is **not** fetched from the network in the first slice. The
  operator pastes the CVE description into `--cve-description <path>`. A
  follow-on slice may add an opt-in NVD lookup behind `--fetch-nvd` once we
  decide how to cache the NIST schema.
- Output: a directory tree at `engagements/<name>/exploits/<cve>/`:
  ```
  exploits/<cve>/
  ├── Cargo.toml
  ├── runbook.md
  ├── src/
  │   ├── main.rs        // thin orchestrator
  │   ├── scanner.rs     // version detection
  │   ├── validator.rs   // proves the precondition without firing payload
  │   ├── payload.rs     // payload primitive stub + comments on legality scope
  │   └── cleanup.rs     // revert artifacts the exploit leaves
  └── tests/
      └── smoke.rs
  ```
- LLM is used **only** to fill the in-file `// TODO:` blocks and the runbook.
  The directory and Cargo skeleton come from a static template embedded in the
  crate via `include_str!`.
- `runbook.md` always carries a top banner:
  `> Authorized testing only. Confirm scope before running.`
- Harness endpoint `exploit.scaffold` mirrors the CLI; risk class is `read`
  because no traffic leaves the box.

**Done when:** scaffold produces a tree that `cargo check` accepts inside the
generated directory.

### Tier A — High-value follow-on

#### A1. Item #01 — OSINT dossier engine (extend `mg-recon`)

Add new stages to `mg-recon`:

- **WHOIS** — use the existing `http-client` to query a configurable RDAP
  endpoint (no third-party paid APIs in the default build).
- **HIBP-style breach lookup** — optional, gated by `HIBP_API_KEY`. Read-only,
  passive risk class.
- **GitHub org & member enumeration** — gated by `GH_TOKEN`. Use the public
  REST API; record repos, top contributors, and any leaked-secret hits via the
  existing `corpus-builder`.
- **Paste-site search** — pluggable provider trait; ship with a noop default.
- New output: `recon/osint-dossier.json` + Markdown view in `mg-tui`.

Risk class: `passive` across the board. Aggregator must record every external
call into `audit.log` with the source name.

#### A2. Item #10 — Supply-chain infiltration mapper (new crate `mg-supplychain`)

Given an org's public GitHub repos and a job-listing URL list:

1. Walk repos via the GitHub API, harvesting `Cargo.toml`, `package.json`,
   `requirements.txt`, `go.mod`, `pom.xml`.
2. Cluster dependencies with version pins; output a `supplychain/deps.json`
   ranked by `repos_using × external_distance`.
3. For each top-N high-value dep, generate typosquat candidates and check
   public-registry availability (read-only). Output `supplychain/typosquat-candidates.json`.
4. Parse job-listing text for tech-stack mentions to corroborate the dep graph.

Risk class: `passive`. No registry publish actions, ever.

#### A3. Item #15 — Network traffic behavioral fingerprinter (new crate `mg-trafficint`)

Reads `.pcap` or NetFlow CSV and produces:

- Flow clusters with named profiles (`shadow_saas`, `internal_db`, `unknown`).
- An LLM-generated narrative summary at `intel/traffic-summary.md`, with raw
  flow data wrapped as `<pcap_summary>` untrusted evidence.
- Per-host outbound endpoint heatmap.

The pcap parser is the heavy lift — use `etherparse` or `pcap-parser` rather
than hand-rolling. Risk class: `read` (no network).

#### A4. Item #12 — Judicial / corporate record excavator (extend `mg-recon` OSINT stage)

Adds two optional sources to the dossier:

- **SEC EDGAR** — parses public XBRL filings via the documented JSON endpoints
  (no scraping).
- **PACER** — only via the documented RSS feeds for free dockets; **do not**
  scrape behind paywalled record fetches.

Both stages must be off by default and require an explicit
`--sources sec,pacer` flag. Risk class: `passive`.

### Tier B — Niche or ethics-heavy

These modules ship behind a per-engagement consent flag in `engagement.json`
(`"phase2_consent": ["persona_forge", "phishing", "stylometry_strip", ...]`).
Harness endpoints refuse to run them without the matching consent entry.

- **#02 Persona forge / #07 Phishing architect (`mg-personaforge`, `mg-phishkit`).**
  Limit output to text artifacts (no auto-posting, no auto-send). Every
  generated persona/lure carries a `WATERMARK: GeistScope authorized test —
  <engagement-id> — <iso-timestamp>` line so the artifacts are
  field-recognizable in case of incident review.
- **#14 Contract / EULA auditor (`mg-legal`).** Pure offline LLM tool reading
  a Markdown/PDF and outputting a clause-by-clause risk table. Useful but
  low-priority for the bug-bounty loop. Easy build (single binary, single
  prompt).
- **#16 Sovereign AI stack builder.** Mostly documentation under
  `docs/SOVEREIGN_STACK.md` plus a `setup-sovereign-stack.sh` provisioner.
  Not a Rust crate.
- **#17 Whistleblower redaction (`mg-redact`).** Offline only. Strips EXIF and
  document metadata (deterministic) and runs a stylometric-rewrite LLM pass
  flagged as **experimental** — stylometric stripping is research-quality and
  must not be presented as a guarantee.

### Tier C — Specialized

Tracked but **not scheduled**. If we pick them up later, each gets its own
specification block here first. None of them block the bug-bounty loop.

- #03 Surveillance-countermeasure / opt-out generator (`mg-optout`).
- #05 Linguistic-fingerprint generator (paired with #02; defer until #02 is
  validated in a real engagement).
- #06 Darknet market intelligence parser — needs a Tor scraping pipeline that
  GeistScope does not currently host.
- #09 Steganographic dead-drop — explicitly out of scope for the bug-bounty
  product; revisit only if a defensive detection use case appears.
- #13 RF / hardware-capture interpreter — different track entirely; spin off
  into a sibling repo rather than adding here.
- #19 Crypto mixer transaction graph — needs on-chain data plumbing that does
  not yet exist in GeistScope.

### Tier X — Declined

- **#20 Memetic warfare lab.** GeistScope will not ship an offensive influence-
  ops generator. The **defensive twin** — detection of coordinated content —
  is already partially addressed by §15 / Item #15 (traffic + content
  behavioral fingerprinting) and that is where any work in this space goes.

### Phase 2 completion checklist

- [x] §14 S1 — `mg-report disclose` + harness `report.disclose`
- [x] §14 S2 — `mg-recopilot` crate + harness `re.analyze` / `re.read`
- [x] §14 S3 — `mg-aifuzz` crate + `PayloadSet::PromptInjection` + harness `aifuzz.run` / `aifuzz.consent`
- [x] §14 S4 — `mg-exploitgen` crate + harness `exploit.scaffold`
- [ ] §14 A1 — `mg-recon` OSINT stage (WHOIS, HIBP, GitHub, paste-site)
- [ ] §14 A2 — `mg-supplychain` crate
- [ ] §14 A3 — `mg-trafficint` crate
- [ ] §14 A4 — `mg-recon` SEC / PACER sources
- [ ] §14 B — Per-engagement `phase2_consent` flag + Tier B crates as needed
