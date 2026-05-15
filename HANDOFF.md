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

## What Already Exists (Do Not Rebuild)

| Binary / Crate | Status |
|---|---|
| `engagement` lib | Complete — workspace, scope, audit, findings |
| `session` lib | Started — env-backed token header resolution and session.json helpers; form/OAuth/tool integration pending |
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

- 2026-05-15: Added initial `mg-harness` crate and CLI with JSON invocation/results, endpoint registry, version/risk checks, confirmation gate for `recon.run`, `engagement.open`, `scope.check`, and scoped `finding.create`. Exposed `mg-recon` as a library so harness calls recon directly instead of shelling out. Added reusable `Finding::next_id`. Updated docs and wiki for the AI harness direction.
- 2026-05-15: Completed the first `mg-tui` Harness tab slice. The TUI now has a Harness tab that reads `audit.log`, shows current/last harness endpoint activity, queue depth placeholder, endpoint registry status, and a harness-only audit tail. This completes the checklist item for a visible Harness tab while the long-running daemon queue is still pending.
- 2026-05-15: Added read-only `mg-harness` endpoints for `engagement.status` and `finding.read`. `engagement.status` summarizes key output files and counts; `finding.read` resolves a safe finding ID prefix, bounds model-visible markdown to 256 KiB, and returns evidence references.
- 2026-05-15: Started §3 session management with a new `session` library crate. The first slice writes and loads `session.json` env-var references, rejects plaintext cookie saves, resolves token auth headers from environment variables, scope-checks session test URLs, and adds `engagements/*/session.json` to `.gitignore`. Form login, OAuth refresh, encryption-at-rest for future stored cookies/tokens, CLI commands, and tool integration remain pending.
- 2026-05-15: Expanded the `mg-tui` browser slice from rendered page viewing toward the roadmap request/response inspector. The Browser tab now shows a side inspector with request method, final URL, response status, MIME type, page inventory, response headers, redacted `Set-Cookie` inventory, and in-page search (`/`, `n`, `N`) with match highlighting. This is a partial completion of the P1 browser-core request/response viewer item; request corpus import, diffing, replay/fuzz actions, and finding creation remain pending.

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
- [ ] `mg-engagement credentials-set / credentials-test` subcommands
- [ ] `mg-crawl` using session headers transparently
- [ ] `mg-fuzz` injecting session headers automatically
- [ ] `mg-probe --active` with all check modules in §4
- [ ] `payload-engine` crate with stack-aware payload selection
- [ ] `mg-fuzz --context-aware` using payload-engine
- [ ] `mg-oob serve / get-url / poll` binary with HTTP + DNS listeners
- [ ] Harness `oob.*` endpoints wired to `mg-oob`
- [ ] `mg-crawl` JS analyzer with GraphQL introspection, library CVE list, internal-ref extraction
- [ ] `ai-prioritize` chain-reasoning second pass writing `chain-analysis.md`
- [ ] `mg-report generate` producing HackerOne-formatted Markdown with CVSS score
- [ ] Harness `report.generate` endpoint
- [ ] `tests/target/docker-compose.yml` with custom vulnerable target
- [ ] Integration test suite asserting full pipeline finds known bugs
- [ ] GitHub Actions CI running clippy, unit tests, integration tests
- [ ] `RateGovernor` in `engagement` lib, wired into all network tools
- [x] `mg-tui` Harness tab showing audit log tail and active endpoint
- [ ] All new crates in workspace `Cargo.toml`
- [ ] `README.md` and wiki updated with new binaries and workflow
