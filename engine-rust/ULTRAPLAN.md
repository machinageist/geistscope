# Bug Bounty Foundation — Plan

## Context

The GeistScope `engine-rust/` workspace has 7 Rust crates for recon and offensive tooling. The most recent crate, `engagement`, defines a per-engagement workspace (scope.json, audit.log, recon/, findings/, etc.) so that the operator and an AI assistant can collaborate on bug bounty work via shared files.

That foundation is in place but no other tool writes to it yet. A code audit (run before this plan) surfaced gaps that need fixing as the rest of the pipeline lands. This plan ships **5 forward features** (tool integration, recon orchestration, AI prioritization, crawling, replay) **interleaved** with **foundational adjustments** to the engagement crate, so each adjustment is justified by the step that uses it.

User choices already made:
- Adjustments ship **interleaved per step**, not preflight
- New tools are **separate binary crates**, not subcommands
- CIDR / URL path / port-spec scope features are **deferred to v2** (current `*.foo.com` semantics suffice)

## Sequence

The 5 steps run in order. Each step lists the engagement-crate adjustments that ship alongside it.

---

### Step 1 — Tool integration `[MEDIUM-LARGE, ~1 day]`

**Goal:** subdomain-enum, mg-scan, and fingerprint each accept `--engagement <name>`. They scope-check before any active probe, write structured JSON to `engagements/<name>/recon/<tool>.json`, and append a structured audit-log line.

**Adjustments shipping with this step:**

- **0a. Output envelope** (`engagement/src/envelope.rs` — NEW). Public `Output<T> { tool, schema_version, target, timestamp, args, data: T }` with serde derive. Every tool wraps its data in this. Schema version starts at 1.
- **0b. JSONL audit log** (`engagement/src/engagement.rs` — modify `audit()` ~line 107). Switch from plain text to JSON Lines: `{"ts":"...","tool":"...","target":"...","detail":{...}}`. `detail` is `serde_json::Value` so each tool can attach structured args. Migrate the existing test at ~line 199 to assert JSONL.
- **0c. Atomic JSON writes** (`engagement/src/engagement.rs` — new private `write_json_atomic`). Writes to `path.tmp` then renames. Replace the `fs::write` calls in `Engagement::init` (~line 50) and `Scope::save` (`scope.rs:50`). Closes the race when two tools edit scope concurrently.
- **0d. `Session` helper** (`engagement/src/session.rs` — NEW). `Session::load(name, root)` returns a struct that wraps the loaded `Engagement` + an open append-mode handle to `audit.log`. Methods: `check_scope(target) -> Result<()>`, `write_output<T: Serialize>(filename, Output<T>)`, `audit(tool, target, detail)`. All step-1 tools use this; no copy-paste of load/scope/audit logic.

**Per-tool changes:**

| Tool | Files | Where |
|------|-------|-------|
| subdomain-enum | `cli.rs`, `main.rs` | Add `engagement: Option<String>` to `Args`. In `main.rs` ~line 103, after `make_output`, if engagement is set: load `Session`, scope-filter the `subdomains` Vec, write `Output<ScanOutput>` to `recon/subdomain-enum.json`, audit with `{count: N, mode}`. |
| mg-scan | `cli.rs`, `main.rs` | Add `engagement: Option<String>` to `Args`. In `main.rs` ~line 66, for each `(display_name, ip)` after `resolve_targets`, check scope before `scanner::scan_ports`. Skip out-of-scope with a warning. Write `Output<Vec<ScanResult>>` to `recon/mg-scan.json`. Audit per host. |
| fingerprint | NEW: `cli.rs`, `main.rs`. Modify `Cargo.toml` to add `[[bin]]` + clap dep. | Minimal binary: take URL/host + `--engagement`. Build one `http_client::Client`, call `fingerprint_url`. Write `Output<Fingerprint>` to `recon/fingerprint.json`. Audit. |

**Tests:** envelope round-trip, atomic write smoke (best-effort), Session loads correctly. End-to-end: `mg-engagement init demo --target acme.test` → `subdomain-enum --engagement demo acme.test` → assert `recon/subdomain-enum.json` exists + audit.log has a JSONL line.

---

### Step 2 — `mg-recon` orchestrator `[MEDIUM, half day]`

**New crate:** `engine-rust/mg-recon/` — depends on `engagement`, `subdomain-enum` (lib), `fingerprint` (lib), `mg-scan` (lib), `http-client` (lib). All **in-process** (no subprocess spawning).

**Architecture choice:** in-process calling of library functions, not subprocess. Reasons: shared HTTP connection pool, typed Results instead of exit codes, single binary install. Tradeoff accepted: a panic in any sub-library would crash the orchestrator, but those libs don't panic.

**Files:**
- `mg-recon/src/main.rs` — CLI takes engagement name + optional `--force`
- `mg-recon/src/orchestrator.rs` — sequential stages

**Stages:**
1. Subdomain enum → discovered hosts (CT logs + brute force)
2. Fingerprint each discovered host → tech stack per host
3. Port scan each host (top 1000 by default) → open ports per host
4. Aggregate → `recon/recon-summary.json` indexed by host

**Resumability:** each stage checks if `recon/<stage>.json` already exists; if so, skips. `--force` overrides.

**Tests:** integration test with a mocked target (HTTP fixture); smoke test against a real engagement.

---

### Step 3 — `ai-prioritize` `[MEDIUM, half day]`

**New crate:** `engine-rust/ai-prioritize/` — depends on `engagement`, `llm-client`.

**Backend selection:**
1. If `ANTHROPIC_API_KEY` is set → use Anthropic (better quality)
2. Else probe `http://localhost:11434/api/tags` (Ollama) — if reachable, use Ollama
3. Else fail with clear "install Ollama or set ANTHROPIC_API_KEY" message

**Default Ollama model:** `llama3.2` (override via `--model`). User can run `ollama pull llama3.2` to install.

**Files:**
- `ai-prioritize/src/main.rs` — CLI
- `ai-prioritize/src/prompt.rs` — builds the structured prompt from `recon/*.json` envelopes + recent audit.log entries
- `ai-prioritize/src/parse.rs` — parses model output (request JSON-formatted ranking with rationale)

**Outputs:**
- `priorities.json` — machine-readable ranked list `[{rank, target, reason, suggested_actions[]}, ...]`
- `priorities.md` — human-readable narrative for the operator + AI assistant collaborator

**Why two outputs:** the AI assistant collaborator reads `priorities.md` to brief itself on the engagement; downstream tools could read `priorities.json` programmatically.

**Risk:** model output non-determinism. Mitigation: priorities are a discussion starter, not a verdict. Always re-runnable.

**Tests:** prompt-builder unit tests (deterministic input → expected prompt string); parse.rs robust to malformed JSON; integration test gated on `OLLAMA_AVAILABLE` env var.

---

### Step 4 — `mg-crawl` + JS analyzer `[LARGE, full day]`

**New crate:** `engine-rust/mg-crawl/` — depends on `engagement`, `http-client`. Adds: `scraper` (HTML parsing), `regex` (pattern catalog).

**Files:**
- `mg-crawl/src/main.rs` — CLI takes engagement name + starting URL(s)
- `mg-crawl/src/crawl.rs` — BFS, depth-limited (default 2), same-origin only, in-scope only
- `mg-crawl/src/extract.rs` — pull `<a href>`, `<script src>`, inline `<script>` blocks from HTML
- `mg-crawl/src/analyze.rs` — regex pass over JS for endpoints (`fetch(`, axios, XHR), secrets (AWS keys, GitHub tokens, JWTs)

**Storage layout:**
```
engagements/<name>/crawl/<host>/
├── pages/<sha256>.html
├── js/<sha256>.js
├── index.json         # URL → sha256 mapping
├── endpoints.json     # extracted endpoint URLs from JS
└── secrets.json       # regex-matched candidate secrets
```

**Etiquette:** honors `robots.txt` by default (`--ignore-robots` override). Default 1 req/sec (`--rate` override). Sets a User-Agent identifying the tool. Scope-checks every fetch and refuses out-of-scope.

**Regex catalog (initial):** ~10 high-precision rules — AWS access keys (`AKIA[0-9A-Z]{16}`), GitHub tokens (`gh[ps]_[A-Za-z0-9]{36}`), JWTs (`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`), Slack tokens, generic `api_key=` / `password=`.

**JS analysis tradeoff:** regex-only (cheap, fast, some false positives). Real parser (oxc/swc) deferred to v2. Document this.

**Tests:** crawl logic against a static localhost fixture; regex catalog unit-tested with positive and negative samples; integration smoke test verifying the storage layout.

---

### Step 5 — `mg-replay` `[SMALL-MEDIUM, half day]`

**New crate:** `engine-rust/mg-replay/` — depends on `engagement`, `http-client`.

**Files:**
- `mg-replay/src/main.rs` — CLI: `mg-replay <engagement> <finding-id>`
- `mg-replay/src/parse.rs` — extract `curl …` commands from the finding markdown's "Evidence" section
- `mg-replay/src/replay.rs` — re-execute parsed requests, diff response

**Logic:**
1. Load finding markdown by ID from `findings/`
2. Parse fenced code blocks (`bash`/`shell`) under `## Evidence`
3. For each curl: parse to URL/method/headers/body via a small parser (or `clap`-style approach)
4. Re-execute via `http-client`, capture response
5. Compare: status code, sha256(body), key headers
6. Write `findings/<id>-replay-<timestamp>.json` with diff
7. Print summary: "still vulnerable" / "appears fixed" / "indeterminate"

**Tests:** curl parser unit tests with realistic invocations; replay logic against a local fixture; ensure `--engagement` scope-check runs (don't replay against an out-of-scope target even if the finding is older).

---

## Critical files

**Modified (engagement crate):**
- `engagement/src/engagement.rs` — JSONL audit, atomic writes, new init dirs (`captures/`, `screenshots/` deferred until step 4 actually needs them)
- `engagement/src/scope.rs` — atomic save

**New files (engagement crate):**
- `engagement/src/envelope.rs` — `Output<T>` envelope
- `engagement/src/session.rs` — `Session` helper

**Modified (existing tool crates):**
- `subdomain-enum/src/{cli,main}.rs`
- `mg-scan/src/{cli,main}.rs`
- `fingerprint/Cargo.toml` (add `[[bin]]`)

**New (in fingerprint):**
- `fingerprint/src/{cli,main}.rs`

**New crates:**
- `engine-rust/mg-recon/`
- `engine-rust/ai-prioritize/`
- `engine-rust/mg-crawl/`
- `engine-rust/mg-replay/`

**Workspace metadata:**
- `engine-rust/Cargo.toml` — add 4 new members
- `engine-rust/README.md` — update crate map after each step

## Architectural risks (acknowledge, don't pre-solve)

1. **Schema versioning.** The `Output` envelope's `schema_version` is the migration handle. Bump it whenever a tool changes its `data` shape; downstream consumers handle multiple versions. Document the bump rule in `envelope.rs`.
2. **In-process orchestrator coupling.** `mg-recon` depends on `subdomain-enum`, `fingerprint`, `mg-scan` libs. Any breaking lib change cascades. The lib/bin split in those crates is already clean — orchestrator uses lib only.
3. **JS regex false positives.** Tunable. Track FP rate per real engagement; defer real parser until FP cost exceeds parser-integration cost.
4. **LLM non-determinism.** `priorities.md` is a discussion starter, not a verdict. Operator and AI assistant treat it as such.
5. **Rate-limit etiquette.** Bug bounty programs vary on probing aggression. `mg-crawl` defaults conservatively (1 req/sec). Document that operators must check program rules.
6. **Deferred scope features.** CIDR / URL paths / port specs are v2. Add a TODO in `scope.rs` referencing this plan.

## Verification per step

- **Step 1:** unit tests for envelope round-trip and atomic writes; end-to-end smoke `mg-engagement init demo --target acme.test && subdomain-enum --engagement demo acme.test && jq . engagements/demo/recon/subdomain-enum.json && tail engagements/demo/audit.log`.
- **Step 2:** integration test with HTTP fixtures; smoke test `mg-recon run demo` producing `recon-summary.json`.
- **Step 3:** prompt-builder and parser unit tests; integration test gated on Ollama availability.
- **Step 4:** crawl logic against static localhost fixture; regex catalog positive/negative tests.
- **Step 5:** curl parser unit tests; smoke test with a fake finding markdown.

After every step: `cargo build --workspace`, `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`.

## Effort total

Approximately **3.5–4 working days** end-to-end if sequenced strictly. Step 4 is the largest single chunk; steps 1 and 2 are the most foundational.

## Out of scope (for this plan)

- Tracing / structured logging across all crates (deferred — separate, independent change)
- `subdomain-enum` migration to use `http-client` (deferred — minor duplication, low value to fix now)
- Frontmatter expansion (CVSS, CWE, OWASP fields) — defer until first real submission needs them
- Additional CLI commands (`edit`, `list-findings`, `show-finding`, `status`) — defer until daily-use friction motivates them
- CIDR / URL path / port-spec scope matching — v2, tracked as TODO
