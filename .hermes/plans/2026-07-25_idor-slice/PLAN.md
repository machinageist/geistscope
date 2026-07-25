# PLAN — IDOR / Broken Access Control slice + auth-aware runner

Dated: 2026-07-25. Slice 1 of the post-SSRF roadmap
(`/Users/machinageist/.claude/plans/start-working-on-making-synthetic-nest.md`). Second priority
vuln class from the 2026-07-23 decision record.

> Living PLAN — status markers `[ ]` pending · `[~]` in progress · `[x]` done. After each task,
> `METHODOLOGY.md` records what tests revealed and downstream tasks adjust here.

## Why this slice

IDOR is the cheapest *new* OWASP class: the candidate (`CrossTenantRead`), the verdict
(`SemanticDiffEngine::classify` → `BoundaryViolationRead`/`SecureDenied`), the live runner, and the
evidence writer already exist, and it needs **no OOB**. The net-new work is auth materialization +
session-swap application + victim-marker derivation — and the auth-aware runner it requires also
unblocks SSRF against authenticated endpoints. Salvage source: `crates/mg-authz/src/main.rs`
(existing IDOR/BOLA two-session replayer). Tested only against `127.0.0.1`.

## Tasks (strict TDD; commit each verified task)

- [x] **0. Scaffold** — this PLAN.md + METHODOLOGY.md. Gate: docs written.
- [x] **1. Session header resolver** (`session`) — `SessionProfile::resolve_headers(env_lookup)` +
  `auth_headers()`; kind→header mapping; rejects plaintext refs; fails on missing env. Gate: passed
  (11 tests).
- [x] **2. Auth-aware runner** (`replay-runner` + `http-client`) — added `http_client::Client::send`
  (method/headers/body, same retry/UA); runner sends the request verbatim (incl. auth headers).
  Refusals unchanged; SSRF E2E still green. Gate: passed.
- [x] **3. Apply substitution + victim markers** (`replay-engine`) — `build_swapped_request` (victim
  request + attacker auth, victim auth stripped). Marker attachment reuses `with_target_tenant_markers`
  + `classify` (no new engine code). Gate: passed (16 tests).
- [~] **4. Refine CrossTenantRead** (`request-corpus`) — designate attacker vs victim record on the
  candidate and carry the victim marker + the two session labels. Gate:
  `cargo test -p request-corpus` + clippy.
- [ ] **5. mg-hunt authz path** (`mg-hunt`) — replace the fixture `load_replay_outcome` in the
  read-only path with a live authz replay (attacker session vs victim resource) through the
  auth-aware runner, under `--confirmed` + approval; classify → evidence → finding → ledger. Gate:
  `cargo test -p mg-hunt` + clippy.
- [ ] **6. Offline E2E + status** — local axum lab with per-identity resources (tenant A/B); attacker
  session reaching a victim object → `BoundaryViolationRead` confirmed + evidence + High finding,
  all on `127.0.0.1`. Update the progress checklist. Gate: E2E passes; full `cargo test`;
  `git diff --check`.

## Reuse (do not rebuild)

`request-corpus` `CrossTenantRead` (`from_traffic_records`) · `replay-engine`
`SemanticDiffEngine::classify` + `ReplaySubstitution` + `PlanBuilder`/approval · `replay-runner`
`ReplayRunner` · `evidence-core` · `session` `SessionProfile`/`SecretRef`. Salvage:
`crates/mg-authz/src/main.rs` (`load_session_headers`, `replay`, `classify`, `is_ownership_scoped`).

## Likely adjustment points

- `http_client::Client` exposes only `get`/`post_json`; sending arbitrary method+headers+auth may
  need a per-identity `Client` with `default_headers` or a reqwest-builder path (as `mg-authz::replay`).
- `ReplaySubstitution` is metadata-only today; wiring its application ripples into the runner call site.
- Deriving `target_tenant_markers` needs a stable victim marker on the candidate (Task 4 feeds Task 3/5).

## Safety

No third-party targets; all tests on `127.0.0.1`. Live sends only for `executable` (scope + approval)
plans. Secrets only via env-backed `SecretRef`; never materialize plaintext into headers or evidence.
Jeff's Rust conventions on every new file.
