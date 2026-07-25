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
- [x] **4. Refine CrossTenantRead** (`request-corpus`) — added `cross_tenant: Option<CrossTenantSwap>`
  (attacker/victim record + session + victim marker), populated from the A/B group; reclassified
  CrossTenantRead as RequiresApproval/not-autonomous (HighActive). Gate: passed (9 tests + 6 rippled
  construction sites fixed).
- [x] **5. mg-hunt authz path** (`mg-hunt`) — added `--risk authz` → `run_authz` + async
  `execute_authz_test` (select CrossTenantRead → approve → resolve victim record + attacker session
  headers → swapped request → send → marker → classify → evidence → finding → ledger). Generalized
  evidence/finding helpers for reuse. Gate: passed (13 tests). *Adjustment: added a dedicated authz
  risk level rather than repurposing the read-only fixture path.*
- [x] **6. Offline E2E + status** — vulnerable two-tenant axum lab; `execute_authz_test` confirms
  `boundary_violation_read` + evidence + High finding + ledger, all on `127.0.0.1`. Checklist
  updated. Gate: E2E passes (14/14 ×3 stable); clippy clean.

## Slice complete

All seven tasks landed as verified commits. Broken access control (IDOR) is now a second confirmed
class, end to end. See `METHODOLOGY.md`. The auth-aware runner also unblocks authenticated SSRF (a
Slice 2 dependency). Next roadmap slice: SSRF hardening.

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
