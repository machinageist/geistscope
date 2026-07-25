# METHODOLOGY — IDOR slice (living dev-log)

Running record of *how* this slice is built, to teach. Per task: **RED** → **what failed** →
**GREEN** → **what the test revealed** → **adjustment**. Companion to the SSRF slice's
methodology; distillable into a public writeup later.

## Why this slice, this way

The SSRF slice proved the adaptive loop but left the runner GET-only and auth-blind, and the
authorization/IDOR path running on fixtures. IDOR is the highest capability-per-line next move: it
reuses the candidate, the verdict, the runner, and the evidence writer that already exist, and needs
no out-of-band machinery — it's a direct-response class. The one real body of work is making the
engine *authenticated*: materialize a named identity's credentials into headers, send a captured
request as a *different* identity (the session swap), and let the existing semantic verdict decide
whether the attacker reached the victim's data. That "auth-aware runner" is also exactly what SSRF
needs to reach authenticated sinks, so it pays for two classes at once.

The discipline is the same: each capability starts as a failing test that pins the behavior —
including the safety refusals (never materialize a plaintext secret; never send a non-executable
plan) — then the minimum code to make it pass.

## Task 0 — Scaffold

Wrote this dev-log and the slice PLAN.md. No code; the gate is that the docs exist. Design intent
recorded so the first RED test (Task 1) fails for the right reason.

## Task 1 — Session header resolver

**Goal.** Turn a named identity's stored credential *references* into real request headers, so the
runner can send a request "as Alice" vs "as Bob" — the primitive a session swap needs.

**Design.** `SessionProfile` stored `auth_refs: Vec<SecretRef{kind, env_var}>` but nothing turned a
*profile* into headers (only a private `SessionConfig` path existed). Added
`SessionProfile::resolve_headers(env_lookup)` with an injectable lookup for testability, plus an
`auth_headers()` convenience over the real environment. Header mapping keys off `SecretRef.kind`:
`token`/`bearer` → `Authorization: Bearer …`, `authorization` → raw `Authorization`, `cookie` →
`Cookie`, anything else → a literal header name (covers `X-Api-Key`, `X-Tenant`, …).

**RED → GREEN.** Three tests: env refs resolve to the right headers; a missing env var fails
(`MissingEnv`); and — the safety property — a plaintext `SecretRef` is **never** materialized into a
header (`PlaintextSecretRejected`). `cargo test -p session` first failed to compile
(`no method resolve_headers`), then passed 11/11; clippy clean.

**What it revealed.** Enforcing the no-plaintext invariant *at resolution* (not just at save) means a
credential can only ever reach the wire through an env reference — the resolver structurally cannot
leak a stored plaintext value, mirroring the same defense the SSRF slice put in `build_injected_request`.

**Adjustment.** None. Task 2's runner will call `resolve_headers` for the attacker identity.

---

## Task 2 — Auth-aware runner

**Goal.** Let the runner send a request *as an identity* — arbitrary method, custom headers
(including auth), and a body — instead of the SSRF slice's bare `GET url`.

**Design.** The gap was in the shared client, not the runner: `http_client::Client` only exposed
`get`/`post_json`. Rather than reach for raw reqwest in the runner (which the conventions forbid),
extended the shared client with a general `send(method, url, headers, body)` carrying the same
throttle/retry/UA behavior, plus an `InvalidMethod` error. `ReplayRunner::run` now calls `send` with
the request's own method/headers/body. The runner stays identity-agnostic — it faithfully sends
whatever request it's handed; assembling the attacker's auth into that request is Task 3/5's job.

**RED → GREEN.** A wiremock test that only responds to `POST /api/resource/42` carrying
`authorization: Bearer alice-jwt` — so a pass proves the method *and* the auth header were sent
verbatim (the SSRF slice could never have sent either). Both existing runner tests (GET record,
no-send refusal) still hold. http-client 3/3, replay-runner 3/3, and mg-hunt 12/12 (the SSRF E2E
routes through the same `send` now) — no regression. Clippy clean.

**What it revealed.** The "auth-aware runner" everyone said IDOR needed turned out to be a
one-method extension to the shared client plus a one-line call-site change — because the SSRF slice
had already built the plan/approval/record/refuse scaffolding around the send. The capability that
unlocks a whole second vuln class (and authenticated SSRF) was mostly already there.

**Adjustment.** None.

---

## Task 3 — Apply the session swap

**Goal.** The core IDOR primitive: take the victim's captured request and re-issue it under the
*attacker's* identity, so the verdict can decide whether the attacker reached the victim's data.

**Design.** Added `build_swapped_request(method, url, base_headers, attacker_headers, body)` — a pure
sibling of `build_injected_request`. It keeps the victim request's URL (pointing at the victim's
resource) and non-secret headers, **strips any auth the capture carried** (reusing the same
`is_sensitive_header` filter), and attaches only the attacker identity's resolved auth. The result
is "the victim's request, sent as the attacker." Marker derivation needs no new code: the existing
`ReplayOutcome::with_target_tenant_markers` + `SemanticDiffEngine::classify` already flag
`BoundaryViolationRead` when a victim marker appears in the attacker's response — Task 5 attaches the
candidate's victim marker to the outcome before classifying.

**RED → GREEN.** One test: given a victim request carrying `Bearer victim-token`, the swapped request
drops it and carries only `Bearer attacker-token`, preserves benign headers, and leaves the victim
resource URL intact. replay-engine 16/16, clippy clean.

**What it revealed.** The `ReplaySubstitution{from_session, to_session}` metadata already in the plan
hash finally has an execution meaning — the swap it described is now a real request transform. And
because the verdict half (`classify` → `BoundaryViolationRead`) was already built for the pre-SSRF
authorization work, Task 3 was a single pure function.

**Adjustment.** None — confirmed that "derive target markers" is orchestration (Task 5) over existing
primitives, not new engine code.

---

## Task 4 — Carry the swap on the candidate

**Goal.** Make a `CrossTenantRead` candidate self-describing: which record is the attacker (whose
session), which is the victim (whose resource + marker), so Task 5 isn't guessing from positional
order.

**Design.** Added a structured `cross_tenant: Option<CrossTenantSwap>` field
(`{attacker_record_id, attacker_session, victim_record_id, victim_marker}`) populated in
`cross_tenant_read_candidate` from the grouped A/B records (attacker = first identity, victim =
second; marker = victim's `tenant_id`). Also **reclassified `CrossTenantRead` as
`RequiresApproval` / not `autonomous_safe`** — a live cross-tenant read under a swapped identity is a
HighActive test, exactly like SSRF, so it must be approval-gated, not auto-run by the old read-only
fixture path.

**RED → GREEN.** Updated the existing A/B test to expect the new safety and assert the populated
swap. Adding the field rippled to seven construction sites (four in `request-corpus`, and the test
helpers in `replay-engine`/`replay-runner`/`mg-hunt`) — each got `cross_tenant: None`. All four
affected crates green (request-corpus 9, replay-engine 16, replay-runner 3, mg-hunt 12), clippy
clean; the `serde(default)` keeps old `candidates.jsonl` deserializable.

**What it revealed.** The shared `CorpusCandidate` struct is now accumulating per-class fields
(`injection_params` for SSRF, `cross_tenant` for IDOR). That's a smell worth watching — a third
class would argue for a typed per-kind payload enum instead of parallel `Option` fields. Noted for a
future refactor; not worth churning now.

**Adjustment.** The safety reclassification means Task 5 needs a new `select_authz_candidates`
(kind == `CrossTenantRead`) path, mirroring `select_ssrf_candidates`; the old read-only fixture path
will no longer pick these (they're not `autonomous_safe`), which is correct.

---

## Task 5 — mg-hunt authz path

**Goal.** Wire the IDOR loop into `mg-hunt`, reusing everything the SSRF path built.

**Design decision (adjustment).** The plan said "point the *read-only* path at the live runner." In
practice it was cleaner to add a dedicated `--risk authz` path than to rip out the tested read-only
fixture logic — so `RiskFilter::Authz` → `run_authz`, mirroring `run_ssrf`. `run_authz` selects
`CrossTenantRead` candidates, requires `--confirmed`, resolves the victim record
(`swap.victim_record_id`) and the attacker's headers (load the named session profile named by
`swap.attacker_session` → `auth_headers()`), and drives `execute_authz_test`, which: approves the
plan, builds the swapped request (victim URL + attacker auth via `build_swapped_request`), sends it,
attaches the victim marker to the outcome, classifies (`BoundaryViolationRead` if the marker leaks),
writes evidence, emits a finding, and records the ledger hash.

**Refactor for reuse.** The SSRF-specific `write_ssrf_evidence`/`emit_ssrf_finding` became generic
`write_replay_evidence(kind_label, …)` and `emit_finding(tool, title, recommendation, …)`, so both
classes share one evidence/finding path. Clippy's `too_many_arguments` (8/7) then forced dropping the
`run_id` parameter — it's always `run-{plan_hash}`, so the helper derives it. A good nudge: the
signature was carrying a value it could compute.

**RED → GREEN.** Unit test pins that `select_authz_candidates` keeps only `CrossTenantRead`. The live
loop is deferred to Task 6's E2E (needs a running multi-identity lab). mg-hunt 13/13; clippy clean;
the SSRF path still routes through the now-generic evidence/finding helpers unchanged.

**What it revealed.** The whole IDOR orchestration is structurally identical to SSRF minus the OOB
half — same plan/approve/send/classify/evidence/finding/ledger spine, with `classify` (not
`classify_ssrf`) and a session-swap request (not a payload injection). The second vuln class cost far
less than the first because the first built the skeleton.

**Adjustment.** None. Task 6 stands up a two-tenant lab and drives `execute_authz_test` directly with
the attacker's headers (bypassing session env), proving the closed IDOR loop.

---

## Task 6 — Offline end-to-end acceptance

**Goal.** One test that fails if any IDOR piece is wrong, against a local target only.

**The lab.** An axum server on `127.0.0.1` with one deliberately *vulnerable* route,
`GET /api/projects/bob-1`, that returns the victim's object (`owner_tenant: tenant-b`) to **any**
caller — no ownership check. That single behavior is a faithful broken-object-level-authorization
sink. The test builds bob's captured request, a `CrossTenantRead` candidate whose swap names alice as
the attacker and `tenant-b` as the victim marker, and drives `execute_authz_test` with alice's
headers.

**What it proves.** The runner replays bob's request carrying alice's `Bearer` token; the vulnerable
lab returns bob's data; the victim marker `tenant-b` is present in alice's response, so `classify`
returns `boundary_violation_read`; an evidence bundle (`replay_io.json`) and a High finding are
written and the plan hash is recorded. The test asserts each. Nothing leaves `127.0.0.1`.

**Result.** mg-hunt 14/14, stable over three repeated runs (both the SSRF and IDOR E2Es); clippy
clean.

## Status: slice complete

Broken access control is now a second confirmed-finding class, closed end to end. Seven tasks, each
a committed RED→GREEN increment. The striking result: the IDOR slice was materially *cheaper* than
SSRF — the verdict, evidence, plan/approval, and runner scaffolding all already existed, so the net-
new work was one session-header resolver, one `Client::send`, one `build_swapped_request`, one
candidate field, and the orchestration wiring. The engine's second vuln class rode almost entirely
on the first one's bones. The one architectural note for later: `CorpusCandidate` now carries two
per-class optional fields (`injection_params`, `cross_tenant`) — a third class should trigger a typed
per-kind payload refactor rather than a third parallel `Option`.
