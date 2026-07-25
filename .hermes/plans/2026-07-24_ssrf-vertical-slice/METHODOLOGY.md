# METHODOLOGY — SSRF Vertical Slice (living dev-log)

A running record of *how* this slice was built, written to teach. Each task gets an entry:
**RED** (the failing test and what it asserts) → **what failed** → **GREEN** (the minimal change) →
**what the test revealed** → **plan adjustment** (if any) and why. Intended to distill into a
public writeup later, so it explains reasoning, not just diffs.

## Why this slice, this way

GeistScope is being rebuilt as an *adaptive hunting engine*, not a scanner. The distinguishing
claim is a closed reasoning loop with a hard wall between an **AI control plane** (proposes,
prioritizes, explains) and a **deterministic execution plane** (validates scope/policy/budgets,
constructs requests, records evidence, decides verdicts). SSRF is the first vulnerability class
wired end-to-end because it is priority #1 and forces every part of that loop to exist: candidate
detection, a policy-gated live request, out-of-band confirmation, a deterministic verdict, and
immutable evidence.

The build is strictly test-first. Every capability starts as a failing test that encodes the
desired behavior (including the *refusals* — an out-of-scope or unapproved plan must send nothing),
then the minimum code to make it pass. This is what keeps an autonomous tool honest: the safety
properties are pinned by tests, not by intentions.

---

## Task 0 — Scaffold

**Goal.** Stand up the plan/methodology docs and two new crates (`oob-core`, `replay-runner`)
without changing behavior anywhere else, so later tasks have a home and the workspace still builds.

**Approach.** No test to write yet — this task's gate is `cargo build` from `crates/`. The two
crates are created as empty, header-only libraries and registered as workspace members. Network I/O
and the OOB listener are deliberately *not* added here; they arrive in Tasks 3–4 behind their own
failing tests. Keeping Task 0 inert means the first real RED test in Task 1 fails for the right
reason (missing SSRF logic), not because the tree doesn't compile.

**Design note — why two new crates instead of extending `replay-engine`.** `replay-engine` is
pure: it builds and hashes plans and classifies provided outcomes, with zero network I/O. That
purity is worth protecting — it is trivially testable and safe to call from anywhere. So live
sending goes in a new `replay-runner` crate, and OOB (token minting + a loopback listener) in
`oob-core`. The engine decides *what* is allowed and *what a result means*; the runner is the only
place that actually touches the network, and only for plans the engine already marked executable.

**GREEN.** Created the two crates as header-only libraries, registered them in
`crates/Cargo.toml`, and confirmed the workspace manifest still parses (`cargo metadata`) and both
compile (`cargo build -p oob-core -p replay-runner`).

**What it revealed.** The workspace root is `crates/Cargo.toml` — there is no manifest at the repo
root — so every `cargo` command must run from `crates/` (or with `--manifest-path`). Pinned that as
the working directory. No behavior change anywhere else; the tree is green and ready for the first
real RED test in Task 1.

**Adjustment.** None. Plan unchanged.

---

## Task 1 — SSRF candidate detector

**Goal.** Teach the corpus to notice server-side-request sinks: given captured traffic, emit a
`ServerSideRequestTarget` candidate for any request that exposes a URL/host-shaped parameter — and
emit nothing for benign inputs. This is the "hypothesize" step's raw material for SSRF.

**RED.** Three tests: a `?url=http://169.254.169.254/...` request must yield exactly one SSRF
candidate that `RequiresApproval`, is not `autonomous_safe`, and names `url` as the injection
param; a `?next=https://internal.svc.local/...` request must be caught by its URL-shaped *value*
even though `next` is an unremarkable name; and a `?q=hello` request must produce no SSRF
candidate. Ran `cargo test -p request-corpus` → compile error (`no variant ServerSideRequestTarget`,
`no field injection_params`). That is the RED: the tests encode an API that does not exist yet.

**GREEN.** Added the `ServerSideRequestTarget` variant, a new `injection_params: Vec<String>` field
on `CorpusCandidate` (so the candidate carries *which* parameter a later task will inject), and an
analyzer that runs for every record: it flags a parameter when the name is in a curated
SSRF-prone set (`url, uri, redirect, callback, webhook, fetch, host, …`) **or** its value looks
like a URL. SSRF candidates are always `RequiresApproval` + `autonomous_safe = false`, matching the
decision record's rule that OOB/internal-network tests need explicit approval. Tests pass 9/9;
clippy clean.

**What it revealed.** Two concrete facts that shaped the code:
1. `TrafficRecord.params` holds parameter *names only* — values are not in it. So name-matching
   alone can't see a URL-valued parameter with a boring name (`next=…`). The analyzer therefore
   parses `record.url` query pairs to inspect values, and still consults `params` for name matches
   (which also covers body parameters whose values weren't captured). This is why the crate gained
   a real `url` dependency (previously dev-only).
2. Adding a field to the shared `CorpusCandidate` struct is exactly the ripple the plan warned
   about: two dependent crates construct it directly in test helpers (`replay-engine`,
   `mg-hunt`) and stopped compiling until each got `injection_params: Vec::new()`. No production
   code outside `request-corpus` builds candidates, and nothing matches `CandidateKind`
   exhaustively, so the new variant was otherwise safe.

**Adjustment.** None to the plan. Note for Task 2/4: the injection target now travels on the
candidate as `injection_params`, so the substitution/runner do not need to re-derive it.

---

## Task 2 — Payload substitution + ReplayOutcome extension

**Goal.** Turn an SSRF candidate into the concrete request a replay will send (payload injected
into the right parameter, secrets stripped), and widen the outcome type so it can carry the
request that was sent and the full response — the raw material Tasks 5–6 need for a verdict and
evidence.

**Plan adjustment (before writing code).** The plan said "make `ReplaySubstitution` real." Reading
the type showed `ReplaySubstitution { name, from_session, to_session }` is a **session-swap**
concept for IDOR/cross-tenant tests, not payload injection — overloading it would conflate two
different ideas. So instead of mutating `ReplaySubstitution`, Task 2 introduces a new
`ReplayRequest` type and a pure `build_injected_request(...)`. Second adjustment: to keep
`replay-engine` free of the heavyweight `engagement` crate, `build_injected_request` takes
**primitives** (`method, url, headers, body, param, payload`) rather than a `TrafficRecord`; the
Task 4 runner will map a record into those. This keeps the engine a pure request/verdict library.

**RED.** Four tests: injection replaces only the target query param and leaves siblings intact;
secret headers (`Authorization`, `Cookie`) are never carried into the built request; an absent
param is appended rather than dropped; and `ReplayOutcome` can carry `response_headers` +
`sent_request`. `cargo test -p replay-engine` → compile errors (`cannot find ReplayRequest`,
`build_injected_request`, `with_response_headers`, ...). RED as intended.

**GREEN.** Added `ReplayRequest`, `build_injected_request` (URL-encoded query injection via the
`url` crate, sensitive-header filtering against a `SENSITIVE_HEADER_NAMES` list), and two new
`#[serde(default)]` fields on `ReplayOutcome` with builder methods. 11/11 tests pass; clippy clean.
mg-hunt (the only external `ReplayOutcome` consumer, via `::http` + serde) still passes 10/10 —
the `serde(default)` fields keep old replay-outcome fixtures deserializable.

**What it revealed.** The secret-redaction property is best enforced *structurally* at the point of
request construction, not assumed from upstream: even though the traffic store already strips
`Authorization`/`Cookie` at import, `build_injected_request` filters them again, so a replay can
never resurrect a credential regardless of how the record was populated. Auth for the replay will
instead be attached by the runner from the session vault (Task 4) — never from the record.

**Adjustment.** Plan wording for Task 4 updated in spirit: the runner maps `TrafficRecord` →
primitive args for `build_injected_request`, then attaches session auth before sending.

---

## Task 3 — OOB core library

**Goal.** Give the hunt a way to *prove blind SSRF*: mint an opaque token bound to a specific
plan/candidate, embed it in a callback URL, and — when the target's server fetches that URL —
correlate the inbound hit back to the plan that caused it. This is the deterministic-plane
capability the decision record insists on: "correlate OOB interactions" is Rust's job, never the
model's.

**Design choice.** Salvaged the token/callback idea from the old `mg-oob` binary but rebuilt it as
a **std-only synchronous listener** (loopback `TcpListener` + a worker thread), deliberately *not*
pulling in tokio/axum. Reasons: the library stays tiny and dependency-light, it is trivially
callable from synchronous test code, and the OOB listener's job (accept a request, read its path,
record a token) needs nothing an async runtime would provide. The key upgrade over `mg-oob` is
*binding*: `mint(engagement, plan_hash, candidate_id)` ties each token to its plan, so a hit
resolves to a structured `OobHit { binding, ... }` instead of mere set-membership.

**RED → GREEN.** Wrote four tests (a registered token's callback correlates to its binding; an
unknown token is not a hit; tokens are 32 lowercase-hex; the OOB URL targets loopback), then the
implementation. First run: 3 passed, **1 failed** — the correlation test timed out waiting for a
hit.

**What the failing test revealed (the useful part).** The correlation test passed when run alone
but flaked under the default parallel test run. Root cause: the listener socket is set
non-blocking (so the accept loop can poll for shutdown), and **on macOS/BSD a socket returned by
`accept()` inherits the listener's non-blocking flag** (unlike Linux, where it does not). So the
per-connection `read_line` intermittently hit `WouldBlock` before the request bytes arrived and
the handler bailed *without recording the hit* — a race that only shows up when the machine is
busy enough that the client's bytes haven't landed at read time. Fix: force the accepted stream
back to blocking (`set_nonblocking(false)`) before reading. After that, 5/5 repeated runs pass.
Lesson worth keeping: non-blocking-ness is a property of each socket and its platform-specific
inheritance — never assume an accepted connection matches the listener you configured.

**Adjustment.** None to the plan. `wait_for_hit(token, timeout)` (blocking, condvar-signalled) is
the API Task 4/7's runner will call after sending an SSRF payload; `correlate(token)` is the
non-blocking variant for after-the-fact checks.

---

## Task 4 — Live replay runner (the load-bearing piece)

**Goal.** The first crate that actually sends a request. Given an approved, in-scope plan and a
concrete request, send it through the shared HTTP client and record exactly what came back — and,
critically, send *nothing* for a plan the engine did not mark executable.

**Design gap surfaced (and fixed) before the runner could work.** Wiring the runner exposed a real
hole in the replay engine's approval model: `requires_approval` is true for any `!autonomous_safe`
candidate (all SSRF), and `executable` was computed as `!approval_required && InScope`. So an SSRF
plan was **never executable — even with a valid approval grant**. The approval-grant hash was
validated but never actually *enabled* execution; the approval mechanism was half-wired. Fixed
`PlanBuilder::build` so `executable = InScope && (!approval_required || approval_satisfied)`, where
`approval_satisfied` means a grant hash matching the plan hash is bound. This preserves every
existing behavior (the only approval-required test uses `Ambiguous` scope, which still fails the
`InScope` check; the mismatch test still errors) and adds the missing capability: an operator can
approve a HighActive SSRF test and it becomes executable. Pinned with a new test.

**Runner shape.** `ReplayRunner::run(plan, request)` gates first — out-of-scope → `OutOfScope`,
not-executable → `NotExecutable`, both without touching the network — then sends via
`http_client::Client::get` and records status, response headers, and body into the `ReplayOutcome`
(with the sent request echoed). v1 replays GET requests whose SSRF payload rides in the URL query
(matching the candidate detector, which flags query params); header/body injection is a documented
later extension. Uses the shared client, never raw reqwest.

**RED → GREEN, tested locally only.** Two `#[tokio::test]`s against a `wiremock` mock server bound
to `127.0.0.1`: an executable (approved) SSRF plan sends exactly one request and records the 200 +
custom header + body; a non-executable (unapproved) plan returns `NotExecutable` and the mock's
`expect(0)` verifies on drop that **zero** requests were sent — the no-send safety property proven,
not assumed. Both pass; clippy clean; `mg-hunt` (also a `PlanBuilder` consumer) stays 10/10.

**Adjustment.** The executable-semantics fix means Task 7 must *bind an approval grant* to the SSRF
plan (hash the plan, record operator approval, rebuild with the grant) before the runner will send
— which is exactly the `--confirmed` + approval flow the plan already calls for.

---

## Task 5 — SSRF/OOB semantic verdict

**Goal.** Turn a replay outcome (plus whatever the OOB listener correlated) into a deterministic
SSRF verdict, where "confirmed" is only ever backed by real evidence.

**Design choice.** Rather than overload the existing `classify` (which is IDOR/authz-shaped —
tenant markers and auth-failure shapes), added a sibling `classify_ssrf(outcome, oob_confirmed,
markers)`. The OOB result arrives as a plain `bool`, so `replay-engine` stays decoupled from
`oob-core` — the orchestrator (Task 7) correlates the hit and passes the answer in. Three new
verdict classes: `SsrfOobConfirmed` (a correlated out-of-band callback — the strongest proof),
`SsrfResponseLeak` (an internal-target marker reflected into the response body), and
`SsrfNoSignal`. The first two set `boundary_violation = true`; only these two are ever "confirmed",
and both require real evidence — a correlated hit or a marker actually present in the real
response. Nothing here is settable by an LLM.

**RED → GREEN.** Three tests, one per branch (OOB hit → confirmed; marker in body → leak; neither →
no-signal). 15/15 replay-engine tests pass; clippy clean. Adding the variants was safe because the
only exhaustive-ish consumer, `mg-hunt`, already matches `classification` with a `_` arm.

**Adjustment.** None. Task 7 will call `classify_ssrf` with `oob_confirmed` from
`OobListener::wait_for_hit` and `markers` being the cloud-metadata / lab-sentinel strings to look
for in the response.
