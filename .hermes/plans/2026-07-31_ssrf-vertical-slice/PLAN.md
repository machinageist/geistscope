# SSRF Vertical Slice — Implementation Plan

Date: 2026-07-31
Status: In progress — Task 3.2 implemented; plan hardening is the next required slice
Change spec: `SPEC.md`
Product decision log: `../../2026-07-23_hunting-engine-restructure.md`
Rust workspace: `/home/mgeist/geistscope/crates`

## Working method

- Strict TDD: add one failing behavior test, observe the failure, implement the minimum behavior, rerun focused tests, then run affected-package tests.
- One logical slice per commit after Jeff reviews the checkpoint result.
- Preserve a working workspace after every task.
- Do not refactor or prune unrelated tools while the benchmark is incomplete.
- Stop at each marked design checkpoint; do not silently choose architecture or product behavior.

## Definition of done

A single offline integration command starts a disposable callback listener and target benchmark, imports an observed URL-input request, builds and policy-checks an immutable SSRF plan, executes exactly one safe callback probe, correlates the token, and writes immutable evidence. The vulnerable endpoint yields `verified_finding`; the secure endpoint yields no finding; an unauthorized plan fails before network execution.

Required final checks:

```bash
cd /home/mgeist/geistscope/crates
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace -- -D warnings
git diff --check
```

## Phase 0 — Align the architecture

### Task 0.1 — Inspect and classify the reusable path

Status: complete

Observed:

- `mg-webscan/src/ssrf.rs` is a standalone payload-spraying scanner that directly emits findings from response keywords or old callback files.
- `mg-oob` is a working HTTP listener, but its token/output model is process-local and file-oriented rather than plan-bound.
- `request-corpus` and `replay-engine` encode authorization-specific enums and cannot represent SSRF cleanly without redesign.
- `mg-hunt` is a fixture-backed orchestrator and does not perform live HTTP replay.
- `action-policy`, engagement scope/program rules, evidence immutability, and plan hashing are suitable safety foundations.

### Design Checkpoint 1 — Authoritative engine boundary

Status: resolved by recommended default after check-in timed out

Recommended choice: create one new library crate, provisionally called `hunt-engine`, containing capability-neutral campaign types and orchestration ports. Keep CLI/TUI/harness as clients. Adapt proven old primitives behind the engine and migrate one vertical slice at a time. Do not make `mg-hunt` main.rs the business-logic owner.

Alternative: incrementally generalize `request-corpus`, `replay-engine`, and `mg-hunt` in place. This touches less initially but risks preserving the fragmented architecture the rebuild is meant to replace.

Decision: create the new capability-neutral `hunt-engine` library. The check-in timed out with
instructions to use best judgment, so implementation proceeded with the recommended boundary.

## Phase 1 — Define capability-neutral campaign contracts

### Task 1.1 — Add result and evidence-contract domain types

Status: complete

Behavior first:

- verified results require explicit evidence-contract satisfaction;
- candidates, negative tests, and invalid tests remain distinct;
- arbitrary model-supplied confidence cannot promote a result;
- result serialization contains references and hashes, not raw secrets.

Expected implementation area depends on Design Checkpoint 1.

Focused verification:

```bash
cargo test -p hunt-engine --test result_contract
cargo clippy -p <approved-engine-crate> -- -D warnings
```

### Task 1.2 — Add capability-neutral observations, hypotheses, and action plans

Status: complete

Behavior first:

- an observation can produce an inert hypothesis;
- an action plan includes scope, risk, budgets, stop conditions, evidence requirements, and immutable hash material;
- plan hashes change when executable semantics change;
- presentation prose does not affect execution semantics;
- unsafe or missing path/budget fields fail validation.

### Design Checkpoint 2 — Benchmark process boundary

Status: resolved — in-process Rust benchmark approved

Recommended choice: start with an in-process Rust integration benchmark using ephemeral loopback ports. It gives deterministic CI, precise network-attempt assertions, and fast TDD. Add a containerized black-box benchmark after the engine path works.

Alternative: containerized lab from day one. This is closer to operator deployment but adds lifecycle and CI complexity before the domain contract is proven.

Decision: use in-process Rust fixtures first; defer the containerized black-box lab until the
engine behavior is proven.

## Phase 2 — Build the controlled SSRF benchmark

### Task 2.1 — Implement vulnerable and secure target fixtures

Status: complete

Behavior first:

- vulnerable endpoint performs one HTTP GET to the supplied callback URL;
- secure endpoint does not contact the callback URL;
- both expose the same input shape;
- fixtures bind only to ephemeral loopback addresses;
- tests can assert exact callback counts and request paths.

### Task 2.2 — Implement a plan-bound callback recorder

Status: complete

Behavior first:

- token is unique, validated, expiring, and bound to one plan hash;
- unknown, malformed, reused, or expired tokens cannot satisfy an evidence contract;
- captured headers/body are bounded and sensitive values redacted;
- callback records are serializable, hashable evidence artifacts.

### Design Checkpoint 3 — Callback ownership

Status: resolved — engine-owned callback API approved

Compare the plan-bound recorder against `mg-oob`. Decide whether `mg-oob` becomes a thin client/worker over the new callback API or remains temporarily quarantined while the engine owns callback lifecycle.

Decision: `hunt-engine` owns plan-bound callback lifecycle and correlation. `mg-oob` may become a
thin worker/client after the engine contract is proven; its current direct finding emission and
unredacted standalone callback-file model are not authoritative.

## Phase 3 — Generate and authorize the SSRF test

### Design Checkpoint 3.5 — Observed-request ownership

Status: resolved — engine-owned normalized HTTP observation approved

Recommended choice: define a minimal capability-neutral observed HTTP request in `hunt-engine`,
then adapt current `engagement::TrafficRecord` data at the boundary. Depending directly on the old
traffic schema would make the new engine inherit authorization-prototype fields and persistence
assumptions before its own state model is designed.

Decision: `hunt-engine` owns the normalized request contract. Existing traffic records will enter
through adapters rather than defining the rebuilt engine's state model.

### Task 3.1 — Generate an inert SSRF candidate from observed traffic

Status: complete

Behavior first:

- URL-like query/body input produces an SSRF candidate with exact source record and mutation location;
- arbitrary headers do not become candidates by default;
- state-changing source requests are not autonomous in this slice;
- candidate generation sends no network traffic.

### Design Checkpoint 3.6 — Callback destination authority

Status: resolved by default — exact campaign callback origin

Recommended choice: each campaign receives one exact engine-owned callback origin (scheme, host,
and port). Plans may append only engine-generated token paths. A host/domain allowlist would permit
model-controlled scheme, port, and path changes and is unnecessarily broad for the first slice.

Decision: the checkpoint timed out with permission to use best judgment; selected the exact-origin
design. Callback URLs may differ only by engine-generated token path.

### Task 3.2 — Build the immutable callback test plan

Status: complete

Behavior first:

- plan mutates exactly one named input with one callback URL;
- redirects disabled, concurrency one, request/time/byte budgets explicit;
- plan carries current scope and program-rule references;
- only campaign-owned callback destinations are accepted;
- plan hash binds token, mutation, target, policy-relevant fields, and evidence contract.

### Task 3.2a — Harden secret and executor boundaries

Status: complete

Before policy or network execution, split engine-only executable state from model-visible plan
metadata. Remove raw callback tokens and observed query values from serializable views, replace
ad-hoc hash material with a named canonical structure, preserve the token for plan-bound callback
registration, and expose an exact one-occurrence mutation contract only to engine code.

Implementation handoff: `agent-specs/00-plan-secret-and-execution-contract.md`.

### Design Checkpoint 3.75 — Policy component reuse

Status: resolved — reuse `action-policy` as the sole authority via a narrow adapter

Recommended choice: keep `action-policy` as the deterministic policy authority and add a narrow
adapter from immutable `hunt-engine` plans. Reimplementing risk and approval rules in the new crate
would create two policy authorities and discard one of the strongest reusable foundations.

Decision: Jeff directed proceeding on all slices; selected the recommended reuse. `action-policy`
remains the only policy evaluator; `hunt-engine::policy` is a thin adapter that maps immutable plan
facts to `PolicyRequest` and never re-implements risk or approval rules.

### Task 3.3 — Gate execution through Rust policy

Status: complete

Behavior first:

- out-of-scope, ambiguous, expired-rules, or automation-disallowed plans fail before network I/O;
- the safe callback-only SSRF probe receives the approved risk classification;
- model arguments cannot lower risk or replace the callback destination;
- an audit decision is recorded for allow, block, or approval-required outcomes.

## Phase 4 — Execute, correlate, and preserve proof

### Task 4.1 — Add the bounded HTTP executor

Status: complete

Behavior first:

- executes only validated immutable plans;
- resolves no model-provided secrets directly;
- follows no redirects;
- enforces byte/time/request budgets;
- stops on 429, WAF signal, 5xx, scope drift, or target instability;
- records exactly one sanitized request/response transaction for the benchmark.

### Task 4.2 — Correlate callback evidence deterministically

Status: complete

Behavior first:

- matching live token plus plan hash yields satisfied SSRF callback evidence;
- no callback yields a negative test after the observation window;
- mismatched/expired callback yields invalid or inconclusive, never verified;
- target response content alone never yields verified SSRF.

### Task 4.3 — Write immutable evidence and result

Status: pending

Evidence bundle includes:

- observation and candidate;
- immutable plan and plan hash;
- scope and policy decisions;
- sanitized request/response metadata;
- callback record and correlation verdict;
- audit references;
- redacted summary;
- human-verification runbook;
- artifact manifest and hashes.

Existing bundle paths cannot be overwritten. Any evidence write failure prevents result promotion.

## Phase 5 — Prove the end-to-end benchmark

### Task 5.1 — Vulnerable, secure, and blocked integration cases

Status: pending

Required assertions:

- vulnerable endpoint: one probe, one correlated callback, one verified finding;
- secure endpoint: one probe, zero callbacks, negative test, zero findings;
- blocked plan: zero target requests, zero callbacks, invalid/blocked result;
- repeated campaign run does not reuse the prior token or overwrite evidence;
- all output remains under the engagement root.

### Design Checkpoint 4 — Local API and persistence

Status: pending

After domain behavior works, choose the versioned local API shape and SQLite boundary based on real campaign state transitions rather than speculative endpoints.

## Phase 6 — Integrate one operator surface and prune the replaced path

### Task 6.1 — Add one thin CLI path

Status: pending

Expose the benchmark/campaign through a thin client of the engine. Do not duplicate orchestration in CLI code. Stable JSON should represent the result contract.

### Design Checkpoint 5 — First pruning decision

Status: pending

Classify `mg-webscan ssrf` and `mg-oob` as adapter, quarantine, or delete based on what the completed slice replaced. Update README claims to distinguish working engine behavior from deferred capabilities.

## Progress log

Detailed implementation handoffs for remaining work are indexed at `agent-specs/README.md`.

- 2026-07-31: inspected the current implementation and wrote the change spec and atomic plan.
- 2026-07-31: paused at Design Checkpoint 1 before production-code changes, per Jeff's request to remain involved in design decisions.
- 2026-07-31: Checkpoint 1 timed out with permission to use best judgment; selected a new
  capability-neutral `hunt-engine` library rather than extending authorization-specific CLI logic.
- 2026-07-31: completed Task 1.1 with behavior-first tests for deterministic evidence-contract
  promotion and distinct verified/candidate/negative/invalid result classes.
- 2026-07-31: Jeff approved the recommended in-process Rust acceptance benchmark at Checkpoint 2.
- 2026-07-31: completed Task 1.2 with capability-neutral observation/hypothesis types and immutable
  plan envelopes that bind scope, risk, budgets, redirects, stop conditions, executable-input
  hashes, and evidence contracts while excluding presentation rationale from approval hashes.
- 2026-07-31: completed Task 2.1 with offline vulnerable/secure fixtures on ephemeral loopback ports;
  tests prove one outbound GET for the vulnerable endpoint and zero for the secure endpoint.
- 2026-07-31: Jeff approved engine-owned, plan-bound callback lifecycle at Checkpoint 3; `mg-oob`
  is deferred as a possible thin worker/client rather than reused as the evidence authority.
- 2026-07-31: completed Task 2.2 with unique expiring callback tokens bound to immutable plan
  hashes, strict unknown/expired/reused/mismatched outcomes, bounded redacted headers, body hashes,
  and deterministic correlation that never stores raw token or body content in evidence records.
- 2026-07-31: Jeff approved an engine-owned normalized HTTP observation at Checkpoint 3.5, with
  adapters from existing traffic storage to be added at the system boundary.
- 2026-07-31: independent review found verified-result constructor/deserialization and artifact
  trust-boundary flaws. Corrected before continuing: validated domain aggregates are serialize-only,
  evidence kind/path/file/hash are checked under a canonical engagement root, symlink escapes fail,
  non-verified results preserve evidence, and verified construction is crate-internal only.
- 2026-07-31: completed Task 3.1 with engine-owned normalized HTTP observations and deterministic,
  network-inert SSRF candidates for absolute HTTP(S) query values. Candidate records retain source
  references, exact mutation locations, and value hashes—not raw suspected destination URLs.
- 2026-07-31: completed Task 3.2 with callback-only SSRF probe plans that bind one exact campaign
  callback origin, engine-generated token path, mutation location, target, policy references,
  callback token, safe one-request budget, no-redirect policy, and evidence contract into the plan
  hash. State-changing source observations are rejected for this autonomous slice.
- 2026-07-31: completed Task 3.2a. Split the plan into three views: a public redacted
  `SsrfProbePlanView` (no raw token, no observed query value, bare callback origin only), a
  policy-safe `ActionPlan` envelope whose target is origin+path with no query, and a crate-private
  `SsrfExecutablePlan` holding the token, observed URL, exact mutation, and callback URL. Replaced
  the ad-hoc newline hash string with a named `SsrfPlanHashMaterial` that binds source/candidate
  hashes, method, target scheme/host/port/path, query name/occurrence, callback origin + token
  hash, scope/rules hashes, and the observation window. Added a `CallbackLease` (token + non-zero
  window) that yields a plan-hash-bound `CallbackRegistration` expiring at issue+window; canonical
  stop-condition hashing; mandatory `AuthorizationExpired`; a fixed SSRF budget safety ceiling;
  callback-origin userinfo rejection; and a candidate/observation value-hash re-check before build.
  `SsrfProbePlan` is no longer `Serialize`. Verification: `cargo test -p hunt-engine` (all pass),
  `cargo clippy -p hunt-engine --all-targets -- -D warnings` clean, `cargo fmt -p hunt-engine --
  --check` clean, `git diff --check` clean.
