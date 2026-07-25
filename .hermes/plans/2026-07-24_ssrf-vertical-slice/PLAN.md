# PLAN — SSRF Vertical Slice (first end-to-end adaptive hunt)

Dated: 2026-07-24. Derives from `.hermes/plans/2026-07-23_hunting-engine-restructure.md`
(the north-star decision record), resolving its open item: *choose and scope the first
implementation vertical slice*. Chosen slice: **SSRF, including blind/OOB**.

> This PLAN.md is **living**. After each task, `METHODOLOGY.md` records what the tests actually
> revealed, and downstream tasks here are adjusted before proceeding. Status markers:
> `[ ]` pending · `[~]` in progress · `[x]` done.

## Why SSRF first

SSRF is priority vuln class #1 in the decision record, and it exercises the entire adaptive loop
(observe → hypothesize → select → execute safely → interpret → verify → report) on the smallest
surface. The engine today is a *half-loop*: the deterministic left half is real and tested, but
nothing sends live traffic — `mg-hunt`'s `load_replay_outcome` returns a fixture or an inert
`ReplayOutcome::http(200,"{}")`. This slice closes the loop for SSRF, tested entirely against
**local `127.0.0.1` fixtures — never a third-party target**.

## Reuse (do not rebuild)

`engagement::Scope::explain` · `action-policy::ActionPolicy::evaluate` · `engagement::program` /
`session` · `engagement::traffic` (`TrafficStore`/`TrafficRecord` + HAR/Burp/Caido import +
redaction) · `replay-engine::PlanBuilder::build` (plan hashing + approval binding) ·
`replay-engine::SemanticDiffEngine` (extend) · `evidence-core::EvidenceBundleWriter` (extend) ·
`payload-engine::PayloadSet::Ssrf` / `ssrf_payloads` · `mg-oob` (salvage into a lib) ·
`mg-webscan/src/ssrf.rs` (reference only) · `security-graph`.

## New crates

- `oob-core` (lib) — deterministic OOB token minting + local listener + hit correlation.
- `replay-runner` (lib) — live, policy-gated replay execution (the only new network I/O); keeps
  `replay-engine` pure.

## Tasks (strict TDD: RED → GREEN → REFACTOR; commit each verified task)

- [x] **0. Scaffold** — repo PLAN.md + METHODOLOGY.md; create `oob-core` + `replay-runner`; add to
  `crates/Cargo.toml`. Gate: `cargo build` from `crates/`.
- [x] **1. SSRF candidate detector** (`request-corpus`) — `CandidateKind::ServerSideRequestTarget`
  + analyzer flagging URL/host-valued or SSRF-prone-named params; `safety = RequiresApproval`,
  `autonomous_safe = false`. Carries `injection_params` on the candidate. Gate: passed.
- [x] **2. Payload substitution + ReplayOutcome extension** (`replay-engine`) — new `ReplayRequest`
  + pure `build_injected_request` (primitives, keeps engine engagement-free); `ReplayOutcome`
  carries `sent_request` + `response_headers`. Secret headers filtered at construction. Gate: passed.
- [x] **3. OOB core library** (`oob-core`) — std-only loopback listener; `mint(engagement,
  plan_hash, candidate_id)` (opaque, bound) · `oob_url` · `wait_for_hit`/`correlate -> OobHit`.
  Gate: passed (5x, no flake).
- [x] **4. Live replay runner** (`replay-runner`) — sends only for `executable` (scope + approval)
  plans, via `http-client` GET, records exact I/O; refuses out-of-scope/unapproved with no send
  (proven via wiremock `expect(0)`). Also fixed replay-engine so a matching approval grant makes an
  approval-required plan executable. Gate: passed.
- [~] **5. SSRF/OOB verdict** (`replay-engine`) — `SsrfOobConfirmed` / `SsrfResponseLeak` /
  `SsrfNoSignal`; confirmed only when the evidence contract is satisfied. Gate:
  `cargo test -p replay-engine` + clippy.
- [ ] **6. Evidence with OOB artifact** (`evidence-core`) — correlated OOB hit + recorded I/O added
  to the bundle, redacted + immutable. Gate: `cargo test -p evidence-core` + clippy.
- [ ] **7. mg-hunt wiring** (`mg-hunt`) — replace fixture loader with the live runner for SSRF:
  select → plan → policy gate (`--confirmed` + approval, HighActive) → OOB token → substitute →
  live send → classify → evidence incl. OOB → ledger; add active/SSRF `RiskFilter`. Gate:
  `cargo test -p mg-hunt` + clippy.
- [ ] **8. Offline end-to-end acceptance** — local axum lab: `url=<oob-url>` triggers a server-side
  GET (blind SSRF); metadata-sentinel host reflects a marker (response-based). Full `mg-hunt run`
  → verified SSRF finding + evidence + ledger, no third party. Update the progress checklist.
  Gate: E2E passes; full `cargo test` from `crates/`; `git diff --check`.

## Likely adjustment points (watch during implementation)

- Extending `ReplayOutcome` (Task 2) may ripple into Tasks 5–7.
- Two `ScopeDecision` types (`engagement::ScopeDecision` vs `replay_engine::ScopeDecision`) need a
  small shared conversion where the runner touches both.
- SSRF candidate `safety`/`state_change` semantics may need tuning once the policy gate runs live.

## Safety constraints (non-negotiable)

No third-party targets — ever; all network tests bind/hit `127.0.0.1`. Live sends only through the
runner, only for `executable` plans; SSRF is HighActive → requires `--confirmed` + approval.
Deterministic Rust owns scope/policy/budgets/OOB-correlation/evidence/verdicts; AI never sets a
verdict, expands scope, or sees raw secrets. Jeff's Rust conventions apply to every new file.

## Out of scope

Harness-API wiring of `hunt.*`/`replay.*`; TUI live drive; externally hosted/managed OOB;
DNS-based OOB; watch mode; IDOR and injection slices; real browser automation.
