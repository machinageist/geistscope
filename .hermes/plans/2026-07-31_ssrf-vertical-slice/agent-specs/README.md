# SSRF Vertical Slice — Agent Implementation Index

Date: 2026-07-31
Status: implementation handoff set
Parent specification: `../SPEC.md`
Parent plan: `../PLAN.md`
Product decision log: `../../2026-07-23_hunting-engine-restructure.md`
Workspace: `/home/mgeist/geistscope/crates`

## Purpose

These documents divide the remaining SSRF benchmark into reviewable implementation slices. Each slice is small enough for one coding agent, states its deterministic behavior before implementation details, and names the exact checks required before handoff.

Agents must read the parent `SPEC.md`, this index, and their assigned slice only. They must inspect current files before editing because the `hunt-engine` crate is uncommitted and may change between assignments.

## Current baseline

Implemented in `hunt-engine`:

- evidence/result class contracts;
- capability-neutral observations, hypotheses, plans, budgets, and hashes;
- in-process vulnerable and secure SSRF fixtures;
- plan-bound callback registration and correlation;
- normalized HTTP observations and inert query-parameter candidates;
- callback-only immutable SSRF plan construction.

The crate tests and Clippy passed immediately before this handoff set was written. The current working tree is intentionally uncommitted; agents must not discard or overwrite existing changes.

## Required sequence

| Order | Slice | Dependency | Implementation status |
|---|---|---|---|
| 0 | `00-plan-secret-and-execution-contract.md` | current Task 3.2 | ready; mandatory hardening |
| 1 | `01-policy-gate-adapter.md` | Slice 0 + policy checkpoint | ready after Jeff confirms reuse |
| 2 | `02-bounded-http-executor.md` | Slice 1 execution permit | ready after Slice 1 |
| 3 | `03-callback-assessment.md` | Slice 2 transaction result | ready after Slice 2 |
| 4 | `04-immutable-evidence-and-results.md` | Slice 3 assessment | ready after Slice 3 |
| 5 | `05-end-to-end-campaign-benchmark.md` | Slices 0–4 | ready after Slice 4 |
| 6 | `06-local-api-and-persistence-discovery.md` | successful Slice 5 | design task; no production implementation |
| 7 | `07-thin-cli-and-pruning.md` | Jeff's API/persistence decision | blocked until Checkpoint 4 |

Do not implement Slices 1–5 in parallel: they intentionally establish compile-time authority tokens and result types consumed by the next slice. Research and review may run in parallel, but two implementation agents must not edit `hunt-engine/src` concurrently.

## Locked decisions

- `hunt-engine` is the business-logic owner; CLIs and workers are clients.
- The acceptance benchmark is in-process Rust on ephemeral loopback ports.
- Callback lifecycle and correlation are engine-owned; `mg-oob` is not authoritative.
- Normalized HTTP observations are engine-owned; existing traffic records enter through adapters.
- One exact callback origin is bound per campaign; plans append only engine-generated token paths.
- Candidate generation, authorization, execution, correlation, evidence promotion, and result classification must work without a model.
- No compatibility preservation is required for old SSRF/OOB JSON or CLI surfaces.

## Open decisions

1. Policy authority reuse: recommended answer is to keep `action-policy` authoritative and implement a narrow `hunt-engine` adapter. Slice 1 must not begin until Jeff confirms or changes this.
2. Local API and persistence: intentionally deferred until the complete domain flow exists. Slice 6 gathers evidence and proposes an ADR; it does not choose silently.
3. Old SSRF/OOB pruning: deferred until the replacement passes end-to-end tests.

## Shared invariants for every slice

- No network request occurs without a Rust-created permit bound to the exact plan hash.
- Model text or deserialized public JSON cannot create a permit, lower risk, replace the callback origin, or promote a finding.
- The only first-slice SSRF payload is the campaign callback URL.
- Redirects are disabled; concurrency and request count are one.
- No permissive TLS and no Internet dependency in tests.
- Raw callback tokens, cookies, authorization headers, request query values, response bodies, and secrets are not model-visible.
- Target/callback content is bounded before storage or serialization.
- Evidence stays under a canonical engagement root, cannot traverse symlinks, and cannot overwrite an existing run.
- Target response content alone never verifies SSRF.
- Every block/allow/approval decision is audited; audit failure blocks execution.
- New validated aggregates are not directly `Deserialize` unless custom deserialization re-runs all invariants.

## Agent workflow

For every implementation slice:

1. Run `git status --short --branch`; do not reset user or prior-agent changes.
2. Read the assigned spec and every file named under "Codebase map."
3. Add the first acceptance test and run it to observe RED.
4. Implement the minimum behavior to reach GREEN.
5. Run focused tests, then all `hunt-engine` tests, Clippy, package-scoped formatting check, and `git diff --check`.
6. Review the diff for secret exposure, unbounded input, authority bypass, and unrelated edits.
7. Return changed paths, exact command results, unresolved questions, and a recommended commit boundary. Do not commit unless Jeff asks.

Default verification footer:

```bash
cd /home/mgeist/geistscope/crates
cargo test -p hunt-engine --test <focused-test>
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p hunt-engine -- --check
git diff --check
```

If another crate is changed, run that crate's tests and Clippy too. Do not run mutating `cargo fmt --all`; format only touched packages after a check.
