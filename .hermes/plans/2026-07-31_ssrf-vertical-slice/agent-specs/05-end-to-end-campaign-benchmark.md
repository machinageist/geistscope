# Slice 5 — End-to-End SSRF Campaign Benchmark

Status: ready after Slices 0–4
Depends on: all prior implementation slices
Parent behavior: `../PLAN.md` Task 5.1

## Goal

Prove the rebuilt hunting-engine path in one offline campaign runner: normalized observation → candidate → immutable plan → policy/audit → one bounded request → callback observation → assessment → immutable evidence → result.

## Production orchestration boundary

Add a small `SsrfCampaignRunner` or equivalent in `hunt-engine`. It owns sequencing and typed state transitions; the integration test drives it but must not reimplement orchestration in test code.

Recommended state progression:

```text
Observed
  -> CandidateGenerated
  -> Planned
  -> PolicyEvaluated
  -> Permitted | Blocked
  -> Executed
  -> CallbackWindowFinalized
  -> Assessed
  -> EvidenceCommitted
  -> ResultEmitted
```

Impossible transitions should be unrepresentable where practical. At minimum, the runner must never call execution without a permit or result promotion without committed evidence.

## Campaign input

The local benchmark input provides:

- engagement root;
- normalized observed GET request and source artifact;
- trusted scope decision and current program rules artifacts;
- exact loopback callback origin;
- approval state;
- deterministic run ID and injected clock/deadline for tests.

No model configuration is accepted or required.

## Required integration cases

### Vulnerable endpoint

- one candidate;
- one allowed policy decision and audit event;
- exactly one target request;
- exactly one correlated callback;
- one committed evidence bundle;
- one `verified_finding`;
- no raw token/secret in public artifacts.

### Secure endpoint

- same request shape and policy path;
- exactly one target request;
- zero callbacks;
- finalized observation window;
- one committed negative evidence bundle;
- `negative_test` and zero findings.

### Blocked plan

Use out-of-scope, expired rules, or automation-disallowed context:

- no permit;
- zero target requests;
- zero callbacks;
- audit event records block;
- no verified finding;
- invalid/blocked structured result according to Slice 4 contract.

### Repeated run

- new run uses a distinct callback token and run ID;
- old token cannot satisfy the new plan;
- old evidence bytes remain unchanged;
- duplicate run ID fails without overwrite.

## Offline network assertion

All listeners bind ephemeral loopback ports. The test must not rely on DNS or Internet. Prefer fixture URLs using `127.0.0.1` rather than hostnames. Add exact counters for target, redirect sink, and callback listener.

## Codebase map

Inspect all `hunt-engine` modules and tests, especially:

- `crates/hunt-engine/tests/support/mod.rs`
- `crates/hunt-engine/tests/ssrf_benchmark.rs`
- Slices 1–4 focused integration tests

Likely additions:

- `crates/hunt-engine/src/campaign.rs`
- `crates/hunt-engine/tests/ssrf_campaign_e2e.rs`

## Behavior-first test order

1. Add blocked-plan case first and prove zero I/O.
2. Add vulnerable path and require callback/evidence verification.
3. Add secure path and require negative classification.
4. Add repeated/duplicate run immutability.
5. Add whole-artifact secret scan.

Do not begin with one giant test. Keep helper assertions reusable and failure messages state-specific.

## Acceptance assertions

In addition to case behavior, assert:

- plan hash in permit, audit, transaction, callback assessment, manifest references, and result is identical;
- every evidence path resolves under the engagement root;
- no final bundle exists before evidence commit;
- callback token is redacted or hashed everywhere model-visible;
- response text cannot create a finding;
- runner works with no model/environment credential variables;
- campaign output is stable structured JSON suitable for a later API/CLI boundary.
- callback and target listener tasks terminate cleanly on every success and failure path.
- injected evidence-writer failure prevents promotion and leaves no verified result.

## Non-goals

- No daemon, SQLite, versioned HTTP API, TUI, container benchmark, remote callback service, report submission, or old-tool pruning.
- Do not expand beyond query-parameter GET callback probes.

## Verification

```bash
cargo test -p hunt-engine --test ssrf_campaign_e2e -- --nocapture
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p hunt-engine -- --check
# Then run affected reusable crates if changed
cargo test -p action-policy -p engagement -p evidence-core
git diff --check
```

After focused success, run the workspace regression suite in a background/long-timeout job if practical:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

Record pre-existing failures separately; do not weaken focused acceptance tests to make broad legacy checks pass.

## Done means

One deterministic offline command proves vulnerable, secure, blocked, and repeated-run behavior through production engine orchestration with exact network counts and immutable evidence.
