# Slice 4 — Immutable Evidence Bundle and Result Promotion

Status: ready after Slice 3
Depends on: policy record, transaction record, callback assessment
Parent behavior: `../PLAN.md` Task 4.3

## Goal

Atomically preserve the complete SSRF run under the engagement root and only then emit the deterministic result class. A verified finding must be impossible if any required artifact is missing, mismatched, unsafe, or failed to commit.

## Evidence-core direction

`evidence-core` is reusable for path validation, hashing, immutable-run behavior, and redaction, but its current request fields are authorization-specific (`approvals_json`, `semantic_diff_json`). Do not force SSRF data into those names.

Preferred change:

- generalize `evidence-core` to accept typed/named structured artifacts plus explicitly raw private artifacts; or
- add a new generic bundle request alongside the old one and migrate later.

No compatibility is required, but avoid unrelated browser-evidence rewrites in this slice.

## Required bundle layout

Under `ENGAGEMENT_ROOT/evidence/<candidate_id>/<run_id>/`, preserve at least:

```text
observation.json
candidate.json
plan.redacted.json
policy-decision.json
transaction.redacted.json
callback-correlation.redacted.json
assessment.json
result.json
runbook.md
summary.redacted.md
manifest.json
```

If raw/private artifacts are required, place them below `raw/` and never reference their content in model-visible summaries. The callback token and raw request/response bodies should not be written at all unless a later approved feature requires encrypted private storage.

## Atomic immutability

The writer must:

1. Canonicalize and validate the engagement root.
2. Validate candidate/run components and reject symlink/path traversal.
3. Create a unique staging directory under the same filesystem.
4. Write bounded artifacts with create-new semantics.
5. Hash every artifact and construct the manifest.
6. Validate the evidence contract against staged files and required evidence kinds.
7. Construct the final result.
8. Atomically rename staging to the final run directory.
9. Fail if the final directory already exists.
10. Remove or clearly quarantine incomplete staging on failure.

A result returned before successful final rename is a bug. Existing runs are never overwritten.

## Result mapping

- `callback_proven` + allowed policy + successful transaction + all required committed artifacts => `verified_finding`.
- `negative` + successful transaction/window + committed supporting evidence => `negative_test`.
- invalid policy/execution/correlation/evidence => `invalid_test` with available safe references.
- `human_verification_candidate` is reserved for a specifically structured inconclusive state; do not use it as a catch-all for errors.
- Evidence writer failure can never return verified. It should return a typed write failure and, if possible, an in-memory invalid result with no claim that a bundle exists.

This slice should remove the temporary dead-code allowances around crate-internal evidence validation and verified construction by wiring the real path.

## Manifest and references

Manifest entries contain engagement-relative paths, SHA-256, byte length, media/content type, and visibility (`model_visible_redacted` or `private_local`). Manifest does not need to hash itself. `EvidenceReference` values in `HuntResult` must match committed files, not staging paths.
Stable result JSON must also carry run ID, plan hash, and explicit bundle/manifest identity. Validate
candidate and run IDs for every result class, not only the verified path.

## Human runbook

Generate deterministic prose from structured data only. Include:

- prerequisite engagement/scope/rules state;
- redacted target origin/path and parameter location;
- one callback-only request description;
- expected callback correlation;
- stop/cleanup instructions;
- exact evidence paths and hashes.

Do not include raw token, original query value, cookies, authorization headers, or response body.

## Codebase map

Inspect:

- `crates/evidence-core/src/lib.rs`
- `crates/engagement/src/lib.rs` and artifact-root guards
- `crates/hunt-engine/src/lib.rs` result/evidence types
- Slice 1 policy record
- Slice 2 transaction record
- Slice 3 assessment

Likely additions:

- `crates/hunt-engine/src/evidence.rs`
- `crates/hunt-engine/tests/evidence_result.rs`
- focused `evidence-core` tests for generic/atomic bundles

## Behavior-first tests

Prove:

1. Complete proven evidence atomically commits and yields one verified finding.
2. Missing policy, transaction, callback, assessment, or manifest requirement cannot verify.
3. Negative assessment commits as `negative_test`, never a finding.
4. Invalid assessment commits as `invalid_test` when safe evidence can be written.
5. Existing run path returns `RunAlreadyExists` and changes no bytes.
6. Traversal, absolute path, and symlink escape are rejected.
7. Injected write failure leaves no final bundle and returns no verified result.
8. Manifest hashes and lengths match every committed artifact.
9. Serialized result and every model-visible artifact contain no raw token/query value/cookie/auth/body fixtures.
10. Runbook references only committed paths and hashes.
11. Revalidating committed evidence produces the same classification.
12. Every fixed artifact—not only raw/screenshot files—appears in the manifest with an engagement-relative path.
13. Modifying any required committed artifact makes revalidation fail and prevents promotion.
14. Stable result JSON binds candidate, run, plan, bundle, and manifest without target-controlled content.

## Non-goals

- No SQLite.
- No report submission.
- No screenshots/browser artifacts beyond preserving existing behavior.
- No encryption/key management design.
- No AI-generated summary requirement.

## Verification

```bash
cargo test -p evidence-core
cargo clippy -p evidence-core --all-targets -- -D warnings
cargo test -p hunt-engine --test evidence_result
cargo test -p hunt-engine
cargo clippy -p hunt-engine --all-targets -- -D warnings
cargo fmt -p evidence-core -p hunt-engine -- --check
git diff --check
```

## Done means

The only engine path to `verified_finding` passes through a successfully committed immutable evidence bundle whose required artifact bytes and hashes deterministically prove authorization, execution, and callback correlation.
