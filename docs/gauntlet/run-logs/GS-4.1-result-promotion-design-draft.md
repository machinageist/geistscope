# GS-4.1 SSRF Evidence/Result Promotion — Draft Design

Date: 2026-08-13
Status: DRAFT; not approved for implementation
Parent spec: `docs/gauntlet/specs/GS-4.1-ssrf.md`
Gate: promote this record into `docs/gauntlet/implementation-briefs/` only after the exact parent spec and generic writer snapshots receive blind PASS verdicts

## Atomic outcome

Add one `hunt-engine` component that:

1. Reads and hash-validates the already-written allowed policy decision at `policy/decisions/{plan_hash}.json`.
2. Atomically commits policy, sanitized transaction, callback assessment, and semantic verdict through `evidence_core::EvidenceBundleWriter::write_generic`.
3. Builds `EvidenceReference`s only from committed bundle metadata.
4. Calls crate-private `EvidenceContract::validate_local` against final files.
5. Constructs a `HuntResult` only after commit and revalidation succeed.

No campaign runner, persistence, API, CLI, reporting, or legacy migration belongs in this slice.

## Files

Modify:

- `crates/hunt-engine/Cargo.toml`: add `evidence-core = { path = "../evidence-core" }`.
- `crates/Cargo.lock`: expected path-dependency lock update only.
- `crates/hunt-engine/src/lib.rs`: add module/re-exports and refactor validated local artifact reading.
- `crates/hunt-engine/src/http_executor.rs`: add `HttpTransactionRecord::candidate_id()`.
- `crates/hunt-engine/src/assessment.rs`: add `SsrfAssessment::candidate_id()`.

Create:

- `crates/hunt-engine/src/evidence.rs`.
- `crates/hunt-engine/tests/evidence_result.rs`.

Do not change `evidence-core` unless its pending exact-snapshot review requires remediation.

## Public seam

```rust
#[derive(Debug)]
pub struct SsrfEvidencePromotionRequest<'a> {
    pub engagement_root: &'a Path,
    pub run_id: &'a str,
    pub plan: &'a SsrfProbePlan,
    pub policy_decision_sha256: &'a str,
    pub transaction: &'a HttpTransactionRecord,
    pub assessment: &'a SsrfAssessment,
}

#[derive(Debug, Default, Clone)]
pub struct SsrfEvidencePromoter;

impl SsrfEvidencePromoter {
    pub fn promote(
        &self,
        request: SsrfEvidencePromotionRequest<'_>,
    ) -> Result<HuntResult, SsrfEvidencePromotionError>;
}
```

The caller captures `permit.policy_decision_sha256()` before `execute` consumes the non-clonable `ExecutionPermit`. Do not make the permit clonable or weaken one-use semantics.

## Errors

`SsrfEvidencePromotionError` needs these typed classes:

- `PlanMismatch`.
- `CandidateMismatch`.
- `PolicyEvidence(ResultContractError)`.
- `Serialization(String)`; never include artifact contents.
- `BundleWrite(EvidenceBundleError)`.
- `MissingBundleArtifact(&'static str)`.
- `EvidenceReference(ResultContractError)`.
- `EvidenceValidation(ResultContractError)`.

Every error returns `Err`; no fallback `HuntResult` is allowed. In particular, writer or post-commit integrity failure produces no result.

## Exact committed artifacts

Final directory:

```text
evidence/<candidate_id>/<run_id>/
├── policy-decision.json
├── transaction.redacted.json
├── callback-assessment.json
├── semantic-verdict.json
└── manifest.json
```

The four supplied artifacts are `application/json` and `ModelVisibleRedacted`.

- `policy-decision.json`: exact bytes from `policy/decisions/{plan_hash}.json`, read only after containment, regular-file, and supplied-digest validation.
- `transaction.redacted.json`: pretty JSON `HttpTransactionRecord`; no raw query value, callback URL, credentials, or response body.
- `callback-assessment.json`: pretty JSON `SsrfAssessment`; supports both correlated callback and bounded callback absence without raw callback secrets.
- `semantic-verdict.json`: private serialization-only shape containing schema version, plan hash, candidate ID, assessment class, and reason. It must not claim `verified_finding` before final evidence validation.
- `manifest.json`: writer-generated; never supplied by the promoter.

## Evidence-reference mapping

Build references only from exact entries returned by `GenericEvidenceBundle.artifacts`; reject missing, duplicate, or unexpected fixed entries.

| Requirement | Kind | Artifact |
|---|---|---|
| `policy` | `PolicyDecision` | `policy-decision.json` |
| `callback` | `CallbackCorrelation` | `callback-assessment.json` |
| `response` | `RequestResponse` | `transaction.redacted.json` |

`semantic-verdict.json` and `manifest.json` are audit artifacts, not extra contract references.

## Promotion sequence

1. Verify transaction and assessment plan hashes equal the plan hash.
2. Verify transaction and assessment candidate IDs equal the plan candidate ID.
3. Derive the only accepted policy source path from the plan hash.
4. Construct a policy `EvidenceReference` using the caller-captured decision digest.
5. Read hash-validated policy bytes through a crate-private helper.
6. Serialize transaction, assessment, and semantic verdict.
7. Submit all four artifacts in one `GenericEvidenceBundleRequest`.
8. Treat `write_generic` as the sole commit point.
9. Build the three required references from committed manifest metadata.
10. Reopen and validate every final referenced file through the plan's `EvidenceContract::validate_local`.
11. Construct the result only after successful validation.

Classification is fixed:

- `CallbackProven` → `VerifiedFinding`.
- `Negative` → `NegativeTest` with evidence.
- `Pending` → `HumanVerificationCandidate` with evidence.
- `Invalid` → `InvalidTest` with evidence.
- Any serialization, policy, writer, reference, or validation failure → `Err`, no result.

No assessment class other than `CallbackProven` may call `HuntResult::verified`.

## Internal helpers

Add candidate accessors to `HttpTransactionRecord` and `SsrfAssessment`; existing plan-hash accessors remain sufficient.

Refactor current local evidence reading into:

```rust
fn read_validated_local_artifact(
    canonical_root: &Path,
    reference: &EvidenceReference,
) -> Result<Vec<u8>, ResultContractError>;
```

It must retain current containment, no-symlink, regular-file, and digest checks and return the checked bytes. Existing `validate_local_artifact` can delegate to it and discard the bytes. Keep the reader crate-private.

For deterministic writer-failure tests, use a private `GenericBundleSink` trait with the concrete writer in production and private fake sinks in unit tests. Do not expose this abstraction publicly.

## Strict TDD slices

1. Add a failing callback-proven integration test; observe RED for missing promoter API.
2. Implement only input binding, policy reading, atomic commit, reference mapping, validation, and verified construction needed for GREEN.
3. Add and make GREEN the negative classification test.
4. Add and make GREEN pending and invalid classification tests.
5. Add mismatch tests proving no writer invocation/final bundle.
6. Add missing/changed policy tests proving no final bundle.
7. Add duplicate-run test proving original bytes remain unchanged and no result is returned.
8. Add manifest-completeness and model-visible secret scans.
9. Add private sink tests for writer failure and post-commit tamper.
10. Table-test that only `CallbackProven` reaches verified construction.

## Required assertions

- Callback-proven produces exactly one verified result and three contract references.
- Negative, pending, and invalid results retain evidence but are never verified.
- Every reference path/digest comes from committed metadata.
- Manifest contains exactly four supplied artifacts with correct path, length, SHA-256, content type, and visibility.
- Plan/candidate mismatch and invalid policy fail before bundle creation.
- Duplicate run returns `BundleWrite(RunAlreadyExists)` and preserves original bytes.
- Writer failure returns no result.
- Post-commit tamper fails local hash validation and returns no result.
- Serialized result and model-visible files contain no raw callback token, original query value, cookie, authorization value, or response body fixture.

## Verification

From repository root:

```text
cd crates
cargo test -p evidence-core --locked
cargo test -p hunt-engine --test evidence_result --locked
cargo test -p hunt-engine --locked
cargo check -p hunt-engine --all-targets --locked
cargo clippy -p hunt-engine --all-targets --locked -- -D warnings
cargo fmt -p evidence-core -p hunt-engine -- --check
cd ..
git diff --check
git diff --cached --check
```

Then freeze the intended atomic staged snapshot, record its SHA-256 fingerprint, and require a fresh blind implementation review.

## Explicit exclusions

- No `SsrfCampaignRunner`.
- No SQLite, migrations, or restart recovery.
- No local HTTP/Unix-socket/stdio API.
- No CLI changes.
- No report generation.
- No raw callback/request/response bodies.
- No changes to permit-gated execution semantics.
- No broad migration of legacy `EvidenceBundleRequest`.
- No implementation before the parent spec and generic writer independently pass their exact-snapshot gates.
