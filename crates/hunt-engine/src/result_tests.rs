// Author: Jeff
// Date: 2026-07-31
// Description: Crate-internal verified-result evidence validation tests
// Notes: Verified construction is intentionally unavailable outside hunt-engine

use std::fs;

use sha2::{Digest, Sha256};

use super::{
    EvidenceContract, EvidenceKind, EvidenceReference, EvidenceRequirement, HuntResult,
    HuntResultClass, ResultContractError,
};

// Build the callback evidence contract used by the first SSRF slice
fn callback_contract() -> EvidenceContract {
    EvidenceContract::new([
        EvidenceRequirement::new("policy", EvidenceKind::PolicyDecision),
        EvidenceRequirement::new("callback", EvidenceKind::CallbackCorrelation),
    ])
    .expect("valid evidence contract")
}

// Write one artifact and return its metadata reference
fn write_evidence(
    root: &std::path::Path,
    requirement_id: &str,
    kind: EvidenceKind,
    relative_path: &str,
    content: &[u8],
) -> EvidenceReference {
    let path = root.join(relative_path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, content).unwrap();
    EvidenceReference::new(
        requirement_id,
        kind,
        relative_path,
        hex::encode(Sha256::digest(content)),
    )
    .expect("valid evidence reference")
}

#[test]
fn verified_result_requires_every_locally_validated_contract_requirement() {
    let root = tempfile::tempdir().unwrap();
    let contract = callback_contract();
    let references = vec![write_evidence(
        root.path(),
        "policy",
        EvidenceKind::PolicyDecision,
        "evidence/run-1/policy.json",
        b"policy",
    )];

    let error = contract
        .validate_local(root.path(), references)
        .unwrap_err();

    assert_eq!(
        error,
        ResultContractError::MissingEvidence {
            requirement_id: "callback".into(),
        }
    );
}

#[test]
fn validated_artifacts_can_produce_verified_result_inside_engine() {
    let root = tempfile::tempdir().unwrap();
    let contract = callback_contract();
    let references = vec![
        write_evidence(
            root.path(),
            "policy",
            EvidenceKind::PolicyDecision,
            "evidence/run-1/policy.json",
            b"policy",
        ),
        write_evidence(
            root.path(),
            "callback",
            EvidenceKind::CallbackCorrelation,
            "evidence/run-1/callback.json",
            b"callback",
        ),
    ];
    let satisfaction = contract.validate_local(root.path(), references).unwrap();

    let result = HuntResult::verified("candidate-1", satisfaction);

    assert_eq!(result.classification(), HuntResultClass::VerifiedFinding);
    assert_eq!(result.candidate_id(), "candidate-1");
}

#[test]
fn wrong_kind_missing_file_or_changed_content_cannot_satisfy_contract() {
    let root = tempfile::tempdir().unwrap();
    let contract = EvidenceContract::new([EvidenceRequirement::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
    )])
    .unwrap();
    let wrong_kind = write_evidence(
        root.path(),
        "callback",
        EvidenceKind::RequestResponse,
        "evidence/run-1/callback.json",
        b"callback",
    );
    assert_eq!(
        contract
            .validate_local(root.path(), vec![wrong_kind])
            .unwrap_err(),
        ResultContractError::EvidenceKindMismatch {
            requirement_id: "callback".into(),
        }
    );

    let missing = EvidenceReference::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
        "evidence/run-1/missing.json",
        "a".repeat(64),
    )
    .unwrap();
    assert_eq!(
        contract
            .validate_local(root.path(), vec![missing])
            .unwrap_err(),
        ResultContractError::ArtifactUnavailable
    );

    let changed = write_evidence(
        root.path(),
        "callback",
        EvidenceKind::CallbackCorrelation,
        "evidence/run-1/changed.json",
        b"before",
    );
    fs::write(root.path().join("evidence/run-1/changed.json"), b"after").unwrap();
    assert_eq!(
        contract
            .validate_local(root.path(), vec![changed])
            .unwrap_err(),
        ResultContractError::ArtifactHashMismatch
    );
}

#[cfg(unix)]
#[test]
fn local_validation_rejects_symlink_escape_from_engagement_root() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("callback.json"), b"callback").unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();
    let reference = EvidenceReference::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
        "escape/callback.json",
        hex::encode(Sha256::digest(b"callback")),
    )
    .unwrap();
    let contract = EvidenceContract::new([EvidenceRequirement::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
    )])
    .unwrap();

    assert_eq!(
        contract
            .validate_local(root.path(), vec![reference])
            .unwrap_err(),
        ResultContractError::ArtifactOutsideRoot
    );
}

#[test]
fn serialized_verified_result_contains_only_validated_evidence_references() {
    let root = tempfile::tempdir().unwrap();
    let contract = callback_contract();
    let satisfaction = contract
        .validate_local(
            root.path(),
            vec![
                write_evidence(
                    root.path(),
                    "policy",
                    EvidenceKind::PolicyDecision,
                    "evidence/run-1/policy.json",
                    b"policy",
                ),
                write_evidence(
                    root.path(),
                    "callback",
                    EvidenceKind::CallbackCorrelation,
                    "evidence/run-1/callback.json",
                    b"callback",
                ),
            ],
        )
        .unwrap();
    let result = HuntResult::verified("candidate-1", satisfaction);

    let serialized = serde_json::to_string(&result).unwrap();

    assert!(serialized.contains("verified_finding"));
    assert!(serialized.contains("callback.json"));
    assert!(!serialized.contains("cookie"));
    assert!(!serialized.contains("token_value"));
    assert!(!serialized.contains("confidence"));
}
