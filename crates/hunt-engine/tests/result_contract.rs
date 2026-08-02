// Author: Jeff
// Date: 2026-07-31
// Description: Public result-contract behavior at the hunt-engine boundary
// Notes: External callers can reference evidence but cannot construct verified findings

use hunt_engine::{
    EvidenceKind, EvidenceReference, HuntResult, HuntResultClass, ResultContractError,
};

#[test]
fn unresolved_negative_and_invalid_results_can_preserve_evidence_references() {
    let reference = EvidenceReference::new(
        "response",
        EvidenceKind::RequestResponse,
        "evidence/run-1/response.json",
        "a".repeat(64),
    )
    .unwrap();

    let candidate =
        HuntResult::human_verification_candidate("candidate-1").with_evidence([reference.clone()]);
    let negative = HuntResult::negative_test("candidate-1").with_evidence([reference.clone()]);
    let invalid = HuntResult::invalid_test("candidate-1").with_evidence([reference]);

    assert_eq!(
        candidate.classification(),
        HuntResultClass::HumanVerificationCandidate
    );
    assert_eq!(negative.classification(), HuntResultClass::NegativeTest);
    assert_eq!(invalid.classification(), HuntResultClass::InvalidTest);
    assert_eq!(candidate.evidence().len(), 1);
    assert_eq!(negative.evidence().len(), 1);
    assert_eq!(invalid.evidence().len(), 1);
}

#[test]
fn evidence_references_reject_unsafe_paths_and_invalid_hashes() {
    let unsafe_path = EvidenceReference::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
        "../callback.json",
        "a".repeat(64),
    );
    let invalid_hash = EvidenceReference::new(
        "callback",
        EvidenceKind::CallbackCorrelation,
        "evidence/run-1/callback.json",
        "not-a-sha256",
    );

    assert_eq!(
        unsafe_path.unwrap_err(),
        ResultContractError::UnsafeArtifactPath
    );
    assert_eq!(
        invalid_hash.unwrap_err(),
        ResultContractError::InvalidSha256
    );
}

#[test]
fn serialized_unresolved_result_contains_references_not_raw_secret_fields() {
    let reference = EvidenceReference::new(
        "response",
        EvidenceKind::RequestResponse,
        "evidence/run-1/response.json",
        "a".repeat(64),
    )
    .unwrap();
    let result = HuntResult::human_verification_candidate("candidate-1").with_evidence([reference]);

    let serialized = serde_json::to_string(&result).unwrap();

    assert!(serialized.contains("human_verification_candidate"));
    assert!(serialized.contains("response.json"));
    assert!(!serialized.contains("cookie"));
    assert!(!serialized.contains("token_value"));
    assert!(!serialized.contains("confidence"));
}
