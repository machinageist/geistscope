// Author: Jeff
// Date: 2026-07-31
// Description: Inert SSRF candidate generation from normalized HTTP observations
// Notes: Candidate generation must not perform network activity

use hunt_engine::{
    EvidenceKind, EvidenceReference, HttpMethod, ObservedHttpRequest, SsrfCandidateGenerator,
    SsrfInputLocation,
};

// Build a source reference without embedding captured request content
fn source_reference() -> EvidenceReference {
    EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/records/request-1.json",
        "a".repeat(64),
    )
    .unwrap()
}

#[test]
fn absolute_http_query_value_produces_one_inert_ssrf_candidate() {
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?url=https%3A%2F%2Fremote.example.test%2Fimage.png",
        source_reference(),
    )
    .unwrap();

    let candidates = SsrfCandidateGenerator.generate(&observation);

    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].source_observation_id(), "request-1");
    assert_eq!(
        candidates[0].input_location(),
        &SsrfInputLocation::QueryParameter {
            name: "url".into(),
            occurrence: 0,
        }
    );
    assert_eq!(candidates[0].original_value_sha256().len(), 64);
}

#[test]
fn non_url_and_non_http_values_do_not_produce_candidates() {
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?name=avatar&file=file%3A%2F%2F%2Fetc%2Fpasswd&javascript=javascript%3Aalert%281%29",
        source_reference(),
    )
    .unwrap();

    assert!(SsrfCandidateGenerator.generate(&observation).is_empty());
}

#[test]
fn duplicate_query_parameter_occurrences_remain_distinct_and_deterministic() {
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Post,
        "https://target.example.test/fetch?url=https%3A%2F%2Fone.example.test&url=https%3A%2F%2Ftwo.example.test",
        source_reference(),
    )
    .unwrap();

    let first = SsrfCandidateGenerator.generate(&observation);
    let second = SsrfCandidateGenerator.generate(&observation);

    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_ne!(first[0].id(), first[1].id());
    assert_eq!(
        first[1].input_location(),
        &SsrfInputLocation::QueryParameter {
            name: "url".into(),
            occurrence: 1,
        }
    );
}

#[test]
fn malformed_observation_urls_fail_before_candidate_generation() {
    let result = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "not a URL",
        source_reference(),
    );

    assert!(result.is_err());
}
