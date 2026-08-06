// Author: Jeff
// Date: 2026-07-31
// Description: Inert SSRF candidate generation from normalized HTTP observations
// Notes: Candidate generation must not perform network activity

use hunt_engine::{
    EvidenceKind, EvidenceReference, HttpMethod, ObservedHttpRequest, SsrfCandidateGenerator,
    SsrfContractError, SsrfInputLocation,
};
use sha2::{Digest, Sha256};

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
        &SsrfInputLocation::QueryParameter { occurrence: 0 }
    );
    assert_eq!(candidates[0].id().len(), 64);
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
        &SsrfInputLocation::QueryParameter { occurrence: 1 }
    );
}

#[test]
fn candidate_serialization_uses_opaque_identity_and_never_exposes_parameter_name() {
    const SECRET_KEY_NAME: &str = "api_key_SECRET_987";
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        format!(
            "https://target.example.test/fetch?{SECRET_KEY_NAME}=https%3A%2F%2Fremote.example.test%2F"
        ),
        source_reference(),
    )
    .unwrap();

    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    let serialized = serde_json::to_string(&candidate).unwrap();

    assert!(!serialized.contains(SECRET_KEY_NAME));
    assert!(!serialized.contains("original_value_sha256"));
    assert!(!serialized.contains(&hex::encode(Sha256::digest(
        b"https://remote.example.test/"
    ))));
    assert!(serialized.contains(candidate.id()));
    assert!(serialized.contains("query_parameter"));
    assert!(serialized.contains("\"occurrence\":0"));
}

#[test]
fn candidate_id_is_not_a_dictionary_oracle_for_guessable_query_material() {
    const SECRET_KEY_NAME: &str = "api_key_SECRET_987";
    const VALUE: &str = "https://remote.example.test/";
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        format!("https://target.example.test/fetch?{SECRET_KEY_NAME}=https%3A%2F%2Fremote.example.test%2F"),
        source_reference(),
    )
    .unwrap();

    let first = SsrfCandidateGenerator.generate(&observation).remove(0);
    let second = SsrfCandidateGenerator.generate(&observation).remove(0);
    let value_hash = hex::encode(Sha256::digest(VALUE.as_bytes()));
    let prior_public_formula = hex::encode(Sha256::digest(
        format!("request-1\n{SECRET_KEY_NAME}\n0\n{value_hash}").as_bytes(),
    ));

    assert_eq!(first.id(), second.id());
    assert_ne!(first.id(), prior_public_formula);
}

#[test]
fn invalid_utf8_query_names_are_rejected_without_stale_candidate_collisions() {
    let ff = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?%FF=http://a.test/",
        source_reference(),
    );
    let fe = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?%FE=http://a.test/",
        source_reference(),
    );

    assert_eq!(
        ff.unwrap_err(),
        SsrfContractError::InvalidQueryParameterName
    );
    assert_eq!(
        fe.unwrap_err(),
        SsrfContractError::InvalidQueryParameterName
    );
}

#[test]
fn semicolon_bearing_candidate_query_segments_are_rejected() {
    let result = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?url=http://a.test/;admin=true",
        source_reference(),
    );

    assert_eq!(
        result.unwrap_err(),
        SsrfContractError::SemicolonQuerySegmentUnsupported
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
