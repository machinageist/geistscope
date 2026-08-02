// Author: Jeff
// Date: 2026-07-31
// Description: Plan-bound callback lifecycle and correlation behavior
// Notes: Raw tokens and callback bodies must not enter model-visible records

use hunt_engine::{
    CallbackCorrelation, CallbackRecordOutcome, CallbackRecorder, CallbackRegistration,
    CallbackRequest, CallbackToken,
};

const RECEIVED_AT_MS: u64 = 1_000;
const EXPIRES_AT_MS: u64 = 2_000;

// Build one bounded callback request containing values that require redaction
fn callback_request() -> CallbackRequest {
    CallbackRequest::new(
        "GET",
        "/raw-token-path",
        [
            ("authorization", "Bearer secret-token"),
            ("cookie", "session=secret-cookie"),
            ("user-agent", "benchmark-client"),
        ],
        b"sensitive callback body".to_vec(),
        Some("127.0.0.1:54321"),
        RECEIVED_AT_MS,
    )
    .expect("valid callback request")
}

#[test]
fn matching_live_token_and_plan_produce_correlated_evidence() {
    let token = CallbackToken::generate();
    let mut recorder = CallbackRecorder::default();
    recorder
        .register(CallbackRegistration::new(
            token.clone(),
            "a".repeat(64),
            EXPIRES_AT_MS,
        ))
        .unwrap();

    let outcome = recorder.record(&token, callback_request());
    let correlation = recorder.correlate(&token, &"a".repeat(64), RECEIVED_AT_MS + 1);

    assert!(matches!(outcome, CallbackRecordOutcome::Accepted(_)));
    assert!(matches!(correlation, CallbackCorrelation::Matched(_)));
}

#[test]
fn unknown_expired_reused_and_plan_mismatched_tokens_never_match() {
    let token = CallbackToken::generate();
    let unknown = CallbackToken::generate();
    let mut recorder = CallbackRecorder::default();
    recorder
        .register(CallbackRegistration::new(
            token.clone(),
            "a".repeat(64),
            EXPIRES_AT_MS,
        ))
        .unwrap();

    assert_eq!(
        recorder.record(&unknown, callback_request()),
        CallbackRecordOutcome::UnknownToken
    );
    assert_eq!(
        recorder.correlate(&token, &"b".repeat(64), RECEIVED_AT_MS),
        CallbackCorrelation::PlanMismatch
    );
    assert_eq!(
        recorder.record(
            &token,
            CallbackRequest::new(
                "GET",
                "/expired",
                std::iter::empty::<(&str, &str)>(),
                [],
                None,
                EXPIRES_AT_MS + 1,
            )
            .unwrap(),
        ),
        CallbackRecordOutcome::Expired
    );

    let live_token = CallbackToken::generate();
    recorder
        .register(CallbackRegistration::new(
            live_token.clone(),
            "c".repeat(64),
            EXPIRES_AT_MS,
        ))
        .unwrap();
    assert!(matches!(
        recorder.record(&live_token, callback_request()),
        CallbackRecordOutcome::Accepted(_)
    ));
    assert_eq!(
        recorder.record(&live_token, callback_request()),
        CallbackRecordOutcome::Reused
    );
    assert_eq!(
        recorder.correlate(&live_token, &"c".repeat(64), RECEIVED_AT_MS + 1),
        CallbackCorrelation::Reused
    );
}

#[test]
fn callback_record_redacts_headers_and_references_body_by_hash() {
    let token = CallbackToken::generate();
    let raw_token = token.as_str().to_string();
    let mut recorder = CallbackRecorder::default();
    recorder
        .register(CallbackRegistration::new(
            token.clone(),
            "a".repeat(64),
            EXPIRES_AT_MS,
        ))
        .unwrap();

    let CallbackRecordOutcome::Accepted(record) = recorder.record(&token, callback_request())
    else {
        panic!("callback should be accepted");
    };
    let serialized = serde_json::to_string(&record).unwrap();

    assert!(!serialized.contains(&raw_token));
    assert!(!serialized.contains("secret-token"));
    assert!(!serialized.contains("secret-cookie"));
    assert!(!serialized.contains("sensitive callback body"));
    assert!(serialized.contains("<redacted>"));
    assert!(serialized.contains("benchmark-client"));
    assert_eq!(record.body_sha256().len(), 64);
}

#[test]
fn callback_tokens_are_unique_lowercase_hex_values() {
    let first = CallbackToken::generate();
    let second = CallbackToken::generate();

    assert_ne!(first, second);
    assert_eq!(first.as_str().len(), 32);
    assert!(
        first
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn only_the_exact_callback_route_yields_a_token() {
    let token = "0123456789abcdef0123456789abcdef";

    assert!(CallbackToken::from_callback_path(&format!("/callbacks/{token}")).is_ok());
    // Prefixes, suffixes, extra segments, and query-carried tokens are rejected
    assert!(CallbackToken::from_callback_path(&format!("/callbacks/{token}/extra")).is_err());
    assert!(CallbackToken::from_callback_path(&format!("/api/callbacks/{token}")).is_err());
    assert!(CallbackToken::from_callback_path(&format!("/callbacks/{token}x")).is_err());
    assert!(CallbackToken::from_callback_path(&format!("/callbacks/{token}?x=1")).is_err());
    assert!(CallbackToken::from_callback_path("/callbacks/not-a-token").is_err());
}

#[test]
fn callback_headers_are_bounded_by_count_and_aggregate_bytes() {
    let many_headers: Vec<(String, String)> = (0..100)
        .map(|index| (format!("x-header-{index}"), "value".to_string()))
        .collect();
    let request = CallbackRequest::new(
        "GET",
        "/callbacks/token",
        many_headers,
        Vec::new(),
        None,
        RECEIVED_AT_MS,
    )
    .unwrap();
    let serialized = serde_json::to_string(&as_record(request)).unwrap();

    // At most 32 headers survive the worker boundary
    assert_eq!(serialized.matches("\"name\"").count(), 32);
}

#[test]
fn oversized_body_and_long_peer_are_bounded_before_storage() {
    let request = CallbackRequest::new(
        "GET",
        "/callbacks/token",
        std::iter::empty::<(&str, &str)>(),
        vec![b'a'; 4096],
        Some(&"9".repeat(4096)),
        RECEIVED_AT_MS,
    )
    .unwrap();

    let record = as_record(request);
    assert!(record.body_truncated());
    assert_eq!(record.body_bytes(), 4096);
    let serialized = serde_json::to_string(&record).unwrap();
    // The peer is bounded well below the raw 4096-character input
    assert!(!serialized.contains(&"9".repeat(200)));
}

// Record one request against a fresh recorder to inspect its stored callback record
fn as_record(request: CallbackRequest) -> hunt_engine::CallbackRecord {
    let token = CallbackToken::generate();
    let mut recorder = CallbackRecorder::default();
    recorder
        .register(CallbackRegistration::new(
            token.clone(),
            "a".repeat(64),
            EXPIRES_AT_MS,
        ))
        .unwrap();
    match recorder.record(&token, request) {
        CallbackRecordOutcome::Accepted(record) => record,
        other => panic!("callback should be accepted, got {other:?}"),
    }
}
