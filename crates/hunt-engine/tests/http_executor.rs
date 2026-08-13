// Author: Jeff
// Date: 2026-07-31
// Description: Bounded permit-gated SSRF executor behavior over ephemeral loopback fixtures
// Notes: Every test binds loopback ports only; secrets and bodies never enter transaction records

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeVerdict};
use hunt_engine::{
    CallbackLease, CallbackToken, CampaignCallbackOrigin, CaptureTrustStore, EvidenceKind,
    EvidenceReference, ExecutionPermit, ExecutorError, ExecutorOutcome, HttpMethod,
    ObservedHttpRequest, PolicyGateOutcome, ScopeDisposition, SignedCaptureClaims,
    SsrfCandidateGenerator, SsrfHttpExecutor, SsrfPolicyContext, SsrfPolicyGate, SsrfProbePlan,
    SsrfProbePlanBuilder,
};
use proxy_core::CaptureSigner;
use sha2::{Digest, Sha256};
use support::{RequestCounter, SsrfBenchmark};
use time::{Duration, OffsetDateTime};
use tokio::task::JoinHandle;

const DEFAULT_TOKEN: &str = "0123456789abcdef0123456789abcdef";
const DUMMY_CALLBACK_ORIGIN: &str = "http://127.0.0.1:1";
const ENGAGEMENT_ID: &str = "engagement-1";
const CAPTURE_KEY_ID: &str = "capture-key-1";
const CAPTURE_SECRET_KEY: [u8; 32] = [7; 32];

// Recreate deterministic trusted capture authority for executor fixtures
fn capture_signer() -> CaptureSigner {
    CaptureSigner::from_bytes(CAPTURE_KEY_ID, &CAPTURE_SECRET_KEY).unwrap()
}

// Supply public-key-only capture trust to the policy gate
fn capture_trust() -> CaptureTrustStore {
    CaptureTrustStore::new([capture_signer().verifier().unwrap()]).unwrap()
}

// Persist immutable request evidence for permit authorization
fn source_reference(root: &Path, observed_url: &str) -> EvidenceReference {
    let relative = "traffic/records/request-1.json";
    let claims = SignedCaptureClaims::new(
        ENGAGEMENT_ID,
        CAPTURE_KEY_ID,
        "0123456789abcdef0123456789abcdef",
        "request-1",
        observed_url,
    )
    .unwrap();
    let evidence = capture_signer().sign_claims(claims).unwrap();
    let bytes = serde_json::to_vec(&evidence).unwrap();
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        relative,
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap()
}

// Persist a policy artifact and return its hash-accurate reference
fn write_reference<T: serde::Serialize>(
    root: &Path,
    relative: &str,
    id: &str,
    value: &T,
) -> EvidenceReference {
    let bytes = serde_json::to_vec(value).unwrap();
    let path = root.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    EvidenceReference::new(
        id,
        EvidenceKind::PolicyDecision,
        relative,
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap()
}

// Build an in-scope, bounty-eligible decision for the plan's normalized target
fn scope_decision(normalized_url: &str) -> ScopeDecision {
    let host = url::Url::parse(normalized_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string));
    ScopeDecision {
        input: normalized_url.into(),
        normalized_host: host,
        normalized_url: Some(normalized_url.into()),
        decision: ScopeVerdict::InScope,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
        reason: "fixture".into(),
        asset_type: None,
        bounty_eligible: Some(true),
        submission_eligible: None,
        notes: Vec::new(),
    }
}

// Build current automation-allowed program rules
fn valid_rules(now: OffsetDateTime) -> ProgramRulesSnapshot {
    ProgramRulesSnapshot {
        captured_at: now - Duration::hours(1),
        expires_at: now + Duration::days(1),
        automation_allowed: true,
        source: "manual".into(),
        notes: Vec::new(),
    }
}

// Derive the normalized origin+path a scope decision must match for an observation URL
fn normalized_target(observation_url: &str) -> String {
    let url = url::Url::parse(observation_url).unwrap();
    format!("{}{}", url.origin().ascii_serialization(), url.path())
}

// Build a plan and obtain a valid execution permit through the policy gate
fn prepare(
    root: &Path,
    observation_url: &str,
    callback_origin: &str,
    occurrence: usize,
    token: &str,
) -> (SsrfProbePlan, ExecutionPermit) {
    let now = OffsetDateTime::now_utc();
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        observation_url,
        source_reference(root, observation_url),
    )
    .unwrap();
    let candidate = SsrfCandidateGenerator
        .generate(&observation)
        .into_iter()
        .nth(occurrence)
        .expect("candidate at occurrence");
    let scope = write_reference(
        root,
        "policy/scope.json",
        "scope",
        &scope_decision(&normalized_target(observation_url)),
    );
    let rules = write_reference(root, "policy/rules.json", "rules", &valid_rules(now));
    let plan = SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new(callback_origin).unwrap())
        .build(
            &observation,
            &candidate,
            ScopeDisposition::InScope,
            scope,
            rules,
            CallbackLease::new(CallbackToken::parse(token).unwrap(), 60_000).unwrap(),
        )
        .unwrap();

    let context = SsrfPolicyContext::new(
        root,
        ENGAGEMENT_ID,
        capture_trust(),
        action_policy::ApprovalState::NotRequired,
        now,
    );
    let permit = match SsrfPolicyGate.evaluate(&plan, &context).unwrap() {
        PolicyGateOutcome::Allowed(permit) => permit,
        other => panic!("expected allowed permit, got {other:?}"),
    };
    (plan, permit)
}

#[tokio::test]
async fn valid_permit_executes_one_request_and_mutates_one_occurrence() {
    let target = RequestCounter::start().await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/vulnerable?url=http%3A%2F%2Ffirst.example.test%2F&keep=stay&url=http%3A%2F%2Fsecond.example.test%2F",
        target.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        1,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    assert_eq!(record.outcome(), ExecutorOutcome::Completed);
    let recorded = target.paths();
    assert_eq!(recorded.len(), 1);
    // Only the second `url` occurrence is replaced with the callback URL
    let received = url::Url::parse(&format!("http://placeholder{}", recorded[0])).unwrap();
    let values: Vec<String> = received
        .query_pairs()
        .filter(|(key, _)| key == "url")
        .map(|(_, value)| value.into_owned())
        .collect();
    assert_eq!(values[0], "http://first.example.test/");
    assert!(values[1].contains(&format!("/callbacks/{DEFAULT_TOKEN}")));
    assert!(received.query().unwrap().contains("keep=stay"));
}

#[tokio::test]
async fn permit_plan_mismatch_performs_zero_network_io() {
    let target = RequestCounter::start().await;
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        target.origin()
    );
    let (_plan_a, permit_a) = prepare(
        root_a.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );
    // Plan B differs by callback token, so its plan hash differs from permit A
    let (plan_b, _permit_b) = prepare(
        root_b.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        "fedcba9876543210fedcba9876543210",
    );

    let result = SsrfHttpExecutor
        .execute(&plan_b, permit_a, OffsetDateTime::now_utc())
        .await;

    assert_eq!(result.unwrap_err(), ExecutorError::PlanMismatch);
    target.assert_no_requests().await;
}

#[tokio::test]
async fn executable_input_mismatch_performs_zero_target_and_callback_io() {
    let target = RequestCounter::start().await;
    let callback = RequestCounter::start().await;
    let root_a = tempfile::tempdir().unwrap();
    let root_b = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        target.origin()
    );
    let (_plan_a, permit_a) = prepare(
        root_a.path(),
        &observation_url,
        &callback.origin(),
        0,
        DEFAULT_TOKEN,
    );
    let (plan_b, _permit_b) = prepare(
        root_b.path(),
        &observation_url,
        &callback.origin(),
        0,
        "aaaaaaaabbbbbbbbccccccccdddddddd",
    );

    let result = SsrfHttpExecutor
        .execute(&plan_b, permit_a, OffsetDateTime::now_utc())
        .await;

    assert_eq!(result.unwrap_err(), ExecutorError::PlanMismatch);
    target.assert_no_requests().await;
    callback.assert_no_requests().await;
}

#[tokio::test]
async fn expired_authorization_performs_zero_network_io() {
    let target = RequestCounter::start().await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        target.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let result = SsrfHttpExecutor
        .execute(
            &plan,
            permit,
            OffsetDateTime::now_utc() + Duration::seconds(120),
        )
        .await;

    assert_eq!(result.unwrap_err(), ExecutorError::AuthorizationExpired);
    target.assert_no_requests().await;
}

#[tokio::test]
async fn redirect_response_is_recorded_but_not_followed() {
    let following = RequestCounter::start().await;
    let location = following.url("followed");
    let redirect = serve(
        Router::new()
            .route("/*path", any(redirect_handler))
            .with_state(Arc::new(location)),
    )
    .await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        redirect.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    assert_eq!(record.status_code(), Some(302));
    assert_eq!(record.outcome(), ExecutorOutcome::Completed);
    following.assert_no_requests().await;
}

#[tokio::test]
async fn rate_limited_and_server_error_produce_explicit_stops() {
    for (code, expected) in [
        (StatusCode::TOO_MANY_REQUESTS, ExecutorOutcome::RateLimited),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            ExecutorOutcome::ServerError,
        ),
    ] {
        let server = serve(Router::new().route("/*path", any(move || async move { code }))).await;
        let root = tempfile::tempdir().unwrap();
        let observation_url = format!(
            "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
            server.origin()
        );
        let (plan, permit) = prepare(
            root.path(),
            &observation_url,
            DUMMY_CALLBACK_ORIGIN,
            0,
            DEFAULT_TOKEN,
        );

        let record = SsrfHttpExecutor
            .execute(&plan, permit, OffsetDateTime::now_utc())
            .await
            .unwrap();

        assert_eq!(record.outcome(), expected);
    }
}

#[tokio::test]
async fn timeout_is_bounded_and_classified_invalid() {
    let server = serve(Router::new().route("/*path", any(slow_handler))).await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        server.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    assert_eq!(record.outcome(), ExecutorOutcome::Timeout);
    assert_eq!(record.status_code(), None);
}

#[tokio::test]
async fn oversized_response_is_stopped_without_retaining_body() {
    let server = serve(Router::new().route("/*path", any(large_handler))).await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        server.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    assert_eq!(record.outcome(), ExecutorOutcome::ResponseTooLarge);
    assert!(record.response_body_truncated());
    assert!(record.response_body_bytes() <= 131_072);
}

#[tokio::test]
async fn tls_failure_against_plaintext_target_is_an_explicit_stop() {
    let server = serve(Router::new().route("/*path", any(|| async { StatusCode::OK }))).await;
    let root = tempfile::tempdir().unwrap();
    // Force an https probe against a plaintext HTTP server to trigger a handshake failure
    let observation_url = format!(
        "https://{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        server.addr()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    assert!(matches!(
        record.outcome(),
        ExecutorOutcome::TlsFailed | ExecutorOutcome::ConnectionFailed
    ));
    assert_eq!(record.status_code(), None);
}

#[tokio::test]
async fn serialized_record_never_leaks_secrets_or_body() {
    let server = serve(Router::new().route("/*path", any(secret_header_handler))).await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/tenant/session-secret-123/fetch?api_key_SECRET_987=http%3A%2F%2Fsecret-origin.example.test%2F",
        server.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let serialized = serde_json::to_string(&record).unwrap();

    assert!(!serialized.contains(DEFAULT_TOKEN));
    assert!(!serialized.contains("/callbacks/"));
    assert!(!serialized.contains("secret-origin.example.test"));
    assert!(!serialized.contains("super-secret-cookie"));
    assert!(!serialized.contains("Bearer leaked-token"));
    assert!(!serialized.contains("sensitive-response-body"));
    assert!(!serialized.contains("api_key_SECRET_987"));
    assert!(!serialized.contains("session-secret-123"));
    assert!(!serialized.contains("target_path_sha256"));
    assert!(serialized.contains("query_parameter"));
    assert!(serialized.contains("\"occurrence\":0"));
    assert!(serialized.contains("<redacted>"));
}

#[tokio::test]
async fn every_model_visible_response_header_value_is_redacted_by_default() {
    let server = serve(Router::new().route("/*path", any(arbitrary_secret_header_handler))).await;
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        server.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();
    let serialized = serde_json::to_string(&record).unwrap();

    for secret in [
        DEFAULT_TOKEN,
        "/callbacks/",
        "target-controlled-location-secret",
        "target-controlled-debug-secret",
        "target-controlled-unknown-secret",
    ] {
        assert!(!serialized.contains(secret));
    }
    for name in ["location", "x-debug-token", "x-arbitrary-secret"] {
        assert!(serialized.contains(name));
    }
}

#[tokio::test]
async fn vulnerable_and_secure_endpoints_each_receive_at_most_one_request() {
    let callback = RequestCounter::start().await;
    let benchmark = SsrfBenchmark::start().await;

    // Vulnerable endpoint performs exactly one outbound callback
    let root_v = tempfile::tempdir().unwrap();
    let vulnerable_url = benchmark.vulnerable_url("http://original.example.test/".into());
    let (plan_v, permit_v) = prepare(
        root_v.path(),
        &vulnerable_url,
        &callback.origin(),
        0,
        DEFAULT_TOKEN,
    );
    let record_v = SsrfHttpExecutor
        .execute(&plan_v, permit_v, OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(record_v.outcome(), ExecutorOutcome::Completed);
    callback.wait_for_requests(1).await;
    assert_eq!(benchmark.vulnerable_requests(), 1);
    assert_eq!(callback.paths().len(), 1);

    // Secure endpoint performs zero outbound callbacks
    let secure_callback = RequestCounter::start().await;
    let root_s = tempfile::tempdir().unwrap();
    let secure_url = benchmark.secure_url("http://original.example.test/".into());
    let (plan_s, permit_s) = prepare(
        root_s.path(),
        &secure_url,
        &secure_callback.origin(),
        0,
        DEFAULT_TOKEN,
    );
    let record_s = SsrfHttpExecutor
        .execute(&plan_s, permit_s, OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(record_s.outcome(), ExecutorOutcome::Completed);
    secure_callback.assert_no_requests().await;
    assert_eq!(benchmark.secure_requests(), 1);
}

#[tokio::test]
async fn configured_environment_proxy_receives_zero_requests() {
    let proxy = RequestCounter::start().await;
    let target = RequestCounter::start().await;
    // The executor disables proxies explicitly, so an env proxy must be ignored
    unsafe {
        std::env::set_var("HTTP_PROXY", proxy.origin());
        std::env::set_var("HTTPS_PROXY", proxy.origin());
    }
    let root = tempfile::tempdir().unwrap();
    let observation_url = format!(
        "{}/fetch?url=http%3A%2F%2Forigin.example.test%2F",
        target.origin()
    );
    let (plan, permit) = prepare(
        root.path(),
        &observation_url,
        DUMMY_CALLBACK_ORIGIN,
        0,
        DEFAULT_TOKEN,
    );

    let record = SsrfHttpExecutor
        .execute(&plan, permit, OffsetDateTime::now_utc())
        .await
        .unwrap();

    unsafe {
        std::env::remove_var("HTTP_PROXY");
        std::env::remove_var("HTTPS_PROXY");
    }
    assert_eq!(record.outcome(), ExecutorOutcome::Completed);
    assert_eq!(target.paths().len(), 1);
    proxy.assert_no_requests().await;
}

// Return a 302 redirect to a configured loopback location
async fn redirect_handler(
    axum::extract::State(location): axum::extract::State<Arc<String>>,
) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.as_str().to_string())],
    )
        .into_response()
}

// Sleep well beyond the plan timeout to force a bounded read timeout
async fn slow_handler() -> StatusCode {
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    StatusCode::OK
}

// Return a body larger than the plan byte budget
async fn large_handler() -> Vec<u8> {
    vec![0u8; 200 * 1024]
}

// Return sensitive headers and a body that must never appear in records
async fn secret_header_handler() -> Response {
    (
        StatusCode::OK,
        [
            (header::SET_COOKIE, "session=super-secret-cookie"),
            (header::WWW_AUTHENTICATE, "Bearer leaked-token"),
        ],
        "sensitive-response-body",
    )
        .into_response()
}

// Return arbitrary target-controlled secrets through commonly trusted and unknown headers
async fn arbitrary_secret_header_handler() -> Response {
    let callback_location = format!(
        "http://callback.example.test/callbacks/{DEFAULT_TOKEN}?target-controlled-location-secret"
    );
    let mut response = StatusCode::FOUND.into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, callback_location.parse().unwrap());
    response.headers_mut().insert(
        "x-debug-token",
        "target-controlled-debug-secret".parse().unwrap(),
    );
    response.headers_mut().insert(
        "x-arbitrary-secret",
        "target-controlled-unknown-secret".parse().unwrap(),
    );
    response
}

// Bind an ephemeral loopback server for one test
struct Server {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Server {
    // Return the plaintext loopback origin
    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }

    // Return the raw loopback socket address
    fn addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Drop for Server {
    // Stop the test server when it leaves scope
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Start one router on an ephemeral loopback port
async fn serve(router: Router) -> Server {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind test server");
    let addr = listener.local_addr().expect("read test server address");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    Server { addr, task }
}
