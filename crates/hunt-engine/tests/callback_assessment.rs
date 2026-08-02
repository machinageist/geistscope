// Author: Jeff
// Date: 2026-07-31
// Description: Deterministic SSRF assessment and the plan-bound callback worker boundary
// Notes: Uses injected clocks and ephemeral loopback ports; no wall-clock sleeps

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{ConnectInfo, DefaultBodyLimit, OriginalUri, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::routing::any;
use hunt_engine::{
    AssessmentClass, AssessmentReason, CallbackLease, CallbackRecordOutcome, CallbackRecorder,
    CallbackRegistration, CallbackRequest, CallbackToken, CampaignCallbackOrigin, EvidenceKind,
    EvidenceReference, ExecutorOutcome, HttpMethod, ObservationWindow, ObservedHttpRequest,
    ScopeDisposition, SsrfAssessor, SsrfCandidateGenerator, SsrfProbePlan, SsrfProbePlanBuilder,
    TransactionState,
};
use tokio::task::JoinHandle;

const START_MS: u64 = 1_000;
const RECEIVED_MS: u64 = 1_500;
const DEADLINE_MS: u64 = 2_000;
const HARD_BODY_CAP: usize = 65_536;

// Build one immutable evidence reference for source and policy artifacts
fn reference(id: &str, kind: EvidenceKind, path: &str, digest: char) -> EvidenceReference {
    EvidenceReference::new(id, kind, path, digest.to_string().repeat(64)).unwrap()
}

// Build one offline SSRF probe plan for assessment inputs
fn build_plan() -> SsrfProbePlan {
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png",
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap();
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
        .build(
            &observation,
            &candidate,
            ScopeDisposition::InScope,
            reference(
                "scope",
                EvidenceKind::PolicyDecision,
                "policy/scope.json",
                'b',
            ),
            reference(
                "rules",
                EvidenceKind::PolicyDecision,
                "policy/rules.json",
                'c',
            ),
            CallbackLease::new(CallbackToken::parse("1".repeat(32)).unwrap(), 60_000).unwrap(),
        )
        .unwrap()
}

// Build one bounded callback request received at a fixed instant
fn callback_request(received_at_ms: u64) -> CallbackRequest {
    CallbackRequest::new(
        "GET",
        "/callbacks/probe",
        [("cookie", "super-secret-cookie"), ("user-agent", "curl")],
        b"sensitive-response-body".to_vec(),
        Some("127.0.0.1:5000"),
        received_at_ms,
    )
    .unwrap()
}

// Register a plan-bound token and return the recorder plus token
fn recorder_with_token(plan: &SsrfProbePlan) -> (CallbackRecorder, CallbackToken) {
    let token = CallbackToken::generate();
    let mut recorder = CallbackRecorder::default();
    recorder
        .register(CallbackRegistration::new(
            token.clone(),
            plan.plan_hash().to_string(),
            DEADLINE_MS,
        ))
        .unwrap();
    (recorder, token)
}

// Build the standard observation window finalized at the deadline
fn window(finalized_at_ms: u64) -> ObservationWindow {
    ObservationWindow::new(START_MS, DEADLINE_MS, finalized_at_ms)
}

// Represent a completed authorized transaction for the given plan
fn completed(plan: &SsrfProbePlan) -> TransactionState {
    TransactionState::Completed {
        plan_hash: plan.plan_hash().to_string(),
    }
}

#[test]
fn matching_callback_after_success_within_window_is_proven() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    recorder.record(&token, callback_request(RECEIVED_MS));
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let assessment =
        SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));

    assert_eq!(assessment.class(), AssessmentClass::CallbackProven);
    assert_eq!(assessment.reason(), AssessmentReason::CallbackProven);
    assert!(assessment.is_callback_proven());
}

#[test]
fn no_callback_at_deadline_is_negative_and_before_deadline_is_pending() {
    let plan = build_plan();
    let (recorder, token) = recorder_with_token(&plan);
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let negative = SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));
    let pending = SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(1_500));

    assert_eq!(negative.class(), AssessmentClass::Negative);
    assert_eq!(pending.class(), AssessmentClass::Pending);
    assert_eq!(pending.reason(), AssessmentReason::ObservationPending);
}

#[test]
fn invalid_callbacks_never_prove_ssrf() {
    let plan = build_plan();

    // Unknown token
    let recorder = CallbackRecorder::default();
    let unknown = recorder.correlate(&CallbackToken::generate(), plan.plan_hash(), DEADLINE_MS);
    assert_eq!(
        SsrfAssessor
            .assess(&plan, &completed(&plan), &unknown, window(DEADLINE_MS))
            .class(),
        AssessmentClass::Invalid
    );

    // Plan mismatch
    let (recorder, token) = recorder_with_token(&plan);
    let mismatch = recorder.correlate(&token, &"9".repeat(64), DEADLINE_MS);
    assert_eq!(
        SsrfAssessor
            .assess(&plan, &completed(&plan), &mismatch, window(DEADLINE_MS))
            .class(),
        AssessmentClass::Invalid
    );

    // Reused token
    let (mut recorder, token) = recorder_with_token(&plan);
    recorder.record(&token, callback_request(RECEIVED_MS));
    recorder.record(&token, callback_request(RECEIVED_MS));
    let reused = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);
    assert_eq!(
        SsrfAssessor
            .assess(&plan, &completed(&plan), &reused, window(DEADLINE_MS))
            .class(),
        AssessmentClass::Invalid
    );
}

#[test]
fn late_callback_is_invalid_not_negative_or_proven() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    // A callback arriving after its lease expiry is rejected and marked late
    assert_eq!(
        recorder.record(&token, callback_request(DEADLINE_MS + 1)),
        CallbackRecordOutcome::Expired
    );
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let assessment =
        SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));

    assert_eq!(assessment.class(), AssessmentClass::Invalid);
    assert_eq!(assessment.reason(), AssessmentReason::InvalidCallback);
}

#[test]
fn matching_callback_with_failed_or_unexecuted_transaction_is_invalid() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    recorder.record(&token, callback_request(RECEIVED_MS));
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let failed = TransactionState::Failed {
        plan_hash: plan.plan_hash().to_string(),
        outcome: ExecutorOutcome::Timeout,
    };
    let unexecuted = TransactionState::not_executed();

    assert_eq!(
        SsrfAssessor
            .assess(&plan, &failed, &correlation, window(DEADLINE_MS))
            .class(),
        AssessmentClass::Invalid
    );
    let unexecuted_assessment =
        SsrfAssessor.assess(&plan, &unexecuted, &correlation, window(DEADLINE_MS));
    assert_eq!(unexecuted_assessment.class(), AssessmentClass::Invalid);
    assert_eq!(
        unexecuted_assessment.reason(),
        AssessmentReason::TransactionMissing
    );
}

#[test]
fn transaction_for_a_different_plan_is_invalid() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    recorder.record(&token, callback_request(RECEIVED_MS));
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let other_plan_transaction = TransactionState::Completed {
        plan_hash: "0".repeat(64),
    };

    let assessment = SsrfAssessor.assess(
        &plan,
        &other_plan_transaction,
        &correlation,
        window(DEADLINE_MS),
    );

    assert_eq!(assessment.class(), AssessmentClass::Invalid);
    assert_eq!(
        assessment.reason(),
        AssessmentReason::TransactionPlanMismatch
    );
}

#[test]
fn matching_callback_remains_proven_when_classified_after_window_closes() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    recorder.record(&token, callback_request(RECEIVED_MS));
    // Classification happens long after the window closed
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let assessment = SsrfAssessor.assess(
        &plan,
        &completed(&plan),
        &correlation,
        window(DEADLINE_MS + 10_000),
    );

    assert_eq!(assessment.class(), AssessmentClass::CallbackProven);
}

#[test]
fn assessment_serialization_contains_no_secrets_and_is_deterministic() {
    let plan = build_plan();
    let (mut recorder, token) = recorder_with_token(&plan);
    let raw_token = token.as_str().to_string();
    recorder.record(&token, callback_request(RECEIVED_MS));
    let correlation = recorder.correlate(&token, plan.plan_hash(), DEADLINE_MS);

    let first = SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));
    let second = SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));
    let serialized = serde_json::to_string(&first).unwrap();

    assert!(!serialized.contains(&raw_token));
    assert!(!serialized.contains("super-secret-cookie"));
    assert!(!serialized.contains("sensitive-response-body"));
    assert!(!serialized.contains("original.example.test"));
    assert!(!serialized.contains("verified_finding"));
    // Identical structured inputs yield byte-identical canonical JSON
    assert_eq!(serialized, serde_json::to_string(&second).unwrap());
}

#[tokio::test]
async fn live_callback_worker_records_exact_route_and_proves_over_http() {
    let plan = build_plan();
    let token = CallbackToken::generate();
    let recorder = Arc::new(Mutex::new(CallbackRecorder::default()));
    recorder
        .lock()
        .unwrap()
        .register(CallbackRegistration::new(
            token.clone(),
            plan.plan_hash().to_string(),
            DEADLINE_MS,
        ))
        .unwrap();
    let listener = start_listener(Arc::clone(&recorder)).await;

    // An exact-route callback is recorded
    let ok = reqwest::get(format!(
        "{}/callbacks/{}",
        listener.origin(),
        token.as_str()
    ))
    .await
    .unwrap();
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);

    // A suffixed route is rejected without recording proof
    let rejected = reqwest::get(format!(
        "{}/callbacks/{}/extra",
        listener.origin(),
        token.as_str()
    ))
    .await
    .unwrap();
    assert_eq!(rejected.status(), StatusCode::NOT_FOUND);

    let correlation = recorder
        .lock()
        .unwrap()
        .correlate(&token, plan.plan_hash(), DEADLINE_MS);
    let assessment =
        SsrfAssessor.assess(&plan, &completed(&plan), &correlation, window(DEADLINE_MS));
    assert_eq!(assessment.class(), AssessmentClass::CallbackProven);
    let serialized = serde_json::to_string(&assessment).unwrap();
    assert!(serialized.contains("\"callback_correlation\":\"matched\""));
}

// Shared listener state binding an injected clock and the plan-bound recorder
struct ListenerState {
    recorder: Arc<Mutex<CallbackRecorder>>,
}

// A running loopback callback worker
struct Listener {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Listener {
    // Return the plaintext loopback origin
    fn origin(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for Listener {
    // Stop the callback worker when it leaves scope
    fn drop(&mut self) {
        self.task.abort();
    }
}

// Start the plan-bound callback worker on an ephemeral loopback port
async fn start_listener(recorder: Arc<Mutex<CallbackRecorder>>) -> Listener {
    let state = Arc::new(ListenerState { recorder });
    let app = Router::new()
        .route("/*path", any(handle_callback))
        .layer(DefaultBodyLimit::max(HARD_BODY_CAP))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind callback worker");
    let addr = listener.local_addr().expect("read callback worker address");
    let task = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });
    Listener { addr, task }
}

// Parse the exact callback route, bound untrusted input, and record proof only
async fn handle_callback(
    State(state): State<Arc<ListenerState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> StatusCode {
    let Ok(token) = CallbackToken::from_callback_path(uri.path()) else {
        return StatusCode::NOT_FOUND;
    };
    let header_pairs = headers.iter().filter_map(|(name, value)| {
        value
            .to_str()
            .ok()
            .map(|value| (name.as_str().to_string(), value.to_string()))
    });
    let peer = peer.to_string();
    let Ok(request) = CallbackRequest::new(
        method.as_str(),
        uri.path(),
        header_pairs,
        body.to_vec(),
        Some(&peer),
        RECEIVED_MS,
    ) else {
        return StatusCode::BAD_REQUEST;
    };
    match state.recorder.lock().unwrap().record(&token, request) {
        CallbackRecordOutcome::Accepted(_) => StatusCode::NO_CONTENT,
        _ => StatusCode::BAD_REQUEST,
    }
}
