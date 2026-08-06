// Author: Jeff
// Date: 2026-07-31
// Description: Secret-boundary and immutable-hash behavior for SSRF probe plans
// Notes: The public plan view must never expose raw tokens or observed query values

mod support;

use hunt_engine::{
    ActionBudget, ActionDescriptor, ActionPlanBuilder, ActionPlanRequest, CallbackLease,
    CallbackToken, CampaignCallbackOrigin, EvidenceContract, EvidenceKind, EvidenceReference,
    EvidenceRequirement, HttpMethod, HuntRisk, ObservedHttpRequest, ScopeDisposition,
    SsrfCandidate, SsrfCandidateGenerator, SsrfProbePlan, SsrfProbePlanBuilder, StopCondition,
};
use support::RequestCounter;

const OBSERVATION_WINDOW_MS: u64 = 60_000;
const RAW_TOKEN: &str = "0123456789abcdef0123456789abcdef";
const SUSPECTED_VALUE: &str = "https://original.example.test/image.png";

// Build one immutable source or policy artifact reference
fn reference(id: &str, kind: EvidenceKind, path: &str, digest: char) -> EvidenceReference {
    EvidenceReference::new(id, kind, path, digest.to_string().repeat(64)).unwrap()
}

// Build one observed GET request carrying a suspected server-side URL input
fn observation(id: &str, method: HttpMethod, source_digest: char) -> ObservedHttpRequest {
    let mut url = url_with_value(SUSPECTED_VALUE);
    if id != "request-1" {
        url = url_with_value("https://different.example.test/other.png");
    }
    ObservedHttpRequest::new(
        id,
        method,
        url,
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            source_digest,
        ),
    )
    .unwrap()
}

// Encode one fetch URL with a single url query parameter value
fn url_with_value(value: &str) -> String {
    let mut url = url::Url::parse("https://target.example.test/fetch").unwrap();
    url.query_pairs_mut().append_pair("url", value);
    url.into()
}

// Build one plan against the standard request-1 observation and callback origin
fn build_plan(
    origin: &str,
    token: &str,
    window_ms: u64,
    source_digest: char,
    scope_digest: char,
    rules_digest: char,
) -> Result<SsrfProbePlan, hunt_engine::SsrfContractError> {
    let observation = observation("request-1", HttpMethod::Get, source_digest);
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new(origin).unwrap()).build(
        &observation,
        &candidate,
        ScopeDisposition::InScope,
        reference(
            "scope",
            EvidenceKind::PolicyDecision,
            "policy/scope.json",
            scope_digest,
        ),
        reference(
            "rules",
            EvidenceKind::PolicyDecision,
            "policy/rules.json",
            rules_digest,
        ),
        CallbackLease::new(CallbackToken::parse(token).unwrap(), window_ms).unwrap(),
    )
}

// Build the canonical plan used by hash-stability assertions
fn baseline_plan() -> SsrfProbePlan {
    build_plan(
        "http://127.0.0.1:43123",
        RAW_TOKEN,
        OBSERVATION_WINDOW_MS,
        'a',
        'b',
        'c',
    )
    .unwrap()
}

// Build one plan from an exact observed URL for executable-identity assertions
fn plan_for_url(url: &str) -> SsrfProbePlan {
    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        url,
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
            CallbackLease::new(
                CallbackToken::parse(RAW_TOKEN).unwrap(),
                OBSERVATION_WINDOW_MS,
            )
            .unwrap(),
        )
        .unwrap()
}

#[test]
fn public_plan_view_hides_raw_token_and_original_query_value() {
    let plan = baseline_plan();
    let serialized = serde_json::to_string(plan.view()).unwrap();

    assert!(!serialized.contains(RAW_TOKEN));
    assert!(!serialized.contains(SUSPECTED_VALUE));
    assert!(!serialized.contains("original.example.test"));
    assert!(!serialized.contains("/callbacks/"));
    // The redacted view still names the bare callback origin and target metadata
    assert!(serialized.contains("http://127.0.0.1:43123/"));
    assert!(serialized.contains("https://target.example.test"));
}

#[test]
fn executable_changes_alter_the_immutable_plan_hash() {
    let baseline = baseline_plan().plan_hash().to_string();

    // Token
    assert_ne!(
        baseline,
        build_plan(
            "http://127.0.0.1:43123",
            "fedcba9876543210fedcba9876543210",
            OBSERVATION_WINDOW_MS,
            'a',
            'b',
            'c'
        )
        .unwrap()
        .plan_hash()
    );
    // Source artifact hash
    assert_ne!(
        baseline,
        build_plan(
            "http://127.0.0.1:43123",
            RAW_TOKEN,
            OBSERVATION_WINDOW_MS,
            'd',
            'b',
            'c'
        )
        .unwrap()
        .plan_hash()
    );
    // Scope artifact hash
    assert_ne!(
        baseline,
        build_plan(
            "http://127.0.0.1:43123",
            RAW_TOKEN,
            OBSERVATION_WINDOW_MS,
            'a',
            'e',
            'c'
        )
        .unwrap()
        .plan_hash()
    );
    // Rules artifact hash
    assert_ne!(
        baseline,
        build_plan(
            "http://127.0.0.1:43123",
            RAW_TOKEN,
            OBSERVATION_WINDOW_MS,
            'a',
            'b',
            'f'
        )
        .unwrap()
        .plan_hash()
    );
    // Callback origin
    assert_ne!(
        baseline,
        build_plan(
            "http://127.0.0.1:43124",
            RAW_TOKEN,
            OBSERVATION_WINDOW_MS,
            'a',
            'b',
            'c'
        )
        .unwrap()
        .plan_hash()
    );
    // Observation-window duration
    assert_ne!(
        baseline,
        build_plan("http://127.0.0.1:43123", RAW_TOKEN, 30_000, 'a', 'b', 'c')
            .unwrap()
            .plan_hash()
    );
}

#[test]
fn unrelated_query_value_changes_the_full_executable_request_identity() {
    let first = plan_for_url(
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png&admin=false",
    );
    let second = plan_for_url(
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png&admin=true",
    );

    assert_ne!(first.plan_hash(), second.plan_hash());
}

#[test]
fn query_order_duplicates_and_percent_encoding_are_bound_exactly() {
    let ordered = plan_for_url(
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png&keep=first&keep=second&note=a%2Fb",
    );
    let reordered = plan_for_url(
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png&keep=second&keep=first&note=a%2Fb",
    );
    let encoding_changed = plan_for_url(
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png&keep=first&keep=second&note=a%2fb",
    );

    assert_ne!(ordered.plan_hash(), reordered.plan_hash());
    assert_ne!(ordered.plan_hash(), encoding_changed.plan_hash());
}

#[test]
fn observed_target_userinfo_is_rejected_before_candidate_or_plan_construction() {
    let result = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        "https://user:password@target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2F",
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    );

    assert_eq!(
        result.unwrap_err(),
        hunt_engine::SsrfContractError::ObservedUrlContainsUserinfo
    );
}

#[test]
fn path_carried_secrets_are_redacted_from_every_public_plan_serialization() {
    let plan = plan_for_url(
        "https://target.example.test/tenant/session-secret-123/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png",
    );
    let view = serde_json::to_string(plan.view()).unwrap();
    let envelope = serde_json::to_string(plan.action_plan()).unwrap();

    for serialized in [&view, &envelope] {
        assert!(!serialized.contains("session-secret-123"));
        assert!(!serialized.contains("/tenant/"));
    }
    assert_eq!(plan.view().target_path(), "/<redacted>");
    assert!(!view.contains("target_path_sha256"));
}

#[test]
fn public_plan_uses_source_pointer_and_opaque_insertion_identity_without_key_name() {
    const SECRET_KEY_NAME: &str = "api_key_SECRET_987";
    let plan = plan_for_url(&format!(
        "https://target.example.test/fetch?{SECRET_KEY_NAME}=https%3A%2F%2Foriginal.example.test%2Fimage.png"
    ));
    let view = serde_json::to_string(plan.view()).unwrap();

    assert!(!view.contains(SECRET_KEY_NAME));
    assert!(view.contains(plan.view().candidate_id()));
    assert!(view.contains("query_parameter"));
    assert!(view.contains("\"occurrence\":0"));
    assert_eq!(
        plan.source_reference().artifact_path(),
        "traffic/records/request-1.json"
    );
    assert_eq!(plan.source_reference().sha256(), "a".repeat(64));
    assert!(view.contains("traffic/records/request-1.json"));
    assert!(view.contains(&"a".repeat(64)));
}

#[test]
fn changing_target_path_or_query_occurrence_changes_the_plan_hash() {
    let baseline = baseline_plan().plan_hash().to_string();

    // Different target path with the same suspected value
    let mut other_path = url::Url::parse("https://target.example.test/proxy").unwrap();
    other_path
        .query_pairs_mut()
        .append_pair("url", SUSPECTED_VALUE);
    let path_observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        other_path,
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap();
    let path_candidate = SsrfCandidateGenerator.generate(&path_observation).remove(0);
    let path_plan =
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
            .build(
                &path_observation,
                &path_candidate,
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
                CallbackLease::new(
                    CallbackToken::parse(RAW_TOKEN).unwrap(),
                    OBSERVATION_WINDOW_MS,
                )
                .unwrap(),
            )
            .unwrap();
    assert_ne!(baseline, path_plan.plan_hash());

    // Second occurrence of the same query parameter name
    let mut duplicate = url::Url::parse("https://target.example.test/fetch").unwrap();
    duplicate
        .query_pairs_mut()
        .append_pair("url", SUSPECTED_VALUE);
    duplicate
        .query_pairs_mut()
        .append_pair("url", SUSPECTED_VALUE);
    let dup_observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        duplicate,
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap();
    let second_candidate = SsrfCandidateGenerator.generate(&dup_observation).remove(1);
    let occurrence_plan =
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
            .build(
                &dup_observation,
                &second_candidate,
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
                CallbackLease::new(
                    CallbackToken::parse(RAW_TOKEN).unwrap(),
                    OBSERVATION_WINDOW_MS,
                )
                .unwrap(),
            )
            .unwrap();
    assert_ne!(baseline, occurrence_plan.plan_hash());
}

#[test]
fn candidate_from_a_different_observation_value_is_rejected() {
    // The candidate is generated from request-1 but built against a mismatched observation value
    let source_observation = observation("request-1", HttpMethod::Get, 'a');
    let candidate: SsrfCandidate = SsrfCandidateGenerator
        .generate(&source_observation)
        .remove(0);
    let mut drifted = url::Url::parse("https://target.example.test/fetch").unwrap();
    drifted
        .query_pairs_mut()
        .append_pair("url", "https://moved.example.test/new.png");
    let drifted_observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        drifted,
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap();

    let result =
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
            .build(
                &drifted_observation,
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
                CallbackLease::new(
                    CallbackToken::parse(RAW_TOKEN).unwrap(),
                    OBSERVATION_WINDOW_MS,
                )
                .unwrap(),
            );

    assert_eq!(
        result.unwrap_err(),
        hunt_engine::SsrfContractError::CandidateObservationMismatch
    );
}

#[test]
fn get_is_permitted_and_other_methods_are_rejected() {
    assert!(
        build_plan(
            "http://127.0.0.1:43123",
            RAW_TOKEN,
            OBSERVATION_WINDOW_MS,
            'a',
            'b',
            'c'
        )
        .is_ok()
    );

    for method in [
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Patch,
        HttpMethod::Delete,
    ] {
        let obs = observation("request-1", method, 'a');
        let candidate = SsrfCandidateGenerator.generate(&obs).remove(0);
        let result = SsrfProbePlanBuilder::new(
            CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap(),
        )
        .build(
            &obs,
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
            CallbackLease::new(
                CallbackToken::parse(RAW_TOKEN).unwrap(),
                OBSERVATION_WINDOW_MS,
            )
            .unwrap(),
        );
        assert_eq!(
            result.unwrap_err(),
            hunt_engine::SsrfContractError::StateChangingObservation
        );
    }
}

#[test]
fn ssrf_plan_always_binds_the_authorization_expiry_stop() {
    let plan = baseline_plan();
    assert!(
        plan.action_plan()
            .stop_conditions()
            .contains(&StopCondition::AuthorizationExpired)
    );
}

#[test]
fn callback_origins_with_userinfo_or_paths_are_rejected() {
    assert!(CampaignCallbackOrigin::new("http://user:pass@127.0.0.1:43123").is_err());
    assert!(CampaignCallbackOrigin::new("http://user@127.0.0.1:43123").is_err());
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123/base").is_err());
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123?x=1").is_err());
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123#frag").is_err());
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123").is_ok());
}

#[test]
fn reordered_and_duplicated_stop_conditions_hash_identically() {
    let plan_request = |conditions: Vec<StopCondition>| {
        ActionPlanRequest::new(
            "hypothesis-1",
            ActionDescriptor::new(
                "ssrf",
                "callback_probe",
                "https://target.example.test/fetch",
                "b".repeat(64),
            )
            .unwrap(),
            ScopeDisposition::InScope,
            HuntRisk::LowActive,
            ActionBudget::new(1, 5_000, 16_384, 1).unwrap(),
            EvidenceContract::new([EvidenceRequirement::new(
                "policy",
                EvidenceKind::PolicyDecision,
            )])
            .unwrap(),
        )
        .with_stop_conditions(conditions)
    };

    let ordered = ActionPlanBuilder
        .build(plan_request(vec![
            StopCondition::RateLimited,
            StopCondition::ServerError,
            StopCondition::ScopeDrift,
        ]))
        .unwrap();
    let shuffled = ActionPlanBuilder
        .build(plan_request(vec![
            StopCondition::ScopeDrift,
            StopCondition::RateLimited,
            StopCondition::ServerError,
            StopCondition::RateLimited,
        ]))
        .unwrap();

    assert_eq!(ordered.plan_hash(), shuffled.plan_hash());
}

#[tokio::test]
async fn plan_construction_sends_no_target_or_callback_traffic() {
    let callback = RequestCounter::start().await;
    let target = RequestCounter::start().await;

    let observation = ObservedHttpRequest::new(
        "request-1",
        HttpMethod::Get,
        target.url_with_query("fetch", "url", SUSPECTED_VALUE),
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap();
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    let _plan = SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new(callback.origin()).unwrap())
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
            CallbackLease::new(
                CallbackToken::parse(RAW_TOKEN).unwrap(),
                OBSERVATION_WINDOW_MS,
            )
            .unwrap(),
        )
        .unwrap();

    callback.assert_no_requests().await;
    target.assert_no_requests().await;
}
