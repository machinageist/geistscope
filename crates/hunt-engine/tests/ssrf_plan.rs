// Author: Jeff
// Date: 2026-07-31
// Description: Immutable callback-only SSRF probe-plan behavior
// Notes: Plans bind campaign callback authority and never execute during construction

use hunt_engine::{
    CallbackLease, CallbackToken, CampaignCallbackOrigin, EvidenceKind, EvidenceReference,
    HttpMethod, ObservedHttpRequest, RedirectPolicy, ScopeDisposition, SsrfCandidateGenerator,
    SsrfProbePlanBuilder, StopCondition,
};

// Build one immutable source or policy artifact reference
fn reference(id: &str, kind: EvidenceKind, path: &str, digest: char) -> EvidenceReference {
    EvidenceReference::new(id, kind, path, digest.to_string().repeat(64)).unwrap()
}

// Build the observed request used by immutable-plan tests
fn observation(method: HttpMethod) -> ObservedHttpRequest {
    ObservedHttpRequest::new(
        "request-1",
        method,
        "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png",
        reference(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/records/request-1.json",
            'a',
        ),
    )
    .unwrap()
}

#[test]
fn callback_probe_plan_binds_token_mutation_policy_references_and_safe_budgets() {
    let observation = observation(HttpMethod::Get);
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    let origin = CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap();
    let token = CallbackToken::parse("1".repeat(32)).unwrap();

    let plan = SsrfProbePlanBuilder::new(origin)
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
            CallbackLease::new(token, 60_000).unwrap(),
        )
        .unwrap();

    // The redacted view exposes the bare callback origin, never the token path
    assert_eq!(plan.view().callback_origin(), "http://127.0.0.1:43123/");
    assert_eq!(plan.action_plan().budget().max_requests(), 1);
    assert_eq!(plan.action_plan().budget().concurrency(), 1);
    assert_eq!(plan.action_plan().redirect_policy(), RedirectPolicy::Deny);
    assert!(
        plan.action_plan()
            .stop_conditions()
            .contains(&StopCondition::AuthorizationExpired)
    );
    assert_eq!(plan.scope_reference().artifact_path(), "policy/scope.json");
    assert_eq!(plan.rules_reference().artifact_path(), "policy/rules.json");
}

#[test]
fn changing_only_callback_token_changes_immutable_plan_hash() {
    let observation = observation(HttpMethod::Get);
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    let builder =
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap());
    let scope = reference(
        "scope",
        EvidenceKind::PolicyDecision,
        "policy/scope.json",
        'b',
    );
    let rules = reference(
        "rules",
        EvidenceKind::PolicyDecision,
        "policy/rules.json",
        'c',
    );

    let first = builder
        .build(
            &observation,
            &candidate,
            ScopeDisposition::InScope,
            scope.clone(),
            rules.clone(),
            CallbackLease::new(CallbackToken::parse("1".repeat(32)).unwrap(), 60_000).unwrap(),
        )
        .unwrap();
    let second = builder
        .build(
            &observation,
            &candidate,
            ScopeDisposition::InScope,
            scope,
            rules,
            CallbackLease::new(CallbackToken::parse("2".repeat(32)).unwrap(), 60_000).unwrap(),
        )
        .unwrap();

    assert_ne!(
        first.action_plan().plan_hash(),
        second.action_plan().plan_hash()
    );
}

#[test]
fn callback_origin_must_be_one_bare_http_or_https_origin() {
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123/base").is_err());
    assert!(CampaignCallbackOrigin::new("http://127.0.0.1:43123?x=1").is_err());
    assert!(CampaignCallbackOrigin::new("ftp://callback.example.test").is_err());
    assert!(CampaignCallbackOrigin::new("https://callback.example.test").is_ok());
}

#[test]
fn state_changing_observation_is_not_eligible_for_autonomous_probe_plan() {
    let observation = observation(HttpMethod::Post);
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    let builder =
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap());

    let result = builder.build(
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
    );

    assert!(result.is_err());
}
