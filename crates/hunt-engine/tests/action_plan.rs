// Author: Jeff
// Date: 2026-07-31
// Description: Capability-neutral observation, hypothesis, and action-plan behavior
// Notes: Plans bind executable semantics but exclude presentation prose from approval hashes

use hunt_engine::{
    ActionBudget, ActionDescriptor, ActionPlanBuilder, ActionPlanRequest, EvidenceContract,
    EvidenceKind, EvidenceReference, EvidenceRequirement, HuntRisk, Hypothesis, Observation,
    PlanContractError, ScopeDisposition, StopCondition,
};

// Build a safe source artifact reference
fn source_reference() -> EvidenceReference {
    EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/records/request-1.json",
        "a".repeat(64),
    )
    .expect("valid source reference")
}

// Build the evidence required from one planned action
fn evidence_contract() -> EvidenceContract {
    EvidenceContract::new([
        EvidenceRequirement::new("policy", EvidenceKind::PolicyDecision),
        EvidenceRequirement::new("response", EvidenceKind::RequestResponse),
    ])
    .expect("valid evidence contract")
}

// Build one valid plan request for hash and validation tests
fn plan_request() -> ActionPlanRequest {
    ActionPlanRequest::new(
        "hypothesis-1",
        ActionDescriptor::new(
            "ssrf",
            "callback_probe",
            "https://target.example.test/fetch",
            "b".repeat(64),
        )
        .expect("valid action descriptor"),
        ScopeDisposition::InScope,
        HuntRisk::LowActive,
        ActionBudget::new(1, 5_000, 16_384, 1).expect("valid budget"),
        evidence_contract(),
    )
    .with_stop_conditions([
        StopCondition::RateLimited,
        StopCondition::ServerError,
        StopCondition::ScopeDrift,
    ])
    .with_rationale("URL-like input may trigger a server-side request")
}

#[test]
fn observation_can_seed_an_inert_hypothesis() {
    let observation = Observation::new("observation-1", source_reference()).unwrap();
    let hypothesis = Hypothesis::new("hypothesis-1", "ssrf", [observation.id()]).unwrap();

    assert_eq!(hypothesis.capability_id(), "ssrf");
    assert_eq!(hypothesis.observation_ids(), &["observation-1"]);
}

#[test]
fn action_plan_preserves_policy_and_budget_metadata() {
    let plan = ActionPlanBuilder.build(plan_request()).unwrap();

    assert_eq!(plan.scope(), ScopeDisposition::InScope);
    assert_eq!(plan.risk(), HuntRisk::LowActive);
    assert_eq!(plan.budget().max_requests(), 1);
    assert_eq!(plan.budget().concurrency(), 1);
    assert_eq!(plan.stop_conditions().len(), 3);
    assert_eq!(plan.plan_hash().len(), 64);
}

#[test]
fn plan_hash_changes_when_executable_semantics_change() {
    let first = ActionPlanBuilder.build(plan_request()).unwrap();
    let changed = ActionPlanBuilder
        .build(
            plan_request()
                .with_budget(ActionBudget::new(1, 5_000, 32_768, 1).expect("valid budget")),
        )
        .unwrap();

    assert_ne!(first.plan_hash(), changed.plan_hash());
}

#[test]
fn presentation_rationale_does_not_change_plan_hash() {
    let first = ActionPlanBuilder.build(plan_request()).unwrap();
    let changed = ActionPlanBuilder
        .build(plan_request().with_rationale("Different model-written explanation"))
        .unwrap();

    assert_eq!(first.plan_hash(), changed.plan_hash());
}

#[test]
fn zero_or_incoherent_budgets_fail_validation() {
    assert_eq!(
        ActionBudget::new(0, 5_000, 16_384, 1).unwrap_err(),
        PlanContractError::InvalidBudget
    );
    assert_eq!(
        ActionBudget::new(1, 5_000, 16_384, 2).unwrap_err(),
        PlanContractError::InvalidBudget
    );
}
