// Author: Jeff
// Date: 2026-07-31
// Description: Policy-gate authority, trusted-context validation, and audit behavior
// Notes: A permit requires current scope/rules policy plus a successful audit write

use std::fs;
use std::path::Path;

use action_policy::ApprovalState;
use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeVerdict};
use hunt_engine::{
    CallbackLease, CallbackToken, CampaignCallbackOrigin, EvidenceKind, EvidenceReference,
    HttpMethod, ObservedHttpRequest, PolicyGateOutcome, ScopeDisposition, SsrfCandidateGenerator,
    SsrfPolicyContext, SsrfPolicyGate, SsrfProbePlan, SsrfProbePlanBuilder,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const TARGET_URL: &str =
    "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png";
const NORMALIZED_TARGET: &str = "https://target.example.test/fetch";

// Build the immutable observation source reference the gate does not re-validate
fn source_reference() -> EvidenceReference {
    EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/records/request-1.json",
        "a".repeat(64),
    )
    .unwrap()
}

// Write one scope artifact and return its plan-bound reference
fn scope_reference(root: &Path, decision: &ScopeDecision) -> EvidenceReference {
    write_reference(root, "policy/scope.json", "scope", decision)
}

// Write one rules artifact and return its plan-bound reference
fn rules_reference(root: &Path, rules: &ProgramRulesSnapshot) -> EvidenceReference {
    write_reference(root, "policy/rules.json", "rules", rules)
}

// Serialize a value to an artifact and bind a hash-accurate evidence reference
fn write_reference<T: serde::Serialize>(
    root: &Path,
    relative: &str,
    id: &str,
    value: &T,
) -> EvidenceReference {
    let bytes = serde_json::to_vec(value).unwrap();
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, &bytes).unwrap();
    EvidenceReference::new(
        id,
        EvidenceKind::PolicyDecision,
        relative,
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap()
}

// Build the standard in-scope, bounty-eligible scope decision for the plan target
fn in_scope_decision() -> ScopeDecision {
    scope_decision(ScopeVerdict::InScope, Some(true), NORMALIZED_TARGET)
}

// Build a scope decision with explicit verdict, eligibility, and normalized target
fn scope_decision(
    verdict: ScopeVerdict,
    bounty_eligible: Option<bool>,
    normalized_url: &str,
) -> ScopeDecision {
    ScopeDecision {
        input: normalized_url.into(),
        normalized_host: Some("target.example.test".into()),
        normalized_url: Some(normalized_url.into()),
        decision: verdict,
        matched_allow: Vec::new(),
        matched_deny: Vec::new(),
        reason: "fixture".into(),
        asset_type: None,
        bounty_eligible,
        submission_eligible: None,
        notes: Vec::new(),
    }
}

// Build current, automation-allowed program rules relative to now
fn valid_rules(now: OffsetDateTime) -> ProgramRulesSnapshot {
    ProgramRulesSnapshot {
        captured_at: now - Duration::hours(1),
        expires_at: now + Duration::days(1),
        automation_allowed: true,
        source: "manual".into(),
        notes: Vec::new(),
    }
}

// Build an immutable SSRF probe plan bound to the supplied policy artifact references
fn build_plan(scope: EvidenceReference, rules: EvidenceReference) -> SsrfProbePlan {
    let observation =
        ObservedHttpRequest::new("request-1", HttpMethod::Get, TARGET_URL, source_reference())
            .unwrap();
    let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
    SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
        .build(
            &observation,
            &candidate,
            ScopeDisposition::InScope,
            scope,
            rules,
            CallbackLease::new(CallbackToken::parse("1".repeat(32)).unwrap(), 60_000).unwrap(),
        )
        .unwrap()
}

// Count audit events written under the engagement root
fn audit_line_count(root: &Path) -> usize {
    fs::read_to_string(root.join("audit/events.jsonl"))
        .map(|raw| raw.lines().count())
        .unwrap_or(0)
}

#[test]
fn valid_policy_yields_one_permit_bound_to_the_plan_hash() {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();

    match outcome {
        PolicyGateOutcome::Allowed(permit) => {
            assert_eq!(permit.plan_hash(), plan.plan_hash());
            assert_eq!(permit.policy_decision_sha256().len(), 64);
        }
        other => panic!("expected allowed, got {other:?}"),
    }
    assert_eq!(audit_line_count(root.path()), 1);
    let audit = fs::read_to_string(root.path().join("audit/events.jsonl")).unwrap();
    assert!(audit.contains("\"decision\":\"allowed\""));
    // Risk comes only from the plan and is recorded as low_active, never lowered
    assert!(audit.contains("\"risk\":\"low_active\""));
    let decision = fs::read_to_string(
        root.path()
            .join(format!("policy/decisions/{}.json", plan.plan_hash())),
    )
    .unwrap();
    assert!(decision.contains(plan.plan_hash()));
}

#[test]
fn ambiguous_and_out_of_scope_decisions_yield_no_permit() {
    for verdict in [ScopeVerdict::Ambiguous, ScopeVerdict::OutOfScope] {
        let root = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::now_utc();
        let plan = build_plan(
            scope_reference(
                root.path(),
                &scope_decision(verdict, Some(true), NORMALIZED_TARGET),
            ),
            rules_reference(root.path(), &valid_rules(now)),
        );
        let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

        let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();

        assert!(matches!(outcome, PolicyGateOutcome::Blocked(_)));
        assert_eq!(audit_line_count(root.path()), 1);
    }
}

#[test]
fn missing_and_expired_rules_yield_no_permit() {
    // Missing rules artifact
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let dangling_rules = EvidenceReference::new(
        "rules",
        EvidenceKind::PolicyDecision,
        "policy/rules.json",
        "b".repeat(64),
    )
    .unwrap();
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        dangling_rules,
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));

    // Expired rules artifact
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let mut expired = valid_rules(now);
    expired.expires_at = now - Duration::seconds(1);
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &expired),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
}

#[test]
fn future_captured_rules_block_even_with_future_expiry() {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let mut future = valid_rules(now);
    future.captured_at = now + Duration::hours(1);
    future.expires_at = now + Duration::days(2);
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &future),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
}

#[test]
fn automation_disallowed_yields_no_permit() {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let mut rules = valid_rules(now);
    rules.automation_allowed = false;
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &rules),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
}

#[test]
fn bounty_ineligible_blocks_and_unknown_requires_approval() {
    // Explicitly ineligible blocks
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let plan = build_plan(
        scope_reference(
            root.path(),
            &scope_decision(ScopeVerdict::InScope, Some(false), NORMALIZED_TARGET),
        ),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));

    // Unknown eligibility requires approval
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let plan = build_plan(
        scope_reference(
            root.path(),
            &scope_decision(ScopeVerdict::InScope, None, NORMALIZED_TARGET),
        ),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::RequiresApproval(_)
    ));
}

#[test]
fn granted_approval_permits_unknown_eligibility_and_records_approval_id() {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let plan = build_plan(
        scope_reference(
            root.path(),
            &scope_decision(ScopeVerdict::InScope, None, NORMALIZED_TARGET),
        ),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        ApprovalState::Granted {
            approval_id: "approval-123".into(),
        },
        now,
    );

    let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();

    assert!(matches!(outcome, PolicyGateOutcome::Allowed(_)));
    let decision = fs::read_to_string(
        root.path()
            .join(format!("policy/decisions/{}.json", plan.plan_hash())),
    )
    .unwrap();
    assert!(decision.contains("approval-123"));
}

#[test]
fn mismatched_target_or_artifact_hashes_yield_no_permit() {
    // Scope decision made for a different target
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let plan = build_plan(
        scope_reference(
            root.path(),
            &scope_decision(
                ScopeVerdict::InScope,
                Some(true),
                "https://evil.example.test/fetch",
            ),
        ),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));

    // Scope artifact whose on-disk hash differs from the plan-bound reference
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let _written = scope_reference(root.path(), &in_scope_decision());
    let tampered_scope = EvidenceReference::new(
        "scope",
        EvidenceKind::PolicyDecision,
        "policy/scope.json",
        "e".repeat(64),
    )
    .unwrap();
    let plan = build_plan(
        tampered_scope,
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));

    // Rules artifact whose on-disk hash differs from the plan-bound reference
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let _written = rules_reference(root.path(), &valid_rules(now));
    let tampered_rules = EvidenceReference::new(
        "rules",
        EvidenceKind::PolicyDecision,
        "policy/rules.json",
        "f".repeat(64),
    )
    .unwrap();
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        tampered_rules,
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
}

#[test]
fn audit_write_failure_yields_no_permit() {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    // Occupy the audit directory path with a regular file so append fails
    fs::write(root.path().join("audit"), b"not a directory").unwrap();
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(SsrfPolicyGate.evaluate(&plan, &context).is_err());
}

#[cfg(unix)]
#[test]
fn audit_directory_symlink_escape_yields_no_permit() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    symlink(outside.path(), root.path().join("audit")).unwrap();
    let plan = build_plan(
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(SsrfPolicyGate.evaluate(&plan, &context).is_err());
}
