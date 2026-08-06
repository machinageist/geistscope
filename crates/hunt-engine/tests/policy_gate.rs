// Author: Jeff
// Date: 2026-07-31
// Description: Policy-gate authority, trusted-context validation, and audit behavior
// Notes: A permit requires current scope/rules policy plus a successful audit write

use std::fs;
use std::path::Path;

use action_policy::ApprovalState;
use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeVerdict};
use hunt_engine::{
    CallbackLease, CallbackToken, CampaignCallbackOrigin, CapturedRequestEvidence, EvidenceKind,
    EvidenceReference, HttpMethod, ObservedHttpRequest, PolicyGateOutcome, ScopeDisposition,
    SsrfCandidateGenerator, SsrfPolicyContext, SsrfPolicyGate, SsrfProbePlan, SsrfProbePlanBuilder,
};
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const TARGET_URL: &str =
    "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png";
const NORMALIZED_TARGET: &str = "https://target.example.test/fetch";

// Persist immutable request evidence and return its hash-accurate private reference
fn source_reference(root: &Path) -> EvidenceReference {
    source_reference_for_url(root, TARGET_URL)
}

fn source_reference_for_url(root: &Path, observed_url: &str) -> EvidenceReference {
    let bytes = captured_request_bytes("request-1", HttpMethod::Get, observed_url);
    source_reference_at(root, "traffic/records/request-1.json", &bytes)
}

// Serialize typed captured-request provenance for authorization fixtures
fn captured_request_bytes(request_id: &str, method: HttpMethod, observed_url: &str) -> Vec<u8> {
    let evidence = CapturedRequestEvidence::new(
        "0123456789abcdef0123456789abcdef",
        request_id,
        method,
        observed_url,
    )
    .unwrap();
    serde_json::to_vec(&evidence).unwrap()
}

// Persist request evidence at an explicit relative path for secrecy regressions
fn source_reference_at(root: &Path, relative: &str, bytes: &[u8]) -> EvidenceReference {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        relative,
        hex::encode(Sha256::digest(bytes)),
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
fn build_plan(root: &Path, scope: EvidenceReference, rules: EvidenceReference) -> SsrfProbePlan {
    build_plan_with_source(source_reference(root), scope, rules)
}

// Build a plan with an explicit source reference for authorization regressions
fn build_plan_with_source(
    source: EvidenceReference,
    scope: EvidenceReference,
    rules: EvidenceReference,
) -> SsrfProbePlan {
    let observation =
        ObservedHttpRequest::new("request-1", HttpMethod::Get, TARGET_URL, source).unwrap();
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
        root.path(),
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
    assert!(!decision.contains("traffic/records/request-1.json"));
    assert!(!audit.contains("traffic/records/request-1.json"));
    let source_sha = hex::encode(Sha256::digest(captured_request_bytes(
        "request-1",
        HttpMethod::Get,
        TARGET_URL,
    )));
    for serialized in [&decision, &audit] {
        assert!(!serialized.contains(&source_sha));
        assert!(!serialized.contains("0123456789abcdef0123456789abcdef"));
        assert!(!serialized.contains("127.0.0.1:43123"));
    }
    assert!(decision.contains("source_evidence_pointer"));
}

#[test]
fn wrong_source_requirement_and_kind_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let cases = [
        ("wrong_requirement", "other", EvidenceKind::RequestResponse),
        ("wrong_kind", "source", EvidenceKind::PolicyDecision),
    ];
    for (case, requirement, kind) in cases {
        let root = tempfile::tempdir().unwrap();
        let bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
        let relative = "traffic/records/request-1.json";
        fs::create_dir_all(root.path().join("traffic/records")).unwrap();
        fs::write(root.path().join(relative), &bytes).unwrap();
        let source = EvidenceReference::new(
            requirement,
            kind,
            relative,
            hex::encode(Sha256::digest(&bytes)),
        )
        .unwrap();
        let plan = build_plan_with_source(
            source,
            scope_reference(root.path(), &in_scope_decision()),
            rules_reference(root.path(), &valid_rules(now)),
        );
        let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
        let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();
        assert!(matches!(outcome, PolicyGateOutcome::Blocked(_)), "{case}");
    }
}

#[test]
fn malformed_schema_version_capture_request_method_and_url_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let valid = serde_json::json!({
        "schema": "geistscope.captured_request",
        "version": 1,
        "capture_id": "0123456789abcdef0123456789abcdef",
        "request_id": "request-1",
        "method": "GET",
        "observed_url": TARGET_URL,
    });
    let mut cases = vec![("malformed_json", b"{not json".to_vec())];
    for (case, field, value) in [
        ("wrong_schema", "schema", serde_json::json!("wrong.schema")),
        ("wrong_version", "version", serde_json::json!(2)),
        (
            "wrong_capture_id",
            "capture_id",
            serde_json::json!("not-a-capture"),
        ),
        (
            "wrong_request_id",
            "request_id",
            serde_json::json!("request-2"),
        ),
        ("wrong_method", "method", serde_json::json!("POST")),
        (
            "wrong_url",
            "observed_url",
            serde_json::json!("https://target.example.test/other?url=http://a.test/"),
        ),
    ] {
        let mut payload = valid.clone();
        payload[field] = value;
        cases.push((case, serde_json::to_vec(&payload).unwrap()));
    }

    for (case, bytes) in cases {
        let root = tempfile::tempdir().unwrap();
        let source = source_reference_at(root.path(), "traffic/records/request-1.json", &bytes);
        let plan = build_plan_with_source(
            source,
            scope_reference(root.path(), &in_scope_decision()),
            rules_reference(root.path(), &valid_rules(now)),
        );
        let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
        let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();
        assert!(matches!(outcome, PolicyGateOutcome::Blocked(_)), "{case}");
    }
}

#[test]
fn missing_hash_mismatched_and_non_regular_source_evidence_yield_no_permit() {
    let now = OffsetDateTime::now_utc();
    for source in [
        EvidenceReference::new(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/missing.json",
            "a".repeat(64),
        )
        .unwrap(),
        EvidenceReference::new(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/request.json",
            "b".repeat(64),
        )
        .unwrap(),
        EvidenceReference::new(
            "source",
            EvidenceKind::RequestResponse,
            "traffic/not-a-file",
            hex::encode(Sha256::digest([])),
        )
        .unwrap(),
    ] {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("traffic/not-a-file")).unwrap();
        fs::write(root.path().join("traffic/request.json"), b"different bytes").unwrap();
        let plan = build_plan_with_source(
            source,
            scope_reference(root.path(), &in_scope_decision()),
            rules_reference(root.path(), &valid_rules(now)),
        );
        let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

        assert!(matches!(
            SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
            PolicyGateOutcome::Blocked(_)
        ));
        assert_eq!(audit_line_count(root.path()), 1);
    }
}

#[cfg(unix)]
#[test]
fn source_evidence_external_symlink_escape_yields_no_permit() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let evidence = CapturedRequestEvidence::new(
        "0123456789abcdef0123456789abcdef",
        "request-1",
        HttpMethod::Get,
        TARGET_URL,
    )
    .unwrap();
    let bytes = serde_json::to_vec(&evidence).unwrap();
    fs::write(outside.path().join("request.json"), &bytes).unwrap();
    fs::create_dir_all(root.path().join("traffic")).unwrap();
    symlink(
        outside.path().join("request.json"),
        root.path().join("traffic/source.json"),
    )
    .unwrap();
    let source = EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/source.json",
        hex::encode(Sha256::digest(bytes)),
    )
    .unwrap();
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
    assert_eq!(audit_line_count(root.path()), 1);
}

#[cfg(unix)]
#[test]
fn source_evidence_in_root_final_symlink_yields_no_permit() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
    fs::create_dir_all(root.path().join("traffic")).unwrap();
    fs::write(root.path().join("traffic/actual.json"), &bytes).unwrap();
    symlink("actual.json", root.path().join("traffic/source.json")).unwrap();
    let source = EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/source.json",
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap();
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
    assert_eq!(audit_line_count(root.path()), 1);
}

#[test]
fn model_and_audit_serialization_hide_source_path_identifiers() {
    const SECRET_PATH: &str = "traffic/tenant-42/session-secret-456/request.json";
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let evidence = CapturedRequestEvidence::new(
        "0123456789abcdef0123456789abcdef",
        "request-1",
        HttpMethod::Get,
        TARGET_URL,
    )
    .unwrap();
    let source = source_reference_at(
        root.path(),
        SECRET_PATH,
        &serde_json::to_vec(&evidence).unwrap(),
    );
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();
    assert!(matches!(outcome, PolicyGateOutcome::Allowed(_)));
    let decision = fs::read_to_string(
        root.path()
            .join(format!("policy/decisions/{}.json", plan.plan_hash())),
    )
    .unwrap();
    let audit = fs::read_to_string(root.path().join("audit/events.jsonl")).unwrap();
    for serialized in [&decision, &audit] {
        assert!(!serialized.contains(SECRET_PATH));
        assert!(!serialized.contains("tenant-42"));
        assert!(!serialized.contains("session-secret-456"));
    }
}

#[test]
fn scope_policy_matches_normalized_origin_and_path_while_permits_bind_full_query() {
    let now = OffsetDateTime::now_utc();
    let first_root = tempfile::tempdir().unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let build_for_query = |root: &Path, admin: bool| {
        let observed_url = format!("{TARGET_URL}&admin={admin}");
        let observation = ObservedHttpRequest::new(
            "request-1",
            HttpMethod::Get,
            &observed_url,
            source_reference_for_url(root, &observed_url),
        )
        .unwrap();
        let candidate = SsrfCandidateGenerator.generate(&observation).remove(0);
        SsrfProbePlanBuilder::new(CampaignCallbackOrigin::new("http://127.0.0.1:43123").unwrap())
            .build(
                &observation,
                &candidate,
                ScopeDisposition::InScope,
                scope_reference(root, &in_scope_decision()),
                rules_reference(root, &valid_rules(now)),
                CallbackLease::new(CallbackToken::parse("1".repeat(32)).unwrap(), 60_000).unwrap(),
            )
            .unwrap()
    };
    let first = build_for_query(first_root.path(), false);
    let second = build_for_query(second_root.path(), true);

    assert_ne!(first.plan_hash(), second.plan_hash());
    for (root, plan) in [(&first_root, &first), (&second_root, &second)] {
        let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);
        let outcome = SsrfPolicyGate.evaluate(plan, &context).unwrap();
        assert!(matches!(outcome, PolicyGateOutcome::Allowed(_)));
    }
}

#[test]
fn ambiguous_and_out_of_scope_decisions_yield_no_permit() {
    for verdict in [ScopeVerdict::Ambiguous, ScopeVerdict::OutOfScope] {
        let root = tempfile::tempdir().unwrap();
        let now = OffsetDateTime::now_utc();
        let plan = build_plan(
            root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
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
        root.path(),
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(root.path(), ApprovalState::NotRequired, now);

    assert!(SsrfPolicyGate.evaluate(&plan, &context).is_err());
}
