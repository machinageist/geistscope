// Author: Jeff
// Date: 2026-07-31
// Description: Policy-gate authority, trusted-context validation, and audit behavior
// Notes: A permit requires current scope/rules policy plus a successful audit write

use std::fs;
use std::path::Path;

use action_policy::ApprovalState;
use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeVerdict};
use hunt_engine::{
    CallbackLease, CallbackToken, CampaignCallbackOrigin, CaptureTrustStore, EvidenceKind,
    EvidenceReference, HttpMethod, ObservedHttpRequest, PolicyGateOutcome, ScopeDisposition,
    SignedCaptureClaims, SsrfCandidateGenerator, SsrfPolicyContext, SsrfPolicyGate, SsrfProbePlan,
    SsrfProbePlanBuilder,
};
use proxy_core::CaptureSigner;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

const TARGET_URL: &str =
    "https://target.example.test/fetch?url=https%3A%2F%2Foriginal.example.test%2Fimage.png";
const NORMALIZED_TARGET: &str = "https://target.example.test/fetch";
const ENGAGEMENT_ID: &str = "engagement-1";
const CAPTURE_KEY_ID: &str = "capture-key-1";
const CAPTURE_SECRET_KEY: [u8; 32] = [7; 32];

// Recreate the trusted process-configured capture signer for deterministic fixtures
fn capture_signer() -> CaptureSigner {
    CaptureSigner::from_bytes(CAPTURE_KEY_ID, &CAPTURE_SECRET_KEY).unwrap()
}

// Supply only public verification authority to policy evaluation
fn capture_trust() -> CaptureTrustStore {
    CaptureTrustStore::new([capture_signer().verifier().unwrap()]).unwrap()
}

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
    assert_eq!(method, HttpMethod::Get);
    signed_request_bytes(
        &capture_signer(),
        ENGAGEMENT_ID,
        CAPTURE_KEY_ID,
        "0123456789abcdef0123456789abcdef",
        request_id,
        observed_url,
    )
}

// Sign exact claims with an explicit authority for adversarial and rotation fixtures
fn signed_request_bytes(
    signer: &CaptureSigner,
    engagement_id: &str,
    key_id: &str,
    capture_id: &str,
    request_id: &str,
    observed_url: &str,
) -> Vec<u8> {
    let claims =
        SignedCaptureClaims::new(engagement_id, key_id, capture_id, request_id, observed_url)
            .unwrap();
    let evidence = signer.sign_claims(claims).unwrap();
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

// Evaluate caller-supplied source bytes with process-supplied trust and engagement identity
fn evaluate_source_bytes(
    bytes: &[u8],
    trust: CaptureTrustStore,
    expected_engagement_id: &str,
) -> PolicyGateOutcome {
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let source = source_reference_at(root.path(), "traffic/records/request-1.json", bytes);
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        expected_engagement_id,
        trust,
        ApprovalState::NotRequired,
        now,
    );
    SsrfPolicyGate.evaluate(&plan, &context).unwrap()
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
        assert!(!serialized.contains(TARGET_URL));
        assert!(!serialized.contains("0123456789abcdef0123456789abcdef"));
        assert!(!serialized.contains(CAPTURE_KEY_ID));
        assert!(!serialized.contains(&hex::encode(CAPTURE_SECRET_KEY)));
        assert!(!serialized.contains("127.0.0.1:43123"));
    }
    assert!(decision.contains("source_evidence_pointer"));
}

#[test]
fn engagement_root_writer_without_trusted_signer_cannot_mint_authority() {
    let attacker = CaptureSigner::from_bytes("attacker-key", &[99; 32]).unwrap();
    let attacker_bytes = signed_request_bytes(
        &attacker,
        ENGAGEMENT_ID,
        "attacker-key",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "request-1",
        TARGET_URL,
    );

    let outcome = evaluate_source_bytes(&attacker_bytes, capture_trust(), ENGAGEMENT_ID);

    match outcome {
        PolicyGateOutcome::Blocked(record) => {
            assert_eq!(
                record.reason(),
                "source evidence capture authority is not trusted"
            );
            assert!(!record.reason().contains("attacker-key"));
        }
        other => panic!("attacker-minted capture granted authority: {other:?}"),
    }
}

#[test]
fn absent_revoked_and_rotated_capture_keys_have_explicit_fail_closed_behavior() {
    let primary_bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
    let absent = evaluate_source_bytes(
        &primary_bytes,
        CaptureTrustStore::new([]).unwrap(),
        ENGAGEMENT_ID,
    );
    assert!(matches!(absent, PolicyGateOutcome::Blocked(_)));

    let mut revoked = capture_trust();
    revoked.revoke(CAPTURE_KEY_ID).unwrap();
    let revoked_outcome = evaluate_source_bytes(&primary_bytes, revoked, ENGAGEMENT_ID);
    assert!(matches!(revoked_outcome, PolicyGateOutcome::Blocked(_)));

    let rotated_signer = CaptureSigner::from_bytes("capture-key-2", &[9; 32]).unwrap();
    let rotated_bytes = signed_request_bytes(
        &rotated_signer,
        ENGAGEMENT_ID,
        "capture-key-2",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "request-1",
        TARGET_URL,
    );
    let rotation_store = CaptureTrustStore::new([
        capture_signer().verifier().unwrap(),
        rotated_signer.verifier().unwrap(),
    ])
    .unwrap();
    assert!(matches!(
        evaluate_source_bytes(&rotated_bytes, rotation_store, ENGAGEMENT_ID),
        PolicyGateOutcome::Allowed(_)
    ));
}

#[test]
fn valid_signatures_fail_on_cross_engagement_replay_and_wrong_observation_tuple() {
    let signer = capture_signer();
    let cross_engagement = signed_request_bytes(
        &signer,
        "engagement-2",
        CAPTURE_KEY_ID,
        "cccccccccccccccccccccccccccccccc",
        "request-1",
        TARGET_URL,
    );
    let wrong_request = signed_request_bytes(
        &signer,
        ENGAGEMENT_ID,
        CAPTURE_KEY_ID,
        "dddddddddddddddddddddddddddddddd",
        "request-2",
        TARGET_URL,
    );
    let wrong_url = signed_request_bytes(
        &signer,
        ENGAGEMENT_ID,
        CAPTURE_KEY_ID,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "request-1",
        "https://target.example.test/fetch?url=https%3A%2F%2Fother.test%2F",
    );

    for bytes in [&cross_engagement, &wrong_request, &wrong_url] {
        assert!(matches!(
            evaluate_source_bytes(bytes, capture_trust(), ENGAGEMENT_ID),
            PolicyGateOutcome::Blocked(_)
        ));
    }
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
        let context = SsrfPolicyContext::new(
            root.path(),
            ENGAGEMENT_ID,
            capture_trust(),
            ApprovalState::NotRequired,
            now,
        );
        let outcome = SsrfPolicyGate.evaluate(&plan, &context).unwrap();
        assert!(matches!(outcome, PolicyGateOutcome::Blocked(_)), "{case}");
    }
}

#[test]
fn malformed_or_tampered_signed_capture_fields_fail_closed() {
    let now = OffsetDateTime::now_utc();
    let valid: serde_json::Value = serde_json::from_slice(&captured_request_bytes(
        "request-1",
        HttpMethod::Get,
        TARGET_URL,
    ))
    .unwrap();
    let mut cases = vec![("malformed_json", b"{not json".to_vec())];
    for (case, field, value) in [
        ("wrong_schema", "schema", serde_json::json!("wrong.schema")),
        ("wrong_version", "version", serde_json::json!(2)),
        ("wrong_signature", "signature", serde_json::json!("00")),
    ] {
        let mut payload = valid.clone();
        payload[field] = value;
        cases.push((case, serde_json::to_vec(&payload).unwrap()));
    }
    for (case, field, value) in [
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
            "canonical_url",
            serde_json::json!("https://target.example.test/other?url=http://a.test/"),
        ),
        (
            "cross_engagement",
            "engagement_id",
            serde_json::json!("engagement-2"),
        ),
    ] {
        let mut payload = valid.clone();
        payload["claims"][field] = value;
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
        let context = SsrfPolicyContext::new(
            root.path(),
            ENGAGEMENT_ID,
            capture_trust(),
            ApprovalState::NotRequired,
            now,
        );
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
        let context = SsrfPolicyContext::new(
            root.path(),
            ENGAGEMENT_ID,
            capture_trust(),
            ApprovalState::NotRequired,
            now,
        );

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
    let bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
    assert_eq!(audit_line_count(root.path()), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn source_evidence_in_root_intermediate_symlink_yields_no_permit() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
    fs::create_dir_all(root.path().join("actual")).unwrap();
    fs::write(root.path().join("actual/source.json"), &bytes).unwrap();
    fs::create_dir_all(root.path().join("traffic")).unwrap();
    symlink("../actual", root.path().join("traffic/records")).unwrap();
    let source = EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/records/source.json",
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap();
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
    assert_eq!(audit_line_count(root.path()), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn source_evidence_external_intermediate_symlink_yields_no_permit() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
    fs::write(outside.path().join("source.json"), &bytes).unwrap();
    fs::create_dir_all(root.path().join("traffic")).unwrap();
    symlink(outside.path(), root.path().join("traffic/records")).unwrap();
    let source = EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/records/source.json",
        hex::encode(Sha256::digest(&bytes)),
    )
    .unwrap();
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

    assert!(matches!(
        SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
        PolicyGateOutcome::Blocked(_)
    ));
    assert_eq!(audit_line_count(root.path()), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn source_evidence_parent_swap_race_yields_no_permit() {
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let valid_bytes = captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL);
    fs::create_dir(root.path().join("traffic")).unwrap();
    fs::write(
        root.path().join("traffic/source.json"),
        b"invalid inside bytes",
    )
    .unwrap();
    fs::write(outside.path().join("source.json"), &valid_bytes).unwrap();
    symlink(outside.path(), root.path().join("swap")).unwrap();
    let source = EvidenceReference::new(
        "source",
        EvidenceKind::RequestResponse,
        "traffic/source.json",
        hex::encode(Sha256::digest(&valid_bytes)),
    )
    .unwrap();
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let traffic = root.path().join("traffic");
    let swap = root.path().join("swap");
    let worker = std::thread::spawn(move || {
        while !worker_stop.load(Ordering::Relaxed) {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                &traffic,
                rustix::fs::CWD,
                &swap,
                rustix::fs::RenameFlags::EXCHANGE,
            )
            .unwrap();
        }
    });

    for _ in 0..200 {
        assert!(matches!(
            SsrfPolicyGate.evaluate(&plan, &context).unwrap(),
            PolicyGateOutcome::Blocked(_)
        ));
    }
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
}

#[test]
fn model_and_audit_serialization_hide_source_path_identifiers() {
    const SECRET_PATH: &str = "traffic/tenant-42/session-secret-456/request.json";
    let root = tempfile::tempdir().unwrap();
    let now = OffsetDateTime::now_utc();
    let source = source_reference_at(
        root.path(),
        SECRET_PATH,
        &captured_request_bytes("request-1", HttpMethod::Get, TARGET_URL),
    );
    let plan = build_plan_with_source(
        source,
        scope_reference(root.path(), &in_scope_decision()),
        rules_reference(root.path(), &valid_rules(now)),
    );
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
        let context = SsrfPolicyContext::new(
            root.path(),
            ENGAGEMENT_ID,
            capture_trust(),
            ApprovalState::NotRequired,
            now,
        );
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
        let context = SsrfPolicyContext::new(
            root.path(),
            ENGAGEMENT_ID,
            capture_trust(),
            ApprovalState::NotRequired,
            now,
        );

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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
        ENGAGEMENT_ID,
        capture_trust(),
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );
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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

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
    let context = SsrfPolicyContext::new(
        root.path(),
        ENGAGEMENT_ID,
        capture_trust(),
        ApprovalState::NotRequired,
        now,
    );

    assert!(SsrfPolicyGate.evaluate(&plan, &context).is_err());
}
