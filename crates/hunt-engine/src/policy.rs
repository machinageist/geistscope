// Author: Jeff
// Date: 2026-07-31
// Description: Deterministic policy gate binding SSRF plans to action-policy and audit
// Notes: The only path to an ExecutionPermit is current scope/rules policy plus an audit write

use std::io::Read;
use std::path::Path;

use action_policy::{
    ActionKind, ActionPolicy, ApprovalState, PolicyRequest, PolicyVerdict, RiskLevel,
    SessionRequirement,
};
use engagement::{
    ArtifactStore, AuditDecision, AuditEvent, AuditRisk, ProgramRulesSnapshot, ScopeDecision,
    append_audit_event,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{CapturedRequestEvidence, EvidenceKind, EvidenceReference, HuntRisk, SsrfProbePlan};

const AUDIT_TOOL: &str = "hunt-engine";
const SSRF_ACTION: &str = "ssrf.callback_probe";
const AUDIT_RELATIVE_PATH: &str = "audit/events.jsonl";

// Carry the trusted engagement context an SSRF plan is evaluated against
#[derive(Debug, Clone)]
pub struct SsrfPolicyContext<'a> {
    engagement_root: &'a Path,
    approval: ApprovalState,
    evaluated_at: OffsetDateTime,
}

impl<'a> SsrfPolicyContext<'a> {
    // Create one evaluation context bound to a canonical engagement root
    pub fn new(
        engagement_root: &'a Path,
        approval: ApprovalState,
        evaluated_at: OffsetDateTime,
    ) -> Self {
        Self {
            engagement_root,
            approval,
            evaluated_at,
        }
    }
}

// Convert immutable plan facts into a deterministic action-policy decision
#[derive(Debug, Default, Clone)]
pub struct SsrfPolicyGate;

// Report the deterministic gate outcome; only Allowed carries an execution permit
#[derive(Debug)]
pub enum PolicyGateOutcome {
    Allowed(ExecutionPermit),
    Blocked(PolicyDecisionRecord),
    RequiresApproval(PolicyDecisionRecord),
}

// Preserve the immutable policy decision written before any permit is granted
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDecisionRecord {
    plan_hash: String,
    action: String,
    risk: RiskLevel,
    verdict: PolicyVerdict,
    target: String,
    reason: String,
    source_evidence_pointer: String,
    scope_evidence_pointer: String,
    rules_evidence_pointer: String,
    approval_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    evaluated_at: OffsetDateTime,
}

impl PolicyDecisionRecord {
    // Return the immutable plan hash the decision was bound to
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the deterministic policy verdict
    pub fn verdict(&self) -> PolicyVerdict {
        self.verdict
    }

    // Return the deterministic decision reason
    pub fn reason(&self) -> &str {
        &self.reason
    }

    // Return the opaque captured-request evidence pointer
    pub fn source_evidence_pointer(&self) -> &str {
        &self.source_evidence_pointer
    }

    // Return the recorded approval identifier when one authorized the action
    pub fn approval_id(&self) -> Option<&str> {
        self.approval_id.as_deref()
    }
}

// Grant network execution for exactly one plan; not clonable and never deserializable
#[derive(Debug)]
pub struct ExecutionPermit {
    plan_hash: String,
    policy_decision_sha256: String,
    authorized_not_after: OffsetDateTime,
}

impl ExecutionPermit {
    // Return the plan hash this permit authorizes
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the immutable policy-decision artifact digest bound to this permit
    pub fn policy_decision_sha256(&self) -> &str {
        &self.policy_decision_sha256
    }

    // Return the moment after which this permit no longer authorizes execution
    pub fn authorized_not_after(&self) -> OffsetDateTime {
        self.authorized_not_after
    }
}

impl SsrfPolicyGate {
    // Evaluate one SSRF plan and persist the audited decision before returning a permit
    pub fn evaluate(
        &self,
        plan: &SsrfProbePlan,
        context: &SsrfPolicyContext,
    ) -> Result<PolicyGateOutcome, PolicyGateError> {
        let canonical_root = context
            .engagement_root
            .canonicalize()
            .map_err(|_| PolicyGateError::EngagementRootUnavailable)?;
        let store = ArtifactStore::new(&canonical_root)
            .map_err(|_| PolicyGateError::EngagementRootUnavailable)?;

        // Map plan risk explicitly; unmappable risk is a hard block, never coerced downward
        let risk = match map_risk(plan.action_plan().risk()) {
            Ok(risk) => risk,
            Err(_) => {
                return self.finalize(
                    &store,
                    &canonical_root,
                    plan,
                    context,
                    RiskLevel::HighActive,
                    PolicyVerdict::Blocked,
                    "risk classification is not permitted for autonomous SSRF probes",
                    None,
                );
            }
        };

        // Verify typed captured-request provenance before any policy path can grant authority
        let source = plan.source_reference();
        let source_result = if source.requirement_id() != "source"
            || source.kind() != EvidenceKind::RequestResponse
        {
            Err(SourceEvidenceError::WrongReferenceType)
        } else {
            read_validated(&store, source)
                .map_err(SourceEvidenceError::Artifact)
                .and_then(|bytes| {
                    serde_json::from_slice::<CapturedRequestEvidence>(&bytes)
                        .map_err(|_| SourceEvidenceError::Malformed)
                })
                .and_then(|evidence| {
                    evidence
                        .validate()
                        .map_err(|_| SourceEvidenceError::Malformed)?;
                    if plan.source_matches(&evidence) {
                        Ok(())
                    } else {
                        Err(SourceEvidenceError::RequestMismatch)
                    }
                })
        };
        if let Err(error) = source_result {
            let reason = match error {
                SourceEvidenceError::WrongReferenceType => {
                    "source evidence reference has the wrong requirement or kind"
                }
                SourceEvidenceError::Malformed => {
                    "source evidence artifact is not a valid captured request"
                }
                SourceEvidenceError::RequestMismatch => {
                    "source evidence request does not match the plan observation"
                }
                SourceEvidenceError::Artifact(ArtifactReadError::Unavailable) => {
                    "source evidence artifact is unavailable"
                }
                SourceEvidenceError::Artifact(ArtifactReadError::NotRegularFile) => {
                    "source evidence artifact is not a regular file"
                }
                SourceEvidenceError::Artifact(ArtifactReadError::HashMismatch) => {
                    "source evidence artifact hash does not match the plan"
                }
            };
            return self.finalize(
                &store,
                &canonical_root,
                plan,
                context,
                risk,
                PolicyVerdict::Blocked,
                reason,
                None,
            );
        }

        // Obtain scope from the plan-bound artifact rather than trusting a caller string
        let scope_decision = match load_scope(&store, plan.scope_reference()) {
            Ok(scope_decision) => scope_decision,
            Err(reason) => {
                return self.finalize(
                    &store,
                    &canonical_root,
                    plan,
                    context,
                    risk,
                    PolicyVerdict::Blocked,
                    reason,
                    None,
                );
            }
        };
        let program_rules = match load_rules(&store, plan.rules_reference()) {
            Ok(program_rules) => program_rules,
            Err(reason) => {
                return self.finalize(
                    &store,
                    &canonical_root,
                    plan,
                    context,
                    risk,
                    PolicyVerdict::Blocked,
                    reason,
                    None,
                );
            }
        };
        if !scope_target_matches(&scope_decision, plan) {
            return self.finalize(
                &store,
                &canonical_root,
                plan,
                context,
                risk,
                PolicyVerdict::Blocked,
                "scope decision target does not match the plan target",
                None,
            );
        }

        let request = PolicyRequest {
            action: ActionKind::HttpRequest,
            risk,
            scope: scope_decision,
            session: SessionRequirement::AnonymousAllowed,
            approval: context.approval.clone(),
            program_rules: Some(program_rules),
            evaluated_at: context.evaluated_at,
        };
        let decision = ActionPolicy.evaluate(&request);
        let approval_id = match &context.approval {
            ApprovalState::Granted { approval_id } => Some(approval_id.clone()),
            _ => None,
        };

        self.finalize(
            &store,
            &canonical_root,
            plan,
            context,
            risk,
            decision.verdict,
            &decision.reason,
            approval_id,
        )
    }

    // Persist the decision artifact and audit event before producing any permit
    #[allow(clippy::too_many_arguments)]
    fn finalize(
        &self,
        store: &ArtifactStore,
        canonical_root: &Path,
        plan: &SsrfProbePlan,
        context: &SsrfPolicyContext,
        risk: RiskLevel,
        verdict: PolicyVerdict,
        reason: &str,
        approval_id: Option<String>,
    ) -> Result<PolicyGateOutcome, PolicyGateError> {
        let target = format!(
            "{}{}",
            plan.view().target_origin(),
            plan.view().target_path()
        );
        let decision_relative = format!("policy/decisions/{}.json", plan.plan_hash());
        let record = PolicyDecisionRecord {
            plan_hash: plan.plan_hash().to_string(),
            action: SSRF_ACTION.to_string(),
            risk,
            verdict,
            target: target.clone(),
            reason: reason.to_string(),
            source_evidence_pointer: plan.view().source_evidence_pointer().to_string(),
            scope_evidence_pointer: plan.view().scope_evidence_pointer().to_string(),
            rules_evidence_pointer: plan.view().rules_evidence_pointer().to_string(),
            approval_id,
            evaluated_at: context.evaluated_at,
        };

        // Reject an audit path that resolves outside the canonical engagement root
        store
            .resolve_relative(AUDIT_RELATIVE_PATH)
            .map_err(|_| PolicyGateError::AuditPathUnsafe)?;
        let write = store
            .atomic_json_write(&decision_relative, &record)
            .map_err(|_| PolicyGateError::ArtifactWriteFailed)?;
        let event = AuditEvent {
            timestamp: context.evaluated_at,
            tool: AUDIT_TOOL.to_string(),
            action: SSRF_ACTION.to_string(),
            risk: audit_risk(risk),
            decision: audit_decision(verdict),
            target,
            reason: reason.to_string(),
            evidence_paths: vec![decision_relative],
        };
        append_audit_event(canonical_root, &event)
            .map_err(|_| PolicyGateError::AuditWriteFailed)?;

        let authorized_not_after = context.evaluated_at
            + time::Duration::milliseconds(plan.view().observation_window_ms() as i64);
        Ok(match verdict {
            PolicyVerdict::Allowed => PolicyGateOutcome::Allowed(ExecutionPermit {
                plan_hash: plan.plan_hash().to_string(),
                policy_decision_sha256: write.sha256,
                authorized_not_after,
            }),
            PolicyVerdict::Blocked => PolicyGateOutcome::Blocked(record),
            PolicyVerdict::RequiresApproval => PolicyGateOutcome::RequiresApproval(record),
        })
    }
}

// Report deterministic gate infrastructure failures that never grant a permit
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PolicyGateError {
    #[error("engagement root is unavailable or not canonical")]
    EngagementRootUnavailable,
    #[error("policy decision artifact could not be written")]
    ArtifactWriteFailed,
    #[error("audit path resolves outside the engagement root")]
    AuditPathUnsafe,
    #[error("audit event could not be appended")]
    AuditWriteFailed,
}

// Map engine risk to policy risk with no silent downgrade
fn map_risk(risk: HuntRisk) -> Result<RiskLevel, UnmappableRisk> {
    match risk {
        HuntRisk::ReadOnly => Ok(RiskLevel::ReadOnly),
        HuntRisk::LowActive => Ok(RiskLevel::LowActive),
        HuntRisk::HighActive => Ok(RiskLevel::HighActive),
        HuntRisk::Observe => Err(UnmappableRisk),
    }
}

// Signal that a risk class has no active-policy equivalent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnmappableRisk;

// Map policy risk into the audit risk vocabulary
fn audit_risk(risk: RiskLevel) -> AuditRisk {
    match risk {
        RiskLevel::ReadOnly => AuditRisk::ReadOnly,
        RiskLevel::LowActive => AuditRisk::LowActive,
        RiskLevel::HighActive => AuditRisk::HighActive,
    }
}

// Map policy verdict into the audit decision vocabulary
fn audit_decision(verdict: PolicyVerdict) -> AuditDecision {
    match verdict {
        PolicyVerdict::Allowed => AuditDecision::Allowed,
        PolicyVerdict::Blocked => AuditDecision::Blocked,
        PolicyVerdict::RequiresApproval => AuditDecision::RequiresApproval,
    }
}

// Load a scope decision from its plan-bound, hash-verified artifact
fn load_scope(
    store: &ArtifactStore,
    reference: &EvidenceReference,
) -> Result<ScopeDecision, &'static str> {
    let bytes = read_validated(store, reference).map_err(|error| match error {
        ArtifactReadError::Unavailable | ArtifactReadError::NotRegularFile => {
            "scope evidence artifact is unavailable"
        }
        ArtifactReadError::HashMismatch => "scope evidence artifact hash does not match the plan",
    })?;
    serde_json::from_slice::<ScopeDecision>(&bytes)
        .map_err(|_| "scope evidence could not be parsed")
}

// Load a program-rules snapshot from its plan-bound, hash-verified artifact
fn load_rules(
    store: &ArtifactStore,
    reference: &EvidenceReference,
) -> Result<ProgramRulesSnapshot, &'static str> {
    let bytes = read_validated(store, reference).map_err(|error| match error {
        ArtifactReadError::Unavailable | ArtifactReadError::NotRegularFile => {
            "rules evidence artifact is unavailable"
        }
        ArtifactReadError::HashMismatch => "rules evidence artifact hash does not match the plan",
    })?;
    serde_json::from_slice::<ProgramRulesSnapshot>(&bytes)
        .map_err(|_| "rules evidence could not be parsed")
}

// Read and hash-verify one plan-bound evidence artifact under the engagement root
fn read_validated(
    store: &ArtifactStore,
    reference: &EvidenceReference,
) -> Result<Vec<u8>, ArtifactReadError> {
    let mut file = store
        .open_relative_read(reference.artifact_path())
        .map_err(|_| ArtifactReadError::Unavailable)?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| ArtifactReadError::Unavailable)?;
    if !opened_metadata.is_file() {
        return Err(ArtifactReadError::NotRegularFile);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| ArtifactReadError::Unavailable)?;
    if opened_metadata.len() != bytes.len() as u64 {
        return Err(ArtifactReadError::Unavailable);
    }
    if hex::encode(Sha256::digest(&bytes)) != reference.sha256() {
        return Err(ArtifactReadError::HashMismatch);
    }
    Ok(bytes)
}

enum SourceEvidenceError {
    WrongReferenceType,
    Malformed,
    RequestMismatch,
    Artifact(ArtifactReadError),
}

// Distinguish a missing artifact from one whose content drifted from the plan
enum ArtifactReadError {
    Unavailable,
    NotRegularFile,
    HashMismatch,
}

// Match query-insensitive policy scope to normalized origin+path; the permit hash binds the query
fn scope_target_matches(decision: &ScopeDecision, plan: &SsrfProbePlan) -> bool {
    match &decision.normalized_url {
        Some(normalized_url) => normalized_url == plan.executable().scope_target(),
        None => match (&decision.normalized_host, plan_host(plan)) {
            (Some(scope_host), Some(plan_host)) => scope_host == &plan_host,
            _ => false,
        },
    }
}

// Return the plan target host for host-scoped decisions
fn plan_host(plan: &SsrfProbePlan) -> Option<String> {
    url::Url::parse(plan.view().target_origin())
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::{UnmappableRisk, map_risk};
    use crate::HuntRisk;
    use action_policy::RiskLevel;

    #[test]
    fn risk_mapping_is_explicit_for_every_class() {
        assert_eq!(map_risk(HuntRisk::ReadOnly), Ok(RiskLevel::ReadOnly));
        assert_eq!(map_risk(HuntRisk::LowActive), Ok(RiskLevel::LowActive));
        assert_eq!(map_risk(HuntRisk::HighActive), Ok(RiskLevel::HighActive));
        assert_eq!(map_risk(HuntRisk::Observe), Err(UnmappableRisk));
    }
}
