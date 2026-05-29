// Author: Jeff
// Date: 2026-05-29
// Description: Replay plan builder for inert autonomous-hunting candidates
// Notes: Plans are immutable JSON metadata only and do not execute requests

use std::path::{Component, PathBuf};

use request_corpus::{CandidateStateChange, CorpusCandidate};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PlanBuilder;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPlanRequest {
    pub candidate: CorpusCandidate,
    pub scope_decision: ScopeDecision,
    pub sessions: Vec<String>,
    pub substitutions: Vec<ReplaySubstitution>,
    pub expected_secure_result: String,
    pub stop_conditions: Vec<String>,
    pub evidence_output_dir: String,
    pub approval_grant_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayPlan {
    pub plan_hash: String,
    pub candidate: CorpusCandidate,
    pub scope_decision: ScopeDecision,
    pub sessions: Vec<String>,
    pub substitutions: Vec<ReplaySubstitution>,
    pub expected_secure_result: String,
    pub stop_conditions: Vec<String>,
    pub evidence_output_dir: String,
    pub executable: bool,
    pub approval_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDecision {
    InScope,
    Ambiguous,
    OutOfScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplaySubstitution {
    pub name: String,
    pub from_session: String,
    pub to_session: String,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayPlanError {
    #[error("out-of-scope candidates cannot produce replay plans")]
    OutOfScope,
    #[error("approval grant hash does not match replay plan hash")]
    ApprovalHashMismatch,
    #[error("evidence output dir must be a safe relative path")]
    UnsafeEvidenceOutputDir,
}

#[derive(Debug, Serialize)]
struct ReplayPlanHashMaterial<'a> {
    candidate_id: &'a str,
    candidate_kind: &'a request_corpus::CandidateKind,
    scope_decision: &'a ScopeDecision,
    sessions: &'a [String],
    substitutions: &'a [ReplaySubstitution],
    expected_secure_result: &'a str,
    stop_conditions: &'a [String],
    evidence_output_dir: &'a str,
}

impl ReplayPlanRequest {
    // Create a replay-plan request from an inert corpus candidate and scope decision
    pub fn new(candidate: CorpusCandidate, scope_decision: ScopeDecision) -> Self {
        Self {
            candidate,
            scope_decision,
            sessions: Vec::new(),
            substitutions: Vec::new(),
            expected_secure_result: String::new(),
            stop_conditions: Vec::new(),
            evidence_output_dir: String::new(),
            approval_grant_hash: None,
        }
    }

    // Attach session labels that the later replay runner must resolve safely
    pub fn with_sessions<I, S>(mut self, sessions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.sessions = sessions.into_iter().map(Into::into).collect();
        self
    }

    // Attach immutable substitution metadata without applying it
    pub fn with_substitutions<I>(mut self, substitutions: I) -> Self
    where
        I: IntoIterator<Item = ReplaySubstitution>,
    {
        self.substitutions = substitutions.into_iter().collect();
        self
    }

    // Attach the expected secure outcome for later verdict checks
    pub fn with_expected_secure_result(
        mut self,
        expected_secure_result: impl Into<String>,
    ) -> Self {
        self.expected_secure_result = expected_secure_result.into();
        self
    }

    // Attach stop conditions that bound later execution
    pub fn with_stop_conditions<I, S>(mut self, stop_conditions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.stop_conditions = stop_conditions.into_iter().map(Into::into).collect();
        self
    }

    // Attach a relative evidence output directory for later bundle writing
    pub fn with_evidence_output_dir(mut self, evidence_output_dir: impl Into<String>) -> Self {
        self.evidence_output_dir = evidence_output_dir.into();
        self
    }

    // Attach an approval grant hash that must match the derived plan hash
    pub fn with_approval_grant_hash(mut self, approval_grant_hash: impl Into<String>) -> Self {
        self.approval_grant_hash = Some(approval_grant_hash.into());
        self
    }
}

impl PlanBuilder {
    // Convert inert candidates into immutable replay-plan metadata
    pub fn build(&self, request: ReplayPlanRequest) -> Result<ReplayPlan, ReplayPlanError> {
        if request.scope_decision == ScopeDecision::OutOfScope {
            return Err(ReplayPlanError::OutOfScope);
        }
        if !is_safe_relative_path(&request.evidence_output_dir) {
            return Err(ReplayPlanError::UnsafeEvidenceOutputDir);
        }

        let approval_required = requires_approval(&request);
        let executable = !approval_required && request.scope_decision == ScopeDecision::InScope;
        let plan_hash = plan_hash(&request);
        if request
            .approval_grant_hash
            .as_deref()
            .is_some_and(|grant_hash| grant_hash != plan_hash)
        {
            return Err(ReplayPlanError::ApprovalHashMismatch);
        }

        Ok(ReplayPlan {
            plan_hash,
            candidate: request.candidate,
            scope_decision: request.scope_decision,
            sessions: request.sessions,
            substitutions: request.substitutions,
            expected_secure_result: request.expected_secure_result,
            stop_conditions: request.stop_conditions,
            evidence_output_dir: request.evidence_output_dir,
            executable,
            approval_required,
        })
    }
}

// Require approval for ambiguous scope or state-changing candidates
fn requires_approval(request: &ReplayPlanRequest) -> bool {
    request.scope_decision == ScopeDecision::Ambiguous
        || request.candidate.state_change == CandidateStateChange::StateChanging
        || !request.candidate.autonomous_safe
}

// Hash immutable plan metadata for approval grants and audit references
fn plan_hash(request: &ReplayPlanRequest) -> String {
    let material = ReplayPlanHashMaterial {
        candidate_id: &request.candidate.id,
        candidate_kind: &request.candidate.kind,
        scope_decision: &request.scope_decision,
        sessions: &request.sessions,
        substitutions: &request.substitutions,
        expected_secure_result: &request.expected_secure_result,
        stop_conditions: &request.stop_conditions,
        evidence_output_dir: &request.evidence_output_dir,
    };
    let bytes = serde_json::to_vec(&material).expect("hash material is serializable");
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

// Keep evidence output paths relative and inside the engagement artifact tree
fn is_safe_relative_path(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }
    let path = PathBuf::from(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

#[cfg(test)]
mod tests {
    use super::*;
    use request_corpus::{
        CandidateKind, CandidateSafety, CandidateSource, CandidateStateChange, CorpusCandidate,
    };

    #[test]
    fn out_of_scope_candidate_cannot_produce_executable_plan() {
        let request = ReplayPlanRequest::new(read_only_candidate(), ScopeDecision::OutOfScope)
            .with_sessions(["attacker-session", "victim-session"])
            .with_evidence_output_dir("evidence/replay/candidate-001");

        let error = PlanBuilder.build(request).unwrap_err();

        assert_eq!(error, ReplayPlanError::OutOfScope);
    }

    #[test]
    fn ambiguous_read_only_proof_requires_approval() {
        let request = ReplayPlanRequest::new(read_only_candidate(), ScopeDecision::Ambiguous)
            .with_sessions(["attacker-session", "victim-session"])
            .with_expected_secure_result("victim object remains inaccessible")
            .with_stop_conditions([
                "stop before state-changing method",
                "stop after first deny verdict",
            ])
            .with_evidence_output_dir("evidence/replay/candidate-001");

        let plan = PlanBuilder.build(request).unwrap();

        assert!(!plan.executable);
        assert!(plan.approval_required);
        assert_eq!(plan.scope_decision, ScopeDecision::Ambiguous);
        assert_eq!(
            plan.expected_secure_result,
            "victim object remains inaccessible"
        );
    }

    #[test]
    fn approval_grant_hash_must_match_plan_hash() {
        let request = ReplayPlanRequest::new(read_only_candidate(), ScopeDecision::InScope)
            .with_sessions(["attacker-session", "victim-session"])
            .with_expected_secure_result("victim object remains inaccessible")
            .with_stop_conditions(["stop before state-changing method"])
            .with_evidence_output_dir("evidence/replay/candidate-001")
            .with_approval_grant_hash("wrong-plan-hash");

        let error = PlanBuilder.build(request).unwrap_err();

        assert_eq!(error, ReplayPlanError::ApprovalHashMismatch);
    }

    fn read_only_candidate() -> CorpusCandidate {
        CorpusCandidate {
            id: "candidate-001".into(),
            kind: CandidateKind::CrossTenantRead,
            source: CandidateSource::Traffic,
            safety: CandidateSafety::ReadOnlyProof,
            state_change: CandidateStateChange::ReadOnly,
            autonomous_safe: true,
            record_ids: vec!["alice-read".into(), "bob-read".into()],
            observation_ids: Vec::new(),
            summary: "compare controlled tenant reads".into(),
        }
    }
}
