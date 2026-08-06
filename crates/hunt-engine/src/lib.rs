// Author: Jeff
// Date: 2026-07-31
// Description: Capability-neutral hunting engine contracts
// Notes: Verified results can only be constructed from locally validated evidence

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod assessment;
mod callback;
mod http_executor;
mod plan;
mod policy;
#[cfg(test)]
mod result_tests;
mod ssrf;

pub use assessment::{
    AssessmentClass, AssessmentReason, CallbackCorrelationClass, ObservationWindow, SsrfAssessment,
    SsrfAssessor, TransactionState,
};
pub use callback::{
    CallbackContractError, CallbackCorrelation, CallbackHeader, CallbackRecord,
    CallbackRecordOutcome, CallbackRecorder, CallbackRegistration, CallbackRequest, CallbackToken,
};
pub use engagement::{
    CaptureProvenanceError, CaptureTrustStore, CaptureVerifier, SignedCaptureClaims,
    SignedCapturedRequestEvidence,
};
pub use http_executor::{
    ExecutorError, ExecutorOutcome, HttpTransactionRecord, SsrfHttpExecutor, TransactionHeader,
};
pub use plan::{
    ActionBudget, ActionDescriptor, ActionPlan, ActionPlanBuilder, ActionPlanRequest, HuntRisk,
    Hypothesis, Observation, PlanContractError, RedirectPolicy, ScopeDisposition, StopCondition,
};
pub use policy::{
    ExecutionPermit, PolicyDecisionRecord, PolicyGateError, PolicyGateOutcome, SsrfPolicyContext,
    SsrfPolicyGate,
};
pub use ssrf::{
    CallbackLease, CampaignCallbackOrigin, HttpMethod, ObservedHttpRequest, SsrfCandidate,
    SsrfCandidateGenerator, SsrfContractError, SsrfInputLocation, SsrfProbePlan,
    SsrfProbePlanBuilder, SsrfProbePlanView,
};

// Describe one deterministic evidence class required by a result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    PolicyDecision,
    CallbackCorrelation,
    RequestResponse,
    SemanticVerdict,
}

// Name one required evidence item without carrying target-controlled content
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceRequirement {
    id: String,
    kind: EvidenceKind,
}

impl EvidenceRequirement {
    // Create one requirement with a stable local identifier
    pub fn new(id: impl Into<String>, kind: EvidenceKind) -> Self {
        Self {
            id: id.into(),
            kind,
        }
    }

    // Return the stable requirement identifier
    pub fn id(&self) -> &str {
        &self.id
    }

    // Return the deterministic evidence class
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }
}

// Hold the complete deterministic proof required for result promotion
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceContract {
    requirements: Vec<EvidenceRequirement>,
}

impl EvidenceContract {
    // Create a contract with unique validated requirement identifiers
    pub fn new<I>(requirements: I) -> Result<Self, ResultContractError>
    where
        I: IntoIterator<Item = EvidenceRequirement>,
    {
        let requirements = requirements.into_iter().collect::<Vec<_>>();
        if requirements.is_empty() {
            return Err(ResultContractError::EmptyContract);
        }

        let mut seen = BTreeSet::new();
        for requirement in &requirements {
            if !is_safe_identifier(&requirement.id) {
                return Err(ResultContractError::InvalidRequirementId);
            }
            if !seen.insert(requirement.id.clone()) {
                return Err(ResultContractError::DuplicateRequirement {
                    requirement_id: requirement.id.clone(),
                });
            }
        }

        Ok(Self { requirements })
    }

    // Return the immutable requirements used for deterministic assessment
    pub fn requirements(&self) -> &[EvidenceRequirement] {
        &self.requirements
    }

    // Validate local artifacts before creating unforgeable evidence satisfaction
    pub(crate) fn validate_local(
        &self,
        engagement_root: &Path,
        references: Vec<EvidenceReference>,
    ) -> Result<EvidenceSatisfaction, ResultContractError> {
        let root = engagement_root
            .canonicalize()
            .map_err(|_| ResultContractError::ArtifactUnavailable)?;
        let required = self
            .requirements
            .iter()
            .map(|requirement| (requirement.id.as_str(), requirement.kind))
            .collect::<BTreeMap<_, _>>();
        let mut supplied = BTreeSet::new();

        for reference in &references {
            let Some(required_kind) = required.get(reference.requirement_id.as_str()) else {
                return Err(ResultContractError::UnexpectedEvidence {
                    requirement_id: reference.requirement_id.clone(),
                });
            };
            if *required_kind != reference.kind {
                return Err(ResultContractError::EvidenceKindMismatch {
                    requirement_id: reference.requirement_id.clone(),
                });
            }
            if !supplied.insert(reference.requirement_id.as_str()) {
                return Err(ResultContractError::DuplicateEvidence {
                    requirement_id: reference.requirement_id.clone(),
                });
            }

            validate_local_artifact(&root, reference)?;
        }

        for requirement in &self.requirements {
            if !supplied.contains(requirement.id.as_str()) {
                return Err(ResultContractError::MissingEvidence {
                    requirement_id: requirement.id.clone(),
                });
            }
        }

        Ok(EvidenceSatisfaction { references })
    }
}

// Carry evidence that passed the engine's local artifact validator
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSatisfaction {
    references: Vec<EvidenceReference>,
}

impl EvidenceSatisfaction {
    // Return validated evidence references for result construction and serialization
    pub fn references(&self) -> &[EvidenceReference] {
        &self.references
    }
}

// Refer to immutable local proof without embedding raw artifact content
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceReference {
    requirement_id: String,
    kind: EvidenceKind,
    artifact_path: String,
    sha256: String,
}

impl EvidenceReference {
    // Create a typed relative artifact reference and claimed SHA-256 digest
    pub fn new(
        requirement_id: impl Into<String>,
        kind: EvidenceKind,
        artifact_path: impl Into<String>,
        sha256: impl Into<String>,
    ) -> Result<Self, ResultContractError> {
        let requirement_id = requirement_id.into();
        let artifact_path = artifact_path.into();
        let sha256 = sha256.into();

        if !is_safe_identifier(&requirement_id) {
            return Err(ResultContractError::InvalidRequirementId);
        }
        if !is_safe_relative_path(&artifact_path) {
            return Err(ResultContractError::UnsafeArtifactPath);
        }
        if !is_sha256(&sha256) {
            return Err(ResultContractError::InvalidSha256);
        }

        Ok(Self {
            requirement_id,
            kind,
            artifact_path,
            sha256,
        })
    }

    // Return the requirement satisfied by this artifact
    pub fn requirement_id(&self) -> &str {
        &self.requirement_id
    }

    // Return the typed evidence class claimed by this artifact
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    // Return the engagement-relative artifact path
    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }

    // Return the immutable artifact digest
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

// Keep verified findings distinct from unresolved and non-finding outcomes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntResultClass {
    VerifiedFinding,
    HumanVerificationCandidate,
    NegativeTest,
    InvalidTest,
}

// Represent a classified hunt result using evidence references only
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HuntResult {
    candidate_id: String,
    classification: HuntResultClass,
    evidence: Vec<EvidenceReference>,
}

impl HuntResult {
    // Create a verified result only from engine-validated local evidence
    #[allow(dead_code)] // Wired into result emission in vertical-slice phase 5
    pub(crate) fn verified(
        candidate_id: impl Into<String>,
        satisfaction: EvidenceSatisfaction,
    ) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            classification: HuntResultClass::VerifiedFinding,
            evidence: satisfaction.references,
        }
    }

    // Create an unresolved result that requires human verification
    pub fn human_verification_candidate(candidate_id: impl Into<String>) -> Self {
        Self::without_evidence(candidate_id, HuntResultClass::HumanVerificationCandidate)
    }

    // Create a completed test that produced no verified issue
    pub fn negative_test(candidate_id: impl Into<String>) -> Self {
        Self::without_evidence(candidate_id, HuntResultClass::NegativeTest)
    }

    // Create a test result that cannot support a security conclusion
    pub fn invalid_test(candidate_id: impl Into<String>) -> Self {
        Self::without_evidence(candidate_id, HuntResultClass::InvalidTest)
    }

    // Attach supporting references without promoting a non-verified result
    pub fn with_evidence<I>(mut self, evidence: I) -> Self
    where
        I: IntoIterator<Item = EvidenceReference>,
    {
        self.evidence = evidence.into_iter().collect();
        self
    }

    // Return the immutable candidate identifier
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    // Return the deterministic result classification
    pub fn classification(&self) -> HuntResultClass {
        self.classification
    }

    // Return local proof references without loading raw evidence
    pub fn evidence(&self) -> &[EvidenceReference] {
        &self.evidence
    }

    // Create a non-verified result without claiming evidence satisfaction
    fn without_evidence(candidate_id: impl Into<String>, classification: HuntResultClass) -> Self {
        Self {
            candidate_id: candidate_id.into(),
            classification,
            evidence: Vec::new(),
        }
    }
}

// Report deterministic contract failures without exposing artifact contents
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResultContractError {
    #[error("evidence contract must contain at least one requirement")]
    EmptyContract,
    #[error("evidence requirement id is invalid")]
    InvalidRequirementId,
    #[error("evidence contract contains duplicate requirement `{requirement_id}`")]
    DuplicateRequirement { requirement_id: String },
    #[error("required evidence `{requirement_id}` is missing")]
    MissingEvidence { requirement_id: String },
    #[error("evidence `{requirement_id}` was supplied more than once")]
    DuplicateEvidence { requirement_id: String },
    #[error("evidence `{requirement_id}` is not part of the contract")]
    UnexpectedEvidence { requirement_id: String },
    #[error("evidence `{requirement_id}` has the wrong deterministic kind")]
    EvidenceKindMismatch { requirement_id: String },
    #[error("artifact path must be a safe relative path")]
    UnsafeArtifactPath,
    #[error("artifact digest must be a lowercase SHA-256 value")]
    InvalidSha256,
    #[error("evidence artifact is unavailable")]
    ArtifactUnavailable,
    #[error("evidence artifact resolves outside the engagement root")]
    ArtifactOutsideRoot,
    #[error("evidence artifact is not a regular file")]
    ArtifactNotFile,
    #[error("evidence artifact hash does not match its reference")]
    ArtifactHashMismatch,
}

// Validate one evidence file against the canonical engagement root and claimed digest
#[allow(dead_code)] // Used by the phase-5 evidence evaluator
fn validate_local_artifact(
    canonical_root: &Path,
    reference: &EvidenceReference,
) -> Result<(), ResultContractError> {
    let artifact = canonical_root
        .join(&reference.artifact_path)
        .canonicalize()
        .map_err(|_| ResultContractError::ArtifactUnavailable)?;
    if !artifact.starts_with(canonical_root) {
        return Err(ResultContractError::ArtifactOutsideRoot);
    }
    let metadata = fs::metadata(&artifact).map_err(|_| ResultContractError::ArtifactUnavailable)?;
    if !metadata.is_file() {
        return Err(ResultContractError::ArtifactNotFile);
    }
    let content = fs::read(&artifact).map_err(|_| ResultContractError::ArtifactUnavailable)?;
    let actual_sha256 = hex::encode(Sha256::digest(content));
    if actual_sha256 != reference.sha256 {
        return Err(ResultContractError::ArtifactHashMismatch);
    }
    Ok(())
}

// Keep contract identifiers stable and safe for structured output
fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

// Keep evidence references inside the engagement artifact namespace
fn is_safe_relative_path(value: &str) -> bool {
    if value.trim().is_empty() {
        return false;
    }

    let path = Path::new(value);
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

// Validate canonical lowercase SHA-256 text without accepting ambiguous encodings
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
