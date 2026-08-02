// Author: Jeff
// Date: 2026-07-31
// Description: Capability-neutral observations, hypotheses, and immutable action plans
// Notes: Approval hashes bind executable semantics and exclude presentation prose

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{EvidenceContract, EvidenceReference};

// Record one local fact without triggering active behavior
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Observation {
    id: String,
    source: EvidenceReference,
}

impl Observation {
    // Create an inert observation backed by an immutable local artifact
    pub fn new(
        id: impl Into<String>,
        source: EvidenceReference,
    ) -> Result<Self, PlanContractError> {
        let id = id.into();
        validate_identifier(&id)?;
        Ok(Self { id, source })
    }

    // Return the stable observation identifier
    pub fn id(&self) -> &str {
        &self.id
    }

    // Return the local source reference without loading raw content
    pub fn source(&self) -> &EvidenceReference {
        &self.source
    }
}

// Link a capability hypothesis to the observations that support it
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hypothesis {
    id: String,
    capability_id: String,
    observation_ids: Vec<String>,
}

impl Hypothesis {
    // Create an inert hypothesis with at least one validated observation reference
    pub fn new<I, S>(
        id: impl Into<String>,
        capability_id: impl Into<String>,
        observation_ids: I,
    ) -> Result<Self, PlanContractError>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let id = id.into();
        let capability_id = capability_id.into();
        let observation_ids = observation_ids
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>();
        validate_identifier(&id)?;
        validate_identifier(&capability_id)?;
        if observation_ids.is_empty() {
            return Err(PlanContractError::MissingObservations);
        }
        for observation_id in &observation_ids {
            validate_identifier(observation_id)?;
        }

        Ok(Self {
            id,
            capability_id,
            observation_ids,
        })
    }

    // Return the stable hypothesis identifier
    pub fn id(&self) -> &str {
        &self.id
    }

    // Return the capability that can test this hypothesis
    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    // Return the observations supporting this hypothesis
    pub fn observation_ids(&self) -> &[String] {
        &self.observation_ids
    }
}

// Classify effective scope without coupling the engine envelope to one importer
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeDisposition {
    InScope,
    Ambiguous,
    OutOfScope,
}

// Classify action risk for policy and approval clients
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HuntRisk {
    Observe,
    ReadOnly,
    LowActive,
    HighActive,
}

// Make redirect behavior explicit in immutable action semantics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectPolicy {
    Deny,
    AllowBounded { max_redirects: u8 },
}

// Bound active work by requests, elapsed time, bytes, and concurrency
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ActionBudget {
    max_requests: u32,
    max_duration_ms: u64,
    max_bytes: u64,
    concurrency: u16,
}

impl ActionBudget {
    // Create a non-zero coherent action budget
    pub fn new(
        max_requests: u32,
        max_duration_ms: u64,
        max_bytes: u64,
        concurrency: u16,
    ) -> Result<Self, PlanContractError> {
        if max_requests == 0
            || max_duration_ms == 0
            || max_bytes == 0
            || concurrency == 0
            || u32::from(concurrency) > max_requests
        {
            return Err(PlanContractError::InvalidBudget);
        }

        Ok(Self {
            max_requests,
            max_duration_ms,
            max_bytes,
            concurrency,
        })
    }

    // Return the maximum network requests
    pub fn max_requests(&self) -> u32 {
        self.max_requests
    }

    // Return the maximum elapsed milliseconds
    pub fn max_duration_ms(&self) -> u64 {
        self.max_duration_ms
    }

    // Return the maximum transferred bytes
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    // Return the maximum concurrent actions
    pub fn concurrency(&self) -> u16 {
        self.concurrency
    }
}

// Name safety conditions that stop an action or campaign branch
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopCondition {
    RateLimited,
    ServerError,
    WafDetected,
    ScopeDrift,
    AuthorizationExpired,
    BudgetExhausted,
    EvidenceFailure,
}

// Bind one capability action to validated executable input by digest
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionDescriptor {
    capability_id: String,
    operation: String,
    target: String,
    executable_input_sha256: String,
}

impl ActionDescriptor {
    // Create a descriptor without embedding capability-specific secrets or payloads
    pub fn new(
        capability_id: impl Into<String>,
        operation: impl Into<String>,
        target: impl Into<String>,
        executable_input_sha256: impl Into<String>,
    ) -> Result<Self, PlanContractError> {
        let capability_id = capability_id.into();
        let operation = operation.into();
        let target = target.into();
        let executable_input_sha256 = executable_input_sha256.into();
        validate_identifier(&capability_id)?;
        validate_identifier(&operation)?;
        if target.is_empty() || target.len() > 2048 || target.chars().any(char::is_control) {
            return Err(PlanContractError::InvalidTarget);
        }
        if !is_sha256(&executable_input_sha256) {
            return Err(PlanContractError::InvalidExecutableInputHash);
        }

        Ok(Self {
            capability_id,
            operation,
            target,
            executable_input_sha256,
        })
    }
}

// Collect all executable and presentation fields before immutable plan construction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionPlanRequest {
    hypothesis_id: String,
    action: ActionDescriptor,
    scope: ScopeDisposition,
    risk: HuntRisk,
    budget: ActionBudget,
    redirect_policy: RedirectPolicy,
    stop_conditions: Vec<StopCondition>,
    evidence_contract: EvidenceContract,
    rationale: String,
}

impl ActionPlanRequest {
    // Create a plan request with fail-closed redirect behavior
    pub fn new(
        hypothesis_id: impl Into<String>,
        action: ActionDescriptor,
        scope: ScopeDisposition,
        risk: HuntRisk,
        budget: ActionBudget,
        evidence_contract: EvidenceContract,
    ) -> Self {
        Self {
            hypothesis_id: hypothesis_id.into(),
            action,
            scope,
            risk,
            budget,
            redirect_policy: RedirectPolicy::Deny,
            stop_conditions: Vec::new(),
            evidence_contract,
            rationale: String::new(),
        }
    }

    // Replace the action budget before immutable plan construction
    pub fn with_budget(mut self, budget: ActionBudget) -> Self {
        self.budget = budget;
        self
    }

    // Attach deterministic safety stop conditions
    pub fn with_stop_conditions<I>(mut self, conditions: I) -> Self
    where
        I: IntoIterator<Item = StopCondition>,
    {
        self.stop_conditions = conditions.into_iter().collect();
        self
    }

    // Attach presentation-only reasoning excluded from the approval hash
    pub fn with_rationale(mut self, rationale: impl Into<String>) -> Self {
        self.rationale = rationale.into();
        self
    }
}

// Build immutable action plans after validating the capability-neutral envelope
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ActionPlanBuilder;

// Represent one immutable policy-ready action plan
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionPlan {
    plan_hash: String,
    hypothesis_id: String,
    action: ActionDescriptor,
    scope: ScopeDisposition,
    risk: HuntRisk,
    budget: ActionBudget,
    redirect_policy: RedirectPolicy,
    stop_conditions: Vec<StopCondition>,
    evidence_contract: EvidenceContract,
    rationale: String,
}

impl ActionPlanBuilder {
    // Validate and hash all executable plan semantics
    pub fn build(&self, mut request: ActionPlanRequest) -> Result<ActionPlan, PlanContractError> {
        validate_identifier(&request.hypothesis_id)?;
        if request.stop_conditions.is_empty() {
            return Err(PlanContractError::MissingStopConditions);
        }
        if request.rationale.len() > 4096 || request.rationale.chars().any(char::is_control) {
            return Err(PlanContractError::InvalidRationale);
        }

        // Canonicalize stop conditions so semantically identical sets hash identically
        request.stop_conditions = request
            .stop_conditions
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        let plan_hash = hash_plan(&request)?;
        Ok(ActionPlan {
            plan_hash,
            hypothesis_id: request.hypothesis_id,
            action: request.action,
            scope: request.scope,
            risk: request.risk,
            budget: request.budget,
            redirect_policy: request.redirect_policy,
            stop_conditions: request.stop_conditions,
            evidence_contract: request.evidence_contract,
            rationale: request.rationale,
        })
    }
}

impl ActionPlan {
    // Return the immutable approval and audit hash
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the effective scope disposition
    pub fn scope(&self) -> ScopeDisposition {
        self.scope
    }

    // Return the action risk classification
    pub fn risk(&self) -> HuntRisk {
        self.risk
    }

    // Return the action budget
    pub fn budget(&self) -> ActionBudget {
        self.budget
    }

    // Return the redirect policy
    pub fn redirect_policy(&self) -> RedirectPolicy {
        self.redirect_policy
    }

    // Return deterministic stop conditions
    pub fn stop_conditions(&self) -> &[StopCondition] {
        &self.stop_conditions
    }

    // Return the deterministic evidence contract
    pub fn evidence_contract(&self) -> &EvidenceContract {
        &self.evidence_contract
    }
}

// Serialize only execution-relevant fields for immutable plan hashing
#[derive(Serialize)]
struct PlanHashMaterial<'a> {
    hypothesis_id: &'a str,
    action: &'a ActionDescriptor,
    scope: ScopeDisposition,
    risk: HuntRisk,
    budget: ActionBudget,
    redirect_policy: RedirectPolicy,
    stop_conditions: &'a [StopCondition],
    evidence_contract: &'a EvidenceContract,
}

// Report invalid plan envelopes without exposing executable input
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlanContractError {
    #[error("identifier is invalid")]
    InvalidIdentifier,
    #[error("hypothesis requires at least one observation")]
    MissingObservations,
    #[error("action budget must be non-zero and coherent")]
    InvalidBudget,
    #[error("action target is invalid")]
    InvalidTarget,
    #[error("executable input digest must be a lowercase SHA-256 value")]
    InvalidExecutableInputHash,
    #[error("action plan requires at least one stop condition")]
    MissingStopConditions,
    #[error("plan rationale is invalid")]
    InvalidRationale,
    #[error("action plan hash material could not be serialized")]
    HashSerialization,
}

// Hash immutable executable semantics for approval, audit, and resume identity
fn hash_plan(request: &ActionPlanRequest) -> Result<String, PlanContractError> {
    let material = PlanHashMaterial {
        hypothesis_id: &request.hypothesis_id,
        action: &request.action,
        scope: request.scope,
        risk: request.risk,
        budget: request.budget,
        redirect_policy: request.redirect_policy,
        stop_conditions: &request.stop_conditions,
        evidence_contract: &request.evidence_contract,
    };
    let serialized =
        serde_json::to_vec(&material).map_err(|_| PlanContractError::HashSerialization)?;
    Ok(hex::encode(Sha256::digest(serialized)))
}

// Validate stable IDs before they enter plan hashes or artifact references
fn validate_identifier(value: &str) -> Result<(), PlanContractError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
    {
        return Err(PlanContractError::InvalidIdentifier);
    }
    Ok(())
}

// Validate canonical lowercase SHA-256 text
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
