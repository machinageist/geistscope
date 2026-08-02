// Author: Jeff
// Date: 2026-07-31
// Description: Normalized HTTP observations and inert SSRF candidate/probe planning
// Notes: Candidate and plan construction hash suspected values and perform no I/O

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::{
    ActionBudget, ActionDescriptor, ActionPlan, ActionPlanBuilder, ActionPlanRequest,
    CallbackRegistration, CallbackToken, EvidenceContract, EvidenceKind, EvidenceReference,
    EvidenceRequirement, HuntRisk, ScopeDisposition, StopCondition,
};

// Cap SSRF probe budgets far below anything an execution adapter would honor
const SSRF_MAX_REQUESTS: u32 = 1;
const SSRF_MAX_DURATION_MS: u64 = 10_000;
const SSRF_MAX_BYTES: u64 = 262_144;
const SSRF_MAX_CONCURRENCY: u16 = 1;

// Represent the normalized HTTP methods accepted from traffic adapters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

// Hold one normalized observed request without making it model-serializable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHttpRequest {
    id: String,
    method: HttpMethod,
    url: Url,
    source: EvidenceReference,
}

impl ObservedHttpRequest {
    // Validate an adapter-provided HTTP observation
    pub fn new(
        id: impl Into<String>,
        method: HttpMethod,
        url: impl AsRef<str>,
        source: EvidenceReference,
    ) -> Result<Self, SsrfContractError> {
        let id = id.into();
        if !is_identifier(&id) {
            return Err(SsrfContractError::InvalidObservationId);
        }
        let url = Url::parse(url.as_ref()).map_err(|_| SsrfContractError::InvalidObservedUrl)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(SsrfContractError::InvalidObservedUrl);
        }

        Ok(Self {
            id,
            method,
            url,
            source,
        })
    }

    // Return the stable observed-request identifier
    pub fn id(&self) -> &str {
        &self.id
    }

    // Return the normalized request method
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    // Return the normalized absolute request URL
    pub fn url(&self) -> &Url {
        &self.url
    }

    // Return the immutable source artifact reference
    pub fn source(&self) -> &EvidenceReference {
        &self.source
    }
}

// Locate a suspected server-side fetch input without retaining its raw value
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SsrfInputLocation {
    QueryParameter { name: String, occurrence: usize },
}

// Represent one deterministic inert SSRF hypothesis candidate
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsrfCandidate {
    id: String,
    source_observation_id: String,
    input_location: SsrfInputLocation,
    original_value_sha256: String,
}

impl SsrfCandidate {
    // Return the deterministic candidate identifier
    pub fn id(&self) -> &str {
        &self.id
    }

    // Return the observation that produced this candidate
    pub fn source_observation_id(&self) -> &str {
        &self.source_observation_id
    }

    // Return the exact request mutation location
    pub fn input_location(&self) -> &SsrfInputLocation {
        &self.input_location
    }

    // Return the suspected value digest without exposing the raw URL
    pub fn original_value_sha256(&self) -> &str {
        &self.original_value_sha256
    }
}

// Generate deterministic candidates without network or filesystem activity
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SsrfCandidateGenerator;

impl SsrfCandidateGenerator {
    // Identify absolute HTTP(S) query values as inert SSRF mutation candidates
    pub fn generate(&self, observation: &ObservedHttpRequest) -> Vec<SsrfCandidate> {
        let mut occurrences = BTreeMap::<String, usize>::new();
        let mut candidates = Vec::new();

        for (name, value) in observation.url.query_pairs() {
            let occurrence = occurrences.entry(name.to_string()).or_default();
            let current_occurrence = *occurrence;
            *occurrence += 1;

            let Ok(suspected_url) = Url::parse(&value) else {
                continue;
            };
            if !matches!(suspected_url.scheme(), "http" | "https")
                || suspected_url.host_str().is_none()
            {
                continue;
            }

            let original_value_sha256 = hex::encode(Sha256::digest(value.as_bytes()));
            let id_material = format!(
                "{}\n{}\n{}\n{}",
                observation.id, name, current_occurrence, original_value_sha256
            );
            candidates.push(SsrfCandidate {
                id: hex::encode(Sha256::digest(id_material.as_bytes())),
                source_observation_id: observation.id.clone(),
                input_location: SsrfInputLocation::QueryParameter {
                    name: name.into_owned(),
                    occurrence: current_occurrence,
                },
                original_value_sha256,
            });
        }

        candidates
    }
}

// Bind one campaign to one exact callback origin
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CampaignCallbackOrigin {
    origin: Url,
}

impl CampaignCallbackOrigin {
    // Accept only a bare absolute HTTP(S) origin; token paths are engine-generated
    pub fn new(origin: impl AsRef<str>) -> Result<Self, SsrfContractError> {
        let origin =
            Url::parse(origin.as_ref()).map_err(|_| SsrfContractError::InvalidCallbackOrigin)?;
        if !matches!(origin.scheme(), "http" | "https")
            || origin.host_str().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.username().is_empty()
            || origin.password().is_some()
        {
            return Err(SsrfContractError::InvalidCallbackOrigin);
        }
        Ok(Self { origin })
    }

    // Return the bare scheme/host/port origin for redacted views without a token path
    pub fn as_str(&self) -> &str {
        self.origin.as_str()
    }

    // Build the only permitted callback URL form for a token
    fn callback_url(&self, token: &CallbackToken) -> String {
        let mut url = self.origin.clone();
        url.set_path(&format!("/callbacks/{}", token.as_str()));
        url.to_string()
    }
}

// Bind one callback token to the observation window its plan-bound lease will honor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackLease {
    token: CallbackToken,
    observation_window_ms: u64,
}

impl CallbackLease {
    // Create a lease with a non-zero observation window
    pub fn new(
        token: CallbackToken,
        observation_window_ms: u64,
    ) -> Result<Self, SsrfContractError> {
        if observation_window_ms == 0 {
            return Err(SsrfContractError::InvalidObservationWindow);
        }
        Ok(Self {
            token,
            observation_window_ms,
        })
    }
}

// Serialize only SSRF executable semantics into a named canonical hash structure
#[derive(Serialize)]
struct SsrfPlanHashMaterial<'a> {
    observation_id: &'a str,
    source_artifact_sha256: &'a str,
    candidate_id: &'a str,
    original_value_sha256: &'a str,
    method: HttpMethod,
    target_scheme: &'a str,
    target_host: &'a str,
    target_port: u16,
    target_path: &'a str,
    query_parameter_name: &'a str,
    query_parameter_occurrence: usize,
    callback_origin: &'a str,
    callback_token_sha256: &'a str,
    scope_artifact_sha256: &'a str,
    rules_artifact_sha256: &'a str,
    observation_window_ms: u64,
}

// Expose only redacted plan metadata that is safe for model and policy inspection
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsrfProbePlanView {
    plan_hash: String,
    observation_id: String,
    candidate_id: String,
    method: HttpMethod,
    target_origin: String,
    target_path: String,
    query_parameter_name: String,
    query_parameter_occurrence: usize,
    callback_origin: String,
    observation_window_ms: u64,
    scope_reference: EvidenceReference,
    rules_reference: EvidenceReference,
}

impl SsrfProbePlanView {
    // Return the immutable approval and audit hash
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the source observation identifier
    pub fn observation_id(&self) -> &str {
        &self.observation_id
    }

    // Return the candidate identifier the plan tests
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }

    // Return the normalized request method
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    // Return the redacted target origin without query values
    pub fn target_origin(&self) -> &str {
        &self.target_origin
    }

    // Return the target request path without query values
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    // Return the mutated query parameter name
    pub fn query_parameter_name(&self) -> &str {
        &self.query_parameter_name
    }

    // Return the mutated query parameter occurrence
    pub fn query_parameter_occurrence(&self) -> usize {
        self.query_parameter_occurrence
    }

    // Return the bare campaign callback origin without the token path
    pub fn callback_origin(&self) -> &str {
        &self.callback_origin
    }

    // Return the callback observation-window duration in milliseconds
    pub fn observation_window_ms(&self) -> u64 {
        self.observation_window_ms
    }

    // Return the scope evidence bound into the plan
    pub fn scope_reference(&self) -> &EvidenceReference {
        &self.scope_reference
    }

    // Return the program-rules evidence bound into the plan
    pub fn rules_reference(&self) -> &EvidenceReference {
        &self.rules_reference
    }
}

// Hold engine-only executable SSRF state that must never be model-serializable
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsrfExecutablePlan {
    plan_hash: String,
    method: HttpMethod,
    observed_url: Url,
    input_location: SsrfInputLocation,
    callback_token: CallbackToken,
    callback_url: String,
    observation_window_ms: u64,
}

// Engine-only accessors consumed by the policy-gate, executor, and correlation slices
#[allow(dead_code)]
impl SsrfExecutablePlan {
    // Produce the exact one-occurrence mutated request the executor will send
    pub(crate) fn mutated_url(&self) -> Url {
        let SsrfInputLocation::QueryParameter { name, occurrence } = &self.input_location;
        let pairs = self
            .observed_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        let mut seen = 0usize;
        let mut mutated = Vec::with_capacity(pairs.len());
        for (key, value) in pairs {
            if &key == name {
                if seen == *occurrence {
                    mutated.push((key, self.callback_url.clone()));
                } else {
                    mutated.push((key, value));
                }
                seen += 1;
            } else {
                mutated.push((key, value));
            }
        }

        let mut url = self.observed_url.clone();
        url.query_pairs_mut().clear().extend_pairs(mutated);
        url
    }

    // Return the normalized request method
    pub(crate) fn method(&self) -> HttpMethod {
        self.method
    }

    // Return the immutable plan hash bound to this executable state
    pub(crate) fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return the raw callback token for engine-only callback registration
    pub(crate) fn callback_token(&self) -> &CallbackToken {
        &self.callback_token
    }

    // Create a plan-bound registration that expires at the observation-window deadline
    pub(crate) fn callback_registration(&self, issued_at_ms: u64) -> CallbackRegistration {
        CallbackRegistration::new(
            self.callback_token.clone(),
            self.plan_hash.clone(),
            issued_at_ms.saturating_add(self.observation_window_ms),
        )
    }
}

// Bind the immutable SSRF plan, its redacted view, and engine-only executable state
#[derive(Debug, Clone)]
pub struct SsrfProbePlan {
    action_plan: ActionPlan,
    view: SsrfProbePlanView,
    executable: SsrfExecutablePlan,
}

impl SsrfProbePlan {
    // Return the immutable capability-neutral plan envelope
    pub fn action_plan(&self) -> &ActionPlan {
        &self.action_plan
    }

    // Return the redacted plan view safe for model and policy inspection
    pub fn view(&self) -> &SsrfProbePlanView {
        &self.view
    }

    // Return the immutable approval and audit hash
    pub fn plan_hash(&self) -> &str {
        self.action_plan.plan_hash()
    }

    // Return the scope evidence that was bound into the plan
    pub fn scope_reference(&self) -> &EvidenceReference {
        &self.view.scope_reference
    }

    // Return the program-rules evidence that was bound into the plan
    pub fn rules_reference(&self) -> &EvidenceReference {
        &self.view.rules_reference
    }

    // Access engine-only executable state for policy-gated execution
    #[allow(dead_code)] // Consumed by the executor slice
    pub(crate) fn executable(&self) -> &SsrfExecutablePlan {
        &self.executable
    }

    // Create a plan-bound callback registration from engine-only state
    #[allow(dead_code)] // Consumed by the callback-registration slice
    pub(crate) fn callback_registration(&self, issued_at_ms: u64) -> CallbackRegistration {
        self.executable.callback_registration(issued_at_ms)
    }
}

// Build callback-only SSRF plans without executing network requests
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfProbePlanBuilder {
    callback_origin: CampaignCallbackOrigin,
}

impl SsrfProbePlanBuilder {
    // Create a builder pinned to one campaign-owned callback origin
    pub fn new(callback_origin: CampaignCallbackOrigin) -> Self {
        Self { callback_origin }
    }

    // Build an immutable callback probe plan from one candidate and policy context
    pub fn build(
        &self,
        observation: &ObservedHttpRequest,
        candidate: &SsrfCandidate,
        scope: ScopeDisposition,
        scope_reference: EvidenceReference,
        rules_reference: EvidenceReference,
        lease: CallbackLease,
    ) -> Result<SsrfProbePlan, SsrfContractError> {
        let CallbackLease {
            token,
            observation_window_ms,
        } = lease;
        if observation.method != HttpMethod::Get {
            return Err(SsrfContractError::StateChangingObservation);
        }
        if observation.id != candidate.source_observation_id {
            return Err(SsrfContractError::CandidateObservationMismatch);
        }

        // Reject a candidate whose recorded value no longer matches the live observation
        let SsrfInputLocation::QueryParameter { name, occurrence } = &candidate.input_location;
        let current_value = query_value_at(&observation.url, name, *occurrence)
            .ok_or(SsrfContractError::CandidateObservationMismatch)?;
        if hex::encode(Sha256::digest(current_value.as_bytes())) != candidate.original_value_sha256
        {
            return Err(SsrfContractError::CandidateObservationMismatch);
        }

        // Derive redacted target origin/path without retaining raw query values
        let target_host = observation
            .url
            .host_str()
            .ok_or(SsrfContractError::PlanBuildFailed)?;
        let target_port = observation
            .url
            .port_or_known_default()
            .ok_or(SsrfContractError::PlanBuildFailed)?;
        let target_path = observation.url.path();
        let target_origin = observation.url.origin().ascii_serialization();

        let callback_url = self.callback_origin.callback_url(&token);
        let callback_token_sha256 = hex::encode(Sha256::digest(token.as_str().as_bytes()));
        let hash_material = SsrfPlanHashMaterial {
            observation_id: &observation.id,
            source_artifact_sha256: observation.source.sha256(),
            candidate_id: &candidate.id,
            original_value_sha256: &candidate.original_value_sha256,
            method: observation.method,
            target_scheme: observation.url.scheme(),
            target_host,
            target_port,
            target_path,
            query_parameter_name: name,
            query_parameter_occurrence: *occurrence,
            callback_origin: self.callback_origin.as_str(),
            callback_token_sha256: &callback_token_sha256,
            scope_artifact_sha256: scope_reference.sha256(),
            rules_artifact_sha256: rules_reference.sha256(),
            observation_window_ms,
        };
        let executable_input_sha256 = hex::encode(Sha256::digest(
            serde_json::to_vec(&hash_material).map_err(|_| SsrfContractError::PlanBuildFailed)?,
        ));

        let budget = ActionBudget::new(1, 2_000, 131_072, 1)
            .map_err(|_| SsrfContractError::PlanBuildFailed)?;
        enforce_ssrf_budget_ceiling(&budget)?;
        let action = ActionDescriptor::new(
            "ssrf",
            "callback_probe",
            format!("{target_origin}{target_path}"),
            executable_input_sha256,
        )
        .map_err(|_| SsrfContractError::PlanBuildFailed)?;
        let contract = EvidenceContract::new([
            EvidenceRequirement::new("policy", EvidenceKind::PolicyDecision),
            EvidenceRequirement::new("callback", EvidenceKind::CallbackCorrelation),
            EvidenceRequirement::new("response", EvidenceKind::RequestResponse),
        ])
        .map_err(|_| SsrfContractError::PlanBuildFailed)?;

        let stop_conditions = ssrf_stop_conditions();
        require_authorization_expired(&stop_conditions)?;
        let request = ActionPlanRequest::new(
            candidate.id.clone(),
            action,
            scope,
            HuntRisk::LowActive,
            budget,
            contract,
        )
        .with_stop_conditions(stop_conditions)
        .with_rationale("callback-only ssrf probe plan");
        let action_plan = ActionPlanBuilder
            .build(request)
            .map_err(|_| SsrfContractError::PlanBuildFailed)?;

        let view = SsrfProbePlanView {
            plan_hash: action_plan.plan_hash().to_string(),
            observation_id: observation.id.clone(),
            candidate_id: candidate.id.clone(),
            method: observation.method,
            target_origin,
            target_path: target_path.to_string(),
            query_parameter_name: name.clone(),
            query_parameter_occurrence: *occurrence,
            callback_origin: self.callback_origin.as_str().to_string(),
            observation_window_ms,
            scope_reference,
            rules_reference,
        };
        let executable = SsrfExecutablePlan {
            plan_hash: action_plan.plan_hash().to_string(),
            method: observation.method,
            observed_url: observation.url.clone(),
            input_location: candidate.input_location.clone(),
            callback_token: token,
            callback_url,
            observation_window_ms,
        };

        Ok(SsrfProbePlan {
            action_plan,
            view,
            executable,
        })
    }
}

// Report normalized observation and probe-plan contract failures
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SsrfContractError {
    #[error("observed request id is invalid")]
    InvalidObservationId,
    #[error("observed request URL must be an absolute HTTP(S) URL")]
    InvalidObservedUrl,
    #[error("callback origin must be a bare absolute HTTP(S) origin")]
    InvalidCallbackOrigin,
    #[error("state-changing observations are not eligible for autonomous SSRF probes")]
    StateChangingObservation,
    #[error("SSRF candidate does not belong to the observed request")]
    CandidateObservationMismatch,
    #[error("callback observation window must be non-zero")]
    InvalidObservationWindow,
    #[error("SSRF probe plan must include the authorization-expiry stop condition")]
    MissingAuthorizationExpiredStop,
    #[error("SSRF probe budget exceeds the engine safety ceiling")]
    BudgetExceedsSafetyCeiling,
    #[error("SSRF probe plan could not be built")]
    PlanBuildFailed,
}

// Keep observation identifiers stable for hashing and audit output
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

// Return the decoded value at the zero-based occurrence of one query parameter name
fn query_value_at(url: &Url, name: &str, occurrence: usize) -> Option<String> {
    url.query_pairs()
        .filter(|(key, _)| key == name)
        .nth(occurrence)
        .map(|(_, value)| value.into_owned())
}

// Fix the deterministic safety stop conditions bound into every SSRF probe plan
fn ssrf_stop_conditions() -> Vec<StopCondition> {
    vec![
        StopCondition::RateLimited,
        StopCondition::ServerError,
        StopCondition::WafDetected,
        StopCondition::ScopeDrift,
        StopCondition::AuthorizationExpired,
        StopCondition::BudgetExhausted,
        StopCondition::EvidenceFailure,
    ]
}

// Require the authorization-expiry stop so no probe outlives its approval window
fn require_authorization_expired(conditions: &[StopCondition]) -> Result<(), SsrfContractError> {
    if conditions.contains(&StopCondition::AuthorizationExpired) {
        Ok(())
    } else {
        Err(SsrfContractError::MissingAuthorizationExpiredStop)
    }
}

// Reject any budget above the fixed SSRF safety ceiling before it reaches an executor
fn enforce_ssrf_budget_ceiling(budget: &ActionBudget) -> Result<(), SsrfContractError> {
    if budget.max_requests() > SSRF_MAX_REQUESTS
        || budget.max_duration_ms() > SSRF_MAX_DURATION_MS
        || budget.max_bytes() > SSRF_MAX_BYTES
        || budget.concurrency() > SSRF_MAX_CONCURRENCY
    {
        return Err(SsrfContractError::BudgetExceedsSafetyCeiling);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build one immutable evidence reference for source and policy artifacts
    fn reference(id: &str, kind: EvidenceKind, path: &str, digest: char) -> EvidenceReference {
        EvidenceReference::new(id, kind, path, digest.to_string().repeat(64)).unwrap()
    }

    // Build one observed GET request with duplicate url query parameters
    fn duplicate_key_observation() -> ObservedHttpRequest {
        ObservedHttpRequest::new(
            "request-1",
            HttpMethod::Get,
            "https://target.example.test/fetch?url=https%3A%2F%2Fone.example.test&keep=stay&url=https%3A%2F%2Ftwo.example.test",
            reference(
                "source",
                EvidenceKind::RequestResponse,
                "traffic/records/request-1.json",
                'a',
            ),
        )
        .unwrap()
    }

    // Build a plan pinned to a loopback callback origin using the second url occurrence
    fn plan_for_second_occurrence() -> SsrfProbePlan {
        let observation = duplicate_key_observation();
        let candidate = SsrfCandidateGenerator.generate(&observation).remove(1);
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
                CallbackLease::new(CallbackToken::parse("1".repeat(32)).unwrap(), 60_000).unwrap(),
            )
            .unwrap()
    }

    #[test]
    fn duplicate_query_keys_mutate_only_the_selected_occurrence() {
        let plan = plan_for_second_occurrence();
        let mutated = plan.executable().mutated_url();

        let pairs = mutated
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();

        assert_eq!(
            pairs,
            vec![
                ("url".to_string(), "https://one.example.test".to_string()),
                ("keep".to_string(), "stay".to_string()),
                (
                    "url".to_string(),
                    "http://127.0.0.1:43123/callbacks/11111111111111111111111111111111".to_string()
                ),
            ]
        );
    }

    #[test]
    fn callback_registration_binds_plan_hash_and_window_deadline() {
        let plan = plan_for_second_occurrence();
        let registration = plan.callback_registration(1_000);

        let mut recorder = crate::CallbackRecorder::default();
        recorder.register(registration).unwrap();

        // Registration expires exactly one window after issuance, never later
        let live = recorder.correlate(plan.executable().callback_token(), plan.plan_hash(), 61_000);
        let expired =
            recorder.correlate(plan.executable().callback_token(), plan.plan_hash(), 61_001);
        assert_eq!(live, crate::CallbackCorrelation::Missing);
        assert_eq!(expired, crate::CallbackCorrelation::Expired);
    }

    #[test]
    fn budgets_above_the_safety_ceiling_are_rejected() {
        let safe = ActionBudget::new(1, 5_000, 131_072, 1).unwrap();
        let heavy = ActionBudget::new(2, 5_000, 131_072, 1).unwrap();

        assert!(enforce_ssrf_budget_ceiling(&safe).is_ok());
        assert_eq!(
            enforce_ssrf_budget_ceiling(&heavy).unwrap_err(),
            SsrfContractError::BudgetExceedsSafetyCeiling
        );
    }

    #[test]
    fn missing_authorization_expiry_stop_is_rejected() {
        assert!(require_authorization_expired(&ssrf_stop_conditions()).is_ok());
        assert_eq!(
            require_authorization_expired(&[StopCondition::RateLimited]).unwrap_err(),
            SsrfContractError::MissingAuthorizationExpiredStop
        );
    }
}
