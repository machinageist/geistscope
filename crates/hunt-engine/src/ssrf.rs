// Author: Jeff
// Date: 2026-07-31
// Description: Normalized HTTP observations and inert SSRF candidate/probe planning
// Notes: Candidate and plan construction hash suspected values and perform no I/O

use serde::{Deserialize, Serialize};
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
const SSRF_HASH_DOMAIN: &str = "geistscope.hunt-engine.ssrf";
const SSRF_HASH_SCHEMA: &str = "ssrf_probe_plan";
const SSRF_HASH_VERSION: u16 = 1;
const CAPTURE_SCHEMA: &str = "geistscope.captured_request";
const CAPTURE_VERSION: u16 = 1;

// Represent the normalized HTTP methods accepted from traffic adapters
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

// Persist the minimal typed request provenance required to authorize this slice
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedRequestEvidence {
    schema: String,
    version: u16,
    capture_id: String,
    request_id: String,
    method: HttpMethod,
    observed_url: String,
}

impl CapturedRequestEvidence {
    pub fn new(
        capture_id: impl Into<String>,
        request_id: impl Into<String>,
        method: HttpMethod,
        observed_url: impl Into<String>,
    ) -> Result<Self, SsrfContractError> {
        let evidence = Self {
            schema: CAPTURE_SCHEMA.to_string(),
            version: CAPTURE_VERSION,
            capture_id: capture_id.into(),
            request_id: request_id.into(),
            method,
            observed_url: observed_url.into(),
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub(crate) fn validate(&self) -> Result<(), SsrfContractError> {
        if self.schema != CAPTURE_SCHEMA
            || self.version != CAPTURE_VERSION
            || self.capture_id.len() != 32
            || !self.capture_id.bytes().all(|byte| byte.is_ascii_hexdigit())
            || self
                .capture_id
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
            || !is_identifier(&self.request_id)
            || self.method != HttpMethod::Get
        {
            return Err(SsrfContractError::InvalidCapturedRequestEvidence);
        }
        let url = Url::parse(&self.observed_url)
            .map_err(|_| SsrfContractError::InvalidCapturedRequestEvidence)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || url.as_str() != self.observed_url
        {
            return Err(SsrfContractError::InvalidCapturedRequestEvidence);
        }
        Ok(())
    }

    pub(crate) fn matches(&self, id: &str, method: HttpMethod, url: &str) -> bool {
        self.request_id == id && self.method == method && self.observed_url == url
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedQuerySegment {
    raw_segment_index: usize,
    raw_segment: String,
    raw_name: String,
    decoded_name: String,
    decoded_value: Option<String>,
    occurrence: usize,
}

// Hold one normalized observed request without making it model-serializable
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHttpRequest {
    id: String,
    method: HttpMethod,
    url: Url,
    source: EvidenceReference,
    observed_url: String,
    query_segments: Vec<ParsedQuerySegment>,
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
        let observed_url = url.as_ref().to_string();
        let url = Url::parse(&observed_url).map_err(|_| SsrfContractError::InvalidObservedUrl)?;
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(SsrfContractError::InvalidObservedUrl);
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(SsrfContractError::ObservedUrlContainsUserinfo);
        }
        if url.as_str() != observed_url {
            return Err(SsrfContractError::InvalidObservedUrl);
        }
        let query_segments = parse_query_segments(&url)?;

        Ok(Self {
            id,
            method,
            url,
            source,
            observed_url,
            query_segments,
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
    QueryParameter { occurrence: usize },
}

// Represent one stable, observation-private inert SSRF hypothesis candidate
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsrfCandidate {
    id: String,
    source_observation_id: String,
    input_location: SsrfInputLocation,
    #[serde(skip)]
    raw_segment_index: usize,
}

impl SsrfCandidate {
    // Return the opaque candidate identifier
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
}

// Generate deterministic candidates without network or filesystem activity
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SsrfCandidateGenerator;

impl SsrfCandidateGenerator {
    // Identify absolute HTTP(S) query values as inert SSRF mutation candidates
    pub fn generate(&self, observation: &ObservedHttpRequest) -> Vec<SsrfCandidate> {
        observation
            .query_segments
            .iter()
            .filter_map(|segment| {
                let value = segment.decoded_value.as_ref()?;
                let suspected_url = Url::parse(value).ok()?;
                if !matches!(suspected_url.scheme(), "http" | "https")
                    || suspected_url.host_str().is_none()
                {
                    return None;
                }
                Some(SsrfCandidate {
                    id: candidate_id(observation, segment),
                    source_observation_id: observation.id.clone(),
                    input_location: SsrfInputLocation::QueryParameter {
                        occurrence: segment.occurrence,
                    },
                    raw_segment_index: segment.raw_segment_index,
                })
            })
            .collect()
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

// Serialize the exact HTTP request target the current executor can send
#[derive(Serialize)]
struct SsrfExecutableRequestHashMaterial<'a> {
    method: HttpMethod,
    target_scheme: &'a str,
    target_host: &'a str,
    target_port: u16,
    target_path: &'a str,
    target_query: Option<&'a str>,
}

// Serialize only SSRF executable semantics into a named canonical hash structure
#[derive(Serialize)]
struct SsrfPlanHashMaterial<'a> {
    hash_domain: &'static str,
    hash_schema: &'static str,
    hash_version: u16,
    observation_id: &'a str,
    source_artifact_sha256: &'a str,
    candidate_id: &'a str,
    executable_request: SsrfExecutableRequestHashMaterial<'a>,
    input_location: &'a SsrfInputLocation,
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
    input_location: SsrfInputLocation,
    callback_service_pointer: String,
    observation_window_ms: u64,
    source_evidence_pointer: String,
    scope_evidence_pointer: String,
    rules_evidence_pointer: String,
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

    // Return a secret-safe placeholder for the target request path
    pub fn target_path(&self) -> &str {
        &self.target_path
    }

    // Return the secret-safe kind and occurrence of the candidate insertion point
    pub fn input_location(&self) -> &SsrfInputLocation {
        &self.input_location
    }

    // Return an opaque stable pointer to the private callback service
    pub fn callback_service_pointer(&self) -> &str {
        &self.callback_service_pointer
    }

    // Return the callback observation-window duration in milliseconds
    pub fn observation_window_ms(&self) -> u64 {
        self.observation_window_ms
    }

    // Return the opaque captured-request evidence pointer
    pub fn source_evidence_pointer(&self) -> &str {
        &self.source_evidence_pointer
    }

    // Return the scope evidence bound into the plan
    pub fn scope_evidence_pointer(&self) -> &str {
        &self.scope_evidence_pointer
    }

    // Return the program-rules evidence bound into the plan
    pub fn rules_evidence_pointer(&self) -> &str {
        &self.rules_evidence_pointer
    }
}

// Hold engine-only executable SSRF state that must never be model-serializable
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SsrfExecutablePlan {
    plan_hash: String,
    method: HttpMethod,
    request_url: Url,
    scope_target: String,
    query_parameter_name: String,
    callback_token: CallbackToken,
    observation_window_ms: u64,
}

// Engine-only accessors consumed by the policy-gate, executor, and correlation slices
#[allow(dead_code)]
impl SsrfExecutablePlan {
    // Produce the exact one-occurrence mutated request the executor will send
    pub(crate) fn mutated_url(&self) -> Url {
        self.request_url.clone()
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

    // Return the normalized origin and path used for deterministic scope matching
    pub(crate) fn scope_target(&self) -> &str {
        &self.scope_target
    }

    // Retain the exact decoded insertion name only inside executable engine state
    pub(crate) fn query_parameter_name(&self) -> &str {
        &self.query_parameter_name
    }
}

// Bind the immutable SSRF plan, its redacted view, and engine-only executable state
#[derive(Clone)]
pub struct SsrfProbePlan {
    action_plan: ActionPlan,
    view: SsrfProbePlanView,
    executable: SsrfExecutablePlan,
    source_reference: EvidenceReference,
    scope_reference: EvidenceReference,
    rules_reference: EvidenceReference,
    observed_request_id: String,
    observed_method: HttpMethod,
    observed_url: String,
}

impl std::fmt::Debug for SsrfProbePlan {
    // Format only the model-safe view so debug output cannot expose executable provenance
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SsrfProbePlan")
            .field("view", &self.view)
            .finish_non_exhaustive()
    }
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

    // Return the captured request evidence that was bound into the plan
    pub(crate) fn source_reference(&self) -> &EvidenceReference {
        &self.source_reference
    }

    // Return the scope evidence that was bound into the plan
    pub fn scope_reference(&self) -> &EvidenceReference {
        &self.scope_reference
    }

    // Return the program-rules evidence that was bound into the plan
    pub fn rules_reference(&self) -> &EvidenceReference {
        &self.rules_reference
    }

    pub(crate) fn source_matches(&self, evidence: &CapturedRequestEvidence) -> bool {
        evidence.matches(
            &self.observed_request_id,
            self.observed_method,
            &self.observed_url,
        )
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

        // Resolve and reject any candidate whose opaque identity no longer matches the observation
        let segment = resolve_candidate_input(observation, candidate)
            .ok_or(SsrfContractError::CandidateObservationMismatch)?;
        let name = segment.decoded_name.clone();

        // Derive the exact executable request before hashing or public redaction
        let target_host = observation
            .url
            .host_str()
            .ok_or(SsrfContractError::PlanBuildFailed)?;
        let target_port = observation
            .url
            .port_or_known_default()
            .ok_or(SsrfContractError::PlanBuildFailed)?;
        let target_origin = observation.url.origin().ascii_serialization();
        let callback_url = self.callback_origin.callback_url(&token);
        let request_url = mutate_query_segment(
            &observation.url,
            &observation.query_segments,
            segment.raw_segment_index,
            &callback_url,
        )?;
        let target_path = request_url.path();
        let scope_target = format!("{target_origin}{target_path}");

        let callback_token_sha256 = hex::encode(Sha256::digest(token.as_str().as_bytes()));
        let hash_material = SsrfPlanHashMaterial {
            hash_domain: SSRF_HASH_DOMAIN,
            hash_schema: SSRF_HASH_SCHEMA,
            hash_version: SSRF_HASH_VERSION,
            observation_id: &observation.id,
            source_artifact_sha256: observation.source.sha256(),
            candidate_id: &candidate.id,
            executable_request: SsrfExecutableRequestHashMaterial {
                method: observation.method,
                target_scheme: request_url.scheme(),
                target_host,
                target_port,
                target_path,
                target_query: request_url.query(),
            },
            input_location: &candidate.input_location,
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
            format!("{target_origin}/<redacted>"),
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

        let source_evidence_pointer =
            opaque_evidence_pointer(observation, "source", &observation.source);
        let scope_evidence_pointer =
            opaque_evidence_pointer(observation, "scope", &scope_reference);
        let rules_evidence_pointer =
            opaque_evidence_pointer(observation, "rules", &rules_reference);
        let callback_service_pointer = private_identity(
            observation.source.sha256().as_bytes(),
            "callback_service",
            self.callback_origin.as_str().as_bytes(),
        );
        let view = SsrfProbePlanView {
            plan_hash: action_plan.plan_hash().to_string(),
            observation_id: observation.id.clone(),
            candidate_id: candidate.id.clone(),
            method: observation.method,
            target_origin,
            target_path: "/<redacted>".to_string(),
            input_location: candidate.input_location.clone(),
            callback_service_pointer,
            observation_window_ms,
            source_evidence_pointer,
            scope_evidence_pointer,
            rules_evidence_pointer,
        };
        let executable = SsrfExecutablePlan {
            plan_hash: action_plan.plan_hash().to_string(),
            method: observation.method,
            request_url,
            scope_target,
            query_parameter_name: name,
            callback_token: token,
            observation_window_ms,
        };

        Ok(SsrfProbePlan {
            action_plan,
            view,
            executable,
            source_reference: observation.source.clone(),
            scope_reference,
            rules_reference,
            observed_request_id: observation.id.clone(),
            observed_method: observation.method,
            observed_url: observation.observed_url.clone(),
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
    #[error("observed request URL must not contain credentials or userinfo")]
    ObservedUrlContainsUserinfo,
    #[error("query parameter names must use valid percent-encoded UTF-8")]
    InvalidQueryParameterName,
    #[error("semicolon query segments are unsupported for SSRF candidates")]
    SemicolonQuerySegmentUnsupported,
    #[error("captured request evidence schema or fields are invalid")]
    InvalidCapturedRequestEvidence,
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

// Parse every query segment once, rejecting ambiguous delimiters before and after decoding
fn parse_query_segments(url: &Url) -> Result<Vec<ParsedQuerySegment>, SsrfContractError> {
    let Some(raw_query) = url.query() else {
        return Ok(Vec::new());
    };
    let mut occurrences = std::collections::BTreeMap::<String, usize>::new();
    let mut parsed = Vec::new();
    for (raw_segment_index, segment) in raw_query.split('&').enumerate() {
        if segment.contains(';') || contains_percent_encoded_semicolon(segment) {
            return Err(SsrfContractError::SemicolonQuerySegmentUnsupported);
        }
        if segment.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = split_query_segment(segment);
        let decoded_name = strict_form_decode(raw_name)
            .map_err(|_| SsrfContractError::InvalidQueryParameterName)?;
        let decoded_value = strict_form_decode(raw_value.unwrap_or_default()).ok();
        if decoded_name.contains(';')
            || decoded_value
                .as_deref()
                .is_some_and(|value| value.contains(';'))
        {
            return Err(SsrfContractError::SemicolonQuerySegmentUnsupported);
        }
        let occurrence = occurrences.entry(decoded_name.clone()).or_default();
        let current_occurrence = *occurrence;
        *occurrence += 1;
        parsed.push(ParsedQuerySegment {
            raw_segment_index,
            raw_segment: segment.to_string(),
            raw_name: raw_name.to_string(),
            decoded_name,
            decoded_value,
            occurrence: current_occurrence,
        });
    }
    Ok(parsed)
}

// Detect an encoded semicolon even when another malformed escape prevents full decoding
fn contains_percent_encoded_semicolon(raw: &str) -> bool {
    raw.as_bytes()
        .windows(3)
        .any(|window| window[0] == b'%' && window[1] == b'3' && matches!(window[2], b'b' | b'B'))
}

// Split one raw query segment without normalizing its encoded identity
fn split_query_segment(segment: &str) -> (&str, Option<&str>) {
    segment
        .split_once('=')
        .map_or((segment, None), |(name, value)| (name, Some(value)))
}

// Decode application/x-www-form-urlencoded bytes without replacement characters
fn strict_form_decode(raw: &str) -> Result<String, ()> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(());
                }
                let high = hex_nibble(bytes[index + 1]).ok_or(())?;
                let low = hex_nibble(bytes[index + 2]).ok_or(())?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| ())
}

// Convert one ASCII hexadecimal digit into its numeric value
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// Derive an artifact-keyed identity that cannot be recomputed from public candidate fields
fn candidate_id(observation: &ObservedHttpRequest, segment: &ParsedQuerySegment) -> String {
    private_identity(
        observation.source.sha256().as_bytes(),
        "candidate",
        format!(
            "{}\n{}\n{}",
            segment.raw_segment_index, segment.occurrence, segment.raw_segment
        )
        .as_bytes(),
    )
}

// Recover the exact insertion segment from the authoritative parsed observation
fn resolve_candidate_input<'a>(
    observation: &'a ObservedHttpRequest,
    candidate: &SsrfCandidate,
) -> Option<&'a ParsedQuerySegment> {
    observation.query_segments.iter().find(|segment| {
        let location = SsrfInputLocation::QueryParameter {
            occurrence: segment.occurrence,
        };
        candidate.raw_segment_index == segment.raw_segment_index
            && candidate.input_location == location
            && candidate.id == candidate_id(observation, segment)
    })
}

// Derive one opaque pointer with stable source-artifact-private key material
fn opaque_evidence_pointer(
    observation: &ObservedHttpRequest,
    domain: &str,
    reference: &EvidenceReference,
) -> String {
    private_identity(
        observation.source.sha256().as_bytes(),
        domain,
        format!(
            "{}\n{}\n{}",
            reference.requirement_id(),
            reference.artifact_path(),
            reference.sha256()
        )
        .as_bytes(),
    )
}

// Hash domain-separated private-key-prefixed material into a fixed public identifier
fn private_identity(key: &[u8], domain: &str, material: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SSRF_HASH_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(key);
    hasher.update([0]);
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(material);
    hex::encode(hasher.finalize())
}

// Replace exactly one authoritative raw segment while preserving every other raw pair
fn mutate_query_segment(
    url: &Url,
    parsed_segments: &[ParsedQuerySegment],
    raw_segment_index: usize,
    replacement: &str,
) -> Result<Url, SsrfContractError> {
    let raw_query = url
        .query()
        .ok_or(SsrfContractError::CandidateObservationMismatch)?;
    let selected = parsed_segments
        .iter()
        .find(|segment| segment.raw_segment_index == raw_segment_index)
        .ok_or(SsrfContractError::CandidateObservationMismatch)?;
    let encoded_replacement =
        url::form_urlencoded::byte_serialize(replacement.as_bytes()).collect::<String>();
    let mut replaced = false;
    let segments = raw_query
        .split('&')
        .enumerate()
        .map(|(index, segment)| {
            if index == raw_segment_index && segment == selected.raw_segment {
                replaced = true;
                format!("{}={encoded_replacement}", selected.raw_name)
            } else {
                segment.to_string()
            }
        })
        .collect::<Vec<_>>();
    if !replaced {
        return Err(SsrfContractError::CandidateObservationMismatch);
    }
    let mut request_url = url.clone();
    request_url.set_query(Some(&segments.join("&")));
    request_url.set_fragment(None);
    Ok(request_url)
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
        assert_eq!(plan.executable().query_parameter_name(), "url");
    }

    #[test]
    fn ssrf_hash_material_has_an_explicit_domain_schema_and_version() {
        let request = SsrfExecutableRequestHashMaterial {
            method: HttpMethod::Get,
            target_scheme: "https",
            target_host: "target.example.test",
            target_port: 443,
            target_path: "/private",
            target_query: Some("url=callback"),
        };
        let location = SsrfInputLocation::QueryParameter { occurrence: 0 };
        let material = SsrfPlanHashMaterial {
            hash_domain: SSRF_HASH_DOMAIN,
            hash_schema: SSRF_HASH_SCHEMA,
            hash_version: SSRF_HASH_VERSION,
            observation_id: "request-1",
            source_artifact_sha256: "source",
            candidate_id: "candidate",
            executable_request: request,
            input_location: &location,
            callback_origin: "http://127.0.0.1:43123/",
            callback_token_sha256: "token",
            scope_artifact_sha256: "scope",
            rules_artifact_sha256: "rules",
            observation_window_ms: 60_000,
        };
        let serialized = serde_json::to_value(material).unwrap();

        assert_eq!(serialized["hash_domain"], SSRF_HASH_DOMAIN);
        assert_eq!(serialized["hash_schema"], SSRF_HASH_SCHEMA);
        assert_eq!(serialized["hash_version"], SSRF_HASH_VERSION);
    }

    #[test]
    fn exact_mutation_preserves_unselected_pair_order_duplicates_and_encoding() {
        let url = Url::parse(
            "https://target.example.test/fetch?keep=a%2fb&url=https%3A%2F%2Foriginal.example.test&keep=a%2Fb",
        )
        .unwrap();
        let parsed = parse_query_segments(&url).unwrap();
        let selected = parsed
            .iter()
            .find(|segment| segment.decoded_name == "url" && segment.occurrence == 0)
            .unwrap();
        let mutated = mutate_query_segment(
            &url,
            &parsed,
            selected.raw_segment_index,
            "http://127.0.0.1:43123/callbacks/11111111111111111111111111111111",
        )
        .unwrap();

        assert_eq!(
            mutated.query(),
            Some(
                "keep=a%2fb&url=http%3A%2F%2F127.0.0.1%3A43123%2Fcallbacks%2F11111111111111111111111111111111&keep=a%2Fb"
            )
        );
    }

    #[test]
    fn exact_mutation_does_not_count_parser_empty_segments_as_empty_name_parameters() {
        let url = Url::parse("https://target.example.test/fetch?&&=http://original.example.test/")
            .unwrap();
        let candidates = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, "");
        let parsed = parse_query_segments(&url).unwrap();
        let selected = parsed
            .iter()
            .find(|segment| segment.decoded_name.is_empty() && segment.occurrence == 0)
            .unwrap();
        let mutated = mutate_query_segment(
            &url,
            &parsed,
            selected.raw_segment_index,
            "http://127.0.0.1:43123/callbacks/11111111111111111111111111111111",
        )
        .unwrap();

        assert_eq!(
            mutated.query(),
            Some(
                "&&=http%3A%2F%2F127.0.0.1%3A43123%2Fcallbacks%2F11111111111111111111111111111111"
            )
        );
    }

    #[test]
    fn exact_mutation_preserves_empty_segments_between_empty_name_parameters() {
        let url = Url::parse(
            "https://target.example.test/fetch?=http://one.example.test/&&=http://two.example.test/",
        )
        .unwrap();
        let candidates = url.query_pairs().collect::<Vec<_>>();
        assert_eq!(candidates.len(), 2);
        assert!(candidates.iter().all(|(name, _)| name.is_empty()));
        let parsed = parse_query_segments(&url).unwrap();
        let selected = parsed
            .iter()
            .find(|segment| segment.decoded_name.is_empty() && segment.occurrence == 1)
            .unwrap();
        let mutated = mutate_query_segment(
            &url,
            &parsed,
            selected.raw_segment_index,
            "http://127.0.0.1:43123/callbacks/11111111111111111111111111111111",
        )
        .unwrap();

        assert_eq!(
            mutated.query(),
            Some(
                "=http://one.example.test/&&=http%3A%2F%2F127.0.0.1%3A43123%2Fcallbacks%2F11111111111111111111111111111111"
            )
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
