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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SemanticDiffEngine;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOutcome {
    pub status: u16,
    pub body: String,
    pub target_tenant_markers: Vec<String>,
    pub auth_failure_shape: Option<AuthFailureShape>,
    pub graphql_errors: bool,
    #[serde(default)]
    pub response_headers: Vec<(String, String)>,
    #[serde(default)]
    pub sent_request: Option<ReplayRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticVerdict {
    pub classification: SemanticVerdictClass,
    pub boundary_violation: bool,
    pub matched_markers: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticVerdictClass {
    SecureDenied,
    InterestingDiff,
    BoundaryViolationRead,
    InvalidTest,
    SsrfOobConfirmed,
    SsrfResponseLeak,
    SsrfNoSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureShape {
    ExpiredToken,
    MissingSession,
}

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
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

impl ReplayOutcome {
    // Create an HTTP replay outcome from local replay metadata
    pub fn http(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            body: body.into(),
            target_tenant_markers: Vec::new(),
            auth_failure_shape: None,
            graphql_errors: false,
            response_headers: Vec::new(),
            sent_request: None,
        }
    }

    // Attach response headers recorded during a live replay
    pub fn with_response_headers<I, K, V>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.response_headers = headers
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    // Attach the concrete request that produced this outcome for evidence
    pub fn with_sent_request(mut self, request: ReplayRequest) -> Self {
        self.sent_request = Some(request);
        self
    }

    // Create a GraphQL outcome carrying error-shape context
    pub fn graphql_errors(status: u16, body: impl Into<String>) -> Self {
        Self {
            graphql_errors: true,
            ..Self::http(status, body)
        }
    }

    // Attach controlled target markers used to detect authorization boundary reads
    pub fn with_target_tenant_markers<I, S>(mut self, markers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.target_tenant_markers = markers.into_iter().map(Into::into).collect();
        self
    }

    // Attach an auth failure shape that invalidates the proof attempt
    pub fn with_auth_failure_shape(mut self, shape: AuthFailureShape) -> Self {
        self.auth_failure_shape = Some(shape);
        self
    }
}

impl SemanticDiffEngine {
    // Classify replay outcome metadata without exposing raw body data in the verdict
    pub fn classify(&self, outcome: &ReplayOutcome) -> SemanticVerdict {
        if outcome.auth_failure_shape == Some(AuthFailureShape::ExpiredToken) {
            return SemanticVerdict {
                classification: SemanticVerdictClass::InvalidTest,
                boundary_violation: false,
                matched_markers: Vec::new(),
                reason: "attacker session token was expired, so the proof is invalid".into(),
            };
        }

        let matched_markers = matched_target_markers(outcome);
        if !matched_markers.is_empty() {
            return SemanticVerdict {
                classification: SemanticVerdictClass::BoundaryViolationRead,
                boundary_violation: true,
                matched_markers,
                reason: "attacker replay response contained controlled target tenant marker".into(),
            };
        }

        if is_secure_denial_status(outcome.status) || is_graphql_authorization_denial(outcome) {
            return SemanticVerdict {
                classification: SemanticVerdictClass::SecureDenied,
                boundary_violation: false,
                matched_markers: Vec::new(),
                reason: "target denied access using an authorization failure shape".into(),
            };
        }

        SemanticVerdict {
            classification: SemanticVerdictClass::InterestingDiff,
            boundary_violation: false,
            matched_markers: Vec::new(),
            reason: "response did not match a secure denial or controlled boundary marker".into(),
        }
    }

    // Classify an SSRF replay from correlated OOB evidence and internal response markers
    pub fn classify_ssrf(
        &self,
        outcome: &ReplayOutcome,
        oob_confirmed: bool,
        markers: &[&str],
    ) -> SemanticVerdict {
        // A correlated out-of-band callback is the strongest, evidence-backed proof
        if oob_confirmed {
            return SemanticVerdict {
                classification: SemanticVerdictClass::SsrfOobConfirmed,
                boundary_violation: true,
                matched_markers: Vec::new(),
                reason:
                    "out-of-band callback correlated to this plan confirms a server-side request"
                        .into(),
            };
        }
        // Otherwise an internal-target marker reflected into the response proves the fetch
        let matched = matched_response_markers(outcome, markers);
        if !matched.is_empty() {
            return SemanticVerdict {
                classification: SemanticVerdictClass::SsrfResponseLeak,
                boundary_violation: true,
                matched_markers: matched,
                reason:
                    "response body reflected an internal-target marker from the injected request"
                        .into(),
            };
        }
        SemanticVerdict {
            classification: SemanticVerdictClass::SsrfNoSignal,
            boundary_violation: false,
            matched_markers: Vec::new(),
            reason: "no correlated out-of-band interaction and no internal marker in the response"
                .into(),
        }
    }
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
        let plan_hash = plan_hash(&request);
        if request
            .approval_grant_hash
            .as_deref()
            .is_some_and(|grant_hash| grant_hash != plan_hash)
        {
            return Err(ReplayPlanError::ApprovalHashMismatch);
        }
        // An approval-required plan only executes once a matching approval grant is bound
        let approval_satisfied = request
            .approval_grant_hash
            .as_deref()
            .is_some_and(|grant_hash| grant_hash == plan_hash);
        let executable = request.scope_decision == ScopeDecision::InScope
            && (!approval_required || approval_satisfied);

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

// Find controlled target markers that appear in the attacker-visible response body
fn matched_target_markers(outcome: &ReplayOutcome) -> Vec<String> {
    outcome
        .target_tenant_markers
        .iter()
        .filter(|marker| !marker.is_empty() && outcome.body.contains(marker.as_str()))
        .cloned()
        .collect()
}

// Find internal-target markers that appear in the injected request's response body
fn matched_response_markers(outcome: &ReplayOutcome, markers: &[&str]) -> Vec<String> {
    markers
        .iter()
        .filter(|marker| !marker.is_empty() && outcome.body.contains(**marker))
        .map(|marker| (*marker).to_string())
        .collect()
}

// Treat standard authz denial statuses as secure denials for replay proofs
fn is_secure_denial_status(status: u16) -> bool {
    matches!(status, 401 | 403 | 404)
}

// Detect common GraphQL authorization-denial error shapes
fn is_graphql_authorization_denial(outcome: &ReplayOutcome) -> bool {
    if !outcome.graphql_errors {
        return false;
    }
    let body = outcome.body.to_ascii_lowercase();
    body.contains("forbidden")
        || body.contains("unauthorized")
        || body.contains("access denied")
        || body.contains("not authorized")
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

// Header names whose values are secrets and must never travel into a replay
const SENSITIVE_HEADER_NAMES: &[&str] = &[
    "authorization",
    "cookie",
    "set-cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
];

// Build a cross-identity request: replay a captured request under a different identity's auth
pub fn build_swapped_request(
    method: &str,
    url: &str,
    base_headers: &[(String, String)],
    attacker_headers: &[(String, String)],
    body: Option<&str>,
) -> ReplayRequest {
    // Drop any auth the victim capture carried, then attach only the attacker identity's auth
    let mut headers: Vec<(String, String)> = base_headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .cloned()
        .collect();
    headers.extend(attacker_headers.iter().cloned());
    ReplayRequest {
        method: method.to_string(),
        url: url.to_string(),
        headers,
        body: body.map(str::to_string),
    }
}

// Build a concrete replay request that injects a payload into one query parameter
pub fn build_injected_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
    param: &str,
    payload: &str,
) -> ReplayRequest {
    // Drop secret-bearing headers so the record never reconstructs a credential
    let safe_headers = headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .cloned()
        .collect();
    ReplayRequest {
        method: method.to_string(),
        url: inject_query_param(url, param, payload),
        headers: safe_headers,
        body: body.map(str::to_string),
    }
}

// Replace one query parameter value or append it when absent, preserving the rest
fn inject_query_param(url: &str, param: &str, payload: &str) -> String {
    let mut parsed = match url::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_) => return url.to_string(),
    };
    let existing: Vec<(String, String)> = parsed
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    let mut replaced = false;
    {
        let mut pairs = parsed.query_pairs_mut();
        pairs.clear();
        for (name, value) in &existing {
            if name == param {
                pairs.append_pair(name, payload);
                replaced = true;
            } else {
                pairs.append_pair(name, value);
            }
        }
        if !replaced {
            pairs.append_pair(param, payload);
        }
    }
    parsed.to_string()
}

// Check whether a header name carries a secret that must be redacted
fn is_sensitive_header(name: &str) -> bool {
    let lowered = name.to_ascii_lowercase();
    SENSITIVE_HEADER_NAMES.contains(&lowered.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use request_corpus::{
        CandidateKind, CandidateSafety, CandidateSource, CandidateStateChange, CorpusCandidate,
    };

    #[test]
    fn ssrf_correlated_oob_hit_is_confirmed() {
        let outcome = ReplayOutcome::http(200, "request accepted");
        let verdict = SemanticDiffEngine.classify_ssrf(&outcome, true, &[]);

        assert_eq!(
            verdict.classification,
            SemanticVerdictClass::SsrfOobConfirmed
        );
        assert!(verdict.boundary_violation);
    }

    #[test]
    fn ssrf_internal_marker_in_response_is_leak() {
        let outcome =
            ReplayOutcome::http(200, "{\"ami-id\":\"ami-123\",\"instance-id\":\"i-abc\"}");
        let verdict = SemanticDiffEngine.classify_ssrf(&outcome, false, &["instance-id"]);

        assert_eq!(
            verdict.classification,
            SemanticVerdictClass::SsrfResponseLeak
        );
        assert!(verdict.boundary_violation);
        assert_eq!(verdict.matched_markers, vec!["instance-id".to_string()]);
    }

    #[test]
    fn ssrf_without_oob_or_marker_is_no_signal() {
        let outcome = ReplayOutcome::http(200, "nothing interesting here");
        let verdict = SemanticDiffEngine.classify_ssrf(&outcome, false, &["instance-id"]);

        assert_eq!(verdict.classification, SemanticVerdictClass::SsrfNoSignal);
        assert!(!verdict.boundary_violation);
    }

    #[test]
    fn build_swapped_request_replaces_victim_auth_with_attacker_auth() {
        let request = build_swapped_request(
            "GET",
            "https://app.example.test/api/projects/victim-123",
            &[
                (
                    "Authorization".to_string(),
                    "Bearer victim-token".to_string(),
                ),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            &[(
                "authorization".to_string(),
                "Bearer attacker-token".to_string(),
            )],
            None,
        );

        assert_eq!(request.method, "GET");
        // The victim's own auth is dropped; only the attacker identity's auth remains
        let auth: Vec<&String> = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value)
            .collect();
        assert_eq!(auth, vec!["Bearer attacker-token"]);
        // Benign headers survive and the victim resource URL is unchanged
        assert!(
            request
                .headers
                .iter()
                .any(|(name, value)| name == "Accept" && value == "application/json")
        );
        assert!(request.url.ends_with("/projects/victim-123"));
    }

    #[test]
    fn build_injected_request_replaces_only_target_param() {
        let request = build_injected_request(
            "GET",
            "https://app.example.test/api/fetch?url=https://orig.example&keep=1",
            &[("Accept".to_string(), "application/json".to_string())],
            None,
            "url",
            "http://127.0.0.1:9/x",
        );

        assert_eq!(request.method, "GET");
        let parsed = url::Url::parse(&request.url).unwrap();
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert!(pairs.contains(&("keep".to_string(), "1".to_string())));
        assert!(pairs.contains(&("url".to_string(), "http://127.0.0.1:9/x".to_string())));
        assert_eq!(
            request.headers,
            vec![("Accept".to_string(), "application/json".to_string())]
        );
    }

    #[test]
    fn build_injected_request_never_reconstructs_secret_headers() {
        let request = build_injected_request(
            "GET",
            "https://app.example.test/api/fetch?url=https://orig.example",
            &[
                (
                    "Authorization".to_string(),
                    "Bearer super-secret".to_string(),
                ),
                ("Cookie".to_string(), "session=raw-secret".to_string()),
                ("Accept".to_string(), "*/*".to_string()),
            ],
            None,
            "url",
            "http://127.0.0.1:9/x",
        );

        assert!(
            request
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("authorization")
                    && !name.eq_ignore_ascii_case("cookie"))
        );
        assert!(request.headers.iter().any(|(name, _)| name == "Accept"));
        assert!(!request.url.contains("super-secret"));
    }

    #[test]
    fn build_injected_request_appends_absent_query_param() {
        let request = build_injected_request(
            "GET",
            "https://app.example.test/api/fetch",
            &[],
            None,
            "url",
            "http://oob.local/token",
        );

        let parsed = url::Url::parse(&request.url).unwrap();
        let value = parsed
            .query_pairs()
            .find(|(name, _)| name == "url")
            .map(|(_, value)| value.into_owned());
        assert_eq!(value, Some("http://oob.local/token".to_string()));
    }

    #[test]
    fn replay_outcome_carries_response_headers_and_sent_request() {
        let request = ReplayRequest {
            method: "GET".to_string(),
            url: "http://target.local/".to_string(),
            headers: Vec::new(),
            body: None,
        };
        let outcome = ReplayOutcome::http(200, "{}")
            .with_response_headers([("content-type".to_string(), "text/html".to_string())])
            .with_sent_request(request.clone());

        assert_eq!(
            outcome.response_headers,
            vec![("content-type".to_string(), "text/html".to_string())]
        );
        assert_eq!(outcome.sent_request, Some(request));
    }

    #[test]
    fn semantic_diff_401_403_404_becomes_secure_denied() {
        for status in [401, 403, 404] {
            let outcome = ReplayOutcome::http(status, "{\"error\":\"denied\"}");
            let verdict = SemanticDiffEngine.classify(&outcome);

            assert_eq!(verdict.classification, SemanticVerdictClass::SecureDenied);
            assert!(!verdict.boundary_violation);
        }
    }

    #[test]
    fn semantic_diff_target_tenant_marker_in_attacker_response_becomes_boundary_violation_read() {
        let outcome = ReplayOutcome::http(
            200,
            "{\"tenant_id\":\"tenant-victim\",\"project\":\"victim-owned\"}",
        )
        .with_target_tenant_markers(["tenant-victim"]);

        let verdict = SemanticDiffEngine.classify(&outcome);

        assert_eq!(
            verdict.classification,
            SemanticVerdictClass::BoundaryViolationRead
        );
        assert!(verdict.boundary_violation);
        assert_eq!(verdict.matched_markers, vec!["tenant-victim"]);
    }

    #[test]
    fn semantic_diff_expired_token_shape_becomes_invalid_test() {
        let outcome = ReplayOutcome::http(401, "{\"error\":\"token expired\"}")
            .with_auth_failure_shape(AuthFailureShape::ExpiredToken);

        let verdict = SemanticDiffEngine.classify(&outcome);

        assert_eq!(verdict.classification, SemanticVerdictClass::InvalidTest);
        assert!(!verdict.boundary_violation);
    }

    #[test]
    fn semantic_diff_graphql_authorization_error_becomes_secure_denied() {
        let outcome = ReplayOutcome::graphql_errors(
            200,
            "{\"errors\":[{\"message\":\"Access denied\",\"extensions\":{\"code\":\"FORBIDDEN\"}}]}",
        );

        let verdict = SemanticDiffEngine.classify(&outcome);

        assert_eq!(verdict.classification, SemanticVerdictClass::SecureDenied);
        assert!(!verdict.boundary_violation);
    }

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

    #[test]
    fn approval_required_plan_becomes_executable_with_matching_grant() {
        let base = ReplayPlanRequest::new(active_candidate(), ScopeDecision::InScope)
            .with_evidence_output_dir("evidence/replay/ssrf-candidate");

        // Without a grant the approval-required plan stays inert
        let unapproved = PlanBuilder.build(base.clone()).unwrap();
        assert!(unapproved.approval_required);
        assert!(!unapproved.executable);

        // Binding the matching grant hash makes the same plan executable
        let approved = PlanBuilder
            .build(base.with_approval_grant_hash(unapproved.plan_hash.clone()))
            .unwrap();
        assert!(approved.approval_required);
        assert!(approved.executable);
    }

    fn active_candidate() -> CorpusCandidate {
        CorpusCandidate {
            id: "ssrf-candidate-001".into(),
            kind: CandidateKind::ServerSideRequestTarget,
            source: CandidateSource::Traffic,
            safety: CandidateSafety::RequiresApproval,
            state_change: CandidateStateChange::ReadOnly,
            autonomous_safe: false,
            record_ids: vec!["fetch-record".into()],
            observation_ids: Vec::new(),
            injection_params: vec!["url".into()],
            cross_tenant: None,
            summary: "server-side request sink pending approval".into(),
        }
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
            injection_params: Vec::new(),
            cross_tenant: None,
            summary: "compare controlled tenant reads".into(),
        }
    }
}
