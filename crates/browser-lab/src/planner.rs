// Author: Jeff
// Date: 2026-05-28
// Description: Safe client-side browser test planning for autonomous hunting
// Notes: Generates non-destructive plans and requires approval for executable or sensitive actions

use crate::BrowserProfile;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

const HARMLESS_MARKER_PREFIX: &str = "mg-marker-";
const DEFAULT_EVIDENCE_DIR: &str = "evidence/client-side";
const BANNED_ACTION_KEYWORDS: &[&str] = &[
    "billing",
    "staff",
    "invite",
    "delete",
    "destroy",
    "integration",
    "webhook",
    "payment",
    "export",
];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlannerError {
    #[error("stored-input plans require controlled sender and viewer profiles")]
    MissingControlledProfile,
    #[error("executable browser payloads require explicit approval")]
    ApprovalRequired,
    #[error("executable browser payloads require a controlled victim profile")]
    ControlledVictimRequired,
    #[error("browser automation action requires approval")]
    SensitiveActionRequiresApproval,
    #[error("evidence path must stay under the client-side evidence directory")]
    UnsafeEvidencePath,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientSideTestKind {
    ReflectedInput,
    StoredInput,
    DomXss,
    OpenRedirect,
    PostMessageOrigin,
    CspWeakness,
    ClientSideAccessControl,
    CacheStorageIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadMode {
    HarmlessMarker,
    ExecutableXss,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserAction {
    pub selector: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePolicy {
    pub screenshot: bool,
    pub dom_snapshot: bool,
    pub console_log: bool,
    pub output_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSidePlanRequest {
    pub kind: ClientSideTestKind,
    pub target_url: String,
    pub sender_profile: Option<BrowserProfile>,
    pub viewer_profile: Option<BrowserProfile>,
    pub victim_profile: Option<BrowserProfile>,
    pub payload_mode: PayloadMode,
    pub approval_id: Option<String>,
    pub actions: Vec<BrowserAction>,
    pub evidence_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientSideTestPlan {
    pub kind: ClientSideTestKind,
    pub target_url: String,
    pub payload: String,
    pub actions: Vec<BrowserAction>,
    pub stop_conditions: Vec<String>,
    pub evidence: EvidencePolicy,
}

#[derive(Debug, Default, Clone)]
pub struct ClientSidePlanner;

impl ClientSidePlanner {
    // Build a safe client-side browser test plan
    pub fn plan(&self, request: ClientSidePlanRequest) -> Result<ClientSideTestPlan, PlannerError> {
        validate_evidence_path(&request.evidence_path)?;
        validate_stored_profiles(&request)?;
        validate_payload_mode(&request)?;
        validate_actions(&request)?;

        let payload = match request.payload_mode {
            PayloadMode::HarmlessMarker => harmless_marker(&request.target_url),
            PayloadMode::ExecutableXss => "<script>alert('mg-controlled-proof')</script>".into(),
        };

        Ok(ClientSideTestPlan {
            kind: request.kind,
            target_url: request.target_url,
            payload,
            actions: request.actions,
            stop_conditions: vec![
                "stop if navigation leaves in-scope origin".into(),
                "stop before destructive or billing-related actions".into(),
                "stop if an unapproved executable sink is reached".into(),
            ],
            evidence: EvidencePolicy {
                screenshot: true,
                dom_snapshot: true,
                console_log: true,
                output_path: request.evidence_path,
            },
        })
    }
}

impl ClientSidePlanRequest {
    // Create a reflected-input request with safe defaults
    pub fn reflected(target_url: &str) -> Self {
        Self {
            kind: ClientSideTestKind::ReflectedInput,
            target_url: target_url.into(),
            sender_profile: None,
            viewer_profile: None,
            victim_profile: None,
            payload_mode: PayloadMode::HarmlessMarker,
            approval_id: None,
            actions: Vec::new(),
            evidence_path: format!("{DEFAULT_EVIDENCE_DIR}/reflected.json"),
        }
    }
}

// Require controlled account pairs for stored-input flows
fn validate_stored_profiles(request: &ClientSidePlanRequest) -> Result<(), PlannerError> {
    if matches!(request.kind, ClientSideTestKind::StoredInput)
        && (request.sender_profile.is_none() || request.viewer_profile.is_none())
    {
        return Err(PlannerError::MissingControlledProfile);
    }
    Ok(())
}

// Require explicit approval and controlled victim profile for executable payloads
fn validate_payload_mode(request: &ClientSidePlanRequest) -> Result<(), PlannerError> {
    if matches!(request.payload_mode, PayloadMode::ExecutableXss) {
        if request.approval_id.is_none() {
            return Err(PlannerError::ApprovalRequired);
        }
        if request.victim_profile.is_none() {
            return Err(PlannerError::ControlledVictimRequired);
        }
    }
    Ok(())
}

// Block sensitive browser clicks unless approval is present
fn validate_actions(request: &ClientSidePlanRequest) -> Result<(), PlannerError> {
    for action in &request.actions {
        let label = action.label.to_lowercase();
        if BANNED_ACTION_KEYWORDS
            .iter()
            .any(|keyword| label.contains(keyword))
            && request.approval_id.is_none()
        {
            return Err(PlannerError::SensitiveActionRequiresApproval);
        }
    }
    Ok(())
}

// Constrain evidence output to client-side evidence paths
fn validate_evidence_path(path: &str) -> Result<(), PlannerError> {
    if !path.starts_with(DEFAULT_EVIDENCE_DIR) || Path::new(path).is_absolute() {
        return Err(PlannerError::UnsafeEvidencePath);
    }
    for component in Path::new(path).components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => return Err(PlannerError::UnsafeEvidencePath),
        }
    }
    Ok(())
}

// Generate a harmless marker payload rather than executable script
fn harmless_marker(target_url: &str) -> String {
    let digest = BrowserProfile::hash_secret(target_url);
    format!("{HARMLESS_MARKER_PREFIX}{}", &digest[..12])
}

#[cfg(test)]
mod tests {
    use crate::planner::{
        BrowserAction, ClientSidePlanRequest, ClientSidePlanner, ClientSideTestKind, PayloadMode,
        PlannerError,
    };
    use crate::BrowserProfile;

    #[test]
    fn reflected_input_plan_uses_harmless_marker_by_default() {
        let request = ClientSidePlanRequest::reflected("https://app.example.test/search?q=x");

        let plan = ClientSidePlanner.plan(request).unwrap();

        assert!(plan.payload.starts_with("mg-marker-"));
        assert!(!plan.payload.contains("<script"));
        assert!(!plan.payload.contains("onerror"));
    }

    #[test]
    fn stored_input_plan_requires_controlled_sender_and_viewer() {
        let mut request = ClientSidePlanRequest::reflected("https://app.example.test/comment");
        request.kind = ClientSideTestKind::StoredInput;

        let err = ClientSidePlanner.plan(request).unwrap_err();

        assert_eq!(err, PlannerError::MissingControlledProfile);
    }

    #[test]
    fn executable_xss_requires_approval_and_controlled_victim() {
        let mut request = ClientSidePlanRequest::reflected("https://app.example.test/search?q=x");
        request.payload_mode = PayloadMode::ExecutableXss;

        let err = ClientSidePlanner.plan(request.clone()).unwrap_err();
        assert_eq!(err, PlannerError::ApprovalRequired);

        request.approval_id = Some("approval-1".into());
        let err = ClientSidePlanner.plan(request).unwrap_err();
        assert_eq!(err, PlannerError::ControlledVictimRequired);
    }

    #[test]
    fn sensitive_browser_actions_require_approval() {
        let mut request = ClientSidePlanRequest::reflected("https://app.example.test/settings");
        request.actions.push(BrowserAction {
            selector: "#export-all".into(),
            label: "Export all customer data".into(),
        });

        let err = ClientSidePlanner.plan(request).unwrap_err();

        assert_eq!(err, PlannerError::SensitiveActionRequiresApproval);
    }

    #[test]
    fn generated_plan_includes_evidence_policy_and_stop_conditions() {
        let profile = BrowserProfile::minimal("victim-profile", "victim").unwrap();
        let mut request = ClientSidePlanRequest::reflected("https://app.example.test/search?q=x");
        request.payload_mode = PayloadMode::ExecutableXss;
        request.approval_id = Some("approval-1".into());
        request.victim_profile = Some(profile);

        let plan = ClientSidePlanner.plan(request).unwrap();

        assert!(plan.evidence.screenshot);
        assert!(plan.evidence.dom_snapshot);
        assert!(plan
            .evidence
            .output_path
            .starts_with("evidence/client-side/"));
        assert!(plan
            .stop_conditions
            .iter()
            .any(|item| item.contains("destructive")));
    }
}
