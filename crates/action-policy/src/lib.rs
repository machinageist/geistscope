// Author: Jeff
// Date: 2026-05-28
// Description: Rust-owned action policy decisions for autonomous hunting tools
// Notes: Active tools must ask this crate before network or browser actions

use engagement::{ScopeDecision, ScopeVerdict};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    HttpRequest,
    ReplayRequest,
    BrowserAutomation,
    ProxyCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    ReadOnly,
    LowActive,
    HighActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRequirement {
    AnonymousAllowed,
    SessionRequired,
    ControlledSessionRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    NotRequired,
    Missing,
    Granted { approval_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub action: ActionKind,
    pub risk: RiskLevel,
    pub scope: ScopeDecision,
    pub session: SessionRequirement,
    pub approval: ApprovalState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyVerdict {
    Allowed,
    Blocked,
    RequiresApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub verdict: PolicyVerdict,
    pub reason: String,
}

#[derive(Debug, Default, Clone)]
pub struct ActionPolicy;

impl ActionPolicy {
    // Evaluate an action request before any active operation runs
    pub fn evaluate(&self, request: &PolicyRequest) -> PolicyDecision {
        if !matches!(request.scope.decision, ScopeVerdict::InScope) {
            return PolicyDecision {
                verdict: PolicyVerdict::Blocked,
                reason: "scope decision is not in_scope".into(),
            };
        }

        if matches!(request.risk, RiskLevel::HighActive)
            && !matches!(request.approval, ApprovalState::Granted { .. })
        {
            return PolicyDecision {
                verdict: PolicyVerdict::RequiresApproval,
                reason: "high-active action requires approval".into(),
            };
        }

        PolicyDecision {
            verdict: PolicyVerdict::Allowed,
            reason: "action allowed by policy".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use engagement::{ScopeDecision, ScopeRuleMatch, ScopeVerdict};

    use crate::{
        ActionKind, ActionPolicy, ApprovalState, PolicyRequest, PolicyVerdict, RiskLevel,
        SessionRequirement,
    };

    fn decision(verdict: ScopeVerdict) -> ScopeDecision {
        ScopeDecision {
            input: "https://admin.example-program.com/".into(),
            normalized_host: Some("admin.example-program.com".into()),
            normalized_url: Some("https://admin.example-program.com/".into()),
            decision: verdict,
            matched_allow: vec![ScopeRuleMatch {
                pattern: "*.example-program.com".into(),
            }],
            matched_deny: Vec::new(),
            reason: "test fixture".into(),
            asset_type: None,
            bounty_eligible: None,
            submission_eligible: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn high_active_actions_require_approval() {
        let request = PolicyRequest {
            action: ActionKind::ReplayRequest,
            risk: RiskLevel::HighActive,
            scope: decision(ScopeVerdict::InScope),
            session: SessionRequirement::AnonymousAllowed,
            approval: ApprovalState::Missing,
        };

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::RequiresApproval);
        assert!(policy_decision.reason.contains("approval"));
    }

    #[test]
    fn out_of_scope_or_ambiguous_scope_fails_closed() {
        for verdict in [ScopeVerdict::OutOfScope, ScopeVerdict::Ambiguous] {
            let request = PolicyRequest {
                action: ActionKind::HttpRequest,
                risk: RiskLevel::LowActive,
                scope: decision(verdict),
                session: SessionRequirement::AnonymousAllowed,
                approval: ApprovalState::NotRequired,
            };

            let policy_decision = ActionPolicy.evaluate(&request);

            assert_eq!(policy_decision.verdict, PolicyVerdict::Blocked);
            assert!(policy_decision.reason.contains("scope"));
        }
    }

    #[test]
    fn read_only_scoped_anonymous_actions_are_allowed() {
        let request = PolicyRequest {
            action: ActionKind::HttpRequest,
            risk: RiskLevel::ReadOnly,
            scope: decision(ScopeVerdict::InScope),
            session: SessionRequirement::AnonymousAllowed,
            approval: ApprovalState::NotRequired,
        };

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::Allowed);
        assert!(policy_decision.reason.contains("allowed"));
    }
}
