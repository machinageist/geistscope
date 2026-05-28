// Author: Jeff
// Date: 2026-05-28
// Description: Rust-owned action policy decisions for autonomous hunting tools
// Notes: Active tools must ask this crate before network or browser actions

use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeVerdict};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

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
    pub program_rules: Option<ProgramRulesSnapshot>,
    pub evaluated_at: OffsetDateTime,
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

        if is_active(request.risk) {
            let Some(program_rules) = &request.program_rules else {
                return PolicyDecision {
                    verdict: PolicyVerdict::Blocked,
                    reason: "active action requires current program rules snapshot".into(),
                };
            };

            if !program_rules.is_current_at(request.evaluated_at) {
                return PolicyDecision {
                    verdict: PolicyVerdict::Blocked,
                    reason: "program rules snapshot is expired".into(),
                };
            }

            if !program_rules.automation_allowed {
                return PolicyDecision {
                    verdict: PolicyVerdict::Blocked,
                    reason: "program rules disallow automation".into(),
                };
            }

            match request.scope.bounty_eligible {
                Some(true) => {}
                Some(false) => {
                    return PolicyDecision {
                        verdict: PolicyVerdict::Blocked,
                        reason: "target is not bounty eligible".into(),
                    };
                }
                None if matches!(request.approval, ApprovalState::Granted { .. }) => {}
                None => {
                    return PolicyDecision {
                        verdict: PolicyVerdict::RequiresApproval,
                        reason: "target eligibility is unknown and requires approval".into(),
                    };
                }
            }
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

// Return true for actions that can touch a target system
fn is_active(risk: RiskLevel) -> bool {
    matches!(risk, RiskLevel::LowActive | RiskLevel::HighActive)
}

#[cfg(test)]
mod tests {
    use engagement::{ProgramRulesSnapshot, ScopeDecision, ScopeRuleMatch, ScopeVerdict};
    use time::{Duration, OffsetDateTime};

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
            bounty_eligible: Some(true),
            submission_eligible: None,
            notes: Vec::new(),
        }
    }

    fn valid_rules(now: OffsetDateTime) -> ProgramRulesSnapshot {
        ProgramRulesSnapshot {
            captured_at: now - Duration::hours(1),
            expires_at: now + Duration::days(1),
            automation_allowed: true,
            source: "manual".into(),
            notes: Vec::new(),
        }
    }

    fn request(risk: RiskLevel, rules: Option<ProgramRulesSnapshot>) -> PolicyRequest {
        let now = OffsetDateTime::now_utc();
        PolicyRequest {
            action: ActionKind::HttpRequest,
            risk,
            scope: decision(ScopeVerdict::InScope),
            session: SessionRequirement::AnonymousAllowed,
            approval: ApprovalState::NotRequired,
            program_rules: rules.or_else(|| Some(valid_rules(now))),
            evaluated_at: now,
        }
    }

    #[test]
    fn high_active_actions_require_approval() {
        let mut request = request(RiskLevel::HighActive, None);
        request.action = ActionKind::ReplayRequest;
        request.approval = ApprovalState::Missing;

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::RequiresApproval);
        assert!(policy_decision.reason.contains("approval"));
    }

    #[test]
    fn out_of_scope_or_ambiguous_scope_fails_closed() {
        for verdict in [ScopeVerdict::OutOfScope, ScopeVerdict::Ambiguous] {
            let mut request = request(RiskLevel::LowActive, None);
            request.scope = decision(verdict);

            let policy_decision = ActionPolicy.evaluate(&request);

            assert_eq!(policy_decision.verdict, PolicyVerdict::Blocked);
            assert!(policy_decision.reason.contains("scope"));
        }
    }

    #[test]
    fn active_actions_without_rules_snapshot_are_blocked() {
        let now = OffsetDateTime::now_utc();
        let request = PolicyRequest {
            action: ActionKind::HttpRequest,
            risk: RiskLevel::LowActive,
            scope: decision(ScopeVerdict::InScope),
            session: SessionRequirement::AnonymousAllowed,
            approval: ApprovalState::NotRequired,
            program_rules: None,
            evaluated_at: now,
        };

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::Blocked);
        assert!(policy_decision.reason.contains("program rules"));
    }

    #[test]
    fn expired_rules_snapshot_blocks_active_actions() {
        let now = OffsetDateTime::now_utc();
        let mut rules = valid_rules(now);
        rules.expires_at = now - Duration::seconds(1);
        let request = request(RiskLevel::LowActive, Some(rules));

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::Blocked);
        assert!(policy_decision.reason.contains("expired"));
    }

    #[test]
    fn automation_disallowed_blocks_active_actions() {
        let now = OffsetDateTime::now_utc();
        let mut rules = valid_rules(now);
        rules.automation_allowed = false;
        let request = request(RiskLevel::LowActive, Some(rules));

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::Blocked);
        assert!(policy_decision.reason.contains("automation"));
    }

    #[test]
    fn unknown_bounty_eligibility_requires_approval_for_active_actions() {
        let mut request = request(RiskLevel::LowActive, None);
        request.scope.bounty_eligible = None;

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::RequiresApproval);
        assert!(policy_decision.reason.contains("eligibility"));
    }

    #[test]
    fn read_only_scoped_anonymous_actions_are_allowed_without_rules_snapshot() {
        let now = OffsetDateTime::now_utc();
        let request = PolicyRequest {
            action: ActionKind::HttpRequest,
            risk: RiskLevel::ReadOnly,
            scope: decision(ScopeVerdict::InScope),
            session: SessionRequirement::AnonymousAllowed,
            approval: ApprovalState::NotRequired,
            program_rules: None,
            evaluated_at: now,
        };

        let policy_decision = ActionPolicy.evaluate(&request);

        assert_eq!(policy_decision.verdict, PolicyVerdict::Allowed);
        assert!(policy_decision.reason.contains("allowed"));
    }
}
