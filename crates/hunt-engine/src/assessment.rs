// Author: Jeff
// Date: 2026-07-31
// Description: Pure deterministic SSRF assessment over execution and callback observation
// Notes: No wall clock, no model judgment, and never promotes a verified finding

use serde::Serialize;

use crate::{
    CallbackCorrelation, EvidenceKind, ExecutorOutcome, HttpTransactionRecord, SsrfProbePlan,
};

// Summarize the authorized execution outcome for deterministic assessment
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionState {
    Completed {
        plan_hash: String,
    },
    Failed {
        plan_hash: String,
        outcome: ExecutorOutcome,
    },
    NotExecuted,
}

impl TransactionState {
    // Summarize a completed or stopped bounded transaction record
    pub fn from_record(record: &HttpTransactionRecord) -> Self {
        if record.outcome() == ExecutorOutcome::Completed {
            Self::Completed {
                plan_hash: record.plan_hash().to_string(),
            }
        } else {
            Self::Failed {
                plan_hash: record.plan_hash().to_string(),
                outcome: record.outcome(),
            }
        }
    }

    // Represent an authorization or execution failure that produced no transaction
    pub fn not_executed() -> Self {
        Self::NotExecuted
    }

    // Return the plan hash the transaction ran for, when one executed
    fn plan_hash(&self) -> Option<&str> {
        match self {
            Self::Completed { plan_hash } | Self::Failed { plan_hash, .. } => Some(plan_hash),
            Self::NotExecuted => None,
        }
    }

    // Return the executor outcome when a transaction was attempted
    fn outcome(&self) -> Option<ExecutorOutcome> {
        match self {
            Self::Completed { .. } => Some(ExecutorOutcome::Completed),
            Self::Failed { outcome, .. } => Some(*outcome),
            Self::NotExecuted => None,
        }
    }
}

// Classify one finalized SSRF observation without promoting a verified finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentClass {
    Pending,
    CallbackProven,
    Negative,
    Invalid,
}

// Explain the deterministic reason for an assessment class
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentReason {
    CallbackProven,
    ObservationPending,
    NoCallbackWithinWindow,
    InvalidCallback,
    ExecutionFailed,
    TransactionPlanMismatch,
    TransactionMissing,
}

// Name the deterministic callback correlation class without carrying secrets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackCorrelationClass {
    Matched,
    Missing,
    UnknownToken,
    PlanMismatch,
    Expired,
    Reused,
}

// Carry the injected observation-window timestamps in milliseconds
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ObservationWindow {
    start_ms: u64,
    deadline_ms: u64,
    finalized_at_ms: u64,
}

impl ObservationWindow {
    // Create an observation window from injected deterministic timestamps
    pub fn new(start_ms: u64, deadline_ms: u64, finalized_at_ms: u64) -> Self {
        Self {
            start_ms,
            deadline_ms,
            finalized_at_ms,
        }
    }
}

// Preserve one deterministic SSRF assessment as serializable evidence input
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SsrfAssessment {
    plan_hash: String,
    candidate_id: String,
    transaction_outcome: Option<ExecutorOutcome>,
    transaction_plan_hash: Option<String>,
    callback_correlation: CallbackCorrelationClass,
    callback_body_sha256: Option<String>,
    observation: ObservationWindow,
    class: AssessmentClass,
    reason: AssessmentReason,
    satisfied_requirements: Vec<EvidenceKind>,
    missing_requirements: Vec<EvidenceKind>,
}

impl SsrfAssessment {
    // Return the deterministic assessment class
    pub fn class(&self) -> AssessmentClass {
        self.class
    }

    // Return the deterministic assessment reason code
    pub fn reason(&self) -> AssessmentReason {
        self.reason
    }

    // Return the plan hash the assessment was computed for
    pub fn plan_hash(&self) -> &str {
        &self.plan_hash
    }

    // Return whether the callback was proven, sufficient for evidence commit only
    pub fn is_callback_proven(&self) -> bool {
        matches!(self.class, AssessmentClass::CallbackProven)
    }
}

// Emit one deterministic assessment from execution output and callback observation
#[derive(Debug, Default, Clone)]
pub struct SsrfAssessor;

impl SsrfAssessor {
    // Classify a finalized observation into exactly one deterministic assessment
    pub fn assess(
        &self,
        plan: &SsrfProbePlan,
        transaction: &TransactionState,
        correlation: &CallbackCorrelation,
        observation: ObservationWindow,
    ) -> SsrfAssessment {
        let (correlation_class, callback_body_sha256) = classify_correlation(correlation);
        let transaction_outcome = transaction.outcome();
        let transaction_plan_hash = transaction.plan_hash().map(str::to_string);

        let (class, reason) = classify(plan, transaction, correlation, observation);
        let (satisfied_requirements, missing_requirements) =
            requirement_state(plan, transaction, correlation);

        SsrfAssessment {
            plan_hash: plan.plan_hash().to_string(),
            candidate_id: plan.view().candidate_id().to_string(),
            transaction_outcome,
            transaction_plan_hash,
            callback_correlation: correlation_class,
            callback_body_sha256,
            observation,
            class,
            reason,
            satisfied_requirements,
            missing_requirements,
        }
    }
}

// Decide the deterministic class and reason for one finalized observation
fn classify(
    plan: &SsrfProbePlan,
    transaction: &TransactionState,
    correlation: &CallbackCorrelation,
    observation: ObservationWindow,
) -> (AssessmentClass, AssessmentReason) {
    let Some(transaction_plan_hash) = transaction.plan_hash() else {
        return (
            AssessmentClass::Invalid,
            AssessmentReason::TransactionMissing,
        );
    };
    if transaction_plan_hash != plan.plan_hash() {
        return (
            AssessmentClass::Invalid,
            AssessmentReason::TransactionPlanMismatch,
        );
    }
    if !matches!(transaction, TransactionState::Completed { .. }) {
        return (AssessmentClass::Invalid, AssessmentReason::ExecutionFailed);
    }

    match correlation {
        CallbackCorrelation::Matched(_) => (
            AssessmentClass::CallbackProven,
            AssessmentReason::CallbackProven,
        ),
        CallbackCorrelation::Missing => {
            if observation.finalized_at_ms >= observation.deadline_ms {
                (
                    AssessmentClass::Negative,
                    AssessmentReason::NoCallbackWithinWindow,
                )
            } else {
                (
                    AssessmentClass::Pending,
                    AssessmentReason::ObservationPending,
                )
            }
        }
        CallbackCorrelation::UnknownToken
        | CallbackCorrelation::PlanMismatch
        | CallbackCorrelation::Expired
        | CallbackCorrelation::Reused => {
            (AssessmentClass::Invalid, AssessmentReason::InvalidCallback)
        }
    }
}

// Map the recorder correlation into a secret-free class plus optional body digest
fn classify_correlation(
    correlation: &CallbackCorrelation,
) -> (CallbackCorrelationClass, Option<String>) {
    match correlation {
        CallbackCorrelation::Matched(record) => (
            CallbackCorrelationClass::Matched,
            Some(record.body_sha256().to_string()),
        ),
        CallbackCorrelation::Missing => (CallbackCorrelationClass::Missing, None),
        CallbackCorrelation::UnknownToken => (CallbackCorrelationClass::UnknownToken, None),
        CallbackCorrelation::PlanMismatch => (CallbackCorrelationClass::PlanMismatch, None),
        CallbackCorrelation::Expired => (CallbackCorrelationClass::Expired, None),
        CallbackCorrelation::Reused => (CallbackCorrelationClass::Reused, None),
    }
}

// Report satisfied and missing evidence requirement kinds without proof construction
fn requirement_state(
    plan: &SsrfProbePlan,
    transaction: &TransactionState,
    correlation: &CallbackCorrelation,
) -> (Vec<EvidenceKind>, Vec<EvidenceKind>) {
    let policy_satisfied = !matches!(transaction, TransactionState::NotExecuted);
    let response_satisfied = matches!(transaction, TransactionState::Completed { .. });
    let callback_satisfied = matches!(correlation, CallbackCorrelation::Matched(_));

    let mut satisfied = Vec::new();
    let mut missing = Vec::new();
    for requirement in plan.action_plan().evidence_contract().requirements() {
        let met = match requirement.kind() {
            EvidenceKind::PolicyDecision => policy_satisfied,
            EvidenceKind::RequestResponse => response_satisfied,
            EvidenceKind::CallbackCorrelation => callback_satisfied,
            EvidenceKind::SemanticVerdict => false,
        };
        if met {
            satisfied.push(requirement.kind());
        } else {
            missing.push(requirement.kind());
        }
    }
    (satisfied, missing)
}
