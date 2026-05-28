/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-02
 * Description:     Bug bounty engagement workspace — directory layout, scope rules, audit log
 * Notes:           Public API surface: Engagement, Scope, Finding, Severity, Status.
 *                  All other types are internal to their respective modules.
 *******************************************************************/

pub mod artifact_store;
pub mod audit;
pub mod engagement;
pub mod finding;
pub mod program;
pub mod scope;
pub mod tool_finding;
pub mod traffic;

pub use artifact_store::{ArtifactStore, ArtifactWriteRecord};
pub use audit::{AuditDecision, AuditEvent, AuditRisk, append_audit_event};
pub use engagement::{Engagement, EngagementMeta};
pub use finding::{Finding, Severity, Status};
pub use program::ProgramRulesSnapshot;
pub use scope::{Scope, ScopeDecision, ScopeRuleMatch, ScopeVerdict};
pub use tool_finding::{FindingSeverity, ToolFinding, write_finding};
pub use traffic::{
    AuthState, BodyRef, HeaderRecord, ImportSummary, ResponseDiff, ResponseFingerprint,
    TrafficFilter, TrafficImportFormat, TrafficRecord, TrafficResponse, TrafficStore,
    diff_response_fingerprints, find_traffic_record, import_traffic_file, load_traffic_records,
    raw_http_request, response_fingerprint_from_parts, response_fingerprint_from_record,
    search_traffic_records,
};

#[derive(Debug, thiserror::Error)]
pub enum EngagementError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("time format: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("engagement already exists at {0}")]
    AlreadyExists(String),
    #[error("engagement not found at {0}")]
    NotFound(String),
    #[error("invalid: {0}")]
    Invalid(String),
}
