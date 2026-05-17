/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-02
 * Description:     Bug bounty engagement workspace — directory layout, scope rules, audit log
 * Notes:           Public API surface: Engagement, Scope, Finding, Severity, Status.
 *                  All other types are internal to their respective modules.
 *******************************************************************/

pub mod engagement;
pub mod finding;
pub mod scope;
pub mod traffic;

pub use engagement::{Engagement, EngagementMeta};
pub use finding::{Finding, Severity, Status};
pub use scope::Scope;
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
