// Author: Jeff
// Date: 2026-05-02
// Description: Bug bounty engagement workspace — directory layout, scope rules, audit log

pub mod engagement;
pub mod finding;
pub mod scope;

pub use engagement::{Engagement, EngagementMeta};
pub use finding::{Finding, Severity, Status};
pub use scope::Scope;

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
