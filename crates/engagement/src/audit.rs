// Author: Jeff
// Date: 2026-05-28
// Description: Typed audit events for autonomous hunting dispatch and policy decisions
// Notes: JSONL audit records keep tool, action, risk, decision, target, and evidence separate

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

use crate::EngagementError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRisk {
    ReadOnly,
    LowActive,
    HighActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allowed,
    Blocked,
    RequiresApproval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: OffsetDateTime,
    pub tool: String,
    pub action: String,
    pub risk: AuditRisk,
    pub decision: AuditDecision,
    pub target: String,
    pub reason: String,
    #[serde(default)]
    pub evidence_paths: Vec<String>,
}

// Append one validated audit event as JSONL under the engagement root
pub fn append_audit_event(root: &Path, event: &AuditEvent) -> Result<PathBuf, EngagementError> {
    validate_event(event)?;
    let audit_dir = root.join("audit");
    std::fs::create_dir_all(&audit_dir)?;
    let path = audit_dir.join("events.jsonl");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let line = serde_json::to_string(event)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    Ok(path)
}

// Reject control characters before they can forge logs or terminal output
fn validate_event(event: &AuditEvent) -> Result<(), EngagementError> {
    for value in [&event.tool, &event.action, &event.target, &event.reason] {
        reject_control_characters(value)?;
    }

    for evidence_path in &event.evidence_paths {
        reject_control_characters(evidence_path)?;
    }

    Ok(())
}

// Reject strings containing line breaks or other control bytes
fn reject_control_characters(value: &str) -> Result<(), EngagementError> {
    if value.chars().any(char::is_control) {
        return Err(EngagementError::Invalid(
            "audit event fields cannot contain control characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;

    use crate::audit::{AuditDecision, AuditEvent, AuditRisk, append_audit_event};

    #[test]
    fn append_typed_audit_event_writes_jsonl() {
        let tmp = tempfile::tempdir().unwrap();
        let event = AuditEvent {
            timestamp: OffsetDateTime::UNIX_EPOCH,
            tool: "mg-harness".into(),
            action: "scope.explain".into(),
            risk: AuditRisk::ReadOnly,
            decision: AuditDecision::Allowed,
            target: "admin.example-program.com".into(),
            reason: "scope explanation allowed".into(),
            evidence_paths: vec!["evidence/scope.json".into()],
        };

        append_audit_event(tmp.path(), &event).unwrap();

        let raw = std::fs::read_to_string(tmp.path().join("audit").join("events.jsonl")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(parsed["tool"], "mg-harness");
        assert_eq!(parsed["risk"], "read_only");
        assert_eq!(parsed["decision"], "allowed");
        assert_eq!(parsed["evidence_paths"][0], "evidence/scope.json");
    }

    #[test]
    fn audit_fields_reject_control_characters() {
        let tmp = tempfile::tempdir().unwrap();
        let event = AuditEvent {
            timestamp: OffsetDateTime::UNIX_EPOCH,
            tool: "mg-harness\nforged".into(),
            action: "scope.explain".into(),
            risk: AuditRisk::ReadOnly,
            decision: AuditDecision::Blocked,
            target: "admin.example-program.com".into(),
            reason: "blocked".into(),
            evidence_paths: Vec::new(),
        };

        let err = append_audit_event(tmp.path(), &event).unwrap_err();

        assert!(err.to_string().contains("control characters"));
    }
}
