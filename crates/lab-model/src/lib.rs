// Author: Jeff
// Date: 2026-05-28
// Description: Controlled lab model for multi-account authorization testing
// Notes: Models identities, tenants, roles, resources, and expected boundaries without secrets

use serde::{Deserialize, Serialize};
use std::path::{Component, Path};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum LabModelError {
    #[error("id must be a single safe component")]
    UnsafeId,
    #[error("lab model item not found")]
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub tenant_id: String,
    pub resource_type: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryExpectation {
    pub subject_identity_id: String,
    pub resource_id: String,
    pub expected: ExpectedDecision,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabModel {
    pub engagement: String,
    #[serde(default)]
    pub identities: Vec<Identity>,
    #[serde(default)]
    pub tenants: Vec<Tenant>,
    #[serde(default)]
    pub roles: Vec<Role>,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub boundaries: Vec<BoundaryExpectation>,
}

impl Identity {
    // Create an identity with a safe local identifier
    pub fn new(id: &str, label: &str) -> Result<Self, LabModelError> {
        validate_id(id)?;
        Ok(Self {
            id: id.into(),
            label: label.into(),
        })
    }
}

impl Tenant {
    // Create a tenant with a safe local identifier
    pub fn new(id: &str, label: &str) -> Result<Self, LabModelError> {
        validate_id(id)?;
        Ok(Self {
            id: id.into(),
            label: label.into(),
        })
    }
}

impl Role {
    // Create a role with a safe local identifier
    pub fn new(id: &str, label: &str) -> Result<Self, LabModelError> {
        validate_id(id)?;
        Ok(Self {
            id: id.into(),
            label: label.into(),
        })
    }
}

impl Resource {
    // Create a controlled resource with safe local identifiers
    pub fn new(id: &str, tenant_id: &str, resource_type: &str) -> Result<Self, LabModelError> {
        validate_id(id)?;
        validate_id(tenant_id)?;
        validate_id(resource_type)?;
        Ok(Self {
            id: id.into(),
            tenant_id: tenant_id.into(),
            resource_type: resource_type.into(),
        })
    }
}

impl LabModel {
    // Create an empty lab model for one engagement
    pub fn new(engagement: &str) -> Result<Self, LabModelError> {
        validate_id(engagement)?;
        Ok(Self {
            engagement: engagement.into(),
            identities: Vec::new(),
            tenants: Vec::new(),
            roles: Vec::new(),
            resources: Vec::new(),
            boundaries: Vec::new(),
        })
    }

    // Query the expected relationship between an identity and a resource
    pub fn expected_decision(
        &self,
        identity_id: &str,
        resource_id: &str,
    ) -> Result<&BoundaryExpectation, LabModelError> {
        self.boundaries
            .iter()
            .find(|boundary| {
                boundary.subject_identity_id == identity_id && boundary.resource_id == resource_id
            })
            .ok_or(LabModelError::NotFound)
    }
}

// Reject IDs that could cross engagement boundaries or become filesystem paths
fn validate_id(id: &str) -> Result<(), LabModelError> {
    if id.is_empty() || id.chars().any(char::is_control) {
        return Err(LabModelError::UnsafeId);
    }

    let mut components = Path::new(id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !id.contains('/') && !id.contains('\\') => Ok(()),
        _ => Err(LabModelError::UnsafeId),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        BoundaryExpectation, ExpectedDecision, Identity, LabModel, Resource, Role, Tenant,
    };

    #[test]
    fn identity_tenant_role_resource_round_trip() {
        let model = LabModel {
            engagement: "example-program".into(),
            identities: vec![Identity::new("alice", "alice@example.test").unwrap()],
            tenants: vec![Tenant::new("tenant-a", "Tenant A").unwrap()],
            roles: vec![Role::new("admin", "Admin").unwrap()],
            resources: vec![Resource::new("invoice-1", "tenant-a", "invoice").unwrap()],
            boundaries: Vec::new(),
        };

        let raw = serde_json::to_string(&model).unwrap();
        let parsed: LabModel = serde_json::from_str(&raw).unwrap();

        assert_eq!(parsed.identities[0].id, "alice");
        assert_eq!(parsed.resources[0].tenant_id, "tenant-a");
    }

    #[test]
    fn expected_deny_boundary_can_be_queried() {
        let mut model = LabModel::new("example-program").unwrap();
        model.boundaries.push(BoundaryExpectation {
            subject_identity_id: "alice".into(),
            resource_id: "invoice-b".into(),
            expected: ExpectedDecision::Deny,
            reason: "alice is not in tenant-b".into(),
        });

        let decision = model.expected_decision("alice", "invoice-b").unwrap();

        assert_eq!(decision.expected, ExpectedDecision::Deny);
    }

    #[test]
    fn invalid_cross_engagement_ids_are_rejected() {
        let err = Identity::new("../other-engagement/alice", "alice@example.test").unwrap_err();

        assert!(err.to_string().contains("single safe component"));
    }
}
