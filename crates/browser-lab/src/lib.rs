// Author: Jeff
// Date: 2026-05-28
// Description: Isolated browser/container profiles for controlled account testing
// Notes: Profile metadata must not expose cookies, storage values, or extension secrets

pub mod client_side;
pub mod planner;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Component, Path};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BrowserLabError {
    #[error("id must be a single safe component")]
    UnsafeId,
    #[error("writable mount source is outside engagement root")]
    MountEscapesRoot,
    #[error("mount target must be an absolute container path")]
    UnsafeMountTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserEngine {
    Podman,
    Docker,
    PlaywrightLocal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxySettings {
    pub host: String,
    pub port: u16,
    pub scheme: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMount {
    pub source: String,
    pub target: String,
    pub mode: MountMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserProfile {
    pub id: String,
    pub engine: BrowserEngine,
    pub image: String,
    pub session_id: String,
    pub identity_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub proxy: ProxySettings,
    pub storage_volume: String,
    pub cache_volume: String,
    #[serde(default)]
    pub mounts: Vec<ProfileMount>,
    #[serde(default)]
    pub cookie_names: Vec<String>,
    #[serde(default)]
    pub local_storage_keys: Vec<String>,
    #[serde(default)]
    pub session_storage_keys: Vec<String>,
    #[serde(default)]
    pub secret_observation_hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedBrowserProfile {
    pub id: String,
    pub engine: BrowserEngine,
    pub session_id: String,
    pub identity_id: String,
    pub tenant_id: String,
    pub role_id: String,
    pub proxy_host: String,
    pub proxy_port: u16,
    pub cookie_names: Vec<String>,
    pub local_storage_keys: Vec<String>,
    pub session_storage_keys: Vec<String>,
    pub secret_observation_hashes: Vec<String>,
}

impl ProxySettings {
    // Create loopback proxy settings for a profile
    pub fn loopback(host: &str, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            scheme: "http".into(),
        }
    }
}

impl BrowserProfile {
    // Create a browser profile bound to one controlled identity and tenant
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &str,
        engine: BrowserEngine,
        image: String,
        session_id: String,
        identity_id: String,
        tenant_id: String,
        role_id: String,
        proxy: ProxySettings,
    ) -> Result<Self, BrowserLabError> {
        validate_id(id)?;
        validate_id(&session_id)?;
        validate_id(&identity_id)?;
        validate_id(&tenant_id)?;
        validate_id(&role_id)?;
        Ok(Self {
            id: id.into(),
            engine,
            image,
            session_id,
            identity_id,
            tenant_id,
            role_id,
            proxy,
            storage_volume: format!("browser-profiles/{id}/storage"),
            cache_volume: format!("browser-profiles/{id}/cache"),
            mounts: Vec::new(),
            cookie_names: Vec::new(),
            local_storage_keys: Vec::new(),
            session_storage_keys: Vec::new(),
            secret_observation_hashes: Vec::new(),
        })
    }

    // Create a minimal local Playwright profile for tests and scaffolding
    pub fn minimal(id: &str, identity_id: &str) -> Result<Self, BrowserLabError> {
        Self::new(
            id,
            BrowserEngine::PlaywrightLocal,
            "mcr.microsoft.com/playwright:latest".into(),
            format!("session-{identity_id}"),
            identity_id.into(),
            "default-tenant".into(),
            "default-role".into(),
            ProxySettings::loopback("127.0.0.1", 8080),
        )
    }

    // Validate profile mounts before container/browser launch
    pub fn validate_mounts(&self) -> Result<(), BrowserLabError> {
        for mount in &self.mounts {
            validate_container_target(&mount.target)?;
            if matches!(mount.mode, MountMode::ReadWrite) {
                validate_relative_source(&mount.source)?;
            }
        }
        Ok(())
    }

    // Return model-visible profile metadata without secret values
    pub fn redacted_metadata(&self) -> RedactedBrowserProfile {
        RedactedBrowserProfile {
            id: self.id.clone(),
            engine: self.engine.clone(),
            session_id: self.session_id.clone(),
            identity_id: self.identity_id.clone(),
            tenant_id: self.tenant_id.clone(),
            role_id: self.role_id.clone(),
            proxy_host: self.proxy.host.clone(),
            proxy_port: self.proxy.port,
            cookie_names: self.cookie_names.clone(),
            local_storage_keys: self.local_storage_keys.clone(),
            session_storage_keys: self.session_storage_keys.clone(),
            secret_observation_hashes: self.secret_observation_hashes.clone(),
        }
    }

    // Hash a secret observation without retaining its raw value
    pub fn hash_secret(value: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(value.as_bytes());
        hex::encode(hasher.finalize())
    }
}

// Reject IDs that could cross profile or engagement boundaries
fn validate_id(id: &str) -> Result<(), BrowserLabError> {
    if id.is_empty() || id.chars().any(char::is_control) {
        return Err(BrowserLabError::UnsafeId);
    }

    let mut components = Path::new(id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !id.contains('/') && !id.contains('\\') => Ok(()),
        _ => Err(BrowserLabError::UnsafeId),
    }
}

// Reject writable sources that are absolute or contain traversal
fn validate_relative_source(source: &str) -> Result<(), BrowserLabError> {
    if source.is_empty() || Path::new(source).is_absolute() {
        return Err(BrowserLabError::MountEscapesRoot);
    }
    for component in Path::new(source).components() {
        match component {
            Component::Normal(_) => {}
            Component::CurDir => {}
            _ => return Err(BrowserLabError::MountEscapesRoot),
        }
    }
    Ok(())
}

// Require absolute container paths without parent traversal
fn validate_container_target(target: &str) -> Result<(), BrowserLabError> {
    let path = Path::new(target);
    if !path.is_absolute() {
        return Err(BrowserLabError::UnsafeMountTarget);
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(BrowserLabError::UnsafeMountTarget);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{BrowserEngine, BrowserProfile, MountMode, ProfileMount, ProxySettings};

    #[test]
    fn browser_profile_serializes_core_account_context() {
        let profile = BrowserProfile::new(
            "alice-admin",
            BrowserEngine::Podman,
            "mcr.microsoft.com/playwright:v1".into(),
            "session-alice".into(),
            "alice".into(),
            "tenant-a".into(),
            "admin".into(),
            ProxySettings::loopback("127.0.0.1", 8080),
        )
        .unwrap();

        let raw = serde_json::to_string(&profile).unwrap();
        let parsed: BrowserProfile = serde_json::from_str(&raw).unwrap();

        assert_eq!(parsed.engine, BrowserEngine::Podman);
        assert_eq!(parsed.identity_id, "alice");
        assert_eq!(
            parsed.storage_volume,
            "browser-profiles/alice-admin/storage"
        );
    }

    #[test]
    fn different_identities_get_distinct_storage_volumes() {
        let alice = BrowserProfile::minimal("alice-profile", "alice").unwrap();
        let bob = BrowserProfile::minimal("bob-profile", "bob").unwrap();

        assert_ne!(alice.storage_volume, bob.storage_volume);
        assert_ne!(alice.cache_volume, bob.cache_volume);
    }

    #[test]
    fn writable_mounts_cannot_escape_engagement_root() {
        let mut profile = BrowserProfile::minimal("alice-profile", "alice").unwrap();
        profile.mounts.push(ProfileMount {
            source: "../outside".into(),
            target: "/data".into(),
            mode: MountMode::ReadWrite,
        });

        let err = profile.validate_mounts().unwrap_err();

        assert!(err.to_string().contains("outside engagement root"));
    }

    #[test]
    fn redacted_metadata_never_emits_browser_secret_values() {
        let mut profile = BrowserProfile::minimal("alice-profile", "alice").unwrap();
        profile.cookie_names.push("sessionid".into());
        profile.local_storage_keys.push("jwt".into());
        profile
            .secret_observation_hashes
            .push(BrowserProfile::hash_secret("super-secret-token"));

        let redacted = profile.redacted_metadata();
        let raw = serde_json::to_string(&redacted).unwrap();

        assert!(raw.contains("sessionid"));
        assert!(raw.contains("jwt"));
        assert!(!raw.contains("super-secret-token"));
        assert!(!raw.contains("cookie_value"));
        assert!(!raw.contains("localStorage_value"));
    }
}
