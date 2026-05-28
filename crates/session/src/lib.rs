/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Engagement session configuration and auth headers
 * Notes:           Initial slice stores environment-variable references in
 *                  session.json, never plaintext token/password values.
 *                  Form/OAuth refresh and encrypted cookie storage are pending.
 *******************************************************************/

use std::env;
use std::fs;
use std::path::{Component, Path, PathBuf};

use engagement::Engagement;
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const SESSIONS_DIR: &str = "sessions";

// Session config persisted at engagements/<name>/session.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    #[serde(default = "default_login_method")]
    pub login_method: String,
    #[serde(default = "default_token_header")]
    pub token_header: String,
    #[serde(default = "default_token_prefix")]
    pub token_prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_cookie: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_refresh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

impl Default for SessionConfig {
    // Build a default token-oriented config
    fn default() -> Self {
        Self {
            username: None,
            password_env: None,
            login_url: None,
            login_method: default_login_method(),
            token_header: default_token_header(),
            token_prefix: default_token_prefix(),
            token_env: None,
            session_cookie: None,
            token_refresh_url: None,
            valid_until: None,
        }
    }
}

// Named session profile persisted under sessions/<name>.json
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionProfile {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login_url: Option<String>,
    #[serde(default)]
    pub auth_refs: Vec<SecretRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_var: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

impl SecretRef {
    // Create a reference to a secret stored in an environment variable
    pub fn env(kind: &str, env_var: &str) -> Self {
        Self {
            kind: kind.into(),
            env_var: Some(env_var.into()),
            value: None,
        }
    }

    // Create an unsafe plaintext ref for rejection tests and validation boundaries
    pub fn plaintext(kind: &str, value: &str) -> Self {
        Self {
            kind: kind.into(),
            env_var: None,
            value: Some(value.into()),
        }
    }
}

impl SessionProfile {
    // Summarize the profile without exposing secret names or values
    pub fn redacted_summary(&self) -> String {
        let auth_kinds: Vec<&str> = self
            .auth_refs
            .iter()
            .map(|auth_ref| auth_ref.kind.as_str())
            .collect();
        format!(
            "session={} username_present={} login_url_present={} auth_refs={}",
            self.name,
            self.username.is_some(),
            self.login_url.is_some(),
            auth_kinds.join(",")
        )
    }
}

// Session errors for callers
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("network: {0}")]
    Network(#[from] reqwest::Error),
    #[error("header value: {0}")]
    HeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("header name: {0}")]
    HeaderName(#[from] reqwest::header::InvalidHeaderName),
    #[error("environment variable {0} is not set")]
    MissingEnv(String),
    #[error("session is not configured")]
    NotConfigured,
    #[error("target {0} is out of scope")]
    OutOfScope(String),
    #[error("plaintext session cookies cannot be saved by this initial session slice")]
    PlaintextSecretRejected,
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("session profile name must be a single safe component")]
    InvalidSessionName,
    #[error("session profile is expired")]
    Expired,
    #[error("invalid session expiry: {0}")]
    InvalidExpiry(String),
}

// Load auth headers for an engagement; empty when no session.json exists
pub async fn get_auth_headers(engagement: &Engagement) -> Result<HeaderMap, SessionError> {
    get_auth_headers_sync(engagement)
}

// Load auth headers for blocking callers such as the TUI browser
pub fn get_auth_headers_sync(engagement: &Engagement) -> Result<HeaderMap, SessionError> {
    let config = match load_session_config(engagement) {
        Ok(config) => config,
        Err(SessionError::NotConfigured) => return Ok(HeaderMap::new()),
        Err(err) => return Err(err),
    };
    build_auth_headers(&config, |name| env::var(name).ok())
}

// Refresh a session if it is close to expiry
pub async fn refresh_if_needed(_engagement: &Engagement) -> Result<(), SessionError> {
    // Form and OAuth refresh flows land in the next session-management slice.
    Ok(())
}

// Test whether current session headers can access a scoped URL
pub async fn test_session(engagement: &Engagement, test_url: &str) -> Result<bool, SessionError> {
    ensure_url_in_scope(engagement, test_url)?;
    let headers = get_auth_headers(engagement).await?;
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client.get(test_url).send().await?;
    Ok(response.status().as_u16() < 400)
}

// Save a session config without writing plaintext secrets
pub fn save_session_config(
    engagement: &Engagement,
    config: &SessionConfig,
) -> Result<PathBuf, SessionError> {
    if config.session_cookie.is_some() {
        return Err(SessionError::PlaintextSecretRejected);
    }
    let path = session_path(engagement);
    let json = serde_json::to_string_pretty(config)?;
    fs::write(&path, json)?;
    Ok(path)
}

// Load session config from session.json
pub fn load_session_config(engagement: &Engagement) -> Result<SessionConfig, SessionError> {
    let path = session_path(engagement);
    if !path.exists() {
        return Err(SessionError::NotConfigured);
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

// Return the session.json path for an engagement
pub fn session_path(engagement: &Engagement) -> PathBuf {
    engagement.root.join("session.json")
}

// Save a named session profile without writing plaintext secret material
pub fn save_session_profile(
    engagement: &Engagement,
    profile: &SessionProfile,
) -> Result<PathBuf, SessionError> {
    validate_session_name(&profile.name)?;
    if profile
        .auth_refs
        .iter()
        .any(|auth_ref| auth_ref.value.is_some())
    {
        return Err(SessionError::PlaintextSecretRejected);
    }

    let path = session_profile_path(engagement, &profile.name)?;
    let parent = path.parent().ok_or(SessionError::InvalidSessionName)?;
    fs::create_dir_all(parent)?;
    let json = serde_json::to_string_pretty(profile)?;
    fs::write(&path, json)?;
    Ok(path)
}

// Load a named session profile by safe local name
pub fn load_session_profile(
    engagement: &Engagement,
    name: &str,
) -> Result<SessionProfile, SessionError> {
    let path = session_profile_path(engagement, name)?;
    if !path.exists() {
        return Err(SessionError::NotConfigured);
    }
    let raw = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

// Load a named session profile and fail closed if expired
pub fn require_active_session_profile(
    engagement: &Engagement,
    name: &str,
) -> Result<SessionProfile, SessionError> {
    let profile = load_session_profile(engagement, name)?;
    if let Some(valid_until) = &profile.valid_until {
        let expires_at = OffsetDateTime::parse(valid_until, &Rfc3339)
            .map_err(|_| SessionError::InvalidExpiry(valid_until.clone()))?;
        if expires_at <= OffsetDateTime::now_utc() {
            return Err(SessionError::Expired);
        }
    }
    Ok(profile)
}

// Return the path for a named profile after validating the name
pub fn session_profile_path(engagement: &Engagement, name: &str) -> Result<PathBuf, SessionError> {
    validate_session_name(name)?;
    Ok(engagement
        .root
        .join(SESSIONS_DIR)
        .join(format!("{name}.json")))
}

// Reject names that could cross engagement boundaries or become paths
fn validate_session_name(name: &str) -> Result<(), SessionError> {
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(SessionError::InvalidSessionName);
    }

    let mut components = Path::new(name).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if !name.contains('/') && !name.contains('\\') => Ok(()),
        _ => Err(SessionError::InvalidSessionName),
    }
}

// Build auth headers with an injectable token lookup for testability
fn build_auth_headers<F>(config: &SessionConfig, token_lookup: F) -> Result<HeaderMap, SessionError>
where
    F: Fn(&str) -> Option<String>,
{
    let mut headers = HeaderMap::new();
    if let Some(token_env) = &config.token_env {
        let token =
            token_lookup(token_env).ok_or_else(|| SessionError::MissingEnv(token_env.clone()))?;
        let header_name = HeaderName::from_bytes(config.token_header.as_bytes())?;
        let value = if config.token_prefix.is_empty() {
            token
        } else {
            format!("{} {}", config.token_prefix, token)
        };
        headers.insert(header_name, HeaderValue::from_str(&value)?);
    }
    if let Some(cookie) = &config.session_cookie {
        headers.insert(COOKIE, HeaderValue::from_str(cookie)?);
    }
    Ok(headers)
}

// Ensure a URL is within engagement scope before testing a session
fn ensure_url_in_scope(engagement: &Engagement, raw_url: &str) -> Result<(), SessionError> {
    let url = Url::parse(raw_url).map_err(|_| SessionError::InvalidUrl(raw_url.into()))?;
    let host = url
        .host_str()
        .ok_or_else(|| SessionError::InvalidUrl(raw_url.into()))?;
    let scope = engagement
        .scope()
        .map_err(|_| SessionError::OutOfScope(host.into()))?;
    if !scope.is_in_scope(host) {
        return Err(SessionError::OutOfScope(host.into()));
    }
    Ok(())
}

// Return default login method
fn default_login_method() -> String {
    "token".into()
}

// Return default token header
fn default_token_header() -> String {
    "Authorization".into()
}

// Return default token prefix
fn default_token_prefix() -> String {
    "Bearer".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::{Engagement, EngagementMeta};
    use std::sync::atomic::{AtomicU64, Ordering};

    // Create a unique temporary engagement root
    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("session-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    // Create a test engagement
    fn test_engagement() -> Engagement {
        let parent = tmp_parent();
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        Engagement::init(&parent, meta).unwrap()
    }

    #[test]
    fn token_headers_use_env_lookup_without_plaintext_storage() {
        let config = SessionConfig {
            token_env: Some("MG_TOKEN".into()),
            ..SessionConfig::default()
        };
        let headers = build_auth_headers(&config, |name| {
            if name == "MG_TOKEN" {
                Some("abc123".into())
            } else {
                None
            }
        })
        .unwrap();
        assert_eq!(headers["Authorization"], "Bearer abc123");
    }

    #[test]
    fn save_and_load_config_round_trips_env_references() {
        let engagement = test_engagement();
        let config = SessionConfig {
            username: Some("user@example.com".into()),
            password_env: Some("MG_PASS".into()),
            login_url: Some("https://example.com/login".into()),
            login_method: "form".into(),
            ..SessionConfig::default()
        };
        save_session_config(&engagement, &config).unwrap();
        let loaded = load_session_config(&engagement).unwrap();
        assert_eq!(loaded.username, config.username);
        assert_eq!(loaded.password_env, config.password_env);
        assert_eq!(loaded.login_url, config.login_url);
    }

    #[test]
    fn saving_plaintext_cookie_is_rejected() {
        let engagement = test_engagement();
        let config = SessionConfig {
            session_cookie: Some("sid=secret".into()),
            ..SessionConfig::default()
        };
        let err = save_session_config(&engagement, &config).unwrap_err();
        assert!(matches!(err, SessionError::PlaintextSecretRejected));
    }

    #[test]
    fn scoped_url_check_blocks_out_of_scope_host() {
        let engagement = test_engagement();
        let err = ensure_url_in_scope(&engagement, "https://other.test/api").unwrap_err();
        assert!(matches!(err, SessionError::OutOfScope(_)));
    }

    #[test]
    fn named_profile_save_stores_metadata_only_and_rejects_plaintext_secret_values() {
        let engagement = test_engagement();
        let profile = SessionProfile {
            name: "alice-admin".into(),
            username: Some("alice@example.test".into()),
            login_url: Some("https://example.com/login".into()),
            auth_refs: vec![SecretRef::env("token", "MG_ALICE_TOKEN")],
            valid_until: None,
        };

        let path = save_session_profile(&engagement, &profile).unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("MG_ALICE_TOKEN"));
        assert!(!raw.contains("Bearer secret-token"));

        let unsafe_profile = SessionProfile {
            name: "unsafe".into(),
            username: None,
            login_url: None,
            auth_refs: vec![SecretRef::plaintext("cookie", "sid=secret-token")],
            valid_until: None,
        };
        let err = save_session_profile(&engagement, &unsafe_profile).unwrap_err();
        assert!(matches!(err, SessionError::PlaintextSecretRejected));
    }

    #[test]
    fn redacted_summary_never_contains_token_like_material() {
        let profile = SessionProfile {
            name: "alice-admin".into(),
            username: Some("alice@example.test".into()),
            login_url: Some("https://example.com/login".into()),
            auth_refs: vec![SecretRef::env("authorization", "MG_ALICE_TOKEN")],
            valid_until: None,
        };

        let summary = profile.redacted_summary();

        assert!(summary.contains("alice-admin"));
        assert!(summary.contains("authorization"));
        assert!(!summary.contains("MG_ALICE_TOKEN"));
        assert!(!summary.contains("secret"));
        assert!(!summary.contains("Bearer"));
    }

    #[test]
    fn expired_named_profile_fails_closed() {
        let engagement = test_engagement();
        let profile = SessionProfile {
            name: "expired".into(),
            username: None,
            login_url: None,
            auth_refs: vec![SecretRef::env("token", "MG_EXPIRED_TOKEN")],
            valid_until: Some("2000-01-01T00:00:00Z".into()),
        };
        save_session_profile(&engagement, &profile).unwrap();

        let err = require_active_session_profile(&engagement, "expired").unwrap_err();

        assert!(matches!(err, SessionError::Expired));
    }

    #[test]
    fn named_session_lookup_returns_secret_refs_not_secret_values() {
        let engagement = test_engagement();
        let profile = SessionProfile {
            name: "alice-admin".into(),
            username: None,
            login_url: None,
            auth_refs: vec![SecretRef::env("token", "MG_ALICE_TOKEN")],
            valid_until: None,
        };
        save_session_profile(&engagement, &profile).unwrap();

        let loaded = load_session_profile(&engagement, "alice-admin").unwrap();

        assert_eq!(
            loaded.auth_refs[0].env_var.as_deref(),
            Some("MG_ALICE_TOKEN")
        );
        assert!(loaded.auth_refs[0].value.is_none());
    }
}
