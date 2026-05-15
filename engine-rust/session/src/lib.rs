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
use std::path::PathBuf;

use engagement::Engagement;
use reqwest::header::{COOKIE, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use url::Url;

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
}

// Load auth headers for an engagement; empty when no session.json exists
pub async fn get_auth_headers(engagement: &Engagement) -> Result<HeaderMap, SessionError> {
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
}
