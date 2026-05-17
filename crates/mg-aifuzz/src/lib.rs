/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Adversarial prompt-injection fuzzer for LLM endpoints
 * Notes:           Loads a request template with a §INJECT§ marker, iterates
 *                  the payload-engine prompt-injection corpus, scopes every
 *                  request, and writes one JSONL row per attempt.
 *******************************************************************/

mod rubric;
mod template;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use engagement::Engagement;
use payload_engine::{PromptInjectionCategory, prompt_injection_payloads};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

pub use rubric::{Rubric, RubricHit};
pub use template::{AiRequestTemplate, InjectedAiRequest};

const REQUEST_EXCERPT_BYTES: usize = 256;
const RESPONSE_EXCERPT_BYTES: usize = 512;
const RESPONSE_READ_LIMIT_BYTES: usize = 64 * 1024;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_RATE_MS: u64 = 500;
const DEFAULT_MAX_ATTEMPTS: usize = 50;
const CONSENT_FILENAME: &str = "CONSENT";

#[derive(Debug, Error)]
pub enum AiFuzzError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("engagement: {0}")]
    Engagement(#[from] engagement::EngagementError),
    #[error("template: {0}")]
    Template(#[from] anyhow::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url: {0}")]
    Url(#[from] url::ParseError),
    #[error("invalid args: {0}")]
    InvalidArgs(String),
    #[error("scope: {0}")]
    OutOfScope(String),
    #[error("consent missing: run `mg-aifuzz consent {0}` first")]
    ConsentMissing(String),
}

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub engagements_dir: PathBuf,
    pub engagement: String,
    pub template_path: PathBuf,
    pub base_url: String,
    pub categories: Vec<PromptInjectionCategory>,
    pub max_attempts: usize,
    pub rate_ms: u64,
    pub timeout_ms: u64,
    pub sentinels_path: Option<PathBuf>,
}

impl FuzzConfig {
    // Default request cap when the operator does not pass --max-attempts
    pub const fn default_max_attempts() -> usize {
        DEFAULT_MAX_ATTEMPTS
    }
    // Default per-request pause when the operator does not pass --rate-ms
    pub const fn default_rate_ms() -> u64 {
        DEFAULT_RATE_MS
    }
    // Default HTTP timeout when the operator does not pass --timeout-ms
    pub const fn default_timeout_ms() -> u64 {
        DEFAULT_TIMEOUT_MS
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzOutput {
    pub run_id: String,
    pub output_path: PathBuf,
    pub attempts: usize,
    pub hits: usize,
}

// Record consent for adversarial AI fuzzing against the engagement
pub fn record_consent(engagements_dir: &Path, engagement: &str) -> Result<PathBuf, AiFuzzError> {
    let eng = Engagement::load_named(engagements_dir, engagement)?;
    let aifuzz_dir = eng.root.join("aifuzz");
    fs::create_dir_all(&aifuzz_dir)?;
    let path = aifuzz_dir.join(CONSENT_FILENAME);
    let ts = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
    fs::write(
        &path,
        format!(
            "consent: aifuzz\nengagement: {engagement}\nrecorded_at: {ts}\nnote: adversarial AI fuzzing authorized for this engagement.\n"
        ),
    )?;
    let _ = eng.audit("mg-aifuzz", engagement, Some("consent recorded"));
    Ok(path)
}

// Return true when the consent file exists for this engagement
pub fn has_consent(eng: &Engagement) -> bool {
    eng.root.join("aifuzz").join(CONSENT_FILENAME).exists()
}

// Run the configured prompt-injection fuzz pass
pub async fn run(config: &FuzzConfig) -> Result<FuzzOutput, AiFuzzError> {
    let eng = Engagement::load_named(&config.engagements_dir, &config.engagement)?;
    if !has_consent(&eng) {
        return Err(AiFuzzError::ConsentMissing(config.engagement.clone()));
    }
    let scope = eng.scope()?;
    let base = Url::parse(&config.base_url)?;
    let base_host = base
        .host_str()
        .ok_or_else(|| AiFuzzError::InvalidArgs("base_url is missing a host".into()))?;
    if !scope.is_in_scope(base_host) {
        return Err(AiFuzzError::OutOfScope(base_host.to_string()));
    }

    let template_raw = fs::read_to_string(&config.template_path)?;
    let template = AiRequestTemplate::parse(&template_raw)?;
    let rubric = Rubric::default_with_sentinels(config.sentinels_path.as_deref())?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.timeout_ms))
        .user_agent("mg-aifuzz/0.1")
        .build()?;

    let aifuzz_dir = eng.root.join("aifuzz");
    fs::create_dir_all(&aifuzz_dir)?;
    let run_id = run_id_for_now();
    let output_path = aifuzz_dir.join(format!("{run_id}.jsonl"));
    let mut output = fs::File::create(&output_path)?;

    let payloads = prompt_injection_payloads(&config.categories);
    let mut attempts = 0;
    let mut hits = 0;
    for payload in payloads.into_iter().take(config.max_attempts) {
        let request = template.inject(&payload.body);
        let url = build_url(&base, &request.path)?;
        if !scope.is_in_scope(
            url.host_str()
                .ok_or_else(|| AiFuzzError::InvalidArgs("request URL missing host".into()))?,
        ) {
            return Err(AiFuzzError::OutOfScope(
                url.host_str().unwrap_or("?").to_string(),
            ));
        }
        let header_map = build_header_map(&request.headers)?;
        let body_bytes = request.body.clone().unwrap_or_default();
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|err| AiFuzzError::InvalidArgs(format!("bad HTTP method: {err}")))?;
        let mut req_builder = client.request(method, url.clone()).headers(header_map);
        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes.clone());
        }
        let response_text = match send_and_bound(req_builder).await {
            Ok(text) => text,
            Err(err) => format!("<request-error: {err}>"),
        };
        let signal = rubric.evaluate(payload.category, &response_text);
        if signal.is_some() {
            hits += 1;
        }
        let row = build_row(&payload, &request, &url, &body_bytes, &response_text, &signal);
        writeln!(output, "{}", serde_json::to_string(&row).unwrap_or_default())?;
        attempts += 1;

        if config.rate_ms > 0 {
            tokio::time::sleep(Duration::from_millis(config.rate_ms)).await;
        }
    }

    let _ = eng.audit(
        "mg-aifuzz",
        base_host,
        Some(&format!(
            "run id={run_id} attempts={attempts} hits={hits} output={}",
            output_path.display()
        )),
    );

    Ok(FuzzOutput {
        run_id,
        output_path,
        attempts,
        hits,
    })
}

// Build the per-attempt JSONL row
fn build_row(
    payload: &payload_engine::PromptInjectionPayload,
    request: &InjectedAiRequest,
    url: &Url,
    body_bytes: &str,
    response_text: &str,
    signal: &Option<RubricHit>,
) -> Value {
    let request_excerpt = bounded(
        &format!(
            "{} {} :: payload={}",
            request.method,
            url,
            truncate(&payload.body, 120)
        ),
        REQUEST_EXCERPT_BYTES,
    );
    let response_excerpt = bounded(response_text, RESPONSE_EXCERPT_BYTES);
    let mut row = json!({
        "payload_category": payload.category.label(),
        "payload_id": payload.id,
        "request_excerpt": request_excerpt,
        "response_excerpt": response_excerpt,
        "body_excerpt": bounded(body_bytes, REQUEST_EXCERPT_BYTES),
    });
    if let Some(hit) = signal {
        row["success_signal"] = json!({
            "matched_category": hit.matched_category.label(),
            "signal": hit.signal,
        });
    } else {
        row["success_signal"] = Value::Null;
    }
    row
}

// Combine base URL with the template's path
fn build_url(base: &Url, path: &str) -> Result<Url, AiFuzzError> {
    Ok(base.join(path)?)
}

// Build a reqwest HeaderMap, skipping the Host header (reqwest sets it from the URL)
fn build_header_map(headers: &[(String, String)]) -> Result<HeaderMap, AiFuzzError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|err| AiFuzzError::InvalidArgs(format!("bad header name `{name}`: {err}")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|err| AiFuzzError::InvalidArgs(format!("bad header value: {err}")))?;
        map.insert(header_name, header_value);
    }
    Ok(map)
}

// Send the request and bound the body read
async fn send_and_bound(builder: reqwest::RequestBuilder) -> Result<String, AiFuzzError> {
    let response = builder.send().await?;
    let bytes = response.bytes().await?;
    let slice = if bytes.len() > RESPONSE_READ_LIMIT_BYTES {
        &bytes[..RESPONSE_READ_LIMIT_BYTES]
    } else {
        &bytes[..]
    };
    Ok(String::from_utf8_lossy(slice).to_string())
}

// Build an ISO-8601-ish run id suitable for a filename
fn run_id_for_now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown-time".into())
        .replace(':', "-")
}

// Truncate a single payload preview without splitting a char
fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "…"
}

// Truncate UTF-8 text on a char boundary at the given byte cap
fn bounded(raw: &str, max_bytes: usize) -> String {
    if raw.len() <= max_bytes {
        return raw.to_string();
    }
    let mut end = max_bytes;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}<truncated {} bytes>",
        &raw[..end],
        raw.len().saturating_sub(end)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::EngagementMeta;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-aifuzz-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn fixture() -> PathBuf {
        let parent = tmp_parent();
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        Engagement::init(&parent, meta).unwrap();
        parent
    }

    #[test]
    fn consent_writes_marker_file() {
        let parent = fixture();
        let path = record_consent(&parent, "acme").unwrap();
        assert!(path.exists());
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("aifuzz"));
        assert!(raw.contains("engagement: acme"));
    }

    #[tokio::test]
    async fn run_fails_without_consent() {
        let parent = fixture();
        let template_path = parent.join("template.txt");
        fs::write(
            &template_path,
            "POST /chat HTTP/1.1\nHost: x.example.com\nContent-Type: application/json\n\n{\"q\":\"§INJECT§\"}",
        )
        .unwrap();
        let config = FuzzConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            template_path,
            base_url: "https://x.example.com".into(),
            categories: Vec::new(),
            max_attempts: 1,
            rate_ms: 0,
            timeout_ms: 1000,
            sentinels_path: None,
        };
        let err = run(&config).await.unwrap_err();
        match err {
            AiFuzzError::ConsentMissing(name) => assert_eq!(name, "acme"),
            other => panic!("expected ConsentMissing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_rejects_out_of_scope_base_url() {
        let parent = fixture();
        record_consent(&parent, "acme").unwrap();
        let template_path = parent.join("template.txt");
        fs::write(
            &template_path,
            "POST /chat HTTP/1.1\nHost: nope.invalid\nContent-Type: application/json\n\n{\"q\":\"§INJECT§\"}",
        )
        .unwrap();
        let config = FuzzConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            template_path,
            base_url: "https://nope.invalid".into(),
            categories: Vec::new(),
            max_attempts: 1,
            rate_ms: 0,
            timeout_ms: 1000,
            sentinels_path: None,
        };
        let err = run(&config).await.unwrap_err();
        match err {
            AiFuzzError::OutOfScope(host) => assert_eq!(host, "nope.invalid"),
            other => panic!("expected OutOfScope, got {other:?}"),
        }
    }
}
