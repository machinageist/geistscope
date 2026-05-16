/*******************************************************************
 * Filename:        traffic.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Engagement traffic corpus import, indexing, and response diff helpers
 * Notes:           The corpus is local-first: normalized request/response
 *                  metadata is stored in traffic/corpus.jsonl and request/
 *                  response bodies are stored as bounded blobs under traffic/bodies/.
 *******************************************************************/

use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

use crate::{Engagement, EngagementError};

const MAX_STORED_BODY_BYTES: usize = 2 * 1024 * 1024;

type RawHeaders = Vec<(String, String)>;
type RawRequestParts = (String, String, RawHeaders, Option<Vec<u8>>);
type RawResponseParts = (u16, RawHeaders, Option<Vec<u8>>);

// Import formats accepted by the traffic corpus importer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficImportFormat {
    Auto,
    Har,
    Burp,
    Caido,
}

impl TrafficImportFormat {
    pub fn parse(raw: &str) -> Result<Self, EngagementError> {
        match raw.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "har" => Ok(Self::Har),
            "burp" | "burp_xml" | "xml" => Ok(Self::Burp),
            "caido" | "json" => Ok(Self::Caido),
            other => Err(EngagementError::Invalid(format!(
                "unknown traffic import format `{other}`"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Har => "har",
            Self::Burp => "burp",
            Self::Caido => "caido",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeaderRecord {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BodyRef {
    pub path: String,
    pub len: usize,
    pub sha256: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthState {
    Unknown,
    Anonymous,
    Authenticated,
}

impl AuthState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Anonymous => "anonymous",
            Self::Authenticated => "authenticated",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficResponse {
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default)]
    pub headers: Vec<HeaderRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<BodyRef>,
    pub body_len: usize,
    pub body_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_location: Option<String>,
    #[serde(default)]
    pub cookie_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_shape: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrafficRecord {
    pub id: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    pub captured_at: String,
    pub imported_at: String,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    #[serde(default)]
    pub params: Vec<String>,
    #[serde(default)]
    pub request_headers: Vec<HeaderRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_body: Option<BodyRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<TrafficResponse>,
    pub auth_state: AuthState,
}

#[derive(Debug, Clone, Default)]
pub struct TrafficFilter {
    pub host: Option<String>,
    pub method: Option<String>,
    pub path_contains: Option<String>,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub auth_state: Option<AuthState>,
    pub source: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportSummary {
    pub source: String,
    pub format: String,
    pub imported: usize,
    pub skipped: usize,
    pub total_records: usize,
    pub corpus_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseFingerprint {
    pub status: u16,
    pub header_names: Vec<String>,
    pub body_len: usize,
    pub body_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_shape: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub html_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_location: Option<String>,
    #[serde(default)]
    pub cookie_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResponseDiff {
    pub status_changed: bool,
    pub body_hash_changed: bool,
    pub body_len_delta: i64,
    pub header_names_added: Vec<String>,
    pub header_names_removed: Vec<String>,
    pub json_shape_changed: bool,
    pub html_title_changed: bool,
    pub redirect_changed: bool,
    pub cookie_names_added: Vec<String>,
    pub cookie_names_removed: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct TrafficStore {
    traffic_dir: PathBuf,
}

#[derive(Debug)]
struct PendingTrafficRecord {
    record: TrafficRecord,
    request_body_bytes: Option<Vec<u8>>,
    response_body_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ParsedResponse {
    status: u16,
    mime: Option<String>,
    headers: RawHeaders,
    body: Option<Vec<u8>>,
    redirect_location: Option<String>,
}

impl TrafficStore {
    pub fn for_engagement(engagement: &Engagement) -> Self {
        Self {
            traffic_dir: engagement.traffic_dir(),
        }
    }

    pub fn traffic_dir(&self) -> &Path {
        &self.traffic_dir
    }

    pub fn corpus_path(&self) -> PathBuf {
        self.traffic_dir.join("corpus.jsonl")
    }

    pub fn bodies_dir(&self) -> PathBuf {
        self.traffic_dir.join("bodies")
    }

    pub fn replays_dir(&self) -> PathBuf {
        self.traffic_dir.join("replays")
    }

    pub fn ensure_dirs(&self) -> Result<(), EngagementError> {
        fs::create_dir_all(&self.traffic_dir)?;
        fs::create_dir_all(self.bodies_dir())?;
        fs::create_dir_all(self.replays_dir())?;
        Ok(())
    }

    fn import_pending(
        &self,
        source: &Path,
        format: TrafficImportFormat,
        mut pending: Vec<PendingTrafficRecord>,
    ) -> Result<ImportSummary, EngagementError> {
        self.ensure_dirs()?;
        let mut known = load_known_ids(&self.corpus_path())?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut corpus = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.corpus_path())?;

        for item in &mut pending {
            if !known.insert(item.record.id.clone()) {
                skipped += 1;
                continue;
            }

            if let Some(bytes) = &item.request_body_bytes {
                item.record.request_body =
                    Some(self.write_body(&item.record.id, "request", bytes)?);
            }
            if let Some(bytes) = &item.response_body_bytes
                && let Some(response) = item.record.response.as_mut()
            {
                response.body = Some(self.write_body(&item.record.id, "response", bytes)?);
            }

            let line = serde_json::to_string(&item.record)?;
            corpus.write_all(line.as_bytes())?;
            corpus.write_all(b"\n")?;
            imported += 1;
        }

        Ok(ImportSummary {
            source: source.display().to_string(),
            format: format.as_str().to_string(),
            imported,
            skipped,
            total_records: imported + skipped,
            corpus_path: self.corpus_path().display().to_string(),
        })
    }

    fn write_body(&self, id: &str, kind: &str, bytes: &[u8]) -> Result<BodyRef, EngagementError> {
        let filename = format!("{id}-{kind}.bin");
        let rel_path = Path::new("traffic").join("bodies").join(&filename);
        let abs_path = self.bodies_dir().join(filename);
        let stored_len = bytes.len().min(MAX_STORED_BODY_BYTES);
        fs::write(&abs_path, &bytes[..stored_len])?;
        Ok(BodyRef {
            path: rel_path.display().to_string(),
            len: bytes.len(),
            sha256: sha256_hex(bytes),
            truncated: stored_len < bytes.len(),
        })
    }
}

pub fn import_traffic_file(
    engagement: &Engagement,
    path: &Path,
    requested_format: TrafficImportFormat,
) -> Result<ImportSummary, EngagementError> {
    let raw = fs::read(path)?;
    let format = detect_format(path, &raw, requested_format)?;
    let source_file = Some(path.display().to_string());
    let pending = match format {
        TrafficImportFormat::Auto => unreachable!("auto is resolved by detect_format"),
        TrafficImportFormat::Har => parse_har(&raw, source_file)?,
        TrafficImportFormat::Burp => parse_burp_xml(&raw, source_file)?,
        TrafficImportFormat::Caido => parse_caido_json(&raw, source_file)?,
    };
    TrafficStore::for_engagement(engagement).import_pending(path, format, pending)
}

pub fn load_traffic_records(
    engagement: &Engagement,
) -> Result<Vec<TrafficRecord>, EngagementError> {
    load_records(&engagement.traffic_corpus_path())
}

pub fn search_traffic_records(
    engagement: &Engagement,
    filter: &TrafficFilter,
) -> Result<Vec<TrafficRecord>, EngagementError> {
    let mut records = load_traffic_records(engagement)?;
    records.retain(|record| record_matches_filter(record, filter));
    records.sort_by(|left, right| right.captured_at.cmp(&left.captured_at));
    if let Some(limit) = filter.limit {
        records.truncate(limit);
    }
    Ok(records)
}

pub fn find_traffic_record(
    engagement: &Engagement,
    id_or_prefix: &str,
) -> Result<TrafficRecord, EngagementError> {
    validate_request_id(id_or_prefix)?;
    let matches: Vec<TrafficRecord> = load_traffic_records(engagement)?
        .into_iter()
        .filter(|record| record.id == id_or_prefix || record.id.starts_with(id_or_prefix))
        .collect();
    match matches.as_slice() {
        [record] => Ok(record.clone()),
        [] => Err(EngagementError::Invalid(format!(
            "request `{id_or_prefix}` not found in traffic corpus"
        ))),
        _ => Err(EngagementError::Invalid(format!(
            "request prefix `{id_or_prefix}` is ambiguous"
        ))),
    }
}

pub fn raw_http_request(
    engagement: &Engagement,
    record: &TrafficRecord,
) -> Result<String, EngagementError> {
    let url = Url::parse(&record.url)
        .map_err(|err| EngagementError::Invalid(format!("invalid corpus URL: {err}")))?;
    let mut path = url.path().to_string();
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut out = format!("{} {path} HTTP/1.1\r\n", record.method);
    out.push_str(&format!("Host: {}\r\n", record.host));
    for header in &record.request_headers {
        if !header.name.eq_ignore_ascii_case("host") {
            out.push_str(&format!("{}: {}\r\n", header.name, header.value));
        }
    }
    out.push_str("\r\n");
    if let Some(body) = &record.request_body {
        let body_path = body_abs_path(engagement, body);
        let bytes = fs::read(&body_path)
            .map_err(|err| EngagementError::Invalid(format!("read body: {err}")))?;
        out.push_str(&String::from_utf8_lossy(&bytes));
    }
    Ok(out)
}

pub fn response_fingerprint_from_parts(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    mime: Option<String>,
) -> ResponseFingerprint {
    let body_text = String::from_utf8_lossy(body);
    let mime = mime.or_else(|| content_type(headers).as_deref().map(mime_without_params));
    ResponseFingerprint {
        status,
        header_names: header_names(headers),
        body_len: body.len(),
        body_sha256: sha256_hex(body),
        mime: mime.clone(),
        json_shape: maybe_json_shape(mime.as_deref(), &body_text),
        html_title: maybe_html_title(mime.as_deref(), &body_text),
        redirect_location: header_value(headers, "location"),
        cookie_names: cookie_names(headers),
    }
}

pub fn response_fingerprint_from_record(response: &TrafficResponse) -> ResponseFingerprint {
    ResponseFingerprint {
        status: response.status,
        header_names: response
            .headers
            .iter()
            .map(|header| header.name.to_ascii_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        body_len: response.body_len,
        body_sha256: response.body_sha256.clone(),
        mime: response.mime.clone(),
        json_shape: response.json_shape.clone(),
        html_title: response.html_title.clone(),
        redirect_location: response.redirect_location.clone(),
        cookie_names: response.cookie_names.clone(),
    }
}

pub fn diff_response_fingerprints(
    original: &ResponseFingerprint,
    replayed: &ResponseFingerprint,
) -> ResponseDiff {
    let original_headers: BTreeSet<_> = original.header_names.iter().cloned().collect();
    let replayed_headers: BTreeSet<_> = replayed.header_names.iter().cloned().collect();
    let original_cookies: BTreeSet<_> = original.cookie_names.iter().cloned().collect();
    let replayed_cookies: BTreeSet<_> = replayed.cookie_names.iter().cloned().collect();

    ResponseDiff {
        status_changed: original.status != replayed.status,
        body_hash_changed: original.body_sha256 != replayed.body_sha256,
        body_len_delta: replayed.body_len as i64 - original.body_len as i64,
        header_names_added: replayed_headers
            .difference(&original_headers)
            .cloned()
            .collect(),
        header_names_removed: original_headers
            .difference(&replayed_headers)
            .cloned()
            .collect(),
        json_shape_changed: original.json_shape != replayed.json_shape,
        html_title_changed: original.html_title != replayed.html_title,
        redirect_changed: original.redirect_location != replayed.redirect_location,
        cookie_names_added: replayed_cookies
            .difference(&original_cookies)
            .cloned()
            .collect(),
        cookie_names_removed: original_cookies
            .difference(&replayed_cookies)
            .cloned()
            .collect(),
    }
}

fn detect_format(
    path: &Path,
    raw: &[u8],
    requested: TrafficImportFormat,
) -> Result<TrafficImportFormat, EngagementError> {
    if requested != TrafficImportFormat::Auto {
        return Ok(requested);
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".har") {
        return Ok(TrafficImportFormat::Har);
    }
    if name.ends_with(".xml") {
        return Ok(TrafficImportFormat::Burp);
    }
    let trimmed = String::from_utf8_lossy(raw)
        .trim_start()
        .chars()
        .take(32)
        .collect::<String>();
    if trimmed.starts_with('<') {
        return Ok(TrafficImportFormat::Burp);
    }
    let value: Value = serde_json::from_slice(raw)?;
    if value
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(Value::as_array)
        .is_some()
    {
        Ok(TrafficImportFormat::Har)
    } else {
        Ok(TrafficImportFormat::Caido)
    }
}

fn parse_har(
    raw: &[u8],
    source_file: Option<String>,
) -> Result<Vec<PendingTrafficRecord>, EngagementError> {
    let value: Value = serde_json::from_slice(raw)?;
    let entries = value
        .get("log")
        .and_then(|log| log.get("entries"))
        .and_then(Value::as_array)
        .ok_or_else(|| EngagementError::Invalid("HAR file does not contain log.entries".into()))?;

    let mut out = Vec::new();
    for entry in entries {
        let Some(request) = entry.get("request") else {
            continue;
        };
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET");
        let Some(url) = request.get("url").and_then(Value::as_str) else {
            continue;
        };
        let captured_at = entry
            .get("startedDateTime")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| now_rfc3339().unwrap_or_else(|_| "unknown".into()));
        let request_headers = headers_from_har(request.get("headers"));
        let (request_body, mut extra_params) = har_request_body(request.get("postData"));
        extra_params.extend(har_param_names(request.get("queryString")));

        let response = entry.get("response").and_then(|response| {
            let status = response.get("status").and_then(Value::as_u64).unwrap_or(0) as u16;
            if status == 0 {
                return None;
            }
            let response_headers = headers_from_har(response.get("headers"));
            let content = response.get("content");
            let mime = content
                .and_then(|content| content.get("mimeType"))
                .and_then(Value::as_str)
                .map(mime_without_params)
                .or_else(|| {
                    content_type(&response_headers)
                        .as_deref()
                        .map(mime_without_params)
                });
            let body = har_content_body(content);
            let redirect = response
                .get("redirectURL")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| header_value(&response_headers, "location"));
            Some(ParsedResponse {
                status,
                mime,
                headers: response_headers,
                body,
                redirect_location: redirect,
            })
        });

        if let Some(record) = build_pending_record(
            "har",
            source_file.clone(),
            captured_at,
            method,
            url,
            request_headers,
            request_body,
            extra_params,
            response,
        ) {
            out.push(record);
        }
    }
    Ok(out)
}

fn parse_caido_json(
    raw: &[u8],
    source_file: Option<String>,
) -> Result<Vec<PendingTrafficRecord>, EngagementError> {
    let value: Value = serde_json::from_slice(raw)?;
    let items = json_items(&value);
    if items.is_empty() {
        return Err(EngagementError::Invalid(
            "Caido JSON import did not contain request items".into(),
        ));
    }

    let mut out = Vec::new();
    for item in items {
        let request = item.get("request").unwrap_or(item);
        let response = item.get("response");

        let mut parsed_raw_request = None;
        if let Some(raw_request) = string_any(request, &["raw", "raw_request", "request_raw"]) {
            parsed_raw_request = parse_raw_http_request(
                raw_request.as_bytes(),
                None,
                string_any(item, &["scheme", "protocol"]).as_deref(),
                string_any(item, &["host"]).as_deref(),
                item.get("port")
                    .and_then(Value::as_u64)
                    .map(|value| value as u16),
            );
        }

        let method = string_any(request, &["method"])
            .or_else(|| parsed_raw_request.as_ref().map(|parsed| parsed.0.clone()))
            .unwrap_or_else(|| "GET".into());
        let url = string_any(request, &["url", "request_url", "target", "full_url"])
            .or_else(|| string_any(item, &["url", "request_url", "target", "full_url"]))
            .or_else(|| parsed_raw_request.as_ref().map(|parsed| parsed.1.clone()));
        let Some(url) = url else {
            continue;
        };
        let captured_at = string_any(item, &["created_at", "timestamp", "time", "captured_at"])
            .unwrap_or_else(|| now_rfc3339().unwrap_or_else(|_| "unknown".into()));
        let mut request_headers = headers_from_json(request.get("headers"));
        if request_headers.is_empty() {
            request_headers = parsed_raw_request
                .as_ref()
                .map(|parsed| parsed.2.clone())
                .unwrap_or_default();
        }
        let request_body = body_from_json(request.get("body"))
            .or_else(|| body_from_json(request.get("raw_body")))
            .or_else(|| {
                parsed_raw_request
                    .as_ref()
                    .and_then(|parsed| parsed.3.clone())
            });

        let parsed_response = response.and_then(|response| {
            let mut parsed_raw_response = None;
            if let Some(raw_response) =
                string_any(response, &["raw", "raw_response", "response_raw"])
            {
                parsed_raw_response = parse_raw_http_response(raw_response.as_bytes());
            }
            let status = response
                .get("status")
                .or_else(|| response.get("status_code"))
                .or_else(|| response.get("code"))
                .and_then(Value::as_u64)
                .map(|value| value as u16)
                .or_else(|| parsed_raw_response.as_ref().map(|parsed| parsed.0))?;
            let mut headers = headers_from_json(response.get("headers"));
            if headers.is_empty() {
                headers = parsed_raw_response
                    .as_ref()
                    .map(|parsed| parsed.1.clone())
                    .unwrap_or_default();
            }
            let body = body_from_json(response.get("body"))
                .or_else(|| body_from_json(response.get("raw_body")))
                .or_else(|| {
                    parsed_raw_response
                        .as_ref()
                        .and_then(|parsed| parsed.2.clone())
                });
            let mime = string_any(response, &["mime", "mime_type", "content_type"])
                .map(|value| mime_without_params(&value))
                .or_else(|| content_type(&headers).as_deref().map(mime_without_params));
            let redirect_location = string_any(response, &["redirect_url", "redirectURL"])
                .or_else(|| header_value(&headers, "location"));
            Some(ParsedResponse {
                status,
                mime,
                headers,
                body,
                redirect_location,
            })
        });

        if let Some(record) = build_pending_record(
            "caido",
            source_file.clone(),
            captured_at,
            &method,
            &url,
            request_headers,
            request_body,
            Vec::new(),
            parsed_response,
        ) {
            out.push(record);
        }
    }
    Ok(out)
}

fn parse_burp_xml(
    raw: &[u8],
    source_file: Option<String>,
) -> Result<Vec<PendingTrafficRecord>, EngagementError> {
    let text = String::from_utf8_lossy(raw);
    let mut out = Vec::new();
    for item in tag_contents(&text, "item") {
        let url = xml_text(&item, "url");
        let method = xml_text(&item, "method");
        let protocol = xml_text(&item, "protocol");
        let host = xml_text(&item, "host");
        let port = xml_text(&item, "port").and_then(|port| port.parse::<u16>().ok());
        let captured_at = xml_text(&item, "time")
            .unwrap_or_else(|| now_rfc3339().unwrap_or_else(|_| "unknown".into()));
        let request_bytes = xml_payload(&item, "request");
        let response_bytes = xml_payload(&item, "response");
        let parsed_request = request_bytes.as_deref().and_then(|bytes| {
            parse_raw_http_request(
                bytes,
                url.as_deref(),
                protocol.as_deref(),
                host.as_deref(),
                port,
            )
        });
        let Some((parsed_method, parsed_url, headers, request_body)) = parsed_request else {
            continue;
        };
        let response = response_bytes.as_deref().and_then(|bytes| {
            let (status, headers, body) = parse_raw_http_response(bytes)?;
            let mime = xml_text(&item, "mimetype")
                .map(|value| value.to_ascii_lowercase())
                .or_else(|| content_type(&headers).as_deref().map(mime_without_params));
            Some(ParsedResponse {
                status,
                mime,
                headers,
                body,
                redirect_location: None,
            })
        });

        if let Some(record) = build_pending_record(
            "burp",
            source_file.clone(),
            captured_at,
            method.as_deref().unwrap_or(&parsed_method),
            &parsed_url,
            headers,
            request_body,
            Vec::new(),
            response,
        ) {
            out.push(record);
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn build_pending_record(
    source: &str,
    source_file: Option<String>,
    captured_at: String,
    method: &str,
    raw_url: &str,
    request_headers: RawHeaders,
    request_body: Option<Vec<u8>>,
    mut extra_params: Vec<String>,
    response: Option<ParsedResponse>,
) -> Option<PendingTrafficRecord> {
    let url = normalize_url(raw_url)?;
    let parsed = Url::parse(&url).ok()?;
    let host = parsed.host_str()?.to_string();
    let path = parsed.path().to_string();
    let mut params: BTreeSet<String> = parsed
        .query_pairs()
        .map(|(name, _)| name.to_string())
        .collect();
    params.extend(extra_params.drain(..));
    if let Some(body) = &request_body {
        params.extend(body_param_names(
            content_type(&request_headers).as_deref(),
            &String::from_utf8_lossy(body),
        ));
    }
    let method = method.to_ascii_uppercase();
    let auth_state = detect_auth_state(&request_headers, &params);
    let request_body_hash = request_body.as_ref().map(sha256_hex).unwrap_or_default();
    let response_status = response
        .as_ref()
        .map(|response| response.status)
        .unwrap_or(0);
    let response_body_hash = response
        .as_ref()
        .and_then(|response| response.body.as_ref())
        .map(sha256_hex)
        .unwrap_or_default();
    let id = traffic_id(
        &method,
        &url,
        &captured_at,
        &request_body_hash,
        response_status,
        &response_body_hash,
    );
    let imported_at = now_rfc3339().unwrap_or_else(|_| captured_at.clone());
    let request_headers = sanitize_headers(&request_headers);
    let response_body_bytes = response.as_ref().and_then(|response| response.body.clone());
    let parsed_response = response.map(|response| {
        let body = response.body.unwrap_or_default();
        let body_text = String::from_utf8_lossy(&body);
        let mime = response.mime.or_else(|| {
            content_type(&response.headers)
                .as_deref()
                .map(mime_without_params)
        });
        TrafficResponse {
            status: response.status,
            mime: mime.clone(),
            headers: sanitize_headers(&response.headers),
            body: None,
            body_len: body.len(),
            body_sha256: sha256_hex(&body),
            redirect_location: response
                .redirect_location
                .or_else(|| header_value(&response.headers, "location")),
            cookie_names: cookie_names(&response.headers),
            html_title: maybe_html_title(mime.as_deref(), &body_text),
            json_shape: maybe_json_shape(mime.as_deref(), &body_text),
        }
    });

    Some(PendingTrafficRecord {
        record: TrafficRecord {
            id,
            source: source.to_string(),
            source_file,
            captured_at,
            imported_at,
            method,
            url,
            host,
            path,
            params: params.into_iter().collect(),
            request_headers,
            request_body: None,
            response: parsed_response,
            auth_state,
        },
        request_body_bytes: request_body,
        response_body_bytes,
    })
}

fn load_records(path: &Path) -> Result<Vec<TrafficRecord>, EngagementError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in raw.lines().filter(|line| !line.trim().is_empty()) {
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

fn load_known_ids(path: &Path) -> Result<BTreeSet<String>, EngagementError> {
    Ok(load_records(path)?
        .into_iter()
        .map(|record| record.id)
        .collect())
}

fn record_matches_filter(record: &TrafficRecord, filter: &TrafficFilter) -> bool {
    if let Some(host) = &filter.host
        && !record.host.eq_ignore_ascii_case(host)
    {
        return false;
    }
    if let Some(method) = &filter.method
        && !record.method.eq_ignore_ascii_case(method)
    {
        return false;
    }
    if let Some(needle) = &filter.path_contains
        && !record.path.contains(needle)
        && !record.url.contains(needle)
    {
        return false;
    }
    if let Some(status) = filter.status
        && record.response.as_ref().map(|response| response.status) != Some(status)
    {
        return false;
    }
    if let Some(mime) = &filter.mime
        && !record
            .response
            .as_ref()
            .and_then(|response| response.mime.as_deref())
            .is_some_and(|value| value.contains(mime))
    {
        return false;
    }
    if let Some(auth_state) = filter.auth_state
        && record.auth_state != auth_state
    {
        return false;
    }
    if let Some(source) = &filter.source
        && record.source != *source
    {
        return false;
    }
    true
}

fn validate_request_id(raw: &str) -> Result<(), EngagementError> {
    if raw.is_empty()
        || raw.contains('/')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(EngagementError::Invalid(
            "request ID must be a safe ID or prefix".into(),
        ));
    }
    Ok(())
}

fn body_abs_path(engagement: &Engagement, body: &BodyRef) -> PathBuf {
    let path = Path::new(&body.path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        engagement.root.join(path)
    }
}

fn headers_from_har(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_array)
        .map(|headers| {
            headers
                .iter()
                .filter_map(|header| {
                    let name = header.get("name").and_then(Value::as_str)?;
                    let value = header
                        .get("value")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    Some((name.to_string(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn har_param_names(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|params| {
            params
                .iter()
                .filter_map(|param| {
                    param
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn har_request_body(post_data: Option<&Value>) -> (Option<Vec<u8>>, Vec<String>) {
    let Some(post_data) = post_data else {
        return (None, Vec::new());
    };
    let params = har_param_names(post_data.get("params"));
    let body = post_data
        .get("text")
        .and_then(Value::as_str)
        .map(|text| text.as_bytes().to_vec());
    (body, params)
}

fn har_content_body(content: Option<&Value>) -> Option<Vec<u8>> {
    let content = content?;
    let text = content.get("text").and_then(Value::as_str)?;
    if content
        .get("encoding")
        .and_then(Value::as_str)
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("base64"))
    {
        general_purpose::STANDARD.decode(text.trim()).ok()
    } else {
        Some(text.as_bytes().to_vec())
    }
}

fn json_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.as_array() {
        return items.iter().collect();
    }
    for key in ["requests", "items", "data", "entries", "history"] {
        if let Some(items) = value.get(key).and_then(Value::as_array) {
            return items.iter().collect();
        }
    }
    Vec::new()
}

fn string_any(value: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(found) = value.get(*key).and_then(Value::as_str) {
            return Some(found.to_string());
        }
    }
    None
}

fn headers_from_json(value: Option<&Value>) -> Vec<(String, String)> {
    let Some(value) = value else {
        return Vec::new();
    };
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .filter_map(|header| {
                if let Some(pair) = header.as_array()
                    && pair.len() >= 2
                {
                    let name = pair[0].as_str()?;
                    let value = pair[1].as_str().unwrap_or_default();
                    return Some((name.to_string(), value.to_string()));
                }
                let name = header
                    .get("name")
                    .or_else(|| header.get("key"))
                    .and_then(Value::as_str)?;
                let value = header
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                Some((name.to_string(), value.to_string()))
            })
            .collect();
    }
    value
        .as_object()
        .map(|map| {
            map.iter()
                .filter_map(|(name, value)| {
                    value
                        .as_str()
                        .map(|value| (name.clone(), value.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn body_from_json(value: Option<&Value>) -> Option<Vec<u8>> {
    let value = value?;
    if let Some(text) = value.as_str() {
        return Some(text.as_bytes().to_vec());
    }
    if let Some(object) = value.as_object()
        && let Some(text) = object
            .get("text")
            .or_else(|| object.get("raw"))
            .or_else(|| object.get("data"))
            .and_then(Value::as_str)
    {
        if object
            .get("encoding")
            .or_else(|| object.get("contentEncoding"))
            .and_then(Value::as_str)
            .is_some_and(|encoding| encoding.eq_ignore_ascii_case("base64"))
        {
            return general_purpose::STANDARD.decode(text.trim()).ok();
        }
        return Some(text.as_bytes().to_vec());
    }
    None
}

fn tag_contents(raw: &str, tag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = raw;
    let open_needle = format!("<{tag}");
    let close_needle = format!("</{tag}>");
    while let Some(open_start) = rest.find(&open_needle) {
        let after_open = &rest[open_start..];
        let Some(open_end) = after_open.find('>') else {
            break;
        };
        let content_start = open_start + open_end + 1;
        let after_content = &rest[content_start..];
        let Some(close_start) = after_content.find(&close_needle) else {
            break;
        };
        out.push(after_content[..close_start].to_string());
        rest = &after_content[close_start + close_needle.len()..];
    }
    out
}

fn xml_text(item: &str, tag: &str) -> Option<String> {
    let content = tag_contents(item, tag).into_iter().next()?;
    Some(xml_unescape(content.trim()))
}

fn xml_payload(item: &str, tag: &str) -> Option<Vec<u8>> {
    let open_needle = format!("<{tag}");
    let open_start = item.find(&open_needle)?;
    let after_open = &item[open_start..];
    let open_end = after_open.find('>')?;
    let open_tag = &after_open[..open_end + 1];
    let content_start = open_start + open_end + 1;
    let close_needle = format!("</{tag}>");
    let close_start = item[content_start..].find(&close_needle)? + content_start;
    let content = item[content_start..close_start].trim();
    let unescaped = xml_unescape(content);
    if open_tag.contains("base64=\"true\"") {
        general_purpose::STANDARD.decode(unescaped.trim()).ok()
    } else {
        Some(unescaped.into_bytes())
    }
}

fn xml_unescape(raw: &str) -> String {
    raw.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_raw_http_request(
    bytes: &[u8],
    fallback_url: Option<&str>,
    fallback_scheme: Option<&str>,
    fallback_host: Option<&str>,
    fallback_port: Option<u16>,
) -> Option<RawRequestParts> {
    let (head, body) = split_http_bytes(bytes);
    let mut lines = head.lines();
    let first = lines.next()?.trim();
    let mut first_parts = first.split_whitespace();
    let method = first_parts.next()?.to_ascii_uppercase();
    let target = first_parts.next()?.to_string();
    let headers = parse_header_lines(lines);
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else if let Some(url) = fallback_url {
        url.to_string()
    } else {
        let host = header_value(&headers, "host").or_else(|| fallback_host.map(str::to_string))?;
        let scheme = fallback_scheme.unwrap_or("https");
        let port = fallback_port
            .filter(|port| {
                !((scheme == "http" && *port == 80) || (scheme == "https" && *port == 443))
            })
            .map(|port| format!(":{port}"))
            .unwrap_or_default();
        format!("{scheme}://{host}{port}{target}")
    };
    Some((method, url, headers, (!body.is_empty()).then_some(body)))
}

fn parse_raw_http_response(bytes: &[u8]) -> Option<RawResponseParts> {
    let (head, body) = split_http_bytes(bytes);
    let mut lines = head.lines();
    let first = lines.next()?.trim();
    let status = first
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse::<u16>().ok())?;
    let headers = parse_header_lines(lines);
    Some((status, headers, (!body.is_empty()).then_some(body)))
}

fn split_http_bytes(bytes: &[u8]) -> (String, Vec<u8>) {
    if let Some(pos) = find_subsequence(bytes, b"\r\n\r\n") {
        return (
            String::from_utf8_lossy(&bytes[..pos]).into_owned(),
            bytes[pos + 4..].to_vec(),
        );
    }
    if let Some(pos) = find_subsequence(bytes, b"\n\n") {
        return (
            String::from_utf8_lossy(&bytes[..pos]).into_owned(),
            bytes[pos + 2..].to_vec(),
        );
    }
    (String::from_utf8_lossy(bytes).into_owned(), Vec::new())
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn parse_header_lines<'a, I>(lines: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = &'a str>,
{
    lines
        .into_iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn sanitize_headers(headers: &[(String, String)]) -> Vec<HeaderRecord> {
    headers
        .iter()
        .map(|(name, value)| {
            let redacted = is_sensitive_header(name);
            HeaderRecord {
                name: name.to_ascii_lowercase(),
                value: if redacted {
                    if name.eq_ignore_ascii_case("set-cookie") {
                        sanitize_set_cookie(value)
                    } else {
                        "<redacted>".into()
                    }
                } else {
                    value.clone()
                },
                redacted,
            }
        })
        .collect()
}

fn is_sensitive_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-xsrf-token"
    )
}

fn detect_auth_state(headers: &[(String, String)], params: &BTreeSet<String>) -> AuthState {
    let has_auth_header = headers.iter().any(|(name, value)| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "authorization" | "cookie" | "x-api-key" | "x-auth-token"
        ) && !value.trim().is_empty()
    });
    let has_auth_param = params.iter().any(|name| {
        matches!(
            name.to_ascii_lowercase().as_str(),
            "token" | "access_token" | "auth" | "api_key" | "session"
        )
    });
    if has_auth_header || has_auth_param {
        AuthState::Authenticated
    } else {
        AuthState::Anonymous
    }
}

fn content_type(headers: &[(String, String)]) -> Option<String> {
    header_value(headers, "content-type")
}

fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.to_string())
}

fn header_names(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn cookie_names(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"))
        .filter_map(|(_, value)| {
            value
                .split_once('=')
                .map(|(name, _)| name.trim().to_string())
                .filter(|name| !name.is_empty())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn sanitize_set_cookie(raw: &str) -> String {
    let mut parts = raw.split(';').map(str::trim);
    let first = parts.next().unwrap_or_default();
    let name = first.split_once('=').map_or(first, |(name, _)| name);
    let attrs = parts.collect::<Vec<_>>();
    if attrs.is_empty() {
        format!("{name}=<redacted>")
    } else {
        format!("{name}=<redacted>; {}", attrs.join("; "))
    }
}

fn mime_without_params(raw: &str) -> String {
    raw.split(';')
        .next()
        .unwrap_or(raw)
        .trim()
        .to_ascii_lowercase()
}

fn body_param_names(mime: Option<&str>, body_text: &str) -> Vec<String> {
    let Some(mime) = mime else {
        return Vec::new();
    };
    if mime.contains("application/json")
        && let Ok(Value::Object(map)) = serde_json::from_str::<Value>(body_text)
    {
        return map.keys().cloned().collect();
    }
    if mime.contains("application/x-www-form-urlencoded") {
        return body_text
            .split('&')
            .filter_map(|pair| pair.split_once('=').map(|(name, _)| name.to_string()))
            .collect();
    }
    Vec::new()
}

fn maybe_html_title(mime: Option<&str>, body_text: &str) -> Option<String> {
    if !mime.is_some_and(|mime| mime.contains("html")) && !body_text.contains("<title") {
        return None;
    }
    let lower = body_text.to_ascii_lowercase();
    let title_start = lower.find("<title")?;
    let after_open = &body_text[title_start..];
    let gt = after_open.find('>')?;
    let content_start = title_start + gt + 1;
    let after_title = &body_text[content_start..];
    let close = after_title.to_ascii_lowercase().find("</title>")?;
    let title = after_title[..close].trim();
    (!title.is_empty()).then(|| xml_unescape(title))
}

fn maybe_json_shape(mime: Option<&str>, body_text: &str) -> Option<String> {
    if !mime.is_some_and(|mime| mime.contains("json")) && !body_text.trim_start().starts_with('{') {
        return None;
    }
    let value: Value = serde_json::from_str(body_text).ok()?;
    Some(json_shape(&value, 0))
}

fn json_shape(value: &Value, depth: usize) -> String {
    if depth >= 3 {
        return value_type(value).into();
    }
    match value {
        Value::Object(map) => {
            let mut entries: Vec<String> = map
                .iter()
                .take(32)
                .map(|(key, value)| format!("{key}:{}", json_shape(value, depth + 1)))
                .collect();
            if map.len() > 32 {
                entries.push("...".into());
            }
            format!("object{{{}}}", entries.join(","))
        }
        Value::Array(values) => values
            .first()
            .map(|value| format!("array<{}>", json_shape(value, depth + 1)))
            .unwrap_or_else(|| "array<empty>".into()),
        _ => value_type(value).into(),
    }
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn normalize_url(raw: &str) -> Option<String> {
    let mut url = Url::parse(raw).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    url.set_host(Some(&host)).ok()?;
    url.set_fragment(None);
    Some(url.to_string())
}

fn traffic_id(
    method: &str,
    url: &str,
    captured_at: &str,
    request_body_hash: &str,
    response_status: u16,
    response_body_hash: &str,
) -> String {
    let digest = sha256_hex(format!(
        "{method}|{url}|{captured_at}|{request_body_hash}|{response_status}|{response_body_hash}"
    ));
    format!("req_{}", &digest[..16])
}

fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hex::encode(hasher.finalize())
}

fn now_rfc3339() -> Result<String, EngagementError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EngagementMeta;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("traffic-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_engagement() -> Engagement {
        let parent = tmp_parent();
        Engagement::init(
            &parent,
            EngagementMeta {
                name: "acme".into(),
                target: "example.com".into(),
                created_at: String::new(),
                platform: None,
                url: None,
                tags: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn har_import_indexes_and_redacts_request() {
        let eng = test_engagement();
        let har_path = eng.root.join("sample.har");
        fs::write(
            &har_path,
            r#"{
              "log": {
                "entries": [{
                  "startedDateTime": "2026-05-15T00:00:00Z",
                  "request": {
                    "method": "GET",
                    "url": "https://API.Example.com/users?id=1",
                    "headers": [{"name":"Authorization","value":"Bearer secret"}],
                    "queryString": [{"name":"id","value":"1"}]
                  },
                  "response": {
                    "status": 200,
                    "headers": [{"name":"Content-Type","value":"text/html"}, {"name":"Set-Cookie","value":"sid=abc; HttpOnly"}],
                    "content": {"mimeType":"text/html","text":"<html><title>Users</title></html>"}
                  }
                }]
              }
            }"#,
        )
        .unwrap();

        let summary = import_traffic_file(&eng, &har_path, TrafficImportFormat::Har).unwrap();
        assert_eq!(summary.imported, 1);

        let records = load_traffic_records(&eng).unwrap();
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.host, "api.example.com");
        assert_eq!(record.path, "/users");
        assert_eq!(record.auth_state, AuthState::Authenticated);
        assert!(record.params.contains(&"id".into()));
        assert_eq!(record.request_headers[0].value, "<redacted>");
        let response = record.response.as_ref().unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.html_title.as_deref(), Some("Users"));
        assert_eq!(response.cookie_names, vec!["sid".to_string()]);
        assert!(eng.traffic_corpus_path().exists());
    }

    #[test]
    fn burp_xml_import_decodes_raw_pair() {
        let eng = test_engagement();
        let request = general_purpose::STANDARD
            .encode("POST /login HTTP/1.1\r\nHost: www.example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=a");
        let response = general_purpose::STANDARD
            .encode("HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Type: text/plain\r\n\r\nok");
        let xml_path = eng.root.join("burp.xml");
        fs::write(
            &xml_path,
            format!(
                "<items><item><time>2026-05-15T00:00:00Z</time><host>www.example.com</host><port>443</port><protocol>https</protocol><method>POST</method><request base64=\"true\">{request}</request><response base64=\"true\">{response}</response></item></items>"
            ),
        )
        .unwrap();

        let summary = import_traffic_file(&eng, &xml_path, TrafficImportFormat::Burp).unwrap();
        assert_eq!(summary.imported, 1);
        let records = load_traffic_records(&eng).unwrap();
        assert_eq!(records[0].method, "POST");
        assert_eq!(records[0].url, "https://www.example.com/login");
        assert!(records[0].request_body.is_some());
        assert_eq!(
            records[0]
                .response
                .as_ref()
                .and_then(|response| response.redirect_location.as_deref()),
            Some("/home")
        );
    }

    #[test]
    fn search_filters_by_method_status_and_source() {
        let eng = test_engagement();
        let har_path = eng.root.join("sample.har");
        fs::write(
            &har_path,
            r#"{"log":{"entries":[
              {"startedDateTime":"2026-05-15T00:00:00Z","request":{"method":"GET","url":"https://example.com/a","headers":[]},"response":{"status":200,"headers":[],"content":{"text":"a"}}},
              {"startedDateTime":"2026-05-15T00:00:01Z","request":{"method":"POST","url":"https://example.com/b","headers":[]},"response":{"status":403,"headers":[],"content":{"text":"b"}}}
            ]}}"#,
        )
        .unwrap();
        import_traffic_file(&eng, &har_path, TrafficImportFormat::Har).unwrap();

        let results = search_traffic_records(
            &eng,
            &TrafficFilter {
                method: Some("POST".into()),
                status: Some(403),
                source: Some("har".into()),
                ..TrafficFilter::default()
            },
        )
        .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, "/b");
    }

    #[test]
    fn response_diff_reports_shape_changes() {
        let original = response_fingerprint_from_parts(
            200,
            &[("content-type".into(), "application/json".into())],
            br#"{"id":1,"name":"a"}"#,
            None,
        );
        let replayed = response_fingerprint_from_parts(
            403,
            &[("content-type".into(), "application/json".into())],
            br#"{"error":"denied"}"#,
            None,
        );

        let diff = diff_response_fingerprints(&original, &replayed);
        assert!(diff.status_changed);
        assert!(diff.body_hash_changed);
        assert!(diff.json_shape_changed);
    }
}
