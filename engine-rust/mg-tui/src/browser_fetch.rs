/*******************************************************************
 * Filename:        browser_fetch.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Blocking HTTP fetchers for pages and images
 * Notes:           All functions run in background threads via std::thread::spawn.
 *                  Results arrive via AppMsg on the main mpsc channel.
 *******************************************************************/

use crate::halfblock;
use crate::html_render::{IMAGE_BLOCK_HEIGHT, RenderedPage, render_html, render_plain};
use ratatui::text::Line;
use reqwest::header::{HeaderMap, HeaderName, SET_COOKIE};
use std::time::Duration;

const TIMEOUT_SECS: u64 = 30;

// Image width used when pre-rendering halfblock (generous; terminal clips extras)
const IMG_RENDER_WIDTH: u16 = 160;

// Successful page fetch
pub struct FetchResult {
    pub url: String,
    pub request_method: String,
    pub status: u16,
    pub content_type: String,
    pub response_headers: Vec<(String, String)>,
    pub response_cookies: Vec<String>,
    pub page: RenderedPage,
}

// Successful image fetch (pre-rendered to halfblock lines)
pub struct ImageFetchResult {
    pub index: usize,
    pub lines: Vec<Line<'static>>,
}

// Messages sent from background threads to the main event loop
pub enum AppMsg {
    Page(Result<Box<FetchResult>, String>),
    Image(ImageFetchResult),
}

// Build a reusable reqwest blocking client
fn make_client() -> Result<reqwest::blocking::Client, String> {
    reqwest::blocking::Client::builder()
        .user_agent("Mozilla/5.0 (compatible; mg-tui/0.1)")
        .timeout(Duration::from_secs(TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::limited(10))
        .build()
        .map_err(|e| e.to_string())
}

// Convert a reqwest response into a FetchResult
fn process_response(
    method: &str,
    resp: reqwest::blocking::Response,
) -> Result<FetchResult, String> {
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/plain")
        .to_string();
    let response_headers = sanitized_headers(resp.headers());
    let response_cookies = sanitized_set_cookies(resp.headers());
    let body = resp.text().map_err(|e| e.to_string())?;
    let page = if content_type.contains("html") {
        render_html(&body, &final_url)
    } else {
        render_plain(&body)
    };
    Ok(FetchResult {
        url: final_url,
        request_method: method.to_string(),
        status,
        content_type,
        response_headers,
        response_cookies,
        page,
    })
}

// Fetch a URL, render the response body, return result or error string
pub fn fetch_page(url: &str) -> Result<FetchResult, String> {
    let client = make_client()?;
    let resp = client.get(url).send().map_err(|e| e.to_string())?;
    process_response("GET", resp)
}

// POST form params to a URL and render the response
pub fn fetch_post(url: &str, params: &[(String, String)]) -> Result<FetchResult, String> {
    let client = make_client()?;
    let resp = client
        .post(url)
        .form(params)
        .send()
        .map_err(|e| e.to_string())?;
    process_response("POST", resp)
}

// Download an image URL and render it to halfblock terminal lines
// Returns None on any error (network, decode, wrong MIME) so callers can ignore silently
pub fn fetch_image(src: &str, index: usize) -> Option<ImageFetchResult> {
    let client = make_client().ok()?;
    let resp = client.get(src).send().ok()?;

    // Reject non-image content types
    let ct = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !ct.starts_with("image/") {
        return None;
    }

    let bytes = resp.bytes().ok()?;
    let img = halfblock::decode(&bytes).ok()?;
    let lines = halfblock::to_lines(&img, IMG_RENDER_WIDTH, IMAGE_BLOCK_HEIGHT as u16);

    Some(ImageFetchResult { index, lines })
}

// Return redacted response headers for display in the TUI inspector
fn sanitized_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            let raw = value.to_str().unwrap_or("<binary>").to_string();
            let safe = if should_redact_header(name) {
                redact_header_value(name, &raw)
            } else {
                raw
            };
            (name.as_str().to_string(), safe)
        })
        .collect()
}

// Return cookie names and attributes without exposing cookie values
fn sanitized_set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(sanitize_set_cookie)
        .collect()
}

// Decide whether a header value may contain secrets
fn should_redact_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str().to_ascii_lowercase().as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie" | "x-api-key"
    )
}

// Redact a sensitive header while preserving useful shape
fn redact_header_value(name: &HeaderName, raw: &str) -> String {
    if name == SET_COOKIE {
        sanitize_set_cookie(raw)
    } else {
        "<redacted>".to_string()
    }
}

// Sanitize a Set-Cookie header into name + attributes only
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

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{AUTHORIZATION, HeaderValue};

    #[test]
    fn sanitizes_secret_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        headers.insert(
            SET_COOKIE,
            HeaderValue::from_static("sid=abc123; HttpOnly; Secure"),
        );

        let rendered = sanitized_headers(&headers);

        assert!(rendered.contains(&("authorization".into(), "<redacted>".into())));
        assert!(rendered.contains(&(
            "set-cookie".into(),
            "sid=<redacted>; HttpOnly; Secure".into()
        )));
    }

    #[test]
    fn extracts_redacted_cookie_inventory() {
        let mut headers = HeaderMap::new();
        headers.append(SET_COOKIE, HeaderValue::from_static("sid=abc123; HttpOnly"));
        headers.append(
            SET_COOKIE,
            HeaderValue::from_static("theme=dark; SameSite=Lax"),
        );

        let cookies = sanitized_set_cookies(&headers);

        assert_eq!(
            cookies,
            vec![
                "sid=<redacted>; HttpOnly".to_string(),
                "theme=<redacted>; SameSite=Lax".to_string()
            ]
        );
    }
}
