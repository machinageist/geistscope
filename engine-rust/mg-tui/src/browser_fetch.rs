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
use std::time::Duration;

const TIMEOUT_SECS: u64 = 30;

// Image width used when pre-rendering halfblock (generous; terminal clips extras)
const IMG_RENDER_WIDTH: u16 = 160;

// Successful page fetch
pub struct FetchResult {
    pub url: String,
    pub status: u16,
    pub content_type: String,
    pub page: RenderedPage,
}

// Successful image fetch (pre-rendered to halfblock lines)
pub struct ImageFetchResult {
    pub index: usize,
    pub lines: Vec<Line<'static>>,
}

// Messages sent from background threads to the main event loop
pub enum AppMsg {
    Page(Result<FetchResult, String>),
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
fn process_response(resp: reqwest::blocking::Response) -> Result<FetchResult, String> {
    let status = resp.status().as_u16();
    let final_url = resp.url().to_string();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("text/plain")
        .to_string();
    let body = resp.text().map_err(|e| e.to_string())?;
    let page = if content_type.contains("html") {
        render_html(&body, &final_url)
    } else {
        render_plain(&body)
    };
    Ok(FetchResult { url: final_url, status, content_type, page })
}

// Fetch a URL, render the response body, return result or error string
pub fn fetch_page(url: &str) -> Result<FetchResult, String> {
    let client = make_client()?;
    let resp = client.get(url).send().map_err(|e| e.to_string())?;
    process_response(resp)
}

// POST form params to a URL and render the response
pub fn fetch_post(url: &str, params: &[(String, String)]) -> Result<FetchResult, String> {
    let client = make_client()?;
    let resp = client.post(url).form(params).send().map_err(|e| e.to_string())?;
    process_response(resp)
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
