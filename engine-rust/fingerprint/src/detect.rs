// Author: Jeff
// Date: 2026-05-01
// Description: Parse HTTP response headers + body to identify server, framework, CDN, CMS, cloud

use http_client::{Client, ClientConfig};
use serde::Serialize;

#[derive(Debug, Default, Serialize, Clone)]
pub struct Fingerprint {
    pub server: Option<String>,
    pub framework: Option<String>,
    pub cdn: Option<String>,
    pub cms: Option<String>,
    pub cloud: Option<String>,
    pub powered_by: Option<String>,
}

// Probe a URL and return the technology fingerprint
pub async fn fingerprint_url(url: &str) -> Result<Fingerprint, http_client::HttpError> {
    let client = Client::new(ClientConfig {
        timeout_ms: 8_000,
        max_retries: 1,
        ..Default::default()
    })?;
    let resp = client.get(url).await?;
    let headers = resp.headers().clone();
    let body = resp.text().await.unwrap_or_default();

    Ok(Fingerprint {
        server: detect_server_header(&headers),
        framework: detect_framework(&headers, &body).map(str::to_string),
        cdn: detect_cdn(&headers).map(str::to_string),
        cms: detect_cms(&body).map(str::to_string),
        cloud: detect_cloud(&headers).map(str::to_string),
        powered_by: detect_powered_by(&headers),
    })
}

fn header_str<'a>(headers: &'a reqwest::header::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn detect_server_header(headers: &reqwest::header::HeaderMap) -> Option<String> {
    header_str(headers, "server").map(|s| s.to_lowercase())
}

fn detect_powered_by(headers: &reqwest::header::HeaderMap) -> Option<String> {
    header_str(headers, "x-powered-by").map(|s| s.to_lowercase())
}

fn detect_cdn(headers: &reqwest::header::HeaderMap) -> Option<&'static str> {
    if headers.contains_key("cf-ray") { return Some("cloudflare"); }
    if headers.contains_key("x-amz-cf-pop") { return Some("cloudfront"); }
    if headers.contains_key("x-vercel-id") { return Some("vercel"); }
    if headers.contains_key("x-netlify-id") { return Some("netlify"); }
    if let Some(via) = header_str(headers, "via") {
        if via.contains("varnish") { return Some("fastly"); }
    }
    if let Some(cache) = header_str(headers, "x-cache") {
        if cache.contains("Fastly") { return Some("fastly"); }
    }
    None
}

fn detect_cloud(headers: &reqwest::header::HeaderMap) -> Option<&'static str> {
    if headers.contains_key("x-cloud-trace-context") { return Some("gcp"); }
    if headers.contains_key("x-ms-request-id") { return Some("azure"); }
    if let Some(server) = header_str(headers, "server") {
        if server.contains("awselb") || server.contains("AmazonS3") { return Some("aws"); }
    }
    None
}

fn detect_cms(body: &str) -> Option<&'static str> {
    if body.contains("/wp-content/") || body.contains("/wp-includes/") { return Some("wordpress"); }
    if body.contains("Drupal.settings") || body.contains("/sites/default/files/") { return Some("drupal"); }
    if body.contains("joomla") || body.contains("/components/com_") { return Some("joomla"); }
    if body.contains("data-shopify") || body.contains("Shopify.theme") { return Some("shopify"); }
    None
}

fn detect_framework(headers: &reqwest::header::HeaderMap, body: &str) -> Option<&'static str> {
    // Header-based detection first (cheaper than body scan)
    if let Some(xpb) = header_str(headers, "x-powered-by") {
        let xpb = xpb.to_lowercase();
        if xpb.contains("express") { return Some("express"); }
        if xpb.contains("asp.net") { return Some("aspnet"); }
        if xpb.contains("php") { return Some("php"); }
        if xpb.contains("next.js") { return Some("nextjs"); }
    }
    if headers.contains_key("x-aspnet-version") { return Some("aspnet"); }
    if headers.contains_key("x-laravel-session") { return Some("laravel"); }

    // Body-based detection
    if body.contains("__NEXT_DATA__") { return Some("nextjs"); }
    if body.contains("__nuxt") || body.contains("__NUXT__") { return Some("nuxt"); }
    if body.contains("ng-version=") || body.contains("data-ng-app") { return Some("angular"); }
    if body.contains("data-reactroot") || body.contains("__react_fiber") { return Some("react"); }
    if body.contains("__vue_app__") || body.contains("data-v-app") { return Some("vue"); }
    if body.contains("Rails.ajax") || body.contains("csrf-param") { return Some("rails"); }
    if body.contains("csrfmiddlewaretoken") { return Some("django"); }
    if body.contains("laravel_session") || body.contains("XSRF-TOKEN") { return Some("laravel"); }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_wordpress_from_body() {
        assert_eq!(detect_cms("<link href='/wp-content/themes/x'"), Some("wordpress"));
    }

    #[test]
    fn detect_nextjs_from_body() {
        assert_eq!(detect_framework(&reqwest::header::HeaderMap::new(), "<script id='__NEXT_DATA__'"), Some("nextjs"));
    }

    #[test]
    fn detect_cloudflare_from_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("cf-ray", "abc123".parse().unwrap());
        assert_eq!(detect_cdn(&headers), Some("cloudflare"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(detect_cms("<html><body>hello</body></html>"), None);
        assert_eq!(detect_cdn(&reqwest::header::HeaderMap::new()), None);
    }
}
