/*******************************************************************
 * Filename:        template.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Parse a raw HTTP request template containing §position§ markers
 *                  into a structured RequestTemplate ready for payload injection
 * Notes:           Template format mirrors Burp Intruder:
 *                    - First line: METHOD /path HTTP/1.1
 *                    - Headers: Key: Value  (blank line separates from body)
 *                    - Body: everything after the blank line
 *                  Markers are §name§ — any text between § delimiters.
 *                  Split on § character: even-indexed parts are literal text,
 *                  odd-indexed parts are marker names.
 *******************************************************************/

use anyhow::{bail, Result};

// One parsed HTTP request template
#[derive(Debug, Clone)]
pub struct RequestTemplate {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    // ordered unique list of marker names in first-appearance order
    pub positions: Vec<String>,
}

// A fully substituted HTTP request ready to send
#[derive(Debug, Clone)]
pub struct InjectedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl RequestTemplate {
    // Parse raw template text; fails if the first line is not METHOD /path
    pub fn parse(raw: &str) -> Result<Self> {
        let mut lines = raw.lines();

        // first line must be "METHOD /path [HTTP/version]"
        let first = lines.next().unwrap_or("").trim();
        let parts: Vec<&str> = first.splitn(3, ' ').collect();
        if parts.len() < 2 {
            bail!("invalid template: first line must be 'METHOD /path [HTTP/version]'");
        }
        let method = parts[0].to_uppercase();
        let path = parts[1].to_string();

        // parse headers until the first blank line, then collect body
        let mut headers = Vec::new();
        let mut body_lines: Vec<&str> = Vec::new();
        let mut in_body = false;

        for line in lines {
            if in_body {
                body_lines.push(line);
                continue;
            }
            if line.trim().is_empty() {
                in_body = true;
                continue;
            }
            // split header on first colon
            if let Some(colon) = line.find(':') {
                headers.push((line[..colon].trim().to_string(), line[colon + 1..].trim().to_string()));
            }
        }

        let body = if body_lines.is_empty() { None } else { Some(body_lines.join("\n")) };

        // collect all unique marker names in order of first appearance
        let mut positions: Vec<String> = Vec::new();
        collect_markers(&path, &mut positions);
        for (_, v) in &headers { collect_markers(v, &mut positions); }
        if let Some(b) = &body { collect_markers(b, &mut positions); }

        Ok(RequestTemplate { method, path, headers, body, positions })
    }

    // Substitute §markers§ with payloads; payloads index aligns with positions list
    pub fn inject(&self, payloads: &[&str]) -> InjectedRequest {
        let sub = |s: &str| substitute(s, &self.positions, payloads);
        InjectedRequest {
            method:  self.method.clone(),
            path:    sub(&self.path),
            headers: self.headers.iter().map(|(k, v)| (k.clone(), sub(v))).collect(),
            body:    self.body.as_deref().map(sub),
        }
    }
}

// Scan a string for §name§ pairs; add each unique name to `out` in appearance order
// Splitting on § gives: [text, marker, text, marker, text, ...]
// Odd-indexed segments (1, 3, 5, ...) are marker names
fn collect_markers(s: &str, out: &mut Vec<String>) {
    let mut parts = s.split('§');
    parts.next(); // skip the segment before the first §
    loop {
        // next segment is a marker name
        let name = match parts.next() {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => break,
        };
        if !out.contains(&name) { out.push(name); }
        // skip the literal segment between the closing § and the next opening §
        if parts.next().is_none() { break; }
    }
}

// Replace every §name§ marker with the corresponding payload string
fn substitute(s: &str, positions: &[String], payloads: &[&str]) -> String {
    let mut result = s.to_string();
    for (idx, name) in positions.iter().enumerate() {
        let marker = format!("§{name}§");
        let replacement = payloads.get(idx).copied().unwrap_or(name.as_str());
        result = result.replace(&marker, replacement);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Template with two distinct positions; "id" appears twice (in path and body)
    fn make_tmpl() -> RequestTemplate {
        let raw = "POST /api/v1/users/§id§ HTTP/1.1\nHost: target.com\nAuthorization: Bearer §token§\n\n{\"id\": §id§}";
        RequestTemplate::parse(raw).unwrap()
    }

    #[test]
    fn parse_extracts_method_and_path() {
        let t = make_tmpl();
        assert_eq!(t.method, "POST");
        assert_eq!(t.path, "/api/v1/users/§id§");
    }

    #[test]
    fn parse_deduplicates_positions_preserving_order() {
        let t = make_tmpl();
        // "id" appears in path first, "token" in header second; second "id" in body is deduplicated
        assert_eq!(t.positions, vec!["id", "token"]);
    }

    #[test]
    fn inject_replaces_all_occurrences_across_fields() {
        let t = make_tmpl();
        let req = t.inject(&["42", "abc123"]);
        assert_eq!(req.path, "/api/v1/users/42");
        assert_eq!(req.body.as_deref(), Some("{\"id\": 42}"));
        assert!(req.headers[1].1.contains("abc123"));
    }

    #[test]
    fn inject_missing_payload_leaves_marker_name() {
        let t = make_tmpl();
        let req = t.inject(&["42"]);  // token not provided
        assert!(req.headers[1].1.contains("token"));
    }

    #[test]
    fn malformed_first_line_returns_error() {
        assert!(RequestTemplate::parse("BADTEMPLATE").is_err());
    }

    #[test]
    fn no_markers_parses_cleanly() {
        let t = RequestTemplate::parse("GET / HTTP/1.1\nHost: x.com\n\n").unwrap();
        assert!(t.positions.is_empty());
    }
}
