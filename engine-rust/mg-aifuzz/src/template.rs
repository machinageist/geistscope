/*******************************************************************
 * Filename:        template.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Slim HTTP request template for prompt-injection fuzzing
 * Notes:           Mirrors the mg-fuzz Burp-Intruder grammar but expects a
 *                  single `§INJECT§` marker per request. Payloads are
 *                  JSON-string-escaped before substitution when the body
 *                  looks like JSON.
 *******************************************************************/

use anyhow::{Result, bail};

const INJECT_MARKER: &str = "§INJECT§";

#[derive(Debug, Clone)]
pub struct AiRequestTemplate {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub body_is_json: bool,
}

#[derive(Debug, Clone)]
pub struct InjectedAiRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

impl AiRequestTemplate {
    // Parse the request template; reject templates with no §INJECT§ marker
    pub fn parse(raw: &str) -> Result<Self> {
        let mut lines = raw.lines();
        let first = lines.next().unwrap_or("").trim();
        let parts: Vec<&str> = first.splitn(3, ' ').collect();
        if parts.len() < 2 {
            bail!("invalid template: first line must be 'METHOD /path [HTTP/version]'");
        }
        let method = parts[0].to_uppercase();
        let path = parts[1].to_string();

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
            if let Some(colon) = line.find(':') {
                headers.push((
                    line[..colon].trim().to_string(),
                    line[colon + 1..].trim().to_string(),
                ));
            }
        }
        let body = if body_lines.is_empty() {
            None
        } else {
            Some(body_lines.join("\n"))
        };

        let combined = format!(
            "{path}\n{}\n{}",
            headers
                .iter()
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>()
                .join("\n"),
            body.as_deref().unwrap_or("")
        );
        if !combined.contains(INJECT_MARKER) {
            bail!("invalid template: no §INJECT§ marker found");
        }

        let body_is_json = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value.contains("json")
        });

        Ok(Self {
            method,
            path,
            headers,
            body,
            body_is_json,
        })
    }

    // Substitute the §INJECT§ marker with one prompt-injection payload
    pub fn inject(&self, payload: &str) -> InjectedAiRequest {
        let replacement = if self.body_is_json {
            json_escape(payload)
        } else {
            payload.to_string()
        };
        let sub = |s: &str| s.replace(INJECT_MARKER, &replacement);
        InjectedAiRequest {
            method: self.method.clone(),
            path: sub(&self.path),
            headers: self
                .headers
                .iter()
                .map(|(name, value)| (name.clone(), sub(value)))
                .collect(),
            body: self.body.as_deref().map(sub),
        }
    }
}

// Escape a payload so it is safe inside a JSON string literal
pub fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json_template() -> AiRequestTemplate {
        let raw = "POST /chat HTTP/1.1\nHost: api.target.example\nContent-Type: application/json\n\n{\"messages\":[{\"role\":\"user\",\"content\":\"§INJECT§\"}]}";
        AiRequestTemplate::parse(raw).unwrap()
    }

    #[test]
    fn parse_detects_json_body() {
        let t = json_template();
        assert!(t.body_is_json);
        assert_eq!(t.method, "POST");
        assert_eq!(t.path, "/chat");
    }

    #[test]
    fn parse_rejects_template_without_marker() {
        let raw = "POST /chat HTTP/1.1\nHost: x\n\n{\"messages\":[]}";
        assert!(AiRequestTemplate::parse(raw).is_err());
    }

    #[test]
    fn inject_escapes_quotes_for_json_body() {
        let t = json_template();
        let req = t.inject("hello \"world\"\nnext line");
        let body = req.body.unwrap();
        assert!(body.contains("hello \\\"world\\\"\\nnext line"));
    }

    #[test]
    fn inject_does_not_escape_when_body_is_not_json() {
        let raw = "POST /chat HTTP/1.1\nHost: x\nContent-Type: text/plain\n\n§INJECT§";
        let t = AiRequestTemplate::parse(raw).unwrap();
        let req = t.inject("\"plain\"\n");
        assert_eq!(req.body.as_deref(), Some("\"plain\"\n"));
    }
}
