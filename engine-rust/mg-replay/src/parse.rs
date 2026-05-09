/*******************************************************************
 * Filename:        parse.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Extract curl commands from finding markdown files
 *                  and parse them into structured CurlRequest values
 * Notes:           Only parses code blocks under the "## Evidence" section.
 *                  Supported curl flags: -X/--request, -H/--header,
 *                  -d/--data/--data-raw/--data-binary, -u/--user,
 *                  -b/--cookie, -k/--insecure, -L/--location.
 *                  Multi-line curl commands joined with backslash-newline are supported.
 *******************************************************************/

use anyhow::{bail, Result};

// One parsed curl invocation
#[derive(Debug, Clone)]
pub struct CurlRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub insecure: bool,
    #[allow(dead_code)]  // respected by client builder in main.rs v2; stored for now
    pub follow_redirects: bool,
}

// Extract all curl commands found in "## Evidence" fenced code blocks of a markdown string
pub fn extract_curl_commands(markdown: &str) -> Vec<String> {
    let mut in_evidence = false;
    let mut in_code_block = false;
    let mut current_block: Vec<&str> = Vec::new();
    let mut commands: Vec<String> = Vec::new();

    for line in markdown.lines() {
        // track which section we're in
        if line.trim_start().starts_with("## ") {
            in_evidence = line.trim().eq_ignore_ascii_case("## Evidence");
            if in_code_block {
                // code block wasn't closed — abandon it
                in_code_block = false;
                current_block.clear();
            }
            continue;
        }

        if !in_evidence { continue; }

        // detect fenced code block open/close (``` with optional language tag)
        if line.trim_start().starts_with("```") {
            if !in_code_block {
                in_code_block = true;
                current_block.clear();
            } else {
                // closing fence — join and keep if it starts with curl
                let joined = join_continuations(&current_block);
                if joined.trim_start().starts_with("curl") {
                    commands.push(joined);
                }
                in_code_block = false;
                current_block.clear();
            }
            continue;
        }

        if in_code_block {
            current_block.push(line);
        }
    }

    commands
}

// Join lines that end with \ into a single logical command line
fn join_continuations(lines: &[&str]) -> String {
    let mut out = String::new();
    for line in lines {
        if let Some(stripped) = line.strip_suffix('\\') {
            out.push_str(stripped.trim_end());
            out.push(' ');
        } else {
            out.push_str(line.trim());
        }
    }
    out
}

// Parse a single curl command string into a CurlRequest
pub fn parse_curl(cmd: &str) -> Result<CurlRequest> {
    // tokenize respecting single- and double-quoted strings
    let tokens = tokenize(cmd);
    if tokens.is_empty() || tokens[0] != "curl" {
        bail!("not a curl command");
    }

    let mut url: Option<String> = None;
    let mut method: Option<String> = None;
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body: Option<String> = None;
    let mut insecure = false;
    let mut follow_redirects = false;

    let mut i = 1;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        match tok {
            "-X" | "--request" => {
                i += 1;
                method = tokens.get(i).cloned();
            }
            "-H" | "--header" => {
                i += 1;
                if let Some(hdr) = tokens.get(i)
                    && let Some(colon) = hdr.find(':')
                {
                    headers.push((
                        hdr[..colon].trim().to_string(),
                        hdr[colon + 1..].trim().to_string(),
                    ));
                }
            }
            "-d" | "--data" | "--data-raw" | "--data-binary" => {
                i += 1;
                body = tokens.get(i).cloned();
            }
            "-u" | "--user" => {
                i += 1;
                if let Some(creds) = tokens.get(i) {
                    // encode credentials as Basic auth header value
                    let encoded = base64_encode(creds.as_bytes());
                    headers.push(("Authorization".into(), format!("Basic {encoded}")));
                }
            }
            "-b" | "--cookie" => {
                i += 1;
                if let Some(cookie) = tokens.get(i) {
                    headers.push(("Cookie".into(), cookie.clone()));
                }
            }
            "-k" | "--insecure" => insecure = true,
            "-L" | "--location" => follow_redirects = true,
            // skip flags we don't handle: -o, --output, --compressed, etc.
            t if t.starts_with('-') => {
                // skip one argument if flag takes a value (heuristic: next token doesn't start with -)
                if let Some(next) = tokens.get(i + 1)
                    && !next.starts_with('-')
                {
                    i += 1;
                }
            }
            // positional argument: the URL
            t => {
                if url.is_none() { url = Some(t.to_string()); }
            }
        }
        i += 1;
    }

    let url = url.ok_or_else(|| anyhow::anyhow!("no URL found in curl command"))?;

    // infer method from presence of body
    let method = method.unwrap_or_else(|| {
        if body.is_some() { "POST".into() } else { "GET".into() }
    });

    Ok(CurlRequest { url, method, headers, body, insecure, follow_redirects })
}

// Naive shell tokenizer: splits on whitespace, respects 'single' and "double" quotes
fn tokenize(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        match c {
            '\'' if !in_double => in_single = !in_single,
            '"'  if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !cur.is_empty() {
                    tokens.push(cur.clone());
                    cur.clear();
                }
            }
            '\\' if !in_single => {
                // escaped character: include the next char literally
                if let Some(next) = chars.next() { cur.push(next); }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() { tokens.push(cur); }
    tokens
}

// Minimal base64 encoder without external crates
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as u32;
        let b1 = if i + 1 < input.len() { input[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] as u32 } else { 0 };
        out.push(ALPHABET[((b0 >> 2) & 0x3F) as usize] as char);
        out.push(ALPHABET[(((b0 & 3) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if i + 1 < input.len() { ALPHABET[(((b1 & 0xF) << 2) | (b2 >> 6)) as usize] as char } else { '=' });
        out.push(if i + 2 < input.len() { ALPHABET[(b2 & 0x3F) as usize] as char } else { '=' });
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const FINDING_MD: &str = "---\ntitle: IDOR\nseverity: high\n---\n\
        ## Summary\n\nDescription here.\n\n\
        ## Evidence\n\n\
        ```bash\ncurl -X GET https://api.target.com/api/v1/users/2 \\\n  -H 'Authorization: Bearer TOKEN'\n```\n\
        ## Remediation\n\nFix it.\n";

    #[test]
    fn extracts_curl_from_evidence_section() {
        let cmds = extract_curl_commands(FINDING_MD);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("curl"));
        assert!(cmds[0].contains("users/2"));
    }

    #[test]
    fn ignores_code_blocks_outside_evidence() {
        let md = "## Summary\n\n```bash\ncurl https://example.com\n```\n\n## Evidence\n\n```bash\ncurl https://target.com\n```\n";
        let cmds = extract_curl_commands(md);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains("target.com"));
    }

    #[test]
    fn parse_curl_get_with_header() {
        let req = parse_curl("curl -X GET https://api.x.com/v1/users -H 'Authorization: Bearer TOKEN'").unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.url, "https://api.x.com/v1/users");
        assert!(req.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn parse_curl_infers_post_from_data() {
        let req = parse_curl(r#"curl https://api.x.com/login -d '{"user":"a","pass":"b"}'"#).unwrap();
        assert_eq!(req.method, "POST");
        assert!(req.body.is_some());
    }

    #[test]
    fn parse_curl_insecure_flag() {
        let req = parse_curl("curl -k https://self-signed.example.com/").unwrap();
        assert!(req.insecure);
    }

    #[test]
    fn no_url_errors() {
        assert!(parse_curl("curl -X GET").is_err());
    }

    #[test]
    fn join_continuations_collapses_backslash_lines() {
        let lines = vec!["curl https://x.com \\", "  -H 'Auth: Bearer token'"];
        let joined = join_continuations(&lines);
        assert!(joined.contains("curl") && joined.contains("Auth"));
    }
}
