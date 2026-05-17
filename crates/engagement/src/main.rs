/*******************************************************************
 * Author:          machinageist
 * Date:            2026-05-02
 * Description:     mg-engagement CLI — initialize, scope, audit, findings
 *******************************************************************/
mod cli;

use anyhow::{Context, Result, anyhow};
use engagement::{
    Engagement, EngagementMeta, Finding, Severity, Status, TrafficFilter, TrafficImportFormat,
};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::path::Path;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SessionConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    login_url: Option<String>,
    #[serde(default)]
    login_method: String,
    #[serde(default)]
    token_header: String,
    #[serde(default)]
    token_prefix: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_cookie: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    token_refresh_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    valid_until: Option<String>,
}

struct CredentialsSetInput {
    username: Option<String>,
    password_env: Option<String>,
    login_url: Option<String>,
    token_env: Option<String>,
    token_header: String,
    token_prefix: String,
    login_method: Option<String>,
}

struct TrafficListInput {
    host: Option<String>,
    method: Option<String>,
    status: Option<u16>,
    mime: Option<String>,
    source: Option<String>,
    path_contains: Option<String>,
    limit: usize,
}

fn parse_severity(s: &str) -> Result<Severity> {
    match s.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(anyhow!("unknown severity: {other}")),
    }
}

fn cmd_credentials_set(root: &Path, name: &str, input: CredentialsSetInput) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    if input.token_env.is_none() && input.password_env.is_none() {
        return Err(anyhow!(
            "provide --token-env for token auth or --password-env with --login-url for form auth"
        ));
    }
    if input.password_env.is_some() && input.login_url.is_none() {
        return Err(anyhow!("--password-env requires --login-url"));
    }

    let method = input.login_method.unwrap_or_else(|| {
        if input.token_env.is_some() {
            "token".into()
        } else {
            "form".into()
        }
    });
    validate_login_method(&method)?;

    let config = SessionConfig {
        username: input.username,
        password_env: input.password_env,
        login_url: input.login_url,
        login_method: method.clone(),
        token_header: input.token_header,
        token_prefix: input.token_prefix,
        token_env: input.token_env,
        session_cookie: None,
        token_refresh_url: None,
        valid_until: None,
    };
    let path = e.root.join("session.json");
    let json = serde_json::to_string_pretty(&config)?;
    std::fs::write(&path, json)?;
    let _ = e.audit(
        "mg-engagement",
        &e.meta.target,
        Some(&format!("credentials-set method={method}")),
    );
    println!(
        "stored {method} credential profile for {name} at {}",
        path.display()
    );
    Ok(())
}

fn cmd_credentials_test(root: &Path, name: &str, test_url: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    ensure_url_in_scope(&e, test_url)?;
    let config = load_session_config(&e)?;
    let headers = build_auth_headers(&config)?;
    let client = reqwest::blocking::Client::builder()
        .default_headers(headers)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;
    let response = client.get(test_url).send()?;
    let status = response.status();
    let _ = e.audit(
        "mg-engagement",
        test_url,
        Some(&format!("credentials-test status={}", status.as_u16())),
    );
    if status.as_u16() < 400 {
        println!("session ok: {} {}", status.as_u16(), test_url);
        Ok(())
    } else {
        println!("session failed: {} {}", status.as_u16(), test_url);
        std::process::exit(2);
    }
}

fn validate_login_method(method: &str) -> Result<()> {
    match method {
        "token" | "form" | "oauth_client_credentials" => Ok(()),
        other => Err(anyhow!("unsupported login method: {other}")),
    }
}

fn load_session_config(engagement: &Engagement) -> Result<SessionConfig> {
    let path = engagement.root.join("session.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read session config {}", path.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

fn build_auth_headers(config: &SessionConfig) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    if let Some(token_env) = &config.token_env {
        let token = std::env::var(token_env)
            .with_context(|| format!("environment variable {token_env} is not set"))?;
        let header_name = HeaderName::from_bytes(config.token_header.as_bytes())?;
        let header_value = if config.token_prefix.is_empty() {
            token
        } else {
            format!("{} {}", config.token_prefix, token)
        };
        headers.insert(header_name, HeaderValue::from_str(&header_value)?);
    } else {
        return Err(anyhow!(
            "credentials-test currently supports token profiles; form/OAuth refresh is pending"
        ));
    }
    Ok(headers)
}

fn ensure_url_in_scope(engagement: &Engagement, raw_url: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw_url).with_context(|| format!("invalid URL {raw_url}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("URL does not contain a host: {raw_url}"))?;
    let scope = engagement.scope()?;
    if !scope.is_in_scope(host) {
        return Err(anyhow!(
            "target {host} is OUT OF SCOPE for engagement {}; refusing credential test",
            engagement.meta.name
        ));
    }
    Ok(())
}

fn cmd_init(
    root: &Path,
    name: String,
    target: String,
    platform: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
) -> Result<()> {
    std::fs::create_dir_all(root).with_context(|| format!("creating {}", root.display()))?;
    let meta = EngagementMeta {
        name: name.clone(),
        target,
        created_at: String::new(),
        platform,
        url,
        tags,
    };
    let e = Engagement::init(root, meta)?;
    println!("initialized engagement {} at {}", name, e.root.display());
    Ok(())
}

fn cmd_list(root: &Path) -> Result<()> {
    let all = Engagement::list(root)?;
    if all.is_empty() {
        println!("no engagements under {}", root.display());
        return Ok(());
    }
    println!("{:<24} {:<28} {:<14} CREATED", "NAME", "TARGET", "PLATFORM");
    for e in &all {
        let plat = e.meta.platform.as_deref().unwrap_or("-");
        println!(
            "{:<24} {:<28} {:<14} {}",
            e.meta.name, e.meta.target, plat, e.meta.created_at
        );
    }
    Ok(())
}

fn cmd_show(root: &Path, name: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    println!("name:       {}", e.meta.name);
    println!("target:     {}", e.meta.target);
    println!("created_at: {}", e.meta.created_at);
    if let Some(p) = &e.meta.platform {
        println!("platform:   {p}");
    }
    if let Some(u) = &e.meta.url {
        println!("url:        {u}");
    }
    if !e.meta.tags.is_empty() {
        println!("tags:       {}", e.meta.tags.join(", "));
    }
    let s = e.scope()?;
    println!("\nin scope:");
    for p in &s.in_scope {
        println!("  + {p}");
    }
    if !s.out_of_scope.is_empty() {
        println!("out of scope:");
        for p in &s.out_of_scope {
            println!("  - {p}");
        }
    }
    println!("\nroot: {}", e.root.display());
    Ok(())
}

fn cmd_check(root: &Path, name: &str, target: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let s = e.scope()?;
    if s.is_in_scope(target) {
        println!("IN SCOPE   {target}");
        Ok(())
    } else {
        println!("OUT OF SCOPE   {target}");
        std::process::exit(2);
    }
}

fn cmd_scope_modify(
    root: &Path,
    name: &str,
    pattern: &str,
    remove: bool,
    deny: bool,
) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let mut s = e.scope()?;
    let list: &mut Vec<String> = if deny {
        &mut s.out_of_scope
    } else {
        &mut s.in_scope
    };
    if remove {
        let before = list.len();
        list.retain(|p| p != pattern);
        if list.len() == before {
            return Err(anyhow!("pattern not found: {pattern}"));
        }
        println!(
            "removed {pattern} from {}",
            if deny { "out_of_scope" } else { "in_scope" }
        );
    } else {
        if list.iter().any(|p| p == pattern) {
            return Err(anyhow!("pattern already present: {pattern}"));
        }
        list.push(pattern.to_string());
        println!(
            "added {pattern} to {}",
            if deny { "out_of_scope" } else { "in_scope" }
        );
    }
    e.save_scope(&s)?;
    Ok(())
}

fn cmd_note(root: &Path, name: &str, text: &str) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    e.append_note(text)?;
    println!("appended note to {}/notes.md", e.root.display());
    Ok(())
}

fn cmd_finding(
    root: &Path,
    name: &str,
    title: String,
    target: String,
    severity: &str,
) -> Result<()> {
    let e = Engagement::load_named(root, name)?;
    let scope = e.scope()?;
    if !scope.is_in_scope(&target) {
        return Err(anyhow!(
            "target {target} is OUT OF SCOPE for engagement {name}; refusing to create finding"
        ));
    }

    let sev = parse_severity(severity)?;
    let id = Finding::next_id(&e.findings_dir())?;
    let now = OffsetDateTime::now_utc().format(&Rfc3339)?;
    let f = Finding {
        id,
        title,
        severity: sev,
        status: Status::Draft,
        target,
        created: now,
        body: Finding::skeleton_body(),
    };
    let path = f.write_to(&e.findings_dir())?;
    println!("created {}", path.display());
    Ok(())
}

fn cmd_traffic_import(root: &Path, name: &str, file: &str, format: &str) -> Result<()> {
    let engagement = Engagement::load_named(root, name)?;
    let format = TrafficImportFormat::parse(format)?;
    let summary = engagement::import_traffic_file(&engagement, Path::new(file), format)?;
    let _ = engagement.audit(
        "mg-engagement",
        &engagement.meta.target,
        Some(&format!(
            "traffic-import format={} imported={} skipped={} source={}",
            summary.format, summary.imported, summary.skipped, summary.source
        )),
    );
    println!(
        "imported {} request(s), skipped {} duplicate(s) into {}",
        summary.imported, summary.skipped, summary.corpus_path
    );
    Ok(())
}

fn cmd_traffic_list(root: &Path, name: &str, input: TrafficListInput) -> Result<()> {
    let engagement = Engagement::load_named(root, name)?;
    let records = engagement::search_traffic_records(
        &engagement,
        &TrafficFilter {
            host: input.host,
            method: input.method,
            path_contains: input.path_contains,
            status: input.status,
            mime: input.mime,
            auth_state: None,
            source: input.source,
            limit: Some(input.limit),
        },
    )?;
    if records.is_empty() {
        println!("no traffic records found for {name}");
        return Ok(());
    }

    println!(
        "{:<20} {:<6} {:<4} {:<22} {:<28} {:<13} SOURCE",
        "ID", "METHOD", "STAT", "HOST", "PATH", "AUTH"
    );
    for record in &records {
        let status = record
            .response
            .as_ref()
            .map(|response| response.status.to_string())
            .unwrap_or_else(|| "-".into());
        println!(
            "{:<20} {:<6} {:<4} {:<22} {:<28} {:<13} {}",
            record.id,
            record.method,
            status,
            truncate(&record.host, 22),
            truncate(&record.path, 28),
            record.auth_state.as_str(),
            record.source
        );
    }
    Ok(())
}

fn cmd_traffic_show(root: &Path, name: &str, request_id: &str, raw: bool) -> Result<()> {
    let engagement = Engagement::load_named(root, name)?;
    let record = engagement::find_traffic_record(&engagement, request_id)?;
    if raw {
        println!("{}", engagement::raw_http_request(&engagement, &record)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&record)?);
    }
    Ok(())
}

fn truncate(value: &str, width: usize) -> String {
    if value.chars().count() <= width {
        return value.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    format!("{}...", value.chars().take(width - 3).collect::<String>())
}

fn main() -> Result<()> {
    let args = cli::get_args();
    let root = Path::new(&args.root);

    match args.command {
        cli::Command::Init {
            name,
            target,
            platform,
            url,
            tags,
        } => cmd_init(root, name, target, platform, url, tags),
        cli::Command::List => cmd_list(root),
        cli::Command::Show { name } => cmd_show(root, &name),
        cli::Command::Check { name, target } => cmd_check(root, &name, &target),
        cli::Command::ScopeAdd {
            name,
            pattern,
            remove,
        } => cmd_scope_modify(root, &name, &pattern, remove, false),
        cli::Command::ScopeDeny {
            name,
            pattern,
            remove,
        } => cmd_scope_modify(root, &name, &pattern, remove, true),
        cli::Command::Note { name, text } => cmd_note(root, &name, &text),
        cli::Command::Finding {
            name,
            title,
            target,
            severity,
        } => cmd_finding(root, &name, title, target, &severity),
        cli::Command::CredentialsSet {
            name,
            username,
            password_env,
            login_url,
            token_env,
            token_header,
            token_prefix,
            login_method,
        } => cmd_credentials_set(
            root,
            &name,
            CredentialsSetInput {
                username,
                password_env,
                login_url,
                token_env,
                token_header,
                token_prefix,
                login_method,
            },
        ),
        cli::Command::CredentialsTest { name, url } => cmd_credentials_test(root, &name, &url),
        cli::Command::Traffic { name, command } => match command {
            cli::TrafficCommand::Import { file, format } => {
                cmd_traffic_import(root, &name, &file, &format)
            }
            cli::TrafficCommand::List {
                host,
                method,
                status,
                mime,
                source,
                path_contains,
                limit,
            } => cmd_traffic_list(
                root,
                &name,
                TrafficListInput {
                    host,
                    method,
                    status,
                    mime,
                    source,
                    path_contains,
                    limit,
                },
            ),
            cli::TrafficCommand::Show { request_id, raw } => {
                cmd_traffic_show(root, &name, &request_id, raw)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::{Engagement, EngagementMeta};
    use std::sync::atomic::{AtomicU64, Ordering};

    fn tmp_parent() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "mg-engagement-session-test-{}-{n}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn test_engagement(parent: &Path) -> Engagement {
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        Engagement::init(parent, meta).unwrap()
    }

    #[test]
    fn credentials_set_writes_env_reference_only() {
        let root = tmp_parent();
        let engagement = test_engagement(&root);

        cmd_credentials_set(
            &root,
            "acme",
            CredentialsSetInput {
                username: None,
                password_env: None,
                login_url: None,
                token_env: Some("MG_TOKEN".into()),
                token_header: "Authorization".into(),
                token_prefix: "Bearer".into(),
                login_method: None,
            },
        )
        .unwrap();

        let raw = std::fs::read_to_string(engagement.root.join("session.json")).unwrap();
        assert!(raw.contains("\"token_env\": \"MG_TOKEN\""));
        assert!(!raw.contains("secret"));
    }

    #[test]
    fn credentials_set_requires_usable_profile() {
        let root = tmp_parent();
        test_engagement(&root);

        let err = cmd_credentials_set(
            &root,
            "acme",
            CredentialsSetInput {
                username: None,
                password_env: None,
                login_url: None,
                token_env: None,
                token_header: "Authorization".into(),
                token_prefix: "Bearer".into(),
                login_method: None,
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("provide --token-env"));
    }
}
