/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Scoped AI harness endpoint dispatcher
 * Notes:           The harness accepts typed JSON invocations, applies
 *                  risk/scope policy, dispatches allowlisted tool endpoints,
 *                  and returns bounded JSON results for TUI or AI callers.
 *******************************************************************/

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use engagement::{Engagement, Finding, Severity, Status};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use url::Url;

const HARNESS_VERSION: &str = "2026-05-15";
const MAX_MODEL_VISIBLE_BYTES: usize = 256 * 1024;

// Risk classes used by endpoint policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    PassiveRemote,
    LowActive,
    HighActive,
    StateChange,
    Destructive,
}

// Status values returned to callers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointStatus {
    Ok,
    Blocked,
    Error,
}

// JSON request accepted by the harness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invocation {
    pub endpoint: String,
    #[serde(default)]
    pub version: Option<String>,
    pub engagement: String,
    #[serde(default)]
    pub risk: Option<RiskClass>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub confirmed: bool,
    #[serde(default)]
    pub args: Value,
}

// JSON result returned by the harness
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointResult {
    pub endpoint: String,
    pub status: EndpointStatus,
    pub risk: RiskClass,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub redactions: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
}

// Static description for an allowlisted endpoint
#[derive(Debug, Clone, Serialize)]
pub struct EndpointSpec {
    pub name: &'static str,
    pub risk: RiskClass,
    pub implemented: bool,
    pub description: &'static str,
}

// Runtime configuration for dispatch
#[derive(Debug, Clone)]
pub struct HarnessConfig {
    pub engagements_dir: PathBuf,
}

// Errors surfaced before a structured endpoint result can be produced
#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("unknown endpoint: {0}")]
    UnknownEndpoint(String),
    #[error("invalid endpoint arguments: {0}")]
    InvalidArgs(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("engagement: {0}")]
    Engagement(#[from] engagement::EngagementError),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("time format: {0}")]
    TimeFormat(#[from] time::error::Format),
    #[error("recon: {0}")]
    Recon(#[from] anyhow::Error),
    #[error("session: {0}")]
    Session(#[from] session::SessionError),
}

impl HarnessConfig {
    // Build a config from an engagements directory
    pub fn new(engagements_dir: impl Into<PathBuf>) -> Self {
        Self {
            engagements_dir: engagements_dir.into(),
        }
    }
}

// Dispatch a single invocation through policy and endpoint handlers
pub async fn dispatch(cfg: &HarnessConfig, invocation: Invocation) -> EndpointResult {
    let endpoint = invocation.endpoint.clone();
    let spec = match endpoint_spec(&endpoint) {
        Some(spec) => spec,
        None => {
            return result_error(
                endpoint,
                RiskClass::ReadOnly,
                "endpoint.unknown",
                "unknown endpoint",
            );
        }
    };

    if let Some(requested_risk) = invocation.risk
        && requested_risk != spec.risk
    {
        return result_blocked(
            endpoint,
            spec.risk,
            "risk.mismatch",
            "invocation risk does not match endpoint risk",
        );
    }

    if let Some(version) = &invocation.version
        && version != HARNESS_VERSION
    {
        return result_blocked(
            endpoint,
            spec.risk,
            "version.unsupported",
            "invocation version is not supported by this harness",
        );
    }

    if matches!(spec.risk, RiskClass::Destructive) {
        return result_blocked(
            endpoint,
            spec.risk,
            "risk.destructive_blocked",
            "destructive endpoints are blocked",
        );
    }

    if matches!(spec.risk, RiskClass::HighActive | RiskClass::StateChange) && !invocation.confirmed
    {
        return result_blocked(
            endpoint,
            spec.risk,
            "risk.confirmation_required",
            "endpoint requires explicit confirmation",
        );
    }

    let dispatch_result = match endpoint.as_str() {
        "endpoint.registry" => Ok(endpoint_registry()),
        "engagement.open" => handle_engagement_open(cfg, &invocation).await,
        "engagement.status" => handle_engagement_status(cfg, &invocation).await,
        "scope.check" => handle_scope_check(cfg, &invocation).await,
        "recon.run" => handle_recon_run(cfg, &invocation).await,
        "session.set" => handle_session_set(cfg, &invocation).await,
        "session.get_headers" => handle_session_get_headers(cfg, &invocation).await,
        "chain.read" => handle_chain_read(cfg, &invocation).await,
        "finding.read" => handle_finding_read(cfg, &invocation).await,
        "finding.create" => handle_finding_create(cfg, &invocation).await,
        _ => Ok(result_blocked(
            endpoint.clone(),
            spec.risk,
            "endpoint.not_implemented",
            "endpoint is registered but not implemented yet",
        )),
    };

    match dispatch_result {
        Ok(result) => result,
        Err(err) => result_error(endpoint, spec.risk, "endpoint.error", &err.to_string()),
    }
}

// Return the allowlisted endpoint registry
pub fn registry() -> Vec<EndpointSpec> {
    vec![
        EndpointSpec {
            name: "endpoint.registry",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "List harness endpoints, risk classes, and implementation status.",
        },
        EndpointSpec {
            name: "engagement.open",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Load engagement metadata, scope, and key workspace file paths.",
        },
        EndpointSpec {
            name: "engagement.status",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Summarize current engagement output files and counts.",
        },
        EndpointSpec {
            name: "scope.check",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Check whether a host or URL is in scope for an engagement.",
        },
        EndpointSpec {
            name: "recon.run",
            risk: RiskClass::HighActive,
            implemented: true,
            description: "Run the scoped mg-recon pipeline after explicit confirmation.",
        },
        EndpointSpec {
            name: "session.set",
            risk: RiskClass::StateChange,
            implemented: true,
            description: "Store a redaction-safe session profile using environment-variable references.",
        },
        EndpointSpec {
            name: "session.get_headers",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Resolve session auth headers and return only redacted header metadata.",
        },
        EndpointSpec {
            name: "crawl.run",
            risk: RiskClass::LowActive,
            implemented: false,
            description: "Run crawler against scoped URLs.",
        },
        EndpointSpec {
            name: "probe.run",
            risk: RiskClass::LowActive,
            implemented: false,
            description: "Run passive and semi-active posture checks.",
        },
        EndpointSpec {
            name: "request.replay",
            risk: RiskClass::LowActive,
            implemented: false,
            description: "Replay one captured request and compare the response.",
        },
        EndpointSpec {
            name: "fuzzer.plan",
            risk: RiskClass::ReadOnly,
            implemented: false,
            description: "Build a fuzz plan without sending traffic.",
        },
        EndpointSpec {
            name: "fuzzer.run",
            risk: RiskClass::HighActive,
            implemented: false,
            description: "Run bounded fuzzing after explicit confirmation.",
        },
        EndpointSpec {
            name: "oob.allocate",
            risk: RiskClass::ReadOnly,
            implemented: false,
            description: "Allocate an OOB callback token.",
        },
        EndpointSpec {
            name: "oob.poll",
            risk: RiskClass::PassiveRemote,
            implemented: false,
            description: "Poll OOB callback logs.",
        },
        EndpointSpec {
            name: "finding.create",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Create a finding skeleton from evidence references.",
        },
        EndpointSpec {
            name: "finding.read",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Read one finding markdown file by finding ID.",
        },
        EndpointSpec {
            name: "chain.read",
            risk: RiskClass::ReadOnly,
            implemented: true,
            description: "Read bounded exploit chain analysis artifacts.",
        },
        EndpointSpec {
            name: "finding.replay",
            risk: RiskClass::LowActive,
            implemented: false,
            description: "Retest finding evidence.",
        },
        EndpointSpec {
            name: "report.draft",
            risk: RiskClass::ReadOnly,
            implemented: false,
            description: "Draft a bounty or consulting report from local evidence.",
        },
        EndpointSpec {
            name: "risk.rank",
            risk: RiskClass::ReadOnly,
            implemented: false,
            description: "Rank targets and hypotheses from local evidence.",
        },
    ]
}

// Return the spec for one endpoint name
fn endpoint_spec(name: &str) -> Option<EndpointSpec> {
    registry().into_iter().find(|spec| spec.name == name)
}

// Handle endpoint.registry
fn endpoint_registry() -> EndpointResult {
    EndpointResult {
        endpoint: "endpoint.registry".into(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some("endpoint registry loaded".into()),
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: Some(json!({
            "version": HARNESS_VERSION,
            "endpoints": registry(),
        })),
        reason: None,
        policy: None,
    }
}

// Handle engagement.open
async fn handle_engagement_open(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let scope = eng.scope()?;
    let recon_dir = display_path(&eng.recon_dir());
    let crawl_dir = display_path(&eng.crawl_dir());
    let findings_dir = display_path(&eng.findings_dir());
    let summary_path = eng.recon_dir().join("summary.json");
    let priorities_path = eng.recon_dir().join("priorities.json");
    let probe_path = eng.recon_dir().join("probe-report.json");

    let data = json!({
        "meta": eng.meta,
        "scope": scope,
        "paths": {
            "root": display_path(&eng.root),
            "recon": recon_dir,
            "crawl": crawl_dir,
            "findings": findings_dir,
            "summary": display_path(&summary_path),
            "priorities": display_path(&priorities_path),
            "probe_report": display_path(&probe_path),
        },
        "exists": {
            "summary": summary_path.exists(),
            "priorities": priorities_path.exists(),
            "probe_report": probe_path.exists(),
        }
    });

    let _ = eng.audit(
        "mg-harness",
        &eng.meta.target,
        Some("endpoint=engagement.open"),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!("engagement {} loaded", invocation.engagement)),
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: Some(data),
        reason: None,
        policy: None,
    })
}

// Handle engagement.status
async fn handle_engagement_status(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let recon_dir = eng.recon_dir();
    let crawl_dir = eng.crawl_dir();
    let findings_dir = eng.findings_dir();
    let audit_path = eng.root.join("audit.log");
    let summary_path = recon_dir.join("summary.json");
    let priorities_path = recon_dir.join("priorities.json");
    let probe_path = recon_dir.join("probe-report.json");

    let data = json!({
        "engagement": invocation.engagement,
        "target": eng.meta.target,
        "files": {
            "summary": file_state(&summary_path),
            "priorities": file_state(&priorities_path),
            "probe_report": file_state(&probe_path),
            "audit_log": file_state(&audit_path),
        },
        "counts": {
            "crawl_hosts": count_dirs(&crawl_dir),
            "findings": count_files_with_extension(&findings_dir, "md"),
            "fuzz_reports": count_files_with_prefix_suffix(&recon_dir, "fuzz-", ".json"),
            "audit_lines": count_lines(&audit_path),
        },
        "paths": {
            "root": display_path(&eng.root),
            "recon": display_path(&recon_dir),
            "crawl": display_path(&crawl_dir),
            "findings": display_path(&findings_dir),
        }
    });

    let _ = eng.audit(
        "mg-harness",
        &eng.meta.target,
        Some("endpoint=engagement.status"),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!(
            "engagement {} status loaded",
            invocation.engagement
        )),
        output_files: vec![display_path(&summary_path), display_path(&priorities_path)],
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: Some(data),
        reason: None,
        policy: None,
    })
}

// Handle finding.create
async fn handle_finding_create(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let title = required_string(&invocation.args, "title")?;
    let raw_target = required_string(&invocation.args, "target")?;
    let normalized_target = normalize_target(&raw_target)?;
    if !eng.scope()?.is_in_scope(&normalized_target) {
        return Ok(result_blocked(
            invocation.endpoint.clone(),
            RiskClass::ReadOnly,
            "scope.default_deny",
            "finding target is out of scope",
        ));
    }

    let severity = parse_severity(&optional_string(&invocation.args, "severity", "medium")?)?;
    let mut body = optional_string(&invocation.args, "body", &Finding::skeleton_body())?;
    let evidence_refs = optional_string_array(&invocation.args, "evidence_refs")?;
    if !evidence_refs.is_empty() {
        body.push_str("\n## Evidence references\n\n");
        for evidence_ref in &evidence_refs {
            body.push_str(&format!("- `{evidence_ref}`\n"));
        }
    }

    let finding = Finding {
        id: Finding::next_id(&eng.findings_dir())?,
        title: title.clone(),
        severity,
        status: Status::Draft,
        target: raw_target,
        created: now_rfc3339()?,
        body,
    };
    let path = finding.write_to(&eng.findings_dir())?;

    let _ = eng.audit(
        "mg-harness",
        &normalized_target,
        Some(&format!("endpoint=finding.create path={}", path.display())),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!("created finding draft: {title}")),
        output_files: vec![display_path(&path)],
        evidence_refs,
        redactions: BTreeMap::new(),
        data: Some(json!({
            "finding_path": display_path(&path),
            "id": finding.id,
            "severity": finding.severity.as_str(),
            "status": finding.status.as_str(),
        })),
        reason: None,
        policy: None,
    })
}

// Handle finding.read
async fn handle_finding_read(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let finding_id = required_string(&invocation.args, "finding_id")?;
    validate_finding_id(&finding_id)?;
    let path = find_finding_path(&eng.findings_dir(), &finding_id)?;
    let raw = fs::read_to_string(&path)?;
    let (markdown, truncated) = truncate_model_visible(&raw);
    let mut redactions = BTreeMap::new();
    if truncated {
        redactions.insert(
            "truncated_bytes".into(),
            raw.len().saturating_sub(markdown.len()),
        );
    }

    let _ = eng.audit(
        "mg-harness",
        &finding_id,
        Some(&format!("endpoint=finding.read path={}", path.display())),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!("finding {finding_id} loaded")),
        output_files: vec![display_path(&path)],
        evidence_refs: vec![format!(
            "evidence://{}/finding/{}",
            invocation.engagement, finding_id
        )],
        redactions,
        data: Some(json!({
            "finding_id": finding_id,
            "path": display_path(&path),
            "markdown": markdown,
            "truncated": truncated,
        })),
        reason: None,
        policy: None,
    })
}

// Handle scope.check
async fn handle_scope_check(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let scope = eng.scope()?;
    let raw_target = required_string(&invocation.args, "target")?;
    let normalized = normalize_target(&raw_target)?;
    let in_scope = scope.is_in_scope(&normalized);
    let data = json!({
        "target": raw_target,
        "normalized_target": normalized,
        "in_scope": in_scope,
    });

    let _ = eng.audit(
        "mg-harness",
        &normalized,
        Some(&format!("endpoint=scope.check in_scope={in_scope}")),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!("scope check: {normalized} -> {in_scope}")),
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: Some(data),
        reason: None,
        policy: None,
    })
}

// Handle recon.run
async fn handle_recon_run(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng_root = Engagement::path_for_name(&cfg.engagements_dir, &invocation.engagement)?;
    let eng = Engagement::load(&eng_root)?;
    ensure_target_in_scope(&eng, &eng.meta.target)?;

    let force = optional_bool(&invocation.args, "force", false)?;
    let concurrency = optional_usize(&invocation.args, "concurrency", 100)?;
    let timeout_ms = optional_u64(&invocation.args, "timeout_ms", 5000)?;
    let ports = optional_string(&invocation.args, "ports", "1-1024")?;
    let (port_start, port_end) = parse_ports(&ports)?;

    if concurrency == 0 {
        return Err(HarnessError::InvalidArgs(
            "concurrency must be at least 1".into(),
        ));
    }

    let run_cfg = mg_recon::orchestrator::RunConfig {
        engagement_name: invocation.engagement.clone(),
        eng_root: eng_root.clone(),
        force,
        concurrency,
        timeout_ms,
        port_start,
        port_end,
    };

    mg_recon::orchestrator::run(run_cfg).await?;

    let summary_path = eng_root.join("recon").join("summary.json");
    let _ = eng.audit(
        "mg-harness",
        &eng.meta.target,
        Some("endpoint=recon.run status=ok"),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::HighActive,
        summary: Some(format!("recon completed for {}", invocation.engagement)),
        output_files: vec![display_path(&summary_path)],
        evidence_refs: vec![format!(
            "evidence://{}/recon/summary",
            invocation.engagement
        )],
        redactions: BTreeMap::new(),
        data: Some(json!({
            "summary_path": display_path(&summary_path),
        })),
        reason: None,
        policy: None,
    })
}

// Handle session.set
async fn handle_session_set(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    reject_plaintext_secret_args(&invocation.args)?;
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let token_env = optional_string_opt(&invocation.args, "token_env")?;
    let password_env = optional_string_opt(&invocation.args, "password_env")?;
    let login_url = optional_string_opt(&invocation.args, "login_url")?;
    let username = optional_string_opt(&invocation.args, "username")?;
    let token_header = optional_string(&invocation.args, "token_header", "Authorization")?;
    let token_prefix = optional_string(&invocation.args, "token_prefix", "Bearer")?;
    let login_method = optional_string(
        &invocation.args,
        "login_method",
        if token_env.is_some() { "token" } else { "form" },
    )?;
    validate_login_method(&login_method)?;

    if token_env.is_none() && password_env.is_none() {
        return Err(HarnessError::InvalidArgs(
            "session.set requires token_env or password_env".into(),
        ));
    }
    if password_env.is_some() && login_url.is_none() {
        return Err(HarnessError::InvalidArgs(
            "password_env requires login_url".into(),
        ));
    }

    let config = session::SessionConfig {
        username,
        password_env,
        login_url,
        login_method: login_method.clone(),
        token_header,
        token_prefix,
        token_env,
        session_cookie: None,
        token_refresh_url: optional_string_opt(&invocation.args, "token_refresh_url")?,
        valid_until: None,
    };
    let path = session::save_session_config(&eng, &config)?;
    let _ = eng.audit(
        "mg-harness",
        &eng.meta.target,
        Some(&format!("endpoint=session.set method={login_method}")),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::StateChange,
        summary: Some(format!(
            "stored {login_method} session profile for {}",
            invocation.engagement
        )),
        output_files: vec![display_path(&path)],
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: Some(json!({
            "path": display_path(&path),
            "login_method": login_method,
            "has_token_env": config.token_env.is_some(),
            "has_password_env": config.password_env.is_some(),
            "has_login_url": config.login_url.is_some(),
        })),
        reason: None,
        policy: None,
    })
}

// Handle session.get_headers
async fn handle_session_get_headers(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    match session::load_session_config(&eng) {
        Ok(_) => {}
        Err(session::SessionError::NotConfigured) => {
            return Ok(EndpointResult {
                endpoint: invocation.endpoint.clone(),
                status: EndpointStatus::Ok,
                risk: RiskClass::ReadOnly,
                summary: Some("no session profile configured".into()),
                output_files: Vec::new(),
                evidence_refs: Vec::new(),
                redactions: BTreeMap::new(),
                data: Some(json!({
                    "configured": false,
                    "headers": {},
                    "header_count": 0,
                })),
                reason: None,
                policy: None,
            });
        }
        Err(err) => return Err(err.into()),
    }

    let headers = session::get_auth_headers_sync(&eng)?;
    let redacted_headers: BTreeMap<String, String> = headers
        .iter()
        .map(|(name, _)| (name.as_str().to_string(), "<redacted>".to_string()))
        .collect();
    let header_count = redacted_headers.len();
    let mut redactions = BTreeMap::new();
    redactions.insert("headers".into(), header_count);
    let _ = eng.audit(
        "mg-harness",
        &eng.meta.target,
        Some(&format!(
            "endpoint=session.get_headers header_count={}",
            header_count
        )),
    );

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some(format!(
            "resolved {} redacted auth header(s)",
            redacted_headers.len()
        )),
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions,
        data: Some(json!({
            "configured": true,
            "headers": redacted_headers,
            "header_count": header_count,
        })),
        reason: None,
        policy: None,
    })
}

// Handle chain.read
async fn handle_chain_read(
    cfg: &HarnessConfig,
    invocation: &Invocation,
) -> Result<EndpointResult, HarnessError> {
    let eng = load_engagement(cfg, &invocation.engagement)?;
    let json_path = eng.recon_dir().join("chain-analysis.json");
    let md_path = eng.recon_dir().join("chain-analysis.md");
    if !json_path.exists() && !md_path.exists() {
        return Ok(result_blocked(
            invocation.endpoint.clone(),
            RiskClass::ReadOnly,
            "chain.missing",
            "chain-analysis artifacts are not present",
        ));
    }

    let json_raw = fs::read_to_string(&json_path).unwrap_or_default();
    let md_raw = fs::read_to_string(&md_path).unwrap_or_default();
    let (json_text, json_truncated) = truncate_model_visible(&json_raw);
    let (markdown, md_truncated) = truncate_model_visible(&md_raw);
    let mut redactions = BTreeMap::new();
    if json_truncated {
        redactions.insert(
            "chain_json_truncated_bytes".into(),
            json_raw.len().saturating_sub(json_text.len()),
        );
    }
    if md_truncated {
        redactions.insert(
            "chain_markdown_truncated_bytes".into(),
            md_raw.len().saturating_sub(markdown.len()),
        );
    }

    let _ = eng.audit("mg-harness", &eng.meta.target, Some("endpoint=chain.read"));

    Ok(EndpointResult {
        endpoint: invocation.endpoint.clone(),
        status: EndpointStatus::Ok,
        risk: RiskClass::ReadOnly,
        summary: Some("chain analysis loaded".into()),
        output_files: vec![display_path(&json_path), display_path(&md_path)],
        evidence_refs: vec![format!(
            "evidence://{}/recon/chain-analysis",
            invocation.engagement
        )],
        redactions,
        data: Some(json!({
            "json_path": display_path(&json_path),
            "markdown_path": display_path(&md_path),
            "chain_json": json_text,
            "markdown": markdown,
            "json_truncated": json_truncated,
            "markdown_truncated": md_truncated,
        })),
        reason: None,
        policy: None,
    })
}

// Load engagement by name
fn load_engagement(cfg: &HarnessConfig, name: &str) -> Result<Engagement, HarnessError> {
    Ok(Engagement::load_named(&cfg.engagements_dir, name)?)
}

// Ensure a target is in the loaded engagement scope
fn ensure_target_in_scope(eng: &Engagement, target: &str) -> Result<(), HarnessError> {
    let normalized = normalize_target(target)?;
    if !eng.scope()?.is_in_scope(&normalized) {
        return Err(HarnessError::InvalidArgs(format!(
            "target {normalized} is out of scope"
        )));
    }
    Ok(())
}

// Extract a required string argument
fn required_string(args: &Value, key: &str) -> Result<String, HarnessError> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| HarnessError::InvalidArgs(format!("missing string arg `{key}`")))
}

// Extract an optional string argument
fn optional_string(args: &Value, key: &str, default: &str) -> Result<String, HarnessError> {
    match args.get(key) {
        Some(value) => value
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| HarnessError::InvalidArgs(format!("arg `{key}` must be a string"))),
        None => Ok(default.to_string()),
    }
}

// Extract an optional string argument as Option
fn optional_string_opt(args: &Value, key: &str) -> Result<Option<String>, HarnessError> {
    match args.get(key) {
        Some(Value::Null) | None => Ok(None),
        Some(value) => value
            .as_str()
            .map(|value| Some(value.to_string()))
            .ok_or_else(|| HarnessError::InvalidArgs(format!("arg `{key}` must be a string"))),
    }
}

// Validate supported session login methods
fn validate_login_method(method: &str) -> Result<(), HarnessError> {
    match method {
        "token" | "form" | "oauth_client_credentials" => Ok(()),
        other => Err(HarnessError::InvalidArgs(format!(
            "unsupported login method `{other}`"
        ))),
    }
}

// Reject direct plaintext secret fields in model-visible invocations
fn reject_plaintext_secret_args(args: &Value) -> Result<(), HarnessError> {
    for key in ["password", "token", "api_key", "session_cookie"] {
        if args.get(key).is_some() {
            return Err(HarnessError::InvalidArgs(format!(
                "arg `{key}` is not allowed; use an environment-variable reference"
            )));
        }
    }
    Ok(())
}

// Extract an optional bool argument
fn optional_bool(args: &Value, key: &str, default: bool) -> Result<bool, HarnessError> {
    match args.get(key) {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| HarnessError::InvalidArgs(format!("arg `{key}` must be a bool"))),
        None => Ok(default),
    }
}

// Extract an optional u64 argument
fn optional_u64(args: &Value, key: &str, default: u64) -> Result<u64, HarnessError> {
    match args.get(key) {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| HarnessError::InvalidArgs(format!("arg `{key}` must be a u64"))),
        None => Ok(default),
    }
}

// Extract an optional usize argument
fn optional_usize(args: &Value, key: &str, default: usize) -> Result<usize, HarnessError> {
    let value = optional_u64(args, key, default as u64)?;
    usize::try_from(value)
        .map_err(|_| HarnessError::InvalidArgs(format!("arg `{key}` is too large")))
}

// Extract an optional array of strings
fn optional_string_array(args: &Value, key: &str) -> Result<Vec<String>, HarnessError> {
    let Some(value) = args.get(key) else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err(HarnessError::InvalidArgs(format!(
            "arg `{key}` must be an array"
        )));
    };
    values
        .iter()
        .map(|value| {
            value.as_str().map(str::to_string).ok_or_else(|| {
                HarnessError::InvalidArgs(format!("arg `{key}` must contain strings"))
            })
        })
        .collect()
}

// Validate a finding ID before matching local files
fn validate_finding_id(finding_id: &str) -> Result<(), HarnessError> {
    if finding_id.is_empty()
        || finding_id.contains('/')
        || finding_id.contains('\\')
        || finding_id.chars().any(char::is_control)
    {
        return Err(HarnessError::InvalidArgs(
            "finding_id must be a safe file prefix".into(),
        ));
    }
    Ok(())
}

// Find a finding markdown path by ID prefix
fn find_finding_path(findings_dir: &Path, finding_id: &str) -> Result<PathBuf, HarnessError> {
    let entries = fs::read_dir(findings_dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with(finding_id) && name.ends_with(".md") {
            return Ok(path);
        }
    }
    Err(HarnessError::InvalidArgs(format!(
        "finding `{finding_id}` not found"
    )))
}

// Truncate model-visible markdown to the configured cap
fn truncate_model_visible(raw: &str) -> (String, bool) {
    if raw.len() <= MAX_MODEL_VISIBLE_BYTES {
        return (raw.to_string(), false);
    }
    let mut end = MAX_MODEL_VISIBLE_BYTES;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    (raw[..end].to_string(), true)
}

// Return file state for status JSON
fn file_state(path: &Path) -> Value {
    match fs::metadata(path) {
        Ok(meta) => json!({
            "exists": true,
            "bytes": meta.len(),
            "path": display_path(path),
        }),
        Err(_) => json!({
            "exists": false,
            "bytes": 0,
            "path": display_path(path),
        }),
    }
}

// Count child directories
fn count_dirs(path: &Path) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| entry.file_type().is_ok_and(|ty| ty.is_dir()))
                .count()
        })
        .unwrap_or(0)
}

// Count files with a specific extension
fn count_files_with_extension(path: &Path, extension: &str) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == extension))
                .count()
        })
        .unwrap_or(0)
}

// Count files by prefix and suffix
fn count_files_with_prefix_suffix(path: &Path, prefix: &str, suffix: &str) -> usize {
    fs::read_dir(path)
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(prefix) && name.ends_with(suffix))
                })
                .count()
        })
        .unwrap_or(0)
}

// Count lines in a UTF-8 text file
fn count_lines(path: &Path) -> usize {
    fs::read_to_string(path)
        .map(|raw| raw.lines().count())
        .unwrap_or(0)
}

// Parse severity from endpoint args
fn parse_severity(raw: &str) -> Result<Severity, HarnessError> {
    match raw.to_lowercase().as_str() {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        other => Err(HarnessError::InvalidArgs(format!(
            "unknown severity `{other}`"
        ))),
    }
}

// Return the current UTC time formatted as RFC3339
fn now_rfc3339() -> Result<String, HarnessError> {
    Ok(OffsetDateTime::now_utc().format(&Rfc3339)?)
}

// Parse an inclusive port range
fn parse_ports(raw: &str) -> Result<(u16, u16), HarnessError> {
    let Some((start_raw, end_raw)) = raw.split_once('-') else {
        return Err(HarnessError::InvalidArgs(
            "ports must use start-end format".into(),
        ));
    };
    let start = start_raw
        .parse::<u16>()
        .map_err(|_| HarnessError::InvalidArgs(format!("invalid start port `{start_raw}`")))?;
    let end = end_raw
        .parse::<u16>()
        .map_err(|_| HarnessError::InvalidArgs(format!("invalid end port `{end_raw}`")))?;
    if start == 0 || start > end {
        return Err(HarnessError::InvalidArgs(format!(
            "invalid port range `{raw}`"
        )));
    }
    Ok((start, end))
}

// Normalize a URL or host into a lower-case hostname for scope checks
fn normalize_target(target: &str) -> Result<String, HarnessError> {
    if let Ok(url) = Url::parse(target) {
        return url
            .host_str()
            .map(|host| host.trim_end_matches('.').to_lowercase())
            .ok_or_else(|| HarnessError::InvalidArgs("URL does not contain a host".into()));
    }

    let without_scheme = target
        .strip_prefix("//")
        .unwrap_or(target)
        .split('/')
        .next()
        .unwrap_or(target);
    let without_port = without_scheme
        .split_once(':')
        .map(|(host, _)| host)
        .unwrap_or(without_scheme);
    let normalized = without_port.trim().trim_end_matches('.').to_lowercase();
    if normalized.is_empty() || normalized.chars().any(char::is_whitespace) {
        return Err(HarnessError::InvalidArgs(format!(
            "invalid target `{target}`"
        )));
    }
    Ok(normalized)
}

// Convert a path into a display string
fn display_path(path: &Path) -> String {
    path.display().to_string()
}

// Build a blocked result
fn result_blocked(endpoint: String, risk: RiskClass, policy: &str, reason: &str) -> EndpointResult {
    EndpointResult {
        endpoint,
        status: EndpointStatus::Blocked,
        risk,
        summary: None,
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: None,
        reason: Some(reason.into()),
        policy: Some(policy.into()),
    }
}

// Build an error result
fn result_error(endpoint: String, risk: RiskClass, policy: &str, reason: &str) -> EndpointResult {
    EndpointResult {
        endpoint,
        status: EndpointStatus::Error,
        risk,
        summary: None,
        output_files: Vec::new(),
        evidence_refs: Vec::new(),
        redactions: BTreeMap::new(),
        data: None,
        reason: Some(reason.into()),
        policy: Some(policy.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::EngagementMeta;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Create a unique temporary engagement root
    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-harness-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    // Create a test engagement
    fn test_config() -> HarnessConfig {
        let parent = tmp_parent();
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        Engagement::init(&parent, meta).unwrap();
        HarnessConfig::new(parent)
    }

    // Build a base invocation
    fn invocation(endpoint: &str) -> Invocation {
        Invocation {
            endpoint: endpoint.into(),
            version: Some(HARNESS_VERSION.into()),
            engagement: "acme".into(),
            risk: None,
            reason: None,
            confirmed: false,
            args: Value::Null,
        }
    }

    #[tokio::test]
    async fn engagement_open_returns_workspace_data() {
        let cfg = test_config();
        let result = dispatch(&cfg, invocation("engagement.open")).await;
        assert_eq!(result.status, EndpointStatus::Ok);
        assert_eq!(result.risk, RiskClass::ReadOnly);
        assert!(result.data.unwrap()["exists"]["summary"].is_boolean());
    }

    #[tokio::test]
    async fn engagement_status_returns_counts() {
        let cfg = test_config();
        let result = dispatch(&cfg, invocation("engagement.status")).await;
        assert_eq!(result.status, EndpointStatus::Ok);
        let data = result.data.unwrap();
        assert_eq!(data["counts"]["findings"], 0);
        assert!(data["files"]["audit_log"]["exists"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn scope_check_normalizes_url_hosts() {
        let cfg = test_config();
        let mut inv = invocation("scope.check");
        inv.args = json!({ "target": "https://API.Example.com:443/path" });
        let result = dispatch(&cfg, inv).await;
        assert_eq!(result.status, EndpointStatus::Ok);
        let data = result.data.unwrap();
        assert_eq!(data["normalized_target"], "api.example.com");
        assert_eq!(data["in_scope"], true);
    }

    #[tokio::test]
    async fn scope_check_reports_out_of_scope() {
        let cfg = test_config();
        let mut inv = invocation("scope.check");
        inv.args = json!({ "target": "other.test" });
        let result = dispatch(&cfg, inv).await;
        assert_eq!(result.status, EndpointStatus::Ok);
        assert_eq!(result.data.unwrap()["in_scope"], false);
    }

    #[tokio::test]
    async fn high_active_requires_confirmation() {
        let cfg = test_config();
        let result = dispatch(&cfg, invocation("recon.run")).await;
        assert_eq!(result.status, EndpointStatus::Blocked);
        assert_eq!(result.policy.as_deref(), Some("risk.confirmation_required"));
    }

    #[tokio::test]
    async fn registered_unimplemented_endpoint_is_blocked() {
        let cfg = test_config();
        let result = dispatch(&cfg, invocation("request.replay")).await;
        assert_eq!(result.status, EndpointStatus::Blocked);
        assert_eq!(result.policy.as_deref(), Some("endpoint.not_implemented"));
    }

    #[tokio::test]
    async fn finding_create_writes_scoped_draft() {
        let cfg = test_config();
        let mut inv = invocation("finding.create");
        inv.args = json!({
            "title": "Controlled IDOR proof",
            "target": "https://api.example.com/v1/users/2",
            "severity": "high",
            "evidence_refs": ["evidence://acme/replay/one"]
        });
        let result = dispatch(&cfg, inv).await;
        assert_eq!(result.status, EndpointStatus::Ok);
        let path = result.output_files.first().unwrap();
        let markdown = fs::read_to_string(path).unwrap();
        assert!(markdown.contains("title: Controlled IDOR proof"));
        assert!(markdown.contains("severity: high"));
        assert!(markdown.contains("evidence://acme/replay/one"));
    }

    #[tokio::test]
    async fn finding_read_loads_created_markdown() {
        let cfg = test_config();
        let mut create = invocation("finding.create");
        create.args = json!({
            "title": "Readable finding",
            "target": "https://api.example.com/v1/users/2"
        });
        let create_result = dispatch(&cfg, create).await;
        let finding_id = create_result.data.unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();

        let mut read = invocation("finding.read");
        read.args = json!({ "finding_id": finding_id });
        let read_result = dispatch(&cfg, read).await;
        assert_eq!(read_result.status, EndpointStatus::Ok);
        let data = read_result.data.unwrap();
        assert!(
            data["markdown"]
                .as_str()
                .unwrap()
                .contains("Readable finding")
        );
        assert_eq!(data["truncated"], false);
    }

    #[tokio::test]
    async fn finding_read_rejects_path_like_ids() {
        let cfg = test_config();
        let mut read = invocation("finding.read");
        read.args = json!({ "finding_id": "../escape" });
        let result = dispatch(&cfg, read).await;
        assert_eq!(result.status, EndpointStatus::Error);
        assert_eq!(result.policy.as_deref(), Some("endpoint.error"));
    }

    #[tokio::test]
    async fn finding_create_blocks_out_of_scope_target() {
        let cfg = test_config();
        let mut inv = invocation("finding.create");
        inv.args = json!({
            "title": "Bad target",
            "target": "https://other.test/path"
        });
        let result = dispatch(&cfg, inv).await;
        assert_eq!(result.status, EndpointStatus::Blocked);
        assert_eq!(result.policy.as_deref(), Some("scope.default_deny"));
    }

    #[tokio::test]
    async fn session_set_writes_env_reference_profile() {
        let cfg = test_config();
        let mut inv = invocation("session.set");
        inv.confirmed = true;
        inv.args = json!({
            "token_env": "MG_HARNESS_TOKEN",
            "token_header": "Authorization",
            "token_prefix": "Bearer"
        });

        let result = dispatch(&cfg, inv).await;

        assert_eq!(result.status, EndpointStatus::Ok);
        let path = result.output_files.first().unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(raw.contains("\"token_env\": \"MG_HARNESS_TOKEN\""));
        assert!(!raw.contains("secret"));
    }

    #[tokio::test]
    async fn session_set_rejects_plaintext_secret_args() {
        let cfg = test_config();
        let mut inv = invocation("session.set");
        inv.confirmed = true;
        inv.args = json!({
            "token": "secret",
            "token_env": "MG_HARNESS_TOKEN"
        });

        let result = dispatch(&cfg, inv).await;

        assert_eq!(result.status, EndpointStatus::Error);
        assert!(result.reason.unwrap().contains("not allowed"));
    }

    #[tokio::test]
    async fn session_get_headers_redacts_values() {
        let cfg = test_config();
        let env_name = format!("MG_HARNESS_TOKEN_{}", std::process::id());
        // Set a uniquely named process env var for this header-resolution test.
        unsafe {
            std::env::set_var(&env_name, "secret-token-value");
        }
        let mut set = invocation("session.set");
        set.confirmed = true;
        set.args = json!({ "token_env": env_name });
        let set_result = dispatch(&cfg, set).await;
        assert_eq!(set_result.status, EndpointStatus::Ok);

        let result = dispatch(&cfg, invocation("session.get_headers")).await;

        assert_eq!(result.status, EndpointStatus::Ok);
        let data = result.data.unwrap();
        assert_eq!(data["configured"], true);
        assert_eq!(data["headers"]["authorization"], "<redacted>");
        assert_eq!(data["header_count"], 1);
    }

    #[tokio::test]
    async fn chain_read_loads_analysis_artifacts() {
        let cfg = test_config();
        let eng = Engagement::load_named(&cfg.engagements_dir, "acme").unwrap();
        fs::write(
            eng.recon_dir().join("chain-analysis.json"),
            "{\"analysis_markdown\":\"## Chains\\nNone\"}",
        )
        .unwrap();
        fs::write(eng.recon_dir().join("chain-analysis.md"), "## Chains\nNone").unwrap();

        let result = dispatch(&cfg, invocation("chain.read")).await;

        assert_eq!(result.status, EndpointStatus::Ok);
        let data = result.data.unwrap();
        assert!(
            data["chain_json"]
                .as_str()
                .unwrap()
                .contains("analysis_markdown")
        );
        assert!(data["markdown"].as_str().unwrap().contains("## Chains"));
    }

    #[test]
    fn port_parser_rejects_bad_ranges() {
        assert!(parse_ports("1-1024").is_ok());
        assert!(parse_ports("0-1024").is_err());
        assert!(parse_ports("9000-80").is_err());
        assert!(parse_ports("443").is_err());
    }

    #[test]
    fn model_visible_truncation_respects_utf8() {
        let raw = format!("{}é", "a".repeat(MAX_MODEL_VISIBLE_BYTES));
        let (truncated, did_truncate) = truncate_model_visible(&raw);
        assert!(did_truncate);
        assert!(truncated.is_char_boundary(truncated.len()));
    }
}
