/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     HackerOne-ready report generation from finding evidence
 * Notes:           The library is shared by the mg-report CLI and mg-harness
 *                  report.generate endpoint.
 *******************************************************************/

pub mod cvss;
pub mod disclosure;
mod prompt;

use std::fs;
use std::path::{Path, PathBuf};

use engagement::Engagement;
use llm_client::{LlmClient, LlmError};
use serde::Serialize;
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

const FINDING_MAX_BYTES: usize = 128 * 1024;
const CONTEXT_MAX_BYTES: usize = 64 * 1024;
const FINGERPRINT_MAX_BYTES: usize = 128 * 1024;
const DISCLOSURE_DEFAULT_DAYS: u32 = 90;

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("engagement: {0}")]
    Engagement(#[from] engagement::EngagementError),
    #[error("llm: {0}")]
    Llm(#[from] LlmError),
    #[error("cvss: {0}")]
    Cvss(#[from] cvss::CvssError),
    #[error("invalid args: {0}")]
    InvalidArgs(String),
}

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub engagements_dir: PathBuf,
    pub engagement: String,
    pub finding_id: String,
    pub model: String,
    pub ollama_model: String,
    pub offline: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportOutput {
    pub finding_id: String,
    pub finding_path: PathBuf,
    pub report_path: PathBuf,
    pub cvss_vector: String,
    pub cvss_score: f64,
    pub severity: String,
    pub generated: bool,
}

#[derive(Debug, Clone)]
pub struct DiscloseConfig {
    pub engagements_dir: PathBuf,
    pub engagement: String,
    pub finding_id: String,
    pub vendor: String,
    pub contact: String,
    pub timeline_days: u32,
    pub model: String,
    pub ollama_model: String,
    pub offline: bool,
    pub force: bool,
}

impl DiscloseConfig {
    // Return the default disclosure timeline used when none is supplied
    pub const fn default_timeline_days() -> u32 {
        DISCLOSURE_DEFAULT_DAYS
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscloseOutput {
    pub finding_id: String,
    pub finding_path: PathBuf,
    pub cve_writeup_path: PathBuf,
    pub disclosure_email_path: PathBuf,
    pub cvss_vector: String,
    pub cvss_score: f64,
    pub severity: String,
    pub timeline_days: u32,
    pub reported_on: String,
    pub generated: bool,
}

#[derive(Debug, Clone)]
struct FindingMeta {
    id: String,
    title: String,
    severity: String,
    status: String,
    target: String,
    verdict: Option<String>,
}

// Generate a report for one finding
pub async fn generate_report(config: &ReportConfig) -> Result<ReportOutput, ReportError> {
    validate_finding_id(&config.finding_id)?;
    let eng = Engagement::load_named(&config.engagements_dir, &config.engagement)?;
    let finding_path = find_finding_path(&eng.findings_dir(), &config.finding_id)?;
    let report_path = report_path_for(&finding_path)?;
    let finding_raw = fs::read_to_string(&finding_path)?;
    let meta = parse_finding_meta(&finding_raw, &config.finding_id);

    if report_path.exists() && !config.force {
        return existing_report_output(&config.finding_id, &finding_path, &report_path, &meta);
    }

    let engagement_json = read_bounded(&eng.root.join("engagement.json"), CONTEXT_MAX_BYTES)?;
    let fingerprint_json = read_optional_bounded(
        &eng.recon_dir().join("fingerprint.json"),
        FINGERPRINT_MAX_BYTES,
    )?
    .unwrap_or_else(|| "(recon/fingerprint.json not present)".into());
    let finding_markdown = bounded_text(&finding_raw, FINDING_MAX_BYTES);
    let body = if config.offline {
        fallback_report_body(&finding_raw, &meta, &fingerprint_json)
    } else {
        run_model_report(
            config,
            &finding_markdown,
            &engagement_json,
            &fingerprint_json,
        )
        .await?
    };
    let vector = cvss::find_vector(&body)
        .unwrap_or_else(|| cvss::default_vector_for_severity(&meta.severity).into());
    let clean_body = strip_cvss_comment(&body);
    let score = cvss::score_vector(&vector)?;
    let severity = cvss::severity_label(score).to_string();
    let report = render_report(&meta.title, &severity, score, &vector, &clean_body);

    fs::write(&report_path, report)?;
    let _ = eng.audit(
        "mg-report",
        &meta.target,
        Some(&format!(
            "finding={} report={}",
            meta.id,
            report_path.display()
        )),
    );

    Ok(ReportOutput {
        finding_id: meta.id,
        finding_path,
        report_path,
        cvss_vector: vector,
        cvss_score: score,
        severity,
        generated: true,
    })
}

// Generate a CVE writeup + disclosure email pair for one finding
pub async fn disclose_finding(config: &DiscloseConfig) -> Result<DiscloseOutput, ReportError> {
    validate_finding_id(&config.finding_id)?;
    validate_vendor_metadata(&config.vendor, &config.contact)?;
    let eng = Engagement::load_named(&config.engagements_dir, &config.engagement)?;
    let finding_path = find_finding_path(&eng.findings_dir(), &config.finding_id)?;
    let cve_path = artifact_path_for(&finding_path, "-cve.md")?;
    let email_path = artifact_path_for(&finding_path, "-disclosure.eml")?;
    let finding_raw = fs::read_to_string(&finding_path)?;
    let meta = parse_finding_meta(&finding_raw, &config.finding_id);
    let reported_on = today_iso_date();

    if cve_path.exists() && email_path.exists() && !config.force {
        return existing_disclose_output(
            &finding_path,
            &cve_path,
            &email_path,
            &meta,
            config.timeline_days,
            &reported_on,
        );
    }

    let fingerprint_json = read_optional_bounded(
        &eng.recon_dir().join("fingerprint.json"),
        FINGERPRINT_MAX_BYTES,
    )?
    .unwrap_or_else(|| "(recon/fingerprint.json not present)".into());
    let finding_markdown = bounded_text(&finding_raw, FINDING_MAX_BYTES);
    let body = if config.offline {
        fallback_cve_body(&finding_raw, &meta)
    } else {
        run_model_cve(config, &finding_markdown, &fingerprint_json).await?
    };
    let vector = cvss::find_vector(&body)
        .unwrap_or_else(|| cvss::default_vector_for_severity(&meta.severity).into());
    let clean_body = strip_cvss_comment(&body);
    let score = cvss::score_vector(&vector)?;
    let severity = cvss::severity_label(score).to_string();
    let cve_doc = render_cve_writeup(&meta.title, &severity, score, &vector, &clean_body);
    fs::write(&cve_path, cve_doc)?;

    let email_doc = render_disclosure_email(&DisclosureEnvelope {
        title: &meta.title,
        severity: &severity,
        score,
        vendor: &config.vendor,
        contact: &config.contact,
        timeline_days: config.timeline_days,
        reported_on: &reported_on,
        cve_path: &cve_path,
    });
    fs::write(&email_path, email_doc)?;

    let _ = eng.audit(
        "mg-report",
        &meta.target,
        Some(&format!(
            "disclose finding={} cve={} email={} timeline={}d",
            meta.id,
            cve_path.display(),
            email_path.display(),
            config.timeline_days,
        )),
    );

    Ok(DiscloseOutput {
        finding_id: meta.id,
        finding_path,
        cve_writeup_path: cve_path,
        disclosure_email_path: email_path,
        cvss_vector: vector,
        cvss_score: score,
        severity,
        timeline_days: config.timeline_days,
        reported_on,
        generated: true,
    })
}

// List finding IDs that can be bulk-reported
pub fn list_reportable_findings(
    engagements_dir: &Path,
    engagement: &str,
) -> Result<Vec<String>, ReportError> {
    let eng = Engagement::load_named(engagements_dir, engagement)?;
    let mut ids = Vec::new();
    for entry in fs::read_dir(eng.findings_dir())? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.ends_with(".md") || name.ends_with("-report.md") {
            continue;
        }
        let raw = fs::read_to_string(&path)?;
        let meta = parse_finding_meta(&raw, "");
        if meta.status == "unconfirmed" || meta.verdict.as_deref() == Some("unconfirmed") {
            continue;
        }
        ids.push(meta.id);
    }
    ids.sort();
    Ok(ids)
}

// Build an LLM report body from local evidence
async fn run_model_report(
    config: &ReportConfig,
    finding_markdown: &str,
    engagement_json: &str,
    fingerprint_json: &str,
) -> Result<String, ReportError> {
    let client = build_client(config)?;
    let system = prompt::system_prompt();
    let user = prompt::user_prompt(finding_markdown, engagement_json, fingerprint_json);
    Ok(client.complete(system, &user).await?)
}

// Build the configured LLM client
fn build_client(config: &ReportConfig) -> Result<LlmClient, ReportError> {
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        return Ok(LlmClient::anthropic(key, &config.model)?);
    }
    Ok(LlmClient::ollama(&config.ollama_model)?)
}

// Return metadata for an existing report without rewriting it
fn existing_report_output(
    finding_id: &str,
    finding_path: &Path,
    report_path: &Path,
    meta: &FindingMeta,
) -> Result<ReportOutput, ReportError> {
    let raw = fs::read_to_string(report_path)?;
    let vector = cvss::find_vector(&raw)
        .unwrap_or_else(|| cvss::default_vector_for_severity(&meta.severity).into());
    let score = cvss::score_vector(&vector)?;
    Ok(ReportOutput {
        finding_id: finding_id.into(),
        finding_path: finding_path.to_path_buf(),
        report_path: report_path.to_path_buf(),
        cvss_vector: vector,
        cvss_score: score,
        severity: cvss::severity_label(score).into(),
        generated: false,
    })
}

// Build an LLM CVE writeup body from local evidence
async fn run_model_cve(
    config: &DiscloseConfig,
    finding_markdown: &str,
    fingerprint_json: &str,
) -> Result<String, ReportError> {
    let client = build_client_for_disclose(config)?;
    let system = disclosure::cve_writeup_system_prompt();
    let user = disclosure::cve_writeup_user_prompt(finding_markdown, fingerprint_json);
    Ok(client.complete(system, &user).await?)
}

// Build an LLM client using the disclose config
fn build_client_for_disclose(config: &DiscloseConfig) -> Result<LlmClient, ReportError> {
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        return Ok(LlmClient::anthropic(key, &config.model)?);
    }
    Ok(LlmClient::ollama(&config.ollama_model)?)
}

// Return metadata for existing disclosure artifacts without rewriting them
fn existing_disclose_output(
    finding_path: &Path,
    cve_path: &Path,
    email_path: &Path,
    meta: &FindingMeta,
    timeline_days: u32,
    reported_on: &str,
) -> Result<DiscloseOutput, ReportError> {
    let raw = fs::read_to_string(cve_path)?;
    let vector = cvss::find_vector(&raw)
        .unwrap_or_else(|| cvss::default_vector_for_severity(&meta.severity).into());
    let score = cvss::score_vector(&vector)?;
    Ok(DiscloseOutput {
        finding_id: meta.id.clone(),
        finding_path: finding_path.to_path_buf(),
        cve_writeup_path: cve_path.to_path_buf(),
        disclosure_email_path: email_path.to_path_buf(),
        cvss_vector: vector,
        cvss_score: score,
        severity: cvss::severity_label(score).into(),
        timeline_days,
        reported_on: reported_on.to_string(),
        generated: false,
    })
}

// Build a deterministic CVE writeup body when the operator requests offline mode
fn fallback_cve_body(finding_raw: &str, meta: &FindingMeta) -> String {
    let body = strip_frontmatter(finding_raw);
    let description = section_or_default(
        body,
        "Summary",
        "See the original finding summary for the vulnerability description.",
    );
    let steps = section_or_default(
        body,
        "Steps to reproduce",
        "1. Re-run the evidence commands from the finding.",
    );
    let impact = section_or_default(
        body,
        "Impact",
        "Impact should be confirmed manually before publication.",
    );
    let remediation = section_or_default(
        body,
        "Remediation",
        "Apply a fix specific to the vulnerable component and add regression tests.",
    );
    let vector = cvss::default_vector_for_severity(&meta.severity);
    format!(
        "<!-- cvss_vector: {vector} -->\n\n\
         ## Affected Versions\n\nUnknown — confirm before publication.\n\n\
         ## Vulnerability Type\n\nSee the finding title and CWE mapping.\n\n\
         ## Technical Description\n\n{description}\n\n\
         ## Reproduction Steps\n\n{steps}\n\n\
         ## Impact\n\n{impact}\n\n\
         ## CWE\n\nCWE mapping should be selected after manual validation.\n\n\
         ## Patch Guidance\n\n{remediation}\n"
    )
}

// Render the CVE writeup wrapper with locally computed severity and score
fn render_cve_writeup(title: &str, severity: &str, score: f64, vector: &str, body: &str) -> String {
    format!(
        "# CVE Writeup — {title}\n\n\
         ## Severity\n\n\
         {severity} (CVSS 3.1: {score:.1})\n\n\
         CVSS Vector: `{vector}`\n\n\
         {}\n",
        body.trim()
    )
}

// Bundled inputs for the deterministic disclosure email renderer
struct DisclosureEnvelope<'a> {
    title: &'a str,
    severity: &'a str,
    score: f64,
    vendor: &'a str,
    contact: &'a str,
    timeline_days: u32,
    reported_on: &'a str,
    cve_path: &'a Path,
}

// Render a deterministic disclosure email envelope for the operator to send
fn render_disclosure_email(env: &DisclosureEnvelope<'_>) -> String {
    let cve_name = env
        .cve_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cve-writeup.md");
    let safe_vendor = sanitize_header(env.vendor);
    let safe_contact = sanitize_header(env.contact);
    let safe_title = sanitize_header(env.title);
    let severity = env.severity;
    let score = env.score;
    let timeline_days = env.timeline_days;
    let reported_on = env.reported_on;
    format!(
        "X-GeistScope-Meta: vendor={safe_vendor}; timeline_days={timeline_days}; reported_on={reported_on}\n\
         Subject: Responsible disclosure: {safe_title}\n\
         To: {safe_contact}\n\
         From: GeistScope authorized researcher\n\
         \n\
         Hello {safe_vendor} security team,\n\
         \n\
         I am reporting a security vulnerability I identified during authorized\n\
         testing. The severity computed locally is {severity} (CVSS 3.1: {score:.1}).\n\
         \n\
         A technical writeup is attached as `{cve_name}` and contains the affected\n\
         component, reproduction steps, impact analysis, and suggested patch\n\
         guidance.\n\
         \n\
         I am requesting a coordinated disclosure timeline of {timeline_days} days\n\
         starting on {reported_on}. Please confirm receipt at your earliest\n\
         convenience and identify a coordination contact on your side.\n\
         \n\
         Thanks,\n\
         GeistScope authorized researcher\n"
    )
}

// Return today's UTC date as ISO-8601 (YYYY-MM-DD)
fn today_iso_date() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(&Rfc3339)
        .ok()
        .and_then(|s| s.split('T').next().map(str::to_string))
        .unwrap_or_else(|| "0000-00-00".into())
}

// Reject vendor and contact strings that would break RFC-822 headers
fn validate_vendor_metadata(vendor: &str, contact: &str) -> Result<(), ReportError> {
    if vendor.trim().is_empty() {
        return Err(ReportError::InvalidArgs("vendor must not be empty".into()));
    }
    if contact.trim().is_empty() {
        return Err(ReportError::InvalidArgs("contact must not be empty".into()));
    }
    for (label, value) in [("vendor", vendor), ("contact", contact)] {
        if value.chars().any(|c| c == '\n' || c == '\r') {
            return Err(ReportError::InvalidArgs(format!(
                "{label} must not contain newlines"
            )));
        }
    }
    Ok(())
}

// Strip newlines from a string before embedding it in an RFC-822 header
fn sanitize_header(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

// Render the final local report wrapper with computed CVSS score
fn render_report(title: &str, severity: &str, score: f64, vector: &str, body: &str) -> String {
    format!(
        "# {title}\n\n\
         ## Severity\n\n\
         {severity} (CVSS 3.1: {score:.1})\n\n\
         CVSS Vector: `{vector}`\n\n\
         {}\n",
        body.trim()
    )
}

// Create a deterministic report body when the operator requests offline mode
fn fallback_report_body(finding_raw: &str, meta: &FindingMeta, fingerprint_json: &str) -> String {
    let body = strip_frontmatter(finding_raw);
    let summary = section_or_default(body, "Summary", "See the original finding summary.");
    let steps = section_or_default(
        body,
        "Steps to reproduce",
        "1. Re-run the evidence commands from the finding.",
    );
    let impact = section_or_default(
        body,
        "Impact",
        "Impact should be confirmed manually before submission.",
    );
    let evidence = section_or_default(
        body,
        "Evidence",
        "Original finding evidence was not structured.",
    );
    let remediation = section_or_default(
        body,
        "Remediation",
        "Apply a fix specific to the vulnerable component and add regression tests.",
    );
    let vector = cvss::default_vector_for_severity(&meta.severity);
    format!(
        "<!-- cvss_vector: {vector} -->\n\n\
         ## Summary\n\n{summary}\n\n\
         ## Steps to Reproduce\n\n{steps}\n\n\
         ## Impact\n\n{impact}\n\n\
         ## Proof of Concept\n\n{evidence}\n\n\
         ## Recommended Fix\n\n{remediation}\n\n\
         ## References\n\n\
         - OWASP Web Security Testing Guide\n\
         - CWE mapping should be selected after manual validation.\n\
         - Fingerprint context: {}\n",
        summarize_context(fingerprint_json)
    )
}

// Parse finding frontmatter into report metadata
fn parse_finding_meta(raw: &str, fallback_id: &str) -> FindingMeta {
    let mut meta = FindingMeta {
        id: fallback_id.into(),
        title: "Vulnerability report".into(),
        severity: "medium".into(),
        status: "draft".into(),
        target: "unknown".into(),
        verdict: None,
    };
    if let Some(frontmatter) = raw
        .strip_prefix("---")
        .and_then(|rest| rest.split("---").next())
    {
        for line in frontmatter.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim().to_string();
            match key.trim() {
                "id" if !value.is_empty() => meta.id = value,
                "title" if !value.is_empty() => meta.title = value,
                "severity" if !value.is_empty() => meta.severity = value.to_ascii_lowercase(),
                "status" if !value.is_empty() => meta.status = value.to_ascii_lowercase(),
                "target" if !value.is_empty() => meta.target = value,
                "verdict" if !value.is_empty() => meta.verdict = Some(value.to_ascii_lowercase()),
                _ => {}
            }
        }
    }
    if meta.id.is_empty() {
        meta.id = fallback_id.into();
    }
    meta
}

// Find a finding markdown path by ID prefix
fn find_finding_path(findings_dir: &Path, finding_id: &str) -> Result<PathBuf, ReportError> {
    let mut matches = Vec::new();
    for entry in fs::read_dir(findings_dir)? {
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name.starts_with(finding_id) && name.ends_with(".md") && !name.ends_with("-report.md") {
            matches.push(path);
        }
    }
    matches.sort();
    matches
        .into_iter()
        .next()
        .ok_or_else(|| ReportError::InvalidArgs(format!("finding `{finding_id}` not found")))
}

// Return the report path for a finding markdown path
fn report_path_for(finding_path: &Path) -> Result<PathBuf, ReportError> {
    artifact_path_for(finding_path, "-report.md")
}

// Build a sibling artifact path for a finding markdown by suffix
fn artifact_path_for(finding_path: &Path, suffix: &str) -> Result<PathBuf, ReportError> {
    let stem = finding_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .ok_or_else(|| ReportError::InvalidArgs("finding path has no valid filename".into()))?;
    Ok(finding_path.with_file_name(format!("{stem}{suffix}")))
}

// Validate a finding ID before matching local files
fn validate_finding_id(finding_id: &str) -> Result<(), ReportError> {
    if finding_id.is_empty()
        || finding_id.contains('/')
        || finding_id.contains('\\')
        || finding_id.chars().any(char::is_control)
    {
        return Err(ReportError::InvalidArgs(
            "finding_id must be a safe file prefix".into(),
        ));
    }
    Ok(())
}

// Read a required file with a byte cap
fn read_bounded(path: &Path, max_bytes: usize) -> Result<String, ReportError> {
    let raw = fs::read_to_string(path)?;
    Ok(bounded_text(&raw, max_bytes))
}

// Read an optional file with a byte cap
fn read_optional_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>, ReportError> {
    if !path.exists() {
        return Ok(None);
    }
    read_bounded(path, max_bytes).map(Some)
}

// Truncate UTF-8 text to a byte cap
fn bounded_text(raw: &str, max_bytes: usize) -> String {
    if raw.len() <= max_bytes {
        return raw.to_string();
    }
    let mut end = max_bytes;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    format!(
        "{}\n\n<!-- truncated: {} bytes hidden -->",
        &raw[..end],
        raw.len().saturating_sub(end)
    )
}

// Remove frontmatter from a finding markdown document
fn strip_frontmatter(raw: &str) -> &str {
    if let Some(rest) = raw.strip_prefix("---")
        && let Some((_, body)) = rest.split_once("---")
    {
        return body.trim();
    }
    raw.trim()
}

// Remove the model-supplied CVSS comment from report content
fn strip_cvss_comment(raw: &str) -> String {
    raw.lines()
        .filter(|line| !line.trim_start().starts_with("<!-- cvss_vector:"))
        .collect::<Vec<_>>()
        .join("\n")
}

// Extract a markdown section by heading text
fn section_or_default<'a>(body: &'a str, heading: &str, default: &'a str) -> String {
    let needle = format!("## {heading}");
    let Some(start) = body.find(&needle) else {
        return default.into();
    };
    let after_heading = &body[start + needle.len()..];
    let after_heading = after_heading.trim_start_matches([' ', '\t', '\r', '\n']);
    let end = after_heading.find("\n## ").unwrap_or(after_heading.len());
    let value = after_heading[..end].trim();
    if value.is_empty() {
        default.into()
    } else {
        value.into()
    }
}

// Collapse optional context into one report-safe line
fn summarize_context(raw: &str) -> String {
    raw.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("not available")
        .chars()
        .take(180)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::{EngagementMeta, Finding, Severity, Status};
    use std::sync::atomic::{AtomicU64, Ordering};

    // Create a unique temporary engagement root
    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-report-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    // Create one finding in a test engagement
    fn fixture() -> (PathBuf, String) {
        let parent = tmp_parent();
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: Some("hackerone".into()),
            url: None,
            tags: Vec::new(),
        };
        let eng = Engagement::init(&parent, meta).unwrap();
        let finding = Finding {
            id: "2026-05-15-001".into(),
            title: "Reflected XSS on search".into(),
            severity: Severity::High,
            status: Status::Confirmed,
            target: "www.example.com".into(),
            created: "2026-05-15T00:00:00Z".into(),
            body: "## Summary\n\nSearch reflects input.\n\n## Steps to reproduce\n\n1. Visit /search?q=<script>alert(1)</script>\n\n## Impact\n\nSession theft.\n\n## Evidence\n\n```bash\ncurl https://www.example.com/search?q=x\n```\n\n## Remediation\n\nEncode output.\n".into(),
        };
        finding.write_to(&eng.findings_dir()).unwrap();
        (parent, "2026-05-15-001".into())
    }

    #[tokio::test]
    async fn generates_offline_report_with_cvss() {
        let (parent, finding_id) = fixture();
        let config = ReportConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            finding_id,
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let output = generate_report(&config).await.unwrap();

        assert!(output.generated);
        assert!(output.report_path.exists());
        assert!(output.cvss_score > 0.0);
        let report = fs::read_to_string(output.report_path).unwrap();
        assert!(report.contains("## Severity"));
        assert!(report.contains("CVSS Vector"));
        assert!(report.contains("## Proof of Concept"));
    }

    #[test]
    fn listing_skips_report_files() {
        let (parent, _) = fixture();
        let ids = list_reportable_findings(&parent, "acme").unwrap();
        assert_eq!(ids, vec!["2026-05-15-001"]);
    }

    #[tokio::test]
    async fn disclose_writes_cve_and_email_offline() {
        let (parent, finding_id) = fixture();
        let config = DiscloseConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            finding_id,
            vendor: "Acme Corp".into(),
            contact: "security@acme.example".into(),
            timeline_days: DiscloseConfig::default_timeline_days(),
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let output = disclose_finding(&config).await.unwrap();

        assert!(output.generated);
        assert!(output.cve_writeup_path.exists());
        assert!(output.disclosure_email_path.exists());
        let cve = fs::read_to_string(&output.cve_writeup_path).unwrap();
        assert!(cve.contains("# CVE Writeup"));
        assert!(cve.contains("## Severity"));
        assert!(cve.contains("## Reproduction Steps"));
        assert!(cve.contains("## CWE"));
        let email = fs::read_to_string(&output.disclosure_email_path).unwrap();
        assert!(email.starts_with("X-GeistScope-Meta: vendor=Acme Corp; timeline_days=90;"));
        assert!(email.contains("Subject: Responsible disclosure: Reflected XSS on search"));
        assert!(email.contains("To: security@acme.example"));
        assert!(email.contains("coordinated disclosure timeline of 90 days"));
        assert_eq!(output.timeline_days, 90);
    }

    #[tokio::test]
    async fn disclose_rejects_header_injection_in_vendor() {
        let (parent, finding_id) = fixture();
        let config = DiscloseConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            finding_id,
            vendor: "Acme\r\nBcc: attacker@example".into(),
            contact: "security@acme.example".into(),
            timeline_days: 30,
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let err = disclose_finding(&config).await.unwrap_err();
        match err {
            ReportError::InvalidArgs(msg) => assert!(msg.contains("vendor")),
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }
}
