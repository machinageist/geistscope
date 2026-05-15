/*******************************************************************
 * Filename:        lib.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     Reverse-engineering copilot for decompiled pseudocode
 * Notes:           Reads engagements/<name>/re/<binary>/raw/<func>.c, runs an
 *                  LLM analysis, and writes <func>.md + <func>.json next to it.
 *******************************************************************/

mod prompt;

use std::fs;
use std::path::{Path, PathBuf};

use engagement::Engagement;
use llm_client::{LlmClient, LlmError};
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

const PSEUDOCODE_MAX_BYTES: usize = 128 * 1024;
const MANIFEST_MAX_BYTES: usize = 16 * 1024;
const MODEL_RESPONSE_MAX_BYTES: usize = 256 * 1024;

const SECTION_HEADERS: &[(&str, &str)] = &[
    ("function_purpose", "Function Purpose"),
    ("variable_map", "Variable Map"),
    ("control_flow_notes", "Control Flow Notes"),
    ("suspicious_logic", "Suspicious Logic"),
    ("exploit_primitives", "Exploit Primitives"),
    ("suggested_next_steps", "Suggested Next Steps"),
];

#[derive(Debug, Error)]
pub enum RecopilotError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("engagement: {0}")]
    Engagement(#[from] engagement::EngagementError),
    #[error("llm: {0}")]
    Llm(#[from] LlmError),
    #[error("invalid args: {0}")]
    InvalidArgs(String),
    #[error("missing input: {0}")]
    MissingInput(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone)]
pub struct AnalyzeConfig {
    pub engagements_dir: PathBuf,
    pub engagement: String,
    pub binary: String,
    pub function: String,
    pub model: String,
    pub ollama_model: String,
    pub offline: bool,
    pub force: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzeOutput {
    pub binary: String,
    pub function: String,
    pub raw_pseudocode_path: PathBuf,
    pub markdown_path: PathBuf,
    pub json_path: PathBuf,
    pub generated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReadOutput {
    pub binary: String,
    pub function: String,
    pub markdown: String,
    pub json: Value,
}

// Analyze one pseudocode function and write Markdown + JSON results
pub async fn analyze_function(
    config: &AnalyzeConfig,
) -> Result<AnalyzeOutput, RecopilotError> {
    validate_path_component(&config.binary, "binary")?;
    validate_path_component(&config.function, "function")?;
    let eng = Engagement::load_named(&config.engagements_dir, &config.engagement)?;
    let binary_dir = eng.re_dir().join(&config.binary);
    let raw_path = binary_dir.join("raw").join(format!("{}.c", &config.function));
    if !raw_path.exists() {
        return Err(RecopilotError::MissingInput(format!(
            "pseudocode file not found at {}",
            raw_path.display()
        )));
    }
    fs::create_dir_all(&binary_dir)?;

    let markdown_path = binary_dir.join(format!("{}.md", &config.function));
    let json_path = binary_dir.join(format!("{}.json", &config.function));
    if markdown_path.exists() && json_path.exists() && !config.force {
        return Ok(AnalyzeOutput {
            binary: config.binary.clone(),
            function: config.function.clone(),
            raw_pseudocode_path: raw_path,
            markdown_path,
            json_path,
            generated: false,
        });
    }

    let pseudocode_raw = fs::read_to_string(&raw_path)?;
    let pseudocode = bounded_text(&pseudocode_raw, PSEUDOCODE_MAX_BYTES);
    let manifest_path = binary_dir.join("manifest.json");
    let manifest_json = read_optional_bounded(&manifest_path, MANIFEST_MAX_BYTES)?
        .unwrap_or_else(|| "{}".into());

    let body = if config.offline {
        fallback_analysis_body(&config.binary, &config.function, &manifest_json)
    } else {
        run_model_analysis(config, &pseudocode, &manifest_json).await?
    };
    let bounded_body = bounded_text(&body, MODEL_RESPONSE_MAX_BYTES);
    let sections = extract_sections(&bounded_body);
    let json_doc = build_json_doc(
        &config.binary,
        &config.function,
        &manifest_json,
        &sections,
        !config.offline,
    )?;

    fs::write(&markdown_path, render_markdown(&config.binary, &config.function, &bounded_body))?;
    fs::write(&json_path, serde_json::to_string_pretty(&json_doc)?)?;

    let _ = eng.audit(
        "mg-recopilot",
        &config.binary,
        Some(&format!(
            "analyze function={} markdown={} json={}",
            config.function,
            markdown_path.display(),
            json_path.display()
        )),
    );

    Ok(AnalyzeOutput {
        binary: config.binary.clone(),
        function: config.function.clone(),
        raw_pseudocode_path: raw_path,
        markdown_path,
        json_path,
        generated: true,
    })
}

// Read a previously generated analysis pair for the harness
pub fn read_analysis(
    engagements_dir: &Path,
    engagement: &str,
    binary: &str,
    function: &str,
) -> Result<AnalysisReadOutput, RecopilotError> {
    validate_path_component(binary, "binary")?;
    validate_path_component(function, "function")?;
    let eng = Engagement::load_named(engagements_dir, engagement)?;
    let binary_dir = eng.re_dir().join(binary);
    let md_path = binary_dir.join(format!("{function}.md"));
    let json_path = binary_dir.join(format!("{function}.json"));
    if !md_path.exists() || !json_path.exists() {
        return Err(RecopilotError::MissingInput(format!(
            "analysis artifacts not found for {binary}/{function}"
        )));
    }
    let md_raw = fs::read_to_string(&md_path)?;
    let json_raw = fs::read_to_string(&json_path)?;
    let json: Value = serde_json::from_str(&json_raw)?;
    Ok(AnalysisReadOutput {
        binary: binary.to_string(),
        function: function.to_string(),
        markdown: bounded_text(&md_raw, MODEL_RESPONSE_MAX_BYTES),
        json,
    })
}

// Run the configured LLM client against the pseudocode + manifest
async fn run_model_analysis(
    config: &AnalyzeConfig,
    pseudocode: &str,
    manifest_json: &str,
) -> Result<String, RecopilotError> {
    let client = build_client(config)?;
    let system = prompt::analyze_system_prompt();
    let user = prompt::analyze_user_prompt(&config.binary, &config.function, manifest_json, pseudocode);
    Ok(client.complete(system, &user).await?)
}

// Build the LLM client from the config
fn build_client(config: &AnalyzeConfig) -> Result<LlmClient, RecopilotError> {
    if let Ok(key) = std::env::var("ANTHROPIC_API_KEY") {
        return Ok(LlmClient::anthropic(key, &config.model)?);
    }
    Ok(LlmClient::ollama(&config.ollama_model)?)
}

// Render the markdown document for a function analysis
fn render_markdown(binary: &str, function: &str, body: &str) -> String {
    format!("# RE Analysis — {binary} :: {function}\n\n{}\n", body.trim())
}

// Build the JSON sidecar from the parsed markdown sections
fn build_json_doc(
    binary: &str,
    function: &str,
    manifest_json: &str,
    sections: &SectionMap,
    llm_generated: bool,
) -> Result<Value, RecopilotError> {
    let manifest_value: Value = match serde_json::from_str(manifest_json) {
        Ok(value) => value,
        Err(_) => Value::Null,
    };
    let mut doc = serde_json::Map::new();
    doc.insert("binary".into(), Value::String(binary.into()));
    doc.insert("function".into(), Value::String(function.into()));
    doc.insert("manifest".into(), manifest_value);
    for (key, _heading) in SECTION_HEADERS {
        doc.insert(
            (*key).into(),
            Value::String(sections.get(*key).cloned().unwrap_or_default()),
        );
    }
    doc.insert("llm_generated".into(), Value::Bool(llm_generated));
    Ok(Value::Object(doc))
}

// Map of section key -> body text
type SectionMap = std::collections::HashMap<&'static str, String>;

// Extract recognised section bodies from model output
fn extract_sections(body: &str) -> SectionMap {
    let mut out = SectionMap::new();
    for (key, heading) in SECTION_HEADERS {
        let needle = format!("## {heading}");
        if let Some(start) = body.find(&needle) {
            let after = &body[start + needle.len()..];
            let after = after.trim_start_matches([' ', '\t', '\r', '\n']);
            let end = after.find("\n## ").unwrap_or(after.len());
            out.insert(*key, after[..end].trim().to_string());
        }
    }
    out
}

// Render a deterministic placeholder body when the operator picks --offline
fn fallback_analysis_body(binary: &str, function: &str, manifest_json: &str) -> String {
    let manifest_summary = manifest_json
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("(no manifest provided)");
    format!(
        "## Function Purpose\n\nOffline mode — manual analysis required for `{function}` in `{binary}`.\n\n\
         ## Variable Map\n\nNo variables annotated. Review the pseudocode at `re/{binary}/raw/{function}.c`.\n\n\
         ## Control Flow Notes\n\nNo control flow notes generated in offline mode.\n\n\
         ## Suspicious Logic\n\nNo suspicious logic flagged in offline mode.\n\n\
         ## Exploit Primitives\n\nNo primitives suggested. Manifest hint: {manifest_summary}\n\n\
         ## Suggested Next Steps\n\n- Re-run without --offline once an LLM backend is available.\n- Confirm the manifest mitigations are accurate before relying on the analysis.\n"
    )
}

// Reject path components that would escape the engagement workspace
fn validate_path_component(value: &str, label: &str) -> Result<(), RecopilotError> {
    if value.is_empty() {
        return Err(RecopilotError::InvalidArgs(format!("{label} must not be empty")));
    }
    if value.contains('/')
        || value.contains('\\')
        || value.contains("..")
        || value.chars().any(char::is_control)
    {
        return Err(RecopilotError::InvalidArgs(format!(
            "{label} must be a safe path component"
        )));
    }
    Ok(())
}

// Read a file with a byte cap when the file exists
fn read_optional_bounded(path: &Path, max_bytes: usize) -> Result<Option<String>, RecopilotError> {
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(bounded_text(&fs::read_to_string(path)?, max_bytes)))
}

// Truncate UTF-8 text on a char boundary at the given byte cap
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

#[cfg(test)]
mod tests {
    use super::*;
    use engagement::EngagementMeta;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Build a unique scratch directory per test
    fn tmp_parent() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("mg-recopilot-test-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    // Build an engagement with a single pseudocode fixture
    fn fixture(binary: &str, function: &str, manifest: Option<&str>) -> PathBuf {
        let parent = tmp_parent();
        let meta = EngagementMeta {
            name: "acme".into(),
            target: "example.com".into(),
            created_at: String::new(),
            platform: None,
            url: None,
            tags: Vec::new(),
        };
        let eng = Engagement::init(&parent, meta).unwrap();
        let binary_dir = eng.re_dir().join(binary);
        fs::create_dir_all(binary_dir.join("raw")).unwrap();
        fs::write(
            binary_dir.join("raw").join(format!("{function}.c")),
            "int parse_header(buf *p) { return p->len; }",
        )
        .unwrap();
        if let Some(content) = manifest {
            fs::write(binary_dir.join("manifest.json"), content).unwrap();
        }
        parent
    }

    #[tokio::test]
    async fn analyze_offline_writes_markdown_and_json() {
        let parent = fixture("libfoo", "parse_header", Some(r#"{"binary_name":"libfoo","arch":"x86_64","mitigations":["NX","ASLR"]}"#));
        let config = AnalyzeConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            binary: "libfoo".into(),
            function: "parse_header".into(),
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let output = analyze_function(&config).await.unwrap();

        assert!(output.generated);
        assert!(output.markdown_path.exists());
        assert!(output.json_path.exists());
        let md = fs::read_to_string(&output.markdown_path).unwrap();
        assert!(md.contains("# RE Analysis"));
        assert!(md.contains("## Function Purpose"));
        assert!(md.contains("## Exploit Primitives"));
        let raw_json = fs::read_to_string(&output.json_path).unwrap();
        let json: Value = serde_json::from_str(&raw_json).unwrap();
        assert_eq!(json["binary"], "libfoo");
        assert_eq!(json["function"], "parse_header");
        assert_eq!(json["llm_generated"], false);
        assert!(json["manifest"]["mitigations"].is_array());
        assert!(!json["function_purpose"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn analyze_rejects_path_traversal_in_binary() {
        let parent = fixture("libfoo", "parse_header", None);
        let config = AnalyzeConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            binary: "../etc/passwd".into(),
            function: "parse_header".into(),
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let err = analyze_function(&config).await.unwrap_err();
        match err {
            RecopilotError::InvalidArgs(msg) => assert!(msg.contains("binary")),
            other => panic!("expected InvalidArgs, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn analyze_errors_on_missing_pseudocode() {
        let parent = fixture("libfoo", "parse_header", None);
        let config = AnalyzeConfig {
            engagements_dir: parent,
            engagement: "acme".into(),
            binary: "libfoo".into(),
            function: "absent".into(),
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };

        let err = analyze_function(&config).await.unwrap_err();
        match err {
            RecopilotError::MissingInput(msg) => assert!(msg.contains("pseudocode")),
            other => panic!("expected MissingInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_analysis_returns_bounded_artifacts() {
        let parent = fixture("libfoo", "parse_header", None);
        let config = AnalyzeConfig {
            engagements_dir: parent.clone(),
            engagement: "acme".into(),
            binary: "libfoo".into(),
            function: "parse_header".into(),
            model: "claude-sonnet-4-6".into(),
            ollama_model: "llama3.2".into(),
            offline: true,
            force: true,
        };
        analyze_function(&config).await.unwrap();

        let read = read_analysis(&parent, "acme", "libfoo", "parse_header").unwrap();

        assert_eq!(read.binary, "libfoo");
        assert_eq!(read.function, "parse_header");
        assert!(read.markdown.contains("# RE Analysis"));
        assert_eq!(read.json["function"], "parse_header");
    }
}
