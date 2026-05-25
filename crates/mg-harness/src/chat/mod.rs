/*******************************************************************
 * Filename:        mod.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     Chat REPL — coding-agent loop over harness endpoints
 * Notes:           Backends are pluggable (Anthropic / OpenAI-compat / Ollama).
 *                  Tool calls are gated by the harness's existing RiskClass
 *                  policy: HighActive/StateChange require user confirmation;
 *                  Destructive endpoints are blocked unless --unsafe is set.
 *******************************************************************/

mod anthropic;
mod ollama;
mod openai;
mod types;

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::{
    EndpointSpec, EndpointStatus, HarnessConfig, Invocation, RiskClass, ToolExposure, dispatch,
    registry,
};
use types::{ChatBackend, ChatMessage, ChatStep, ToolCall, ToolDef};

pub use types::ChatError;

const MAX_AGENT_STEPS: usize = 20;

// ---- backend selection

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum BackendKind {
    Anthropic,
    Openai,
    Ollama,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ToolProfile {
    Default,
    Advanced,
    Lab,
}

impl ToolProfile {
    fn allows(self, exposure: ToolExposure) -> bool {
        match self {
            ToolProfile::Default => matches!(exposure, ToolExposure::DefaultProfile),
            ToolProfile::Advanced => matches!(
                exposure,
                ToolExposure::DefaultProfile | ToolExposure::AdvancedProfile
            ),
            ToolProfile::Lab => !matches!(exposure, ToolExposure::ServiceInternal),
        }
    }

    fn label(self) -> &'static str {
        match self {
            ToolProfile::Default => "default",
            ToolProfile::Advanced => "advanced",
            ToolProfile::Lab => "lab",
        }
    }
}

pub struct ChatOptions {
    pub backend: BackendKind,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
    pub tool_profile: ToolProfile,
    pub allow_destructive: bool,
    pub auto_confirm: bool,
}

// Construct a ChatBackend trait object from the chosen options
fn build_backend(opts: &ChatOptions) -> Result<Box<dyn ChatBackend>> {
    Ok(match opts.backend {
        BackendKind::Anthropic => {
            let key = opts
                .api_key
                .clone()
                .or_else(|| std::env::var("ANTHROPIC_API_KEY").ok())
                .context("ANTHROPIC_API_KEY not set; pass --api-key")?;
            Box::new(anthropic::AnthropicChat::new(key, opts.model.clone())?)
        }
        BackendKind::Openai => {
            let key = opts
                .api_key
                .clone()
                .or_else(|| std::env::var("OPENAI_API_KEY").ok());
            Box::new(openai::OpenAiChat::new(
                key,
                opts.base_url.clone(),
                opts.model.clone(),
            )?)
        }
        BackendKind::Ollama => Box::new(ollama::OllamaChat::new(
            opts.base_url.clone(),
            opts.model.clone(),
        )?),
    })
}

// ---- tool registry from harness endpoints

// Map a harness endpoint name like "tls.scan" to a model-safe identifier
fn safe_tool_name(endpoint: &str) -> String {
    endpoint.replace('.', "_")
}

fn endpoint_from_safe_name(safe: &str) -> String {
    safe.replacen('_', ".", 1)
}

// Build the tool catalog presented to the model. Profiles hide sharp/noisy
// endpoints before the model can select them; dispatch still enforces risk.
fn build_tool_defs(profile: ToolProfile, allow_destructive: bool) -> Vec<ToolDef> {
    registry()
        .into_iter()
        .filter(|s| s.implemented)
        .filter(|s| profile.allows(s.exposure))
        .filter(|s| allow_destructive || !matches!(s.risk, RiskClass::Destructive))
        .map(|s| ToolDef {
            name: safe_tool_name(s.name),
            description: format!(
                "[{:?} pack={:?} exposure={:?}] {}{}",
                s.risk,
                s.pack,
                s.exposure,
                s.description,
                s.repurpose
                    .map(|note| format!(" Repurpose: {note}"))
                    .unwrap_or_default()
            ),
            parameters: json!({
                "type": "object",
                "properties": {},
                "additionalProperties": { "type": "string" },
                "description": "String key/value arguments forwarded to the tool's CLI as --key value pairs"
            }),
        })
        .collect()
}

// Spec for an endpoint name (None if unknown)
fn spec_for_endpoint(endpoint: &str) -> Option<EndpointSpec> {
    registry().into_iter().find(|s| s.name == endpoint)
}

// ---- system prompt

fn build_system_prompt(
    engagement_name: &str,
    model_label: &str,
    profile_label: &str,
    tool_count: usize,
) -> String {
    format!(
        "You are an offensive-security assistant embedded in GeistScope.\n\
         You are working inside engagement \"{engagement_name}\" — every action must \
         stay within this engagement's scope. The user has authorized testing of any \
         target on the scope list.\n\n\
         Backend: {model_label}. Tool profile: {profile_label}. {tool_count} tools are exposed.\n\n\
         Tool-call rules:\n\
         - Prefer calling tools over guessing. Findings from tools land in \
         engagements/{engagement_name}/findings/ automatically.\n\
         - Tool names use underscores instead of dots (e.g. tls_scan, not tls.scan).\n\
         - Arguments are forwarded as --key value pairs to the tool's CLI.\n\
         - Read-only and PassiveRemote tools run immediately. LowActive, HighActive, \
         and StateChange tools require the user to confirm in the REPL before they run.\n\
         - When you have enough information, answer in plain text. Don't keep calling \
         tools indefinitely — the harness caps you at {MAX_AGENT_STEPS} tool turns per user message.\n"
    )
}

// ---- REPL

// Run the chat REPL — blocks until the user types /quit or hits EOF
pub async fn run_repl(cfg: HarnessConfig, engagement: String, opts: ChatOptions) -> Result<()> {
    let backend = build_backend(&opts)?;
    let tools = build_tool_defs(opts.tool_profile, opts.allow_destructive);

    println!(
        "mg-harness chat — engagement={} backend={} profile={} tools={}",
        engagement,
        backend.model_label(),
        opts.tool_profile.label(),
        tools.len()
    );
    println!("commands: /help /tools /reset /quit\n");

    let mut messages: Vec<ChatMessage> = vec![ChatMessage::system(build_system_prompt(
        &engagement,
        &backend.model_label(),
        opts.tool_profile.label(),
        tools.len(),
    ))];

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut input_line = String::new();
    let mut handle = stdin.lock();

    loop {
        print!("> ");
        stdout.flush().ok();
        input_line.clear();
        let n = handle.read_line(&mut input_line)?;
        if n == 0 {
            println!();
            break; // EOF
        }
        let line = input_line.trim();
        if line.is_empty() {
            continue;
        }

        // slash commands
        if let Some(cmd) = line.strip_prefix('/') {
            match cmd {
                "quit" | "exit" => break,
                "reset" => {
                    messages.truncate(1);
                    println!("[conversation reset]");
                }
                "tools" => {
                    for t in &tools {
                        println!("  {} — {}", t.name, t.description);
                    }
                }
                "help" => {
                    println!(
                        "/help    show this help\n\
                         /tools   list available tools\n\
                         /reset   clear conversation history (keeps system prompt)\n\
                         /quit    exit"
                    );
                }
                other => println!("unknown command: /{other}"),
            }
            continue;
        }

        messages.push(ChatMessage::user(line));

        // Inner agent loop — keep stepping until the model gives a text answer
        // or we hit MAX_AGENT_STEPS
        for step_n in 0..MAX_AGENT_STEPS {
            let step = match backend.step(&messages, &tools).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[backend error] {e}");
                    break;
                }
            };

            match step {
                ChatStep::Message(text) => {
                    if !text.is_empty() {
                        println!("{text}");
                    }
                    messages.push(ChatMessage::assistant_text(text));
                    break;
                }
                ChatStep::ToolCalls(calls) => {
                    messages.push(ChatMessage::assistant_tool_calls(calls.clone()));
                    for call in &calls {
                        let result = execute_tool_call(
                            &cfg,
                            &engagement,
                            call,
                            opts.auto_confirm,
                            opts.allow_destructive,
                            opts.tool_profile,
                        )
                        .await;
                        let (content, is_error) = match result {
                            Ok(v) => (v, false),
                            Err(e) => (json!({"error": e.to_string()}), true),
                        };
                        let body = serde_json::to_string(&content).unwrap_or_else(|_| "{}".into());
                        messages.push(ChatMessage::tool_result(call, body, is_error));
                    }
                    if step_n == MAX_AGENT_STEPS - 1 {
                        eprintln!(
                            "[agent step cap hit at {MAX_AGENT_STEPS} — interrupting and asking for final answer]"
                        );
                        messages.push(ChatMessage::user(
                            "You've hit the tool-call cap for this turn. Summarize what you've found so far in plain text.",
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

// Resolve, gate, and invoke one tool call; return the JSON the model receives
async fn execute_tool_call(
    cfg: &HarnessConfig,
    engagement: &str,
    call: &ToolCall,
    auto_confirm: bool,
    allow_destructive: bool,
    tool_profile: ToolProfile,
) -> Result<Value> {
    let endpoint = endpoint_from_safe_name(&call.name);
    let spec = spec_for_endpoint(&endpoint)
        .ok_or_else(|| anyhow::anyhow!("unknown endpoint {endpoint}"))?;
    if !tool_profile.allows(spec.exposure) {
        anyhow::bail!(
            "endpoint {endpoint} is hidden from the {} tool profile ({:?})",
            tool_profile.label(),
            spec.exposure
        );
    }
    let risk = spec.risk;

    // Risk gating ----
    let requires_confirm = matches!(
        risk,
        RiskClass::LowActive | RiskClass::HighActive | RiskClass::StateChange
    );
    let is_destructive = matches!(risk, RiskClass::Destructive);

    if is_destructive && !allow_destructive {
        anyhow::bail!("destructive endpoint {endpoint} blocked (pass --unsafe to allow)");
    }

    if requires_confirm && !auto_confirm {
        eprintln!(
            "\n[confirm] model wants to call {endpoint} ({:?}) with args:",
            risk
        );
        eprintln!(
            "  {}",
            serde_json::to_string(&call.args).unwrap_or_default()
        );
        eprint!("approve? [y/N] ");
        std::io::stderr().flush().ok();
        let mut buf = String::new();
        std::io::stdin().read_line(&mut buf)?;
        if !buf.trim().eq_ignore_ascii_case("y") {
            anyhow::bail!("user denied {endpoint}");
        }
    }

    // Build invocation — args are forwarded verbatim
    let mut args = call.args.clone();
    // If model didn't pass an engagement, fill it in
    if args.get("engagement").is_none()
        && let Some(obj) = args.as_object_mut()
    {
        obj.insert("engagement".into(), json!(engagement));
    }

    let inv = Invocation {
        endpoint: endpoint.clone(),
        version: None,
        engagement: engagement.to_string(),
        risk: Some(risk),
        reason: Some("invoked by mg-harness chat".into()),
        confirmed: true,
        args,
    };

    let result = dispatch(cfg, inv).await;
    let status_label = match result.status {
        EndpointStatus::Ok => "ok",
        EndpointStatus::Blocked => "blocked",
        EndpointStatus::Error => "error",
    };

    Ok(json!({
        "status": status_label,
        "summary": result.summary,
        "output_files": result.output_files,
        "data": result.data,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_tool_name_swaps_first_dot() {
        assert_eq!(safe_tool_name("tls.scan"), "tls_scan");
        assert_eq!(endpoint_from_safe_name("tls_scan"), "tls.scan");
    }

    #[test]
    fn default_tool_profile_hides_retired_lab_and_internal_tools() {
        let defs = build_tool_defs(ToolProfile::Default, false);
        let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();

        assert!(!names.contains(&"brute_run"));
        assert!(!names.contains(&"snmp_brute"));
        assert!(!names.contains(&"dns_rebind"));
        assert!(!names.contains(&"exploit_scaffold"));
        assert!(!names.contains(&"loot_run"));
        assert!(!names.contains(&"notify_start"));
    }

    #[test]
    fn advanced_tool_profile_includes_advanced_but_not_retired_or_lab_tools() {
        let defs = build_tool_defs(ToolProfile::Advanced, false);
        let names: Vec<&str> = defs.iter().map(|t| t.name.as_str()).collect();

        assert!(names.contains(&"oob_start"));
        assert!(names.contains(&"xss_scan"));
        assert!(!names.contains(&"brute_run"));
        assert!(!names.contains(&"dns_rebind"));
        assert!(!names.contains(&"exploit_scaffold"));
        assert!(!names.contains(&"notify_start"));
    }

    #[test]
    fn lab_tool_profile_requires_unsafe_for_destructive_tools() {
        let lab_safe = build_tool_defs(ToolProfile::Lab, false);
        let lab_unsafe = build_tool_defs(ToolProfile::Lab, true);
        let safe_names: Vec<&str> = lab_safe.iter().map(|t| t.name.as_str()).collect();
        let unsafe_names: Vec<&str> = lab_unsafe.iter().map(|t| t.name.as_str()).collect();

        assert!(safe_names.contains(&"exploit_scaffold"));
        assert!(!safe_names.contains(&"privesc_linux"));
        assert!(!safe_names.contains(&"loot_run"));
        assert!(unsafe_names.contains(&"privesc_linux"));
        assert!(unsafe_names.contains(&"loot_run"));
    }

    #[test]
    fn tool_defs_cover_profile_visible_registry_entries() {
        let defs = build_tool_defs(ToolProfile::Lab, true);
        let visible_count = registry()
            .iter()
            .filter(|s| s.implemented && ToolProfile::Lab.allows(s.exposure))
            .count();
        assert_eq!(defs.len(), visible_count);
    }
}
