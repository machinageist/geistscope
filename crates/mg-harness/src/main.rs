/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-harness CLI: single-shot JSON dispatch, or chat REPL
 * Notes:           Default subcommand is "dispatch" (reads Invocation JSON
 *                  from stdin or file). The "chat" subcommand opens a coding-
 *                  agent REPL backed by Anthropic / OpenAI-compatible / Ollama
 *                  with tool-use over the harness endpoint catalog.
 *******************************************************************/

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mg_harness::{HarnessConfig, Invocation, chat, dispatch};

#[derive(Parser, Debug)]
#[command(
    name = "mg-harness",
    about = "Dispatch scoped GeistScope tool endpoint invocations or open a chat REPL"
)]
struct Args {
    /// Engagements root directory (overrides MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements", global = true)]
    engagements_dir: PathBuf,

    #[command(subcommand)]
    command: Option<Command>,

    /// JSON invocation file; reads stdin when omitted (used when no subcommand given)
    #[arg(long)]
    input: Option<PathBuf>,

    /// Pretty-print JSON output (used when no subcommand given)
    #[arg(long)]
    pretty: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Dispatch a single Invocation JSON from file or stdin
    Dispatch {
        /// JSON invocation file; reads stdin when omitted
        #[arg(long)]
        input: Option<PathBuf>,
        /// Pretty-print JSON output
        #[arg(long)]
        pretty: bool,
    },
    /// Open an interactive chat REPL bound to one engagement
    Chat {
        /// Engagement name
        engagement: String,

        /// LLM backend
        #[arg(long, value_enum, default_value_t = chat::BackendKind::Ollama)]
        backend: chat::BackendKind,

        /// Model identifier (e.g. claude-opus-4-7, gpt-5, qwen2.5-coder)
        #[arg(long, default_value = "qwen2.5-coder")]
        model: String,

        /// Base URL override (Ollama, OpenAI-compatible servers)
        #[arg(long)]
        base_url: Option<String>,

        /// API key (also read from ANTHROPIC_API_KEY / OPENAI_API_KEY env vars)
        #[arg(long)]
        api_key: Option<String>,

        /// Allow destructive endpoints (privesc, loot) in the tool catalog
        #[arg(long)]
        unsafe_mode: bool,

        /// Skip the interactive confirm prompt for active endpoints
        #[arg(long)]
        yes: bool,
    },
}

// Read invocation JSON from file or stdin
fn read_input(path: Option<PathBuf>) -> Result<String> {
    if let Some(path) = path {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("read invocation {}", path.display()));
    }

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .context("read invocation from stdin")?;
    Ok(input)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = HarnessConfig::new(args.engagements_dir);

    match args.command {
        Some(Command::Chat {
            engagement,
            backend,
            model,
            base_url,
            api_key,
            unsafe_mode,
            yes,
        }) => {
            chat::run_repl(
                cfg,
                engagement,
                chat::ChatOptions {
                    backend,
                    model,
                    base_url,
                    api_key,
                    allow_destructive: unsafe_mode,
                    auto_confirm: yes,
                },
            )
            .await
        }
        Some(Command::Dispatch { input, pretty }) => run_dispatch(&cfg, input, pretty).await,
        None => run_dispatch(&cfg, args.input, args.pretty).await,
    }
}

// Run a single-shot dispatch — preserves the original mg-harness behavior
async fn run_dispatch(cfg: &HarnessConfig, input: Option<PathBuf>, pretty: bool) -> Result<()> {
    let raw = read_input(input)?;
    let invocation: Invocation = serde_json::from_str(&raw).context("parse invocation JSON")?;
    let result = dispatch(cfg, invocation).await;

    if pretty {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", serde_json::to_string(&result)?);
    }
    Ok(())
}
