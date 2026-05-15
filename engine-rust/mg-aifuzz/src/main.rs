/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     mg-aifuzz CLI for adversarial LLM-endpoint fuzzing
 * Notes:           Operators must run `consent` once per engagement before
 *                  `run` will send any requests.
 *******************************************************************/

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mg_aifuzz::{FuzzConfig, record_consent, run};
use payload_engine::PromptInjectionCategory;

// CLI root
#[derive(Parser, Debug)]
#[command(
    name = "mg-aifuzz",
    about = "Adversarial prompt-injection fuzzer for LLM endpoints"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

// CLI subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Record adversarial-AI fuzz consent for one engagement
    Consent {
        engagement: String,

        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        engagements_dir: PathBuf,
    },

    /// Run a bounded prompt-injection fuzz pass against an LLM endpoint
    Run {
        engagement: String,

        /// Path to a §INJECT§ request template
        #[arg(long)]
        template: PathBuf,

        /// Base URL (scheme + host) for the target; the template path is joined onto this
        #[arg(long)]
        base_url: String,

        /// Optional sentinels file (one string per line) for system-prompt-leak detection
        #[arg(long)]
        sentinels: Option<PathBuf>,

        /// Only fuzz the listed prompt-injection categories
        #[arg(long, value_delimiter = ',')]
        categories: Vec<String>,

        /// Maximum number of payload attempts
        #[arg(long, default_value_t = FuzzConfig::default_max_attempts())]
        max_attempts: usize,

        /// Per-request pause in milliseconds
        #[arg(long, default_value_t = FuzzConfig::default_rate_ms())]
        rate_ms: u64,

        /// HTTP timeout per request in milliseconds
        #[arg(long, default_value_t = FuzzConfig::default_timeout_ms())]
        timeout_ms: u64,

        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        engagements_dir: PathBuf,
    },
}

// Run the selected command
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Consent {
            engagement,
            engagements_dir,
        } => {
            let path =
                record_consent(&engagements_dir, &engagement).context("record consent")?;
            println!("{}", path.display());
        }
        Command::Run {
            engagement,
            template,
            base_url,
            sentinels,
            categories,
            max_attempts,
            rate_ms,
            timeout_ms,
            engagements_dir,
        } => {
            let parsed_categories = parse_categories(&categories)?;
            let output = run(&FuzzConfig {
                engagements_dir,
                engagement,
                template_path: template,
                base_url,
                categories: parsed_categories,
                max_attempts,
                rate_ms,
                timeout_ms,
                sentinels_path: sentinels,
            })
            .await
            .context("aifuzz run")?;
            println!(
                "{} attempts={} hits={}",
                output.output_path.display(),
                output.attempts,
                output.hits
            );
        }
    }
    Ok(())
}

// Map CLI category strings to PromptInjectionCategory values
fn parse_categories(values: &[String]) -> Result<Vec<PromptInjectionCategory>> {
    let mut out = Vec::new();
    for raw in values {
        let category = PromptInjectionCategory::from_name(raw.trim())
            .with_context(|| format!("unknown prompt-injection category `{raw}`"))?;
        out.push(category);
    }
    Ok(out)
}
