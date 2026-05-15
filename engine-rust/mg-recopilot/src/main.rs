/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     mg-recopilot CLI for decompiled-pseudocode analysis
 * Notes:           Reads engagements/<name>/re/<binary>/raw/<func>.c and
 *                  writes <func>.md + <func>.json next to it.
 *******************************************************************/

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mg_recopilot::{AnalyzeConfig, analyze_function};

// CLI root
#[derive(Parser, Debug)]
#[command(
    name = "mg-recopilot",
    about = "Reverse-engineering copilot for decompiled pseudocode"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

// CLI subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Analyze one pseudocode function and write a Markdown + JSON pair
    Analyze {
        /// Engagement name
        engagement: String,

        /// Binary identifier (must be a single path component)
        binary: String,

        /// Function name (must be a single path component)
        function: String,

        /// Engagements root directory
        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        engagements_dir: PathBuf,

        /// Claude model ID to use when ANTHROPIC_API_KEY is set
        #[arg(long, default_value = "claude-sonnet-4-6")]
        model: String,

        /// Ollama model to use when ANTHROPIC_API_KEY is absent
        #[arg(long, default_value = "llama3.2")]
        ollama_model: String,

        /// Produce a deterministic placeholder analysis without calling an LLM
        #[arg(long)]
        offline: bool,

        /// Rewrite existing analysis files
        #[arg(long)]
        force: bool,
    },
}

// Run the selected command
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Analyze {
            engagement,
            binary,
            function,
            engagements_dir,
            model,
            ollama_model,
            offline,
            force,
        } => {
            let output = analyze_function(&AnalyzeConfig {
                engagements_dir,
                engagement,
                binary,
                function,
                model,
                ollama_model,
                offline,
                force,
            })
            .await
            .context("analyze function")?;
            println!("{}", output.markdown_path.display());
            println!("{}", output.json_path.display());
        }
    }
    Ok(())
}
