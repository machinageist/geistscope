/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     mg-report CLI for bounty-ready report generation
 * Notes:           Default mode uses the configured LLM backend. --offline
 *                  creates a deterministic draft without a model call.
 *******************************************************************/

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use mg_report::{
    DiscloseConfig, ReportConfig, disclose_finding, generate_report, list_reportable_findings,
};

// CLI root
#[derive(Parser, Debug)]
#[command(name = "mg-report", about = "Generate HackerOne-ready finding reports")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

// CLI subcommands
#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a report for one finding, or bulk-generate reportable findings
    Generate {
        /// Engagement name
        engagement: String,

        /// Finding ID prefix, such as 2026-05-15-001
        finding_id: Option<String>,

        /// Engagements root directory
        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        engagements_dir: PathBuf,

        /// Claude model ID to use when ANTHROPIC_API_KEY is set
        #[arg(long, default_value = "claude-sonnet-4-6")]
        model: String,

        /// Ollama model to use when ANTHROPIC_API_KEY is absent
        #[arg(long, default_value = "llama3.2")]
        ollama_model: String,

        /// Generate a deterministic report without calling an LLM
        #[arg(long)]
        offline: bool,

        /// Rewrite an existing report file
        #[arg(long)]
        force: bool,

        /// Generate reports for all findings except explicit unconfirmed ones
        #[arg(long)]
        all_unconfirmed: bool,
    },

    /// Draft a CVE writeup + disclosure email for one finding
    Disclose {
        /// Engagement name
        engagement: String,

        /// Finding ID prefix, such as 2026-05-15-001
        finding_id: String,

        /// Vendor name, used in the email subject and salutation
        #[arg(long)]
        vendor: String,

        /// Vendor security contact, used in the To: header
        #[arg(long)]
        contact: String,

        /// Disclosure timeline in days
        #[arg(long, default_value_t = DiscloseConfig::default_timeline_days())]
        timeline_days: u32,

        /// Engagements root directory
        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        engagements_dir: PathBuf,

        /// Claude model ID to use when ANTHROPIC_API_KEY is set
        #[arg(long, default_value = "claude-sonnet-4-6")]
        model: String,

        /// Ollama model to use when ANTHROPIC_API_KEY is absent
        #[arg(long, default_value = "llama3.2")]
        ollama_model: String,

        /// Generate a deterministic writeup without calling an LLM
        #[arg(long)]
        offline: bool,

        /// Rewrite existing CVE writeup and disclosure files
        #[arg(long)]
        force: bool,
    },
}

// Run the selected command
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Command::Generate {
            engagement,
            finding_id,
            engagements_dir,
            model,
            ollama_model,
            offline,
            force,
            all_unconfirmed,
        } => {
            if all_unconfirmed {
                let ids = list_reportable_findings(&engagements_dir, &engagement)
                    .context("list reportable findings")?;
                for id in ids {
                    let output = generate_report(&ReportConfig {
                        engagements_dir: engagements_dir.clone(),
                        engagement: engagement.clone(),
                        finding_id: id,
                        model: model.clone(),
                        ollama_model: ollama_model.clone(),
                        offline,
                        force,
                    })
                    .await
                    .context("generate report")?;
                    println!("{}", output.report_path.display());
                }
                return Ok(());
            }

            let Some(finding_id) = finding_id else {
                anyhow::bail!("finding_id is required unless --all-unconfirmed is set");
            };
            let output = generate_report(&ReportConfig {
                engagements_dir,
                engagement,
                finding_id,
                model,
                ollama_model,
                offline,
                force,
            })
            .await
            .context("generate report")?;
            println!("{}", output.report_path.display());
        }
        Command::Disclose {
            engagement,
            finding_id,
            vendor,
            contact,
            timeline_days,
            engagements_dir,
            model,
            ollama_model,
            offline,
            force,
        } => {
            let output = disclose_finding(&DiscloseConfig {
                engagements_dir,
                engagement,
                finding_id,
                vendor,
                contact,
                timeline_days,
                model,
                ollama_model,
                offline,
                force,
            })
            .await
            .context("draft disclosure")?;
            println!("{}", output.cve_writeup_path.display());
            println!("{}", output.disclosure_email_path.display());
        }
    }
    Ok(())
}
