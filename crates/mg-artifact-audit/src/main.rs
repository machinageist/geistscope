/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-22
 * Description:     mg-artifact-audit — merged artifact analyzer covering
 *                  JS scraping, sourcemaps, API-key extraction, document
 *                  metadata, APK static analysis, and IPA static analysis.
 * Notes:           Subcommand-routed; each module owns its CLI args and
 *                  output subdir under the engagement workspace.
 *                  Replaces mg-js-analyze, mg-sourcemap, mg-apikey,
 *                  mg-metadata, mg-apk, and mg-ipa.
 *******************************************************************/

use anyhow::Result;
use clap::{Parser, Subcommand};

mod apikey;
mod apk;
mod ipa;
mod js;
mod metadata;
mod sourcemap;

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-artifact-audit",
    about = "Merged artifact analyzer — JS, sourcemaps, API keys, doc metadata, APK, IPA"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Static JS analysis — endpoints, secrets, source maps
    Js(js::Args),
    /// Source map downloader and analyzer
    Sourcemap(sourcemap::Args),
    /// API key extraction from crawl corpus
    Apikey(apikey::Args),
    /// Document metadata extraction
    Metadata(metadata::Args),
    /// Android APK static analysis
    Apk(apk::Args),
    /// iOS IPA static analysis
    Ipa(ipa::Args),
    /// Run multiple analyzers in one pass
    Audit(audit::Args),
}

mod audit {
    use clap::Parser;

    #[derive(Parser, Debug)]
    pub struct Args {
        /// Engagement name
        pub engagement: String,

        /// Engagements root directory
        #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
        pub engagements_dir: String,

        /// Analyzer types to run (comma-separated: js,sourcemap,apikey,metadata,apk,ipa)
        #[arg(long, value_delimiter = ',')]
        pub types: Vec<String>,

        /// Optional APK path for apk analyzer
        #[arg(long)]
        pub apk: Option<String>,

        /// Optional IPA path for ipa analyzer
        #[arg(long)]
        pub ipa: Option<String>,
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Js(args) => js::run(args).await,
        Command::Sourcemap(args) => sourcemap::run(args).await,
        Command::Apikey(args) => apikey::run(args).await,
        Command::Metadata(args) => metadata::run(args).await,
        Command::Apk(args) => apk::run(args),
        Command::Ipa(args) => ipa::run(args),
        Command::Audit(args) => run_audit(args).await,
    }
}

// Run multiple analyzers sequentially in one invocation
async fn run_audit(args: audit::Args) -> Result<()> {
    for ty in &args.types {
        match ty.as_str() {
            "js" => {
                js::run(js::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    concurrency: 5,
                    timeout: 15,
                })
                .await?
            }
            "sourcemap" => {
                sourcemap::run(sourcemap::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    concurrency: 5,
                    timeout: 15,
                })
                .await?
            }
            "apikey" => {
                apikey::run(apikey::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    concurrency: 5,
                    timeout: 15,
                })
                .await?
            }
            "metadata" => {
                metadata::run(metadata::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    concurrency: 3,
                    timeout: 30,
                })
                .await?
            }
            "apk" => {
                let apk_path = args
                    .apk
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--apk required for apk type"))?;
                apk::run(apk::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    apk: apk_path,
                })?
            }
            "ipa" => {
                let ipa_path = args
                    .ipa
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("--ipa required for ipa type"))?;
                ipa::run(ipa::Args {
                    engagement: args.engagement.clone(),
                    engagements_dir: args.engagements_dir.clone(),
                    ipa: ipa_path,
                })?
            }
            other => anyhow::bail!("unknown analyzer type: {other}"),
        }
    }
    Ok(())
}
