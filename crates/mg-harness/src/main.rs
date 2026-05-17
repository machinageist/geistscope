/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     mg-harness CLI wrapper for JSON endpoint invocations
 * Notes:           Reads one Invocation JSON document from a file or stdin
 *                  and prints one EndpointResult JSON document to stdout.
 *******************************************************************/

use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use mg_harness::{HarnessConfig, Invocation, dispatch};

#[derive(Parser, Debug)]
#[command(
    name = "mg-harness",
    about = "Dispatch scoped GeistScope tool endpoint invocations"
)]
struct Args {
    /// Engagements root directory (overrides MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: PathBuf,

    /// JSON invocation file; reads stdin when omitted
    #[arg(long)]
    input: Option<PathBuf>,

    /// Pretty-print JSON output
    #[arg(long)]
    pretty: bool,
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
    let raw = read_input(args.input)?;
    let invocation: Invocation = serde_json::from_str(&raw).context("parse invocation JSON")?;
    let cfg = HarnessConfig::new(args.engagements_dir);
    let result = dispatch(&cfg, invocation).await;

    if args.pretty {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", serde_json::to_string(&result)?);
    }

    Ok(())
}
