/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     mg-recon CLI — run the full recon pipeline against an engagement
 * Notes:           Calls lib functions in-process (no subprocess); each stage checks
 *                  for an existing output file and skips unless --force is passed
 *******************************************************************/

use anyhow::Result;
use clap::Parser;
use mg_recon::orchestrator;

#[derive(Parser, Debug)]
#[command(
    name = "mg-recon",
    about = "Full recon pipeline — subdomain enum → fingerprint → port scan → summary"
)]
struct Args {
    /// Engagement name (must already be initialized with mg-engagement init)
    engagement: String,

    /// Engagements root directory (overrides MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    engagements_dir: String,

    /// Re-run all stages even if cached output exists
    #[arg(long)]
    force: bool,

    /// Max concurrent DNS/HTTP probes
    #[arg(long, default_value_t = 100)]
    concurrency: usize,

    /// Timeout for DNS and HTTP requests in milliseconds
    #[arg(long, default_value_t = 5000)]
    timeout_ms: u64,

    /// Port range to scan on each discovered host (e.g. 1-1024)
    #[arg(long, default_value = "1-1024")]
    ports: String,
}

// Parse port range string; exits on invalid input
fn parse_ports(s: &str) -> (u16, u16) {
    let parts: Vec<&str> = s.splitn(2, '-').collect();
    if parts.len() != 2 {
        eprintln!("invalid port range '{s}': expected start-end");
        std::process::exit(1);
    }
    let start = parts[0].parse::<u16>().unwrap_or_else(|_| {
        eprintln!("invalid port '{}'", parts[0]);
        std::process::exit(1);
    });
    let end = parts[1].parse::<u16>().unwrap_or_else(|_| {
        eprintln!("invalid port '{}'", parts[1]);
        std::process::exit(1);
    });
    if start == 0 || start > end {
        eprintln!("invalid port range '{s}'");
        std::process::exit(1);
    }
    (start, end)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.concurrency == 0 {
        anyhow::bail!("concurrency must be at least 1");
    }
    let (port_start, port_end) = parse_ports(&args.ports);

    // build the engagement root path and hand off to the orchestrator
    let eng_root = engagement::Engagement::path_for_name(
        std::path::Path::new(&args.engagements_dir),
        &args.engagement,
    )?;

    let cfg = orchestrator::RunConfig {
        engagement_name: args.engagement.clone(),
        eng_root,
        force: args.force,
        concurrency: args.concurrency,
        timeout_ms: args.timeout_ms,
        port_start,
        port_end,
    };

    orchestrator::run(cfg).await
}
