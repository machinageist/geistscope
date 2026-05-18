/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     mg-recon CLI — run the full recon pipeline against an engagement
 * Notes:           Calls lib functions in-process (no subprocess); each stage checks
 *                  for an existing output file and skips unless --force is passed.
 *                  --with <tool> flags run additional binaries after stage 4.
 *******************************************************************/

use anyhow::{Context, Result};
use clap::Parser;
use mg_recon::orchestrator;

// Valid tool names accepted by --with
const VALID_WITH_TOOLS: &[&str] = &[
    "crawl",
    "probe",
    "graphql",
    "screenshot",
    "takeover",
    "tls",
    "dns-enum",
    "vhost",
    "xss",
    "sqli",
    "ssrf",
    "cors",
    "jwt",
    "oauth",
    "github",
    "cloud-enum",
    "shodan",
    "whois",
];

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

    /// Additional tool to run after the recon pipeline (repeatable)
    /// Valid values: crawl, probe, graphql, screenshot, takeover, tls, dns-enum,
    /// vhost, xss, sqli, ssrf, cors, jwt, oauth, github, cloud-enum, shodan, whois
    #[arg(long = "with", value_name = "TOOL")]
    with_tools: Vec<String>,
}

// Map a --with tool name to its binary name
fn tool_binary(name: &str) -> &'static str {
    match name {
        "crawl" => "mg-crawl",
        "probe" => "mg-probe",
        "graphql" => "mg-graphql",
        "screenshot" => "mg-screenshot",
        "takeover" => "mg-takeover",
        "tls" => "mg-tls-scan",
        "dns-enum" => "mg-dns-enum",
        "vhost" => "mg-vhost",
        "xss" => "mg-xss",
        "sqli" => "mg-sqli",
        "ssrf" => "mg-ssrf",
        "cors" => "mg-cors-exploit",
        "jwt" => "mg-jwt",
        "oauth" => "mg-oauth",
        "github" => "mg-github",
        "cloud-enum" => "mg-cloud-enum",
        "shodan" => "mg-shodan",
        "whois" => "mg-whois",
        // caller validates before calling this; unreachable in practice
        _ => "unknown",
    }
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

// Validate all --with tool names against the known list; bail on first unknown
fn validate_with_tools(tools: &[String]) -> Result<()> {
    for tool in tools {
        if !VALID_WITH_TOOLS.contains(&tool.as_str()) {
            anyhow::bail!(
                "unknown --with tool '{}'; valid values: {}",
                tool,
                VALID_WITH_TOOLS.join(", ")
            );
        }
    }
    Ok(())
}

// Run each requested post-recon tool sequentially via tokio::process::Command
async fn run_with_tools(
    tools: &[String],
    engagement: &str,
    engagements_dir: &str,
) -> Result<()> {
    for tool in tools {
        let binary = tool_binary(tool);
        eprintln!("=== --with {tool}: running {binary} ===");
        let status = tokio::process::Command::new(binary)
            .arg(engagement)
            .arg("--engagements-dir")
            .arg(engagements_dir)
            .status()
            .await
            .with_context(|| format!("spawn {binary}"))?;
        if status.success() {
            eprintln!("=== --with {tool}: done ===");
        } else {
            eprintln!(
                "=== --with {tool}: {binary} exited with {} ===",
                status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into())
            );
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.concurrency == 0 {
        anyhow::bail!("concurrency must be at least 1");
    }
    validate_with_tools(&args.with_tools)?;
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

    orchestrator::run(cfg).await?;

    // run any post-recon tools requested via --with
    if !args.with_tools.is_empty() {
        run_with_tools(&args.with_tools, &args.engagement, &args.engagements_dir).await?;
    }

    Ok(())
}
