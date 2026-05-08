// Author: Jeff
// Date: 2026-05-08
// Description: CLI arguments for mg-fingerprint
// Notes: probes a single URL and optionally writes to an engagement recon file

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "mg-fingerprint", about = "HTTP fingerprinting — detect server, framework, CDN, CMS, cloud")]
pub struct Args {
    /// Target URL to probe (e.g. https://api.example.com)
    pub url: String,

    /// Connection + read timeout in milliseconds
    #[arg(short, long, default_value_t = 8000)]
    pub timeout_ms: u64,

    /// Engagement name — write result to recon/fingerprint.json and audit
    #[arg(long)]
    pub engagement: Option<String>,

    /// Engagements root directory (overrides MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    pub engagements_dir: String,
}

// Parse and return CLI arguments
pub fn get_args() -> Args {
    Args::parse()
}
