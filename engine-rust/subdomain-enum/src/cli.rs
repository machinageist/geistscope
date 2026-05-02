// Author: Jeff
// Date: 2026-05-01
// Description: CLI argument definitions for subdomain-enum

use clap::{Parser, ValueEnum};

#[derive(Clone, ValueEnum, Debug)]
pub enum Mode {
    Passive,
    Active,
    All,
}

#[derive(Clone, ValueEnum, Debug)]
pub enum OutputFormat {
    Table,
    Json,
}

#[derive(Parser, Debug)]
#[command(name = "subdomain-enum", about = "Subdomain enumerator — CT logs + DNS brute force")]
pub struct Args {
    /// Target domain (e.g. example.com)
    pub domain: String,

    /// Enumeration mode: passive (CT logs only), active (brute force only), all
    #[arg(long, default_value = "all")]
    pub mode: Mode,

    /// Path to custom wordlist; uses embedded default if omitted
    #[arg(long)]
    pub wordlist: Option<String>,

    /// Max concurrent DNS probes during brute force
    #[arg(short, long, default_value_t = 100)]
    pub concurrency: usize,

    /// DNS/HTTP timeout in milliseconds
    #[arg(short, long, default_value_t = 5000)]
    pub timeout_ms: u64,

    /// Output format
    #[arg(short, long, default_value = "table")]
    pub format: OutputFormat,
}

pub fn get_args() -> Args {
    Args::parse()
}
