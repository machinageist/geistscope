// Author: Jeff
// Date: 2026-05-01
// Description: CLI subcommands for corpus-builder

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "corpus-builder", about = "Build and query a subdomain/path corpus")]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Mine crt.sh CT logs for subdomains
    MineCt {
        /// File containing one domain per line
        #[arg(long)]
        domains: String,
        /// SQLite corpus database path
        #[arg(long, default_value = "corpus.db")]
        db: String,
        /// Milliseconds between crt.sh requests
        #[arg(long, default_value_t = 1500)]
        rate_limit_ms: u64,
    },
    /// Mine Wayback Machine CDX API for historical paths
    MineWayback {
        #[arg(long)]
        domains: String,
        #[arg(long, default_value = "corpus.db")]
        db: String,
        #[arg(long, default_value_t = 2000)]
        rate_limit_ms: u64,
    },
    /// Query known subdomains for a domain
    Query {
        domain: String,
        #[arg(long, default_value = "corpus.db")]
        db: String,
    },
    /// Show corpus statistics
    Stats {
        #[arg(long, default_value = "corpus.db")]
        db: String,
    },
}

pub fn get_args() -> Args {
    Args::parse()
}
