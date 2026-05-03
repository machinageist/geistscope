// Author: Jeff
// Date: 2026-05-02
// Description: CLI subcommands for mg-engagement

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "mg-engagement", about = "Manage bug bounty engagements")]
pub struct Args {
    /// Engagements directory (default: ./engagements, or $MG_ENGAGEMENTS_DIR)
    #[arg(long, env = "MG_ENGAGEMENTS_DIR", default_value = "engagements")]
    pub root: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialize a new engagement
    Init {
        /// Short name (used as directory name); e.g. "acme-bounty"
        name: String,
        /// Root domain in scope; e.g. "example.com"
        #[arg(long)]
        target: String,
        /// Bounty platform (hackerone, bugcrowd, intigriti, etc.)
        #[arg(long)]
        platform: Option<String>,
        /// Program URL
        #[arg(long)]
        url: Option<String>,
        /// Tags
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// List engagements
    List,
    /// Show engagement metadata + scope summary
    Show { name: String },
    /// Check whether a target is in scope for an engagement
    Check { name: String, target: String },
    /// Add a pattern to in-scope (or remove via --remove)
    ScopeAdd {
        name: String,
        pattern: String,
        #[arg(long)]
        remove: bool,
    },
    /// Add a pattern to out-of-scope
    ScopeDeny {
        name: String,
        pattern: String,
        #[arg(long)]
        remove: bool,
    },
    /// Append a timestamped note to the engagement
    Note { name: String, text: String },
    /// Create a new finding skeleton in the findings/ directory
    Finding {
        name: String,
        /// Title; will be slugified for the filename
        title: String,
        /// Affected target (host or URL)
        #[arg(long)]
        target: String,
        /// Severity: info|low|medium|high|critical
        #[arg(long, default_value = "medium")]
        severity: String,
    },
}

pub fn get_args() -> Args {
    Args::parse()
}
