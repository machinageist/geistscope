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
    /// Store an auth/session profile for an engagement
    CredentialsSet {
        name: String,
        /// Username for form login flows
        #[arg(long)]
        username: Option<String>,
        /// Environment variable containing the password
        #[arg(long)]
        password_env: Option<String>,
        /// Login endpoint for form login flows
        #[arg(long)]
        login_url: Option<String>,
        /// Environment variable containing a static token
        #[arg(long)]
        token_env: Option<String>,
        /// HTTP header for static tokens
        #[arg(long, default_value = "Authorization")]
        token_header: String,
        /// Token prefix such as Bearer; use an empty string for raw tokens
        #[arg(long, default_value = "Bearer")]
        token_prefix: String,
        /// Login method: token|form|oauth_client_credentials
        #[arg(long)]
        login_method: Option<String>,
    },
    /// Test the configured auth/session profile against an in-scope URL
    CredentialsTest {
        name: String,
        /// In-scope URL to request with configured auth headers
        #[arg(long)]
        url: String,
    },
    /// Import and inspect normalized request/response traffic
    Traffic {
        name: String,
        #[command(subcommand)]
        command: TrafficCommand,
    },
}

#[derive(Subcommand, Debug)]
pub enum TrafficCommand {
    /// Import HAR, Burp XML, or Caido JSON traffic into traffic/corpus.jsonl
    Import {
        file: String,
        /// Import format: auto|har|burp|caido
        #[arg(long, default_value = "auto")]
        format: String,
    },
    /// List indexed corpus requests with optional filters
    List {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        method: Option<String>,
        #[arg(long)]
        status: Option<u16>,
        #[arg(long)]
        mime: Option<String>,
        #[arg(long)]
        source: Option<String>,
        #[arg(long)]
        path_contains: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Show one request by ID or unambiguous ID prefix
    Show {
        request_id: String,
        /// Emit a raw HTTP request template instead of JSON metadata
        #[arg(long)]
        raw: bool,
    },
}

pub fn get_args() -> Args {
    Args::parse()
}
