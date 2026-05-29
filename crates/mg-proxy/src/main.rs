// Author: Jeff
// Date: 2026-05-28
// Description: CLI skeleton for GeistScope proxy capture
// Notes: Dry-run and export scaffolding only; live proxy networking is intentionally not started here

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use engagement::Engagement;
use proxy_core::ProxyConfig;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const DEFAULT_CA_RELATIVE_PATH: &str = "proxy/ca/geistscope-ca.pem";

#[derive(Debug, Parser)]
#[command(
    name = "mg-proxy",
    about = "Manage GeistScope proxy capture scaffolding"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start proxy capture, or print a safe dry-run plan
    Start {
        /// Engagement root directory
        engagement: PathBuf,
        /// Validate and print the start plan without binding sockets
        #[arg(long)]
        dry_run: bool,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
        /// Listen address for local browser proxy wiring
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Allow non-loopback proxy exposure
        #[arg(long)]
        allow_non_loopback: bool,
        /// CA certificate path, relative to engagement root unless absolute
        #[arg(long, default_value = DEFAULT_CA_RELATIVE_PATH)]
        ca_path: PathBuf,
    },
    /// List known proxy/browser sessions
    Sessions {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Tail proxy capture events
    Tail {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Export captured traffic corpus JSONL
    Export {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct StartOutput {
    dry_run: bool,
    launched: bool,
    listen_addr: String,
    ca_path: String,
}

#[derive(Debug, Serialize)]
struct EmptyListOutput {
    kind: &'static str,
    items: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ExportOutput {
    corpus_path: String,
    records: usize,
}

fn main() -> Result<()> {
    let output = run_from(std::env::args())?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

// Run the CLI from an argv iterator and return captured output for tests
fn run_from<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let args = Args::parse_from(args);
    run(args)
}

// Dispatch parsed CLI commands
fn run(args: Args) -> Result<String> {
    match args.command {
        Command::Start {
            engagement,
            dry_run,
            json,
            listen,
            allow_non_loopback,
            ca_path,
        } => start(
            &engagement,
            dry_run,
            json,
            listen,
            allow_non_loopback,
            &ca_path,
        ),
        Command::Sessions { engagement, json } => list_empty(&engagement, json, "sessions"),
        Command::Tail { engagement, json } => list_empty(&engagement, json, "events"),
        Command::Export { engagement, json } => export(&engagement, json),
    }
}

// Build a start plan without starting live network capture
fn start(
    engagement_root: &Path,
    dry_run: bool,
    json: bool,
    listen: SocketAddr,
    allow_non_loopback: bool,
    ca_path: &Path,
) -> Result<String> {
    let engagement = Engagement::load(engagement_root).context("load engagement")?;
    let config = ProxyConfig {
        listen_addr: listen,
        allow_non_loopback,
    };
    config.validate()?;
    if !dry_run {
        bail!("live proxy start is not implemented; use --dry-run for the scaffold");
    }

    let ca_path = if ca_path.is_absolute() {
        ca_path.to_path_buf()
    } else {
        engagement.root.join(ca_path)
    };
    let output = StartOutput {
        dry_run,
        launched: false,
        listen_addr: listen.to_string(),
        ca_path: ca_path.display().to_string(),
    };
    render(json, &output, || {
        format!(
            "dry-run proxy listen={} ca={}",
            output.listen_addr, output.ca_path
        )
    })
}

// Return empty scaffold lists until capture indexing exists
fn list_empty(engagement_root: &Path, json: bool, kind: &'static str) -> Result<String> {
    Engagement::load(engagement_root).context("load engagement")?;
    let output = EmptyListOutput {
        kind,
        items: Vec::new(),
    };
    render(json, &output, || format!("{kind}: 0"))
}

// Ensure the traffic corpus JSONL exists under the engagement root
fn export(engagement_root: &Path, json: bool) -> Result<String> {
    let engagement = Engagement::load(engagement_root).context("load engagement")?;
    let corpus_path = engagement.traffic_corpus_path();
    if let Some(parent) = corpus_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !corpus_path.exists() {
        std::fs::write(&corpus_path, b"")?;
    }
    let records = std::fs::read_to_string(&corpus_path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    let output = ExportOutput {
        corpus_path: corpus_path.display().to_string(),
        records,
    };
    render(json, &output, || {
        format!("exported {} records to {}", records, output.corpus_path)
    })
}

// Render either stable JSON or human text
fn render<T, F>(json: bool, value: &T, text: F) -> Result<String>
where
    T: Serialize,
    F: FnOnce() -> String,
{
    if json {
        Ok(serde_json::to_string_pretty(value)?)
    } else {
        Ok(text())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use engagement::{Engagement, EngagementMeta};

    fn test_engagement() -> Engagement {
        let tmp = tempfile::tempdir().unwrap().keep();
        Engagement::init(
            &tmp,
            EngagementMeta {
                name: "acme".into(),
                target: "example.com".into(),
                created_at: String::new(),
                platform: None,
                url: None,
                tags: Vec::new(),
            },
        )
        .unwrap()
    }

    #[test]
    fn help_includes_start_sessions_tail_and_export() {
        let mut help = Vec::new();
        Args::command().write_long_help(&mut help).unwrap();
        let help = String::from_utf8(help).unwrap();

        assert!(help.contains("start"));
        assert!(help.contains("sessions"));
        assert!(help.contains("tail"));
        assert!(help.contains("export"));
    }

    #[test]
    fn start_dry_run_json_reports_listen_address_and_ca_path() {
        let engagement = test_engagement();
        let output = run_from([
            "mg-proxy",
            "start",
            engagement.root.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();

        assert_eq!(json["dry_run"], true);
        assert_eq!(json["listen_addr"], "127.0.0.1:8080");
        assert!(
            json["ca_path"]
                .as_str()
                .unwrap()
                .starts_with(engagement.root.to_str().unwrap())
        );
    }

    #[test]
    fn export_writes_corpus_jsonl_under_engagement_root() {
        let engagement = test_engagement();
        let output = run_from([
            "mg-proxy",
            "export",
            engagement.root.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        let path = std::path::PathBuf::from(json["corpus_path"].as_str().unwrap());

        assert!(path.starts_with(&engagement.root));
        assert_eq!(path.file_name().unwrap(), "corpus.jsonl");
        assert!(path.exists());
    }
}
