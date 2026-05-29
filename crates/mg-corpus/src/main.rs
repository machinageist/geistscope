// Author: Jeff
// Date: 2026-05-29
// Description: CLI for building and querying inert request-corpus candidates
// Notes: Emits stable JSON metadata only; no replay, request execution, or browser automation

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use engagement::{Engagement, load_traffic_records};
use request_corpus::{CandidateBuilder, CandidateStateChange, CorpusCandidate};
use serde::Serialize;

const CANDIDATES_RELATIVE_PATH: &str = "corpus/candidates.jsonl";

#[derive(Debug, Parser)]
#[command(
    name = "mg-corpus",
    about = "Build and query inert GeistScope corpus candidates"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build candidates from the captured traffic corpus
    Build {
        /// Engagement root directory
        engagement: PathBuf,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
    /// Query previously built candidates
    Candidates {
        /// Engagement root directory
        engagement: PathBuf,
        /// Filter by candidate risk class
        #[arg(long, value_enum)]
        risk_class: Option<RiskClassFilter>,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
enum RiskClassFilter {
    ReadOnly,
    StateChanging,
    BrowserObservationOnly,
}

#[derive(Debug, Serialize)]
struct BuildOutput {
    candidates_path: String,
    candidate_count: usize,
}

#[derive(Debug, Serialize)]
struct CandidatesOutput {
    candidates_path: String,
    candidate_count: usize,
    candidates: Vec<CorpusCandidate>,
}

fn main() -> Result<()> {
    let output = run_from(std::env::args())?;
    if !output.is_empty() {
        println!("{output}");
    }
    Ok(())
}

// Run CLI from argv and return output for tests
fn run_from<I, S>(args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: Into<std::ffi::OsString> + Clone,
{
    let args = Args::parse_from(args);
    run(args)
}

// Dispatch parsed commands
fn run(args: Args) -> Result<String> {
    match args.command {
        Command::Build { engagement, json } => build(&engagement, json),
        Command::Candidates {
            engagement,
            risk_class,
            json,
        } => candidates(&engagement, risk_class, json),
    }
}

// Build inert candidates from stored traffic records
fn build(engagement_root: &Path, json: bool) -> Result<String> {
    let engagement = Engagement::load(engagement_root).context("load engagement")?;
    let records = load_traffic_records(&engagement).context("load traffic corpus")?;
    let candidates = CandidateBuilder::default().from_traffic_records(&records);
    let candidates_path = candidates_path(&engagement.root);
    write_candidates(&candidates_path, &candidates).context("write candidates")?;
    let output = BuildOutput {
        candidates_path: candidates_path.display().to_string(),
        candidate_count: candidates.len(),
    };
    render(json, &output, || {
        format!(
            "built {} candidates at {}",
            output.candidate_count, output.candidates_path
        )
    })
}

// List candidates with an optional risk-class filter
fn candidates(
    engagement_root: &Path,
    risk_class: Option<RiskClassFilter>,
    json: bool,
) -> Result<String> {
    let engagement = Engagement::load(engagement_root).context("load engagement")?;
    let candidates_path = candidates_path(&engagement.root);
    let mut candidates = load_candidates(&candidates_path).context("load candidates")?;
    if let Some(filter) = risk_class {
        candidates.retain(|candidate| risk_filter_matches(candidate, filter));
    }
    let output = CandidatesOutput {
        candidates_path: candidates_path.display().to_string(),
        candidate_count: candidates.len(),
        candidates,
    };
    render(json, &output, || {
        format!(
            "{} candidates from {}",
            output.candidate_count, output.candidates_path
        )
    })
}

// Resolve candidate output under the engagement root
fn candidates_path(engagement_root: &Path) -> PathBuf {
    engagement_root.join(CANDIDATES_RELATIVE_PATH)
}

// Write candidates as stable JSONL metadata
fn write_candidates(path: &Path, candidates: &[CorpusCandidate]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut body = String::new();
    for candidate in candidates {
        body.push_str(&serde_json::to_string(candidate)?);
        body.push('\n');
    }
    std::fs::write(path, body)?;
    Ok(())
}

// Load candidates from stable JSONL metadata
fn load_candidates(path: &Path) -> Result<Vec<CorpusCandidate>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)?;
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("parse candidate"))
        .collect()
}

// Match candidate state-change class to CLI filter
fn risk_filter_matches(candidate: &CorpusCandidate, filter: RiskClassFilter) -> bool {
    matches!(
        (candidate.state_change, filter),
        (CandidateStateChange::ReadOnly, RiskClassFilter::ReadOnly)
            | (
                CandidateStateChange::StateChanging,
                RiskClassFilter::StateChanging
            )
            | (
                CandidateStateChange::BrowserObservationOnly,
                RiskClassFilter::BrowserObservationOnly
            )
    )
}

// Render stable JSON or terse operator text
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
    use engagement::{AuthState, EngagementMeta, TrafficRecord, TrafficRiskClass};
    use serde_json::Value;

    #[test]
    fn build_json_emits_candidate_count() {
        let engagement = test_engagement();
        write_traffic_records(&engagement, comparable_read_records());

        let output = run_from([
            "mg-corpus",
            "build",
            engagement.root.to_str().unwrap(),
            "--json",
        ])
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(value["candidate_count"], 1);
        assert_eq!(
            value["candidates_path"],
            engagement
                .root
                .join("corpus/candidates.jsonl")
                .display()
                .to_string()
        );
    }

    #[test]
    fn candidates_risk_class_read_only_filters_stable_json() {
        let engagement = test_engagement();
        write_traffic_records(&engagement, mixed_records());
        run_from([
            "mg-corpus",
            "build",
            engagement.root.to_str().unwrap(),
            "--json",
        ])
        .unwrap();

        let output = run_from([
            "mg-corpus",
            "candidates",
            engagement.root.to_str().unwrap(),
            "--risk-class",
            "read_only",
            "--json",
        ])
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();
        let items = value["candidates"].as_array().unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["kind"], "cross_tenant_read");
        assert_eq!(items[0]["state_change"], "read_only");
        assert_eq!(items[0]["autonomous_safe"], true);
    }

    fn test_engagement() -> Engagement {
        let root = tempfile::tempdir().unwrap().keep();
        Engagement::init(
            &root,
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

    fn write_traffic_records(engagement: &Engagement, records: Vec<TrafficRecord>) {
        let path = engagement.traffic_corpus_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let body = records
            .iter()
            .map(|record| serde_json::to_string(record).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(path, format!("{body}\n")).unwrap();
    }

    fn comparable_read_records() -> Vec<TrafficRecord> {
        vec![
            traffic_record(
                "alice-read",
                "GET",
                "https://app.example.test/api/projects/123",
                Some("alice"),
                Some("tenant-a"),
            ),
            traffic_record(
                "bob-read",
                "GET",
                "https://app.example.test/api/projects/123",
                Some("bob"),
                Some("tenant-b"),
            ),
        ]
    }

    fn mixed_records() -> Vec<TrafficRecord> {
        let mut records = comparable_read_records();
        records.push(traffic_record(
            "create-product",
            "POST",
            "https://app.example.test/api/products",
            Some("alice"),
            Some("tenant-a"),
        ));
        records
    }

    fn traffic_record(
        id: &str,
        method: &str,
        url: &str,
        identity_id: Option<&str>,
        tenant_id: Option<&str>,
    ) -> TrafficRecord {
        let parsed = url::Url::parse(url).unwrap();
        TrafficRecord {
            id: id.into(),
            source: "test".into(),
            source_file: None,
            captured_at: "2026-05-29T00:00:00Z".into(),
            imported_at: "2026-05-29T00:00:00Z".into(),
            method: method.into(),
            url: url.into(),
            host: parsed.host_str().unwrap().into(),
            path: parsed.path().into(),
            scheme: parsed.scheme().into(),
            port: parsed.port(),
            query: parsed.query().map(str::to_owned),
            session_id: identity_id.map(|id| format!("session-{id}")),
            identity_id: identity_id.map(str::to_owned),
            role_id: None,
            tenant_id: tenant_id.map(str::to_owned),
            operation: None,
            scope_decision: Some("in_scope".into()),
            risk_class: TrafficRiskClass::Authorization,
            tags: Vec::new(),
            request_sha256: String::new(),
            response_sha256: String::new(),
            params: Vec::new(),
            request_headers: Vec::new(),
            request_body: None,
            response: None,
            auth_state: AuthState::Authenticated,
        }
    }
}
