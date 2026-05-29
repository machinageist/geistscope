// Author: Jeff
// Date: 2026-05-29
// Description: CLI for writing immutable evidence bundles
// Notes: Wraps evidence-core without exposing secrets to model-visible output

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use evidence_core::{EvidenceBundleRequest, EvidenceBundleWriter};
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(
    name = "mg-evidence",
    about = "Write immutable GeistScope evidence bundles"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Write an immutable evidence run bundle
    Write {
        /// Engagement root directory
        engagement: PathBuf,
        /// Corpus candidate id
        #[arg(long)]
        candidate_id: String,
        /// Evidence run id
        #[arg(long)]
        run_id: String,
        /// Operator summary; redacted before writing
        #[arg(long, default_value = "")]
        summary: String,
        /// Replay plan JSON string
        #[arg(long, default_value = "{}")]
        plan_json: String,
        /// Approval metadata JSON string
        #[arg(long, default_value = "[]")]
        approvals_json: String,
        /// Semantic diff JSON string
        #[arg(long, default_value = "{}")]
        semantic_diff_json: String,
        /// Emit stable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug)]
struct WriteOptions {
    engagement: PathBuf,
    candidate_id: String,
    run_id: String,
    summary: String,
    plan_json: String,
    approvals_json: String,
    semantic_diff_json: String,
    json: bool,
}

#[derive(Debug, Serialize)]
struct WriteOutput {
    bundle_dir: String,
    manifest_path: String,
    artifact_count: usize,
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
        Command::Write {
            engagement,
            candidate_id,
            run_id,
            summary,
            plan_json,
            approvals_json,
            semantic_diff_json,
            json,
        } => write_bundle(WriteOptions {
            engagement,
            candidate_id,
            run_id,
            summary,
            plan_json,
            approvals_json,
            semantic_diff_json,
            json,
        }),
    }
}

// Write an immutable evidence bundle and emit only paths/counts
fn write_bundle(options: WriteOptions) -> Result<String> {
    let request =
        EvidenceBundleRequest::new(&options.engagement, options.candidate_id, options.run_id)
            .with_summary(options.summary)
            .with_plan_json(options.plan_json)
            .with_approvals_json(options.approvals_json)
            .with_semantic_diff_json(options.semantic_diff_json);
    let bundle = EvidenceBundleWriter.write(request)?;
    let output = WriteOutput {
        manifest_path: bundle
            .bundle_dir
            .join("manifest.json")
            .display()
            .to_string(),
        bundle_dir: bundle.bundle_dir.display().to_string(),
        artifact_count: bundle.artifacts.len(),
    };
    render(options.json, &output, || output.bundle_dir.clone())
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
    use serde_json::Value;

    #[test]
    fn write_json_emits_bundle_path_and_manifest_path() {
        let root = tempfile::tempdir().unwrap();
        let output = run_from([
            "mg-evidence",
            "write",
            root.path().to_str().unwrap(),
            "--candidate-id",
            "candidate-001",
            "--run-id",
            "run-abc",
            "--summary",
            "safe summary",
            "--json",
        ])
        .unwrap();
        let value: Value = serde_json::from_str(&output).unwrap();

        assert_eq!(
            value["bundle_dir"],
            root.path()
                .join("evidence/candidate-001/run-abc")
                .display()
                .to_string()
        );
        assert_eq!(
            value["manifest_path"],
            root.path()
                .join("evidence/candidate-001/run-abc/manifest.json")
                .display()
                .to_string()
        );
    }
}
