/*******************************************************************
 * Filename:        report.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Write fuzz results to JSON and print a human-readable
 *                  summary table to stdout highlighting interesting responses
 * Notes:           Full results always written to fuzz-<timestamp>.json.
 *                  Interesting responses (status change, large body delta,
 *                  timing anomaly) are also printed to stderr for live feedback.
 *******************************************************************/

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::diff::{Diff, ResponseRecord};

// One recorded fuzz result
#[derive(Debug, Serialize, Deserialize)]
pub struct FuzzResult {
    pub label: String,
    pub payloads: Vec<String>,
    pub response: ResponseRecord,
    pub diff: Diff,
}

// Full fuzz run output written to disk
#[derive(Serialize, Deserialize)]
pub struct FuzzReport {
    pub engagement: String,
    pub template: String,
    pub attack_mode: String,
    pub generated_at: String,
    pub total_requests: usize,
    pub interesting_count: usize,
    pub results: Vec<FuzzResult>,
}

// Emit a single result line to stderr — called during the fuzzing loop for live feedback
pub fn print_result(result: &FuzzResult) {
    let d = &result.diff;
    let flag = if result.diff.interesting {
        "*** "
    } else {
        "    "
    };
    eprintln!(
        "{flag}{:>5} | {:>6} | {:>+7}B | {:>6}ms | {}",
        d.probe_status,
        if d.hash_match { "same" } else { "diff" },
        d.len_delta,
        result.response.elapsed_ms,
        result.label,
    );
}

// Print column headers once before the fuzzing loop begins
pub fn print_header() {
    eprintln!("  *** = interesting (status change / body delta > 50B / timing anomaly)");
    eprintln!(
        " {:>5} | {:>6} | {:>7} | {:>6} | label",
        "status", "body", "delta", "time"
    );
    eprintln!(" {}", "-".repeat(60));
}

// Write the complete fuzz report to JSON; file is named with the provided timestamp
pub fn write_report(report: &FuzzReport, out_dir: &Path) -> Result<()> {
    let filename = format!(
        "fuzz-{}.json",
        report.generated_at.replace(':', "-").replace(' ', "T")
    );
    let path = out_dir.join(filename);
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(&path, json)?;
    eprintln!("  written: {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::ResponseRecord;

    // Build a minimal FuzzResult for testing
    fn make_result(_interesting: bool) -> FuzzResult {
        let rec = ResponseRecord::new(200, "body".to_string(), 100, None, None);
        let base = ResponseRecord::new(200, "body".to_string(), 100, None, None);
        FuzzResult {
            label: "test".into(),
            payloads: vec!["payload".into()],
            response: rec.clone(),
            diff: crate::diff::diff(&base, &rec),
        }
    }

    #[test]
    fn write_creates_json_file() {
        let dir = tempfile::tempdir().unwrap();
        let report = FuzzReport {
            engagement: "test".into(),
            template: "tmpl.txt".into(),
            attack_mode: "sniper".into(),
            generated_at: "2026-05-09T00:00:00Z".into(),
            total_requests: 1,
            interesting_count: 0,
            results: vec![make_result(false)],
        };
        write_report(&report, dir.path()).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path().to_str().unwrap().contains("fuzz-"));
    }
}
