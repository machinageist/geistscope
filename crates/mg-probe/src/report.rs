/*******************************************************************
 * Filename:        report.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Serialize ProbeIssues to findings/ markdown files and
 *                  a machine-readable probe-report.json
 * Notes:           Each unique (host, title) pair becomes one finding file.
 *                  Multiple issues with the same title on the same host are
 *                  collapsed into one finding with concatenated evidence.
 *******************************************************************/

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use engagement::{Finding, Status};

use crate::checks::ProbeIssue;

// Machine-readable summary of one probe run
#[derive(Serialize, Deserialize)]
pub struct ProbeReport {
    pub engagement: String,
    pub generated_at: String,
    pub issue_count: usize,
    pub issues: Vec<ProbeIssue>,
}

// Write probe-report.json and one finding .md per unique issue to the engagement dirs
pub fn write_report(
    issues: &[ProbeIssue],
    findings_dir: &Path,
    recon_dir: &Path,
    engagement: &str,
) -> Result<()> {
    let ts = OffsetDateTime::now_utc().format(&Rfc3339)?;

    // serialize the full issue list to probe-report.json
    let report = ProbeReport {
        engagement: engagement.to_string(),
        generated_at: ts.clone(),
        issue_count: issues.len(),
        issues: issues.to_vec(),
    };
    let json = serde_json::to_string_pretty(&report)?;
    std::fs::write(recon_dir.join("probe-report.json"), json)?;

    // collapse issues into unique (host, title) pairs for finding files
    let mut grouped: HashMap<String, Vec<&ProbeIssue>> = HashMap::new();
    for issue in issues {
        let key = format!("{}-{}", issue.host, issue.title);
        grouped.entry(key).or_default().push(issue);
    }

    // sequence counter for finding IDs within this run
    let date_str = &ts[..10].replace('-', "");

    for (n, group) in grouped.values().enumerate() {
        let n = n + 1;
        let first = group[0];

        // collect all evidence lines from the group into the finding body
        let evidence_block = group.iter()
            .map(|i| format!("```\n{}\n```", i.evidence))
            .collect::<Vec<_>>()
            .join("\n\n");

        let body = format!(
            "## Summary\n\n{}\n\n## Steps to reproduce\n\n1. {}\n\n\
             ## Impact\n\n_{}_\n\n## Evidence\n\n{}\n\n## Remediation\n\n_see OWASP guidance_\n",
            first.detail,
            first.evidence.lines().next().unwrap_or(""),
            first.title,
            evidence_block,
        );

        let finding = Finding {
            id: format!("{date_str}-probe-{n:03}"),
            title: first.title.clone(),
            severity: first.severity_enum(),
            status: Status::Draft,
            target: first.host.clone(),
            created: ts.clone(),
            body,
        };

        // write markdown file, log path; non-fatal if one finding fails
        match finding.write_to(findings_dir) {
            Ok(p) => eprintln!("  [finding] {}", p.display()),
            Err(e) => eprintln!("  [finding err] {}: {e}", first.title),
        }

    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::ProbeIssue;

    // Build a minimal ProbeIssue for testing
    fn make_issue(check: &str, host: &str, sev: &str, title: &str) -> ProbeIssue {
        ProbeIssue {
            check:    check.into(),
            host:     host.into(),
            severity: sev.into(),
            title:    title.into(),
            detail:   "test detail".into(),
            evidence: "GET / → 200".into(),
        }
    }

    #[test]
    fn report_writes_json_and_finding() {
        let dir = tempfile::tempdir().unwrap();
        let findings = dir.path().join("findings");
        let recon = dir.path().join("recon");
        std::fs::create_dir_all(&findings).unwrap();
        std::fs::create_dir_all(&recon).unwrap();

        let issues = vec![make_issue("cors", "api.example.com", "high", "CORS misconfiguration")];
        write_report(&issues, &findings, &recon, "test-eng").unwrap();

        assert!(recon.join("probe-report.json").exists());
        // finding file must exist
        let entries: Vec<_> = std::fs::read_dir(&findings).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn duplicate_titles_collapsed_to_one_finding() {
        let dir = tempfile::tempdir().unwrap();
        let findings = dir.path().join("findings");
        let recon = dir.path().join("recon");
        std::fs::create_dir_all(&findings).unwrap();
        std::fs::create_dir_all(&recon).unwrap();

        let issues = vec![
            make_issue("cookies", "api.x.com", "medium", "Cookie 'session' missing HttpOnly"),
            make_issue("cookies", "api.x.com", "medium", "Cookie 'session' missing HttpOnly"),
        ];
        write_report(&issues, &findings, &recon, "test-eng").unwrap();

        let entries: Vec<_> = std::fs::read_dir(&findings).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
    }
}
