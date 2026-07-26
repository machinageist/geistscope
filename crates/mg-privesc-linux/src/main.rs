/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-privesc-linux — Linux local privilege escalation enumeration
 * Notes:           Runs ON the target machine. All checks are local — no network.
 *                  No engagement dep; writes to a local output path only.
 *******************************************************************/

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

// ── Constants ────────────────────────────────────────────────────────────────

const SUID_WHITELIST: &[&str] = &[
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/newgrp",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/bin/su",
    "/bin/mount",
    "/bin/umount",
];

const CRON_FILES: &[&str] = &["/etc/crontab"];

const CRON_DIRS: &[&str] = &["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"];

const DANGEROUS_CAPS: &[&str] = &["cap_setuid", "cap_net_admin", "cap_dac_override"];

const INTERESTING_FILES: &[(&str, &str)] = &[
    (".ssh/id_rsa", "readable private SSH key"),
    (".aws/credentials", "readable AWS credentials"),
    (".docker/config.json", "readable Docker config"),
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-privesc-linux",
    about = "Linux local privilege escalation enumeration"
)]
struct Args {
    /// Output path for JSON results (default: ./privesc-linux-<ts>.json)
    #[arg(long)]
    output_dir: Option<String>,

    /// Run all checks including slow ones
    #[arg(long)]
    full: bool,
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Severity {
    High,
    Medium,
    #[allow(dead_code)] // reserved for future informational checks
    Info,
}

#[derive(Debug, Serialize)]
struct Finding {
    check: String,
    severity: Severity,
    detail: String,
}

#[derive(Debug, Serialize)]
struct Report {
    generated_at: String,
    findings: Vec<Finding>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    let args = Args::parse();

    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let out_path = match &args.output_dir {
        Some(p) => format!(
            "{}/privesc-linux-{}.json",
            p.trim_end_matches('/'),
            ts[..19].replace(':', "-")
        ),
        None => format!("./privesc-linux-{}.json", ts[..19].replace(':', "-")),
    };

    let mut findings: Vec<Finding> = Vec::new();

    // Run SUID/SGID binary check
    findings.extend(check_suid());

    // Run writable PATH entries check
    findings.extend(check_writable_path());

    // Run sudo rules check
    findings.extend(check_sudo());

    // Run world-writable cron files check
    findings.extend(check_cron());

    // Run Linux capabilities check
    findings.extend(check_capabilities());

    // Run kernel version check
    findings.extend(check_kernel());

    // Run docker group membership check
    findings.extend(check_docker_group());

    // Run writable sensitive file check
    findings.extend(check_writable_sensitive_files());

    // Run NFS no_root_squash check
    findings.extend(check_nfs_exports());

    // Run interesting file check
    findings.extend(check_interesting_files());

    // Print all findings to stdout
    for f in &findings {
        let sev = match f.severity {
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Info => "INFO",
        };
        println!("[{}] {} — {}", sev, f.check, f.detail);
    }

    println!("\n{} finding(s)", findings.len());

    // Write JSON report to output path
    let report = Report {
        generated_at: ts,
        findings,
    };
    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    fs::write(&out_path, &json).with_context(|| format!("write {out_path}"))?;
    println!("Written: {out_path}");

    let _ = args.full; // reserved for future slow checks

    Ok(())
}

// ── Checks ───────────────────────────────────────────────────────────────────

// Check for SUID/SGID binaries not in the known-safe whitelist
fn check_suid() -> Vec<Finding> {
    let output = Command::new("find")
        .args(["/", "-perm", "-4000", "-o", "-perm", "-2000"])
        .stderr(std::process::Stdio::null())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let path = line.trim();
        if path.is_empty() {
            continue;
        }
        if !SUID_WHITELIST.contains(&path) {
            findings.push(Finding {
                check: "SUID_SGID_BINARY".into(),
                severity: Severity::High,
                detail: format!("non-whitelisted SUID/SGID binary: {path}"),
            });
        }
    }

    findings
}

// Check each directory in $PATH for world-writability
fn check_writable_path() -> Vec<Finding> {
    let path_env = match std::env::var("PATH") {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    for dir in path_env.split(':') {
        if dir.is_empty() {
            continue;
        }
        if let Ok(meta) = fs::metadata(dir) {
            // World-writable bit is 0o002
            if meta.permissions().mode() & 0o002 != 0 {
                findings.push(Finding {
                    check: "WRITABLE_PATH_DIR".into(),
                    severity: Severity::High,
                    detail: format!("world-writable directory in PATH: {dir}"),
                });
            }
        }
    }

    findings
}

// Check sudo rules for NOPASSWD and (ALL) entries
fn check_sudo() -> Vec<Finding> {
    let output = Command::new("sudo")
        .args(["-l"])
        .stderr(std::process::Stdio::null())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_sudo_output(&stdout)
}

// Parse sudo -l output for dangerous privilege entries
fn parse_sudo_output(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("NOPASSWD") {
            findings.push(Finding {
                check: "SUDO_NOPASSWD".into(),
                severity: Severity::High,
                detail: format!("NOPASSWD sudo rule: {trimmed}"),
            });
        } else if trimmed.contains("(ALL)") {
            findings.push(Finding {
                check: "SUDO_ALL".into(),
                severity: Severity::Medium,
                detail: format!("sudo (ALL) rule: {trimmed}"),
            });
        }
    }

    findings
}

// Check cron files and directories for world-writable permissions
fn check_cron() -> Vec<Finding> {
    let mut findings = Vec::new();

    // Check individual cron files
    for path in CRON_FILES {
        if let Ok(meta) = fs::metadata(path)
            && meta.permissions().mode() & 0o002 != 0
        {
            findings.push(Finding {
                check: "WRITABLE_CRON_FILE".into(),
                severity: Severity::High,
                detail: format!("world-writable cron file: {path}"),
            });
        }
    }

    // Check files inside cron directories
    for dir in CRON_DIRS {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(meta) = fs::metadata(&p)
                && meta.permissions().mode() & 0o002 != 0
            {
                findings.push(Finding {
                    check: "WRITABLE_CRON_FILE".into(),
                    severity: Severity::High,
                    detail: format!("world-writable cron file: {}", p.display()),
                });
            }
        }
    }

    findings
}

// Check for dangerous Linux capability assignments
fn check_capabilities() -> Vec<Finding> {
    let output = Command::new("getcap")
        .args(["-r", "/"])
        .stderr(std::process::Stdio::null())
        .output();

    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_capabilities_output(&stdout)
}

// Parse getcap -r output for dangerous capability flags
fn parse_capabilities_output(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let lower = line.to_lowercase();
        for cap in DANGEROUS_CAPS {
            if lower.contains(cap) {
                findings.push(Finding {
                    check: "DANGEROUS_CAPABILITY".into(),
                    severity: Severity::High,
                    detail: format!("dangerous capability ({cap}): {}", line.trim()),
                });
                break;
            }
        }
    }

    findings
}

// Check kernel version and flag if older than 5.x
fn check_kernel() -> Vec<Finding> {
    let proc_version = match fs::read_to_string("/proc/version") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    parse_kernel_version(&proc_version)
}

// Parse /proc/version content and flag kernels older than 5.x
fn parse_kernel_version(proc_version: &str) -> Vec<Finding> {
    // Format: "Linux version X.Y.Z-..."
    let version_str = proc_version
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .to_string();

    let major: u32 = version_str
        .split('.')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(99);

    if major < 5 {
        vec![Finding {
            check: "OLD_KERNEL".into(),
            severity: Severity::Medium,
            detail: format!(
                "kernel version {version_str} is older than 5.x — may have known exploits"
            ),
        }]
    } else {
        Vec::new()
    }
}

// Check if the current user is a member of the docker group
fn check_docker_group() -> Vec<Finding> {
    let groups_content = match fs::read_to_string("/etc/group") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let current_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();

    if current_user.is_empty() {
        return Vec::new();
    }

    parse_docker_group(&groups_content, &current_user)
}

// Parse /etc/group content to check if user is in the docker group
fn parse_docker_group(groups_content: &str, username: &str) -> Vec<Finding> {
    for line in groups_content.lines() {
        // Format: groupname:x:gid:member1,member2,...
        let parts: Vec<&str> = line.splitn(4, ':').collect();
        if parts.len() < 4 {
            continue;
        }
        if parts[0] == "docker" {
            let members: Vec<&str> = parts[3].split(',').collect();
            if members.iter().any(|m| m.trim() == username) {
                return vec![Finding {
                    check: "DOCKER_GROUP_MEMBERSHIP".into(),
                    severity: Severity::High,
                    detail: format!(
                        "user '{username}' is in the docker group — trivial root escape via `docker run`"
                    ),
                }];
            }
        }
    }
    Vec::new()
}

// Check write permission on /etc/passwd and /etc/shadow
fn check_writable_sensitive_files() -> Vec<Finding> {
    let mut findings = Vec::new();

    for path in &["/etc/passwd", "/etc/shadow"] {
        if let Ok(meta) = fs::metadata(path) {
            // Check world-writable bit
            if meta.permissions().mode() & 0o002 != 0 {
                findings.push(Finding {
                    check: "WRITABLE_SENSITIVE_FILE".into(),
                    severity: Severity::High,
                    detail: format!("world-writable sensitive file: {path}"),
                });
            }
        }
    }

    findings
}

// Check /etc/exports for NFS shares with no_root_squash
fn check_nfs_exports() -> Vec<Finding> {
    let content = match fs::read_to_string("/etc/exports") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    parse_nfs_exports(&content)
}

// Parse /etc/exports content for no_root_squash entries
fn parse_nfs_exports(content: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed.contains("no_root_squash") {
            findings.push(Finding {
                check: "NFS_NO_ROOT_SQUASH".into(),
                severity: Severity::High,
                detail: format!("NFS export with no_root_squash: {trimmed}"),
            });
        }
    }

    findings
}

// Check for readable high-value credential and key files under the home directory
fn check_interesting_files() -> Vec<Finding> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();

    for (rel_path, desc) in INTERESTING_FILES {
        let full_path = format!("{home}/{rel_path}");
        let p = Path::new(&full_path);
        if !p.exists() {
            continue;
        }
        // Try to open for reading to confirm access
        if let Ok(mut f) = fs::File::open(p) {
            let mut buf = [0u8; 1];
            if f.read(&mut buf).is_ok() {
                findings.push(Finding {
                    check: "INTERESTING_FILE".into(),
                    severity: Severity::High,
                    detail: format!("{desc}: {full_path}"),
                });
            }
        }
    }

    findings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_nopasswd_flagged_as_high() {
        // First line has NOPASSWD → HIGH; second has (ALL) only → MEDIUM
        let output = "    (ALL) NOPASSWD: /bin/bash\n    (ALL) /usr/bin/vim\n";
        let findings = parse_sudo_output(output);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[1].severity, Severity::Medium);
    }

    #[test]
    fn sudo_clean_output_no_findings() {
        let findings = parse_sudo_output("User jeff may not run sudo on this host.\n");
        assert!(findings.is_empty());
    }

    #[test]
    fn capabilities_dangerous_flagged() {
        let output = "/usr/bin/python3 = cap_setuid+ep\n/usr/bin/ping = cap_net_raw+ep\n";
        let findings = parse_capabilities_output(output);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("cap_setuid"));
    }

    #[test]
    fn capabilities_cap_net_admin_flagged() {
        let output = "/usr/sbin/tcpdump = cap_net_admin+ep\n";
        let findings = parse_capabilities_output(output);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn kernel_old_version_flagged() {
        let proc_version = "Linux version 4.15.0-123-generic (buildd@...) ...";
        let findings = parse_kernel_version(proc_version);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn kernel_new_version_clean() {
        let proc_version = "Linux version 6.5.0-35-generic (buildd@...) ...";
        let findings = parse_kernel_version(proc_version);
        assert!(findings.is_empty());
    }

    #[test]
    fn docker_group_member_flagged() {
        let groups = "docker:x:999:jeff,alice\nroot:x:0:\n";
        let findings = parse_docker_group(groups, "jeff");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn docker_group_nonmember_clean() {
        let groups = "docker:x:999:alice\nroot:x:0:\n";
        let findings = parse_docker_group(groups, "jeff");
        assert!(findings.is_empty());
    }

    #[test]
    fn nfs_no_root_squash_flagged() {
        let exports = "# NFS exports\n/data *(rw,no_root_squash)\n/backup *(ro,root_squash)\n";
        let findings = parse_nfs_exports(exports);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("no_root_squash"));
    }

    #[test]
    fn nfs_clean_exports_no_findings() {
        let exports = "/data *(ro,root_squash)\n";
        let findings = parse_nfs_exports(exports);
        assert!(findings.is_empty());
    }
}
