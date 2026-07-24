/*******************************************************************
 * Filename:        main.rs
 * Author:          Jeff
 * Date:            2026-05-18
 * Description:     mg-privesc-windows — Windows local privilege escalation enumeration
 * Notes:           Runs ON the target machine post-access. No engagement dep.
 *                  Command execution is cfg(target_os="windows")-gated.
 *                  On non-Windows hosts, prints a message and exits.
 *                  Parsing functions are platform-independent for testing.
 *******************************************************************/

#[cfg(target_os = "windows")]
use std::fs;
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use serde::Serialize;
#[cfg(target_os = "windows")]
use time::OffsetDateTime;
#[cfg(target_os = "windows")]
use time::format_description::well_known::Rfc3339;

// ── Constants ────────────────────────────────────────────────────────────────

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const DANGEROUS_PRIVS: &[&str] = &[
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeDebugPrivilege",
    "SeTcbPrivilege",
];

// ── CLI ──────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "mg-privesc-windows",
    about = "Windows local privilege escalation enumeration"
)]
struct Args {
    /// Output path for JSON results (default: ./privesc-windows-<ts>.json)
    #[arg(long)]
    output_dir: Option<String>,

    /// Run all checks including slow ones
    #[arg(long)]
    full: bool,
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
enum Severity {
    High,
    Medium,
    Info,
}

#[derive(Debug, Serialize)]
struct Finding {
    check: String,
    severity: Severity,
    detail: String,
}

#[derive(Debug, Serialize)]
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
struct Report {
    generated_at: String,
    findings: Vec<Finding>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("This tool must be run on a Windows target");
        std::process::exit(1);
    }

    #[cfg(target_os = "windows")]
    run_checks()
}

// Run all Windows privesc checks and write the report
#[cfg(target_os = "windows")]
fn run_checks() -> Result<()> {
    let args = Args::parse();

    let ts = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format timestamp")?;

    let safe_ts = &ts[..19].replace(':', "-");
    let out_path = match &args.output_dir {
        Some(p) => format!(
            "{}\\privesc-windows-{}.json",
            p.trim_end_matches('\\'),
            safe_ts
        ),
        None => format!(".\\privesc-windows-{}.json", safe_ts),
    };

    let mut findings: Vec<Finding> = Vec::new();

    findings.extend(check_token_privileges());
    findings.extend(check_unquoted_service_paths());
    findings.extend(check_writable_service_binaries());
    findings.extend(check_always_install_elevated());
    findings.extend(check_stored_credentials());
    findings.extend(check_autologon_credentials());
    findings.extend(check_scheduled_tasks());
    findings.extend(check_uac_config());

    for f in &findings {
        let sev = match f.severity {
            Severity::High => "HIGH",
            Severity::Medium => "MED ",
            Severity::Info => "INFO",
        };
        println!("[{}] {} — {}", sev, f.check, f.detail);
    }

    println!("\n{} finding(s)", findings.len());

    let report = Report {
        generated_at: ts,
        findings,
    };
    let json = serde_json::to_string_pretty(&report).context("serialize report")?;
    fs::write(&out_path, &json).with_context(|| format!("write {out_path}"))?;
    println!("Written: {out_path}");

    let _ = args.full;

    Ok(())
}

// ── Checks (Windows-only execution) ─────────────────────────────────────────

// Check current token privileges for dangerous entries
#[cfg(target_os = "windows")]
fn check_token_privileges() -> Vec<Finding> {
    let output = Command::new("whoami")
        .args(["/priv"])
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) => parse_token_privileges(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

// Check service paths for unquoted paths with spaces
#[cfg(target_os = "windows")]
fn check_unquoted_service_paths() -> Vec<Finding> {
    let output = Command::new("wmic")
        .args(["service", "get", "name,pathname,startmode"])
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) => parse_unquoted_service_paths(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

// Check service binary files for user-writability via icacls
#[cfg(target_os = "windows")]
fn check_writable_service_binaries() -> Vec<Finding> {
    let output = Command::new("wmic")
        .args(["service", "get", "pathname"])
        .stderr(std::process::Stdio::null())
        .output();

    let service_out = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let mut findings = Vec::new();
    let stdout = String::from_utf8_lossy(&service_out.stdout);

    for line in stdout.lines().skip(1) {
        let path = line.trim().trim_matches('"');
        if path.is_empty() || path.eq_ignore_ascii_case("PathName") {
            continue;
        }
        // Extract just the binary path (strip args after .exe)
        let bin_path = extract_exe_path(path);
        if bin_path.is_empty() {
            continue;
        }

        let icacls_out = Command::new("icacls")
            .arg(&bin_path)
            .stderr(std::process::Stdio::null())
            .output();

        if let Ok(ic) = icacls_out {
            let ic_str = String::from_utf8_lossy(&ic.stdout);
            // Flag if current user group has (W) or (F) write access
            if ic_str.contains("(W)") || ic_str.contains("(F)") {
                findings.push(Finding {
                    check: "WRITABLE_SERVICE_BINARY".into(),
                    severity: Severity::High,
                    detail: format!("writable service binary: {bin_path}"),
                });
            }
        }
    }

    findings
}

// Check AlwaysInstallElevated registry keys in HKLM and HKCU
#[cfg(target_os = "windows")]
fn check_always_install_elevated() -> Vec<Finding> {
    let hklm = reg_query_value(
        "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        "AlwaysInstallElevated",
    );
    let hkcu = reg_query_value(
        "HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
        "AlwaysInstallElevated",
    );

    parse_always_install_elevated(hklm.as_deref(), hkcu.as_deref())
}

// Check for stored credentials via cmdkey
#[cfg(target_os = "windows")]
fn check_stored_credentials() -> Vec<Finding> {
    let output = Command::new("cmdkey")
        .args(["/list"])
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) => parse_stored_credentials(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

// Check for autologon credentials in Winlogon registry key
#[cfg(target_os = "windows")]
fn check_autologon_credentials() -> Vec<Finding> {
    let username = reg_query_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "DefaultUserName",
    );
    let password = reg_query_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "DefaultPassword",
    );

    parse_autologon_credentials(username.as_deref(), password.as_deref())
}

// Check scheduled tasks for SYSTEM tasks with user-writable scripts
#[cfg(target_os = "windows")]
fn check_scheduled_tasks() -> Vec<Finding> {
    let output = Command::new("schtasks")
        .args(["/query", "/fo", "CSV", "/v"])
        .stderr(std::process::Stdio::null())
        .output();

    match output {
        Ok(o) => parse_scheduled_tasks(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => Vec::new(),
    }
}

// Check UAC configuration via registry
#[cfg(target_os = "windows")]
fn check_uac_config() -> Vec<Finding> {
    let value = reg_query_value(
        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
        "EnableLUA",
    );
    parse_uac_config(value.as_deref())
}

// Query a registry value via `reg query`, return the data string or None
#[cfg(target_os = "windows")]
fn reg_query_value(key: &str, value: &str) -> Option<String> {
    let output = Command::new("reg")
        .args(["query", key, "/v", value])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "    ValueName    REG_DWORD    0x1"
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(value) {
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            if let Some(data) = parts.last() {
                return Some(data.trim().to_string());
            }
        }
    }
    None
}

// Extract the .exe path from a service pathname string that may have arguments
#[cfg(target_os = "windows")]
fn extract_exe_path(path: &str) -> String {
    let lower = path.to_lowercase();
    if let Some(pos) = lower.find(".exe") {
        path[..pos + 4].trim_matches('"').to_string()
    } else {
        String::new()
    }
}

// ── Parsers (platform-independent, tested on macOS) ─────────────────────────

// Parse whoami /priv output for dangerous privilege entries
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_token_privileges(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        for priv_name in DANGEROUS_PRIVS {
            if line.contains(priv_name) && line.to_lowercase().contains("enabled") {
                findings.push(Finding {
                    check: "DANGEROUS_TOKEN_PRIVILEGE".into(),
                    severity: Severity::High,
                    detail: format!("dangerous privilege enabled: {priv_name}"),
                });
                break;
            }
        }
    }

    findings
}

// Parse wmic service output for unquoted paths containing spaces
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_unquoted_service_paths(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines().skip(1) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Columns: Name  PathName  StartMode — split on 2+ spaces
        let parts: Vec<&str> = trimmed.splitn(3, "  ").map(|s| s.trim()).collect();
        if parts.len() < 2 {
            continue;
        }
        let path = parts[1];
        // Unquoted path: not wrapped in quotes AND contains a space before .exe
        if !path.starts_with('"') && path.contains(' ') && path.to_lowercase().contains(".exe") {
            findings.push(Finding {
                check: "UNQUOTED_SERVICE_PATH".into(),
                severity: Severity::High,
                detail: format!("unquoted service path with spaces: {path}"),
            });
        }
    }

    findings
}

// Parse AlwaysInstallElevated registry values — both keys must be 0x1 for the vuln
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_always_install_elevated(hklm: Option<&str>, hkcu: Option<&str>) -> Vec<Finding> {
    let hklm_set = hklm.map(|v| v == "0x1").unwrap_or(false);
    let hkcu_set = hkcu.map(|v| v == "0x1").unwrap_or(false);

    if hklm_set && hkcu_set {
        vec![Finding {
            check: "ALWAYS_INSTALL_ELEVATED".into(),
            severity: Severity::High,
            detail: "AlwaysInstallElevated is enabled in both HKLM and HKCU — MSI packages install as SYSTEM".into(),
        }]
    } else {
        Vec::new()
    }
}

// Parse cmdkey /list output for stored credential entries
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_stored_credentials(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut in_entry = false;

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Target:") {
            in_entry = true;
            findings.push(Finding {
                check: "STORED_CREDENTIAL".into(),
                severity: Severity::High,
                detail: format!("stored credential: {trimmed}"),
            });
        } else if trimmed.is_empty() {
            in_entry = false;
        }
        let _ = in_entry;
    }

    findings
}

// Parse Winlogon registry values for cleartext autologon credentials
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_autologon_credentials(username: Option<&str>, password: Option<&str>) -> Vec<Finding> {
    if let (Some(user), Some(pass)) = (username, password)
        && !user.is_empty()
        && !pass.is_empty()
    {
        return vec![Finding {
            check: "AUTOLOGON_CREDENTIALS".into(),
            severity: Severity::High,
            detail: format!("autologon credentials found — user: {user}"),
        }];
    }
    Vec::new()
}

// Parse schtasks CSV output for SYSTEM tasks with potentially writable scripts
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_scheduled_tasks(stdout: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for line in stdout.lines().skip(1) {
        let lower = line.to_lowercase();
        // Flag tasks running as SYSTEM that reference a script file
        if lower.contains("system")
            && (lower.contains(".bat") || lower.contains(".ps1") || lower.contains(".vbs"))
        {
            findings.push(Finding {
                check: "SCHEDULED_TASK_SYSTEM".into(),
                severity: Severity::Medium,
                detail: format!("scheduled task runs as SYSTEM with script: {}", line.trim()),
            });
        }
    }

    findings
}

// Parse EnableLUA registry value — 0x0 means UAC is disabled
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_uac_config(value: Option<&str>) -> Vec<Finding> {
    if value == Some("0x0") {
        vec![Finding {
            check: "UAC_DISABLED".into(),
            severity: Severity::High,
            detail: "UAC is disabled (EnableLUA=0) — elevation prompts bypassed".into(),
        }]
    } else {
        Vec::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_privs_dangerous_enabled_flagged() {
        let output = "SeImpersonatePrivilege   Impersonate a client after authentication   Enabled\n\
                      SeShutdownPrivilege      Shut down the system                       Disabled\n";
        let findings = parse_token_privileges(output);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("SeImpersonatePrivilege"));
    }

    #[test]
    fn token_privs_disabled_not_flagged() {
        let output = "SeDebugPrivilege   Debug programs   Disabled\n";
        let findings = parse_token_privileges(output);
        assert!(findings.is_empty());
    }

    #[test]
    fn unquoted_path_with_spaces_flagged() {
        let output = "Name       PathName                               StartMode\n\
                      MyService  C:\\Program Files\\My App\\service.exe    Auto\n";
        let findings = parse_unquoted_service_paths(output);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].detail.contains("C:\\Program Files"));
    }

    #[test]
    fn quoted_path_with_spaces_not_flagged() {
        let output = "Name       PathName                                 StartMode\n\
                      MySvc      \"C:\\Program Files\\Safe\\service.exe\"    Auto\n";
        let findings = parse_unquoted_service_paths(output);
        assert!(findings.is_empty());
    }

    #[test]
    fn always_install_elevated_both_set_flagged() {
        let findings = parse_always_install_elevated(Some("0x1"), Some("0x1"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn always_install_elevated_only_hklm_not_flagged() {
        let findings = parse_always_install_elevated(Some("0x1"), None);
        assert!(findings.is_empty());
    }

    #[test]
    fn stored_credentials_flagged() {
        let output = "    Target: MicrosoftOffice16_Data:target=jeff\n    Type: Generic\n";
        let findings = parse_stored_credentials(output);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn autologon_user_and_pass_flagged() {
        let findings = parse_autologon_credentials(Some("Administrator"), Some("P@ssw0rd"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn autologon_empty_password_not_flagged() {
        let findings = parse_autologon_credentials(Some("Administrator"), Some(""));
        assert!(findings.is_empty());
    }

    #[test]
    fn uac_disabled_flagged() {
        let findings = parse_uac_config(Some("0x0"));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn uac_enabled_not_flagged() {
        let findings = parse_uac_config(Some("0x1"));
        assert!(findings.is_empty());
    }

    #[test]
    fn scheduled_task_system_bat_flagged() {
        let output = "TaskName,Status,Run As User,Task To Run\n\
                      \\BackupTask,Ready,SYSTEM,C:\\scripts\\backup.bat\n";
        let findings = parse_scheduled_tasks(output);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn scheduled_task_user_not_flagged() {
        let output = "TaskName,Status,Run As User,Task To Run\n\
                      \\UpdateTask,Ready,jeff,C:\\tools\\update.exe\n";
        let findings = parse_scheduled_tasks(output);
        assert!(findings.is_empty());
    }
}
