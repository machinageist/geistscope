/*******************************************************************
 * Filename:        scope.rs
 * Author:          Jeff
 * Date:            2026-05-02
 * Description:     Scope rules for an engagement — wildcard match, default-deny
 * Notes:           out_of_scope wins over in_scope.
 *                  Wildcard pattern *.foo.com matches subdomains but not the apex.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use std::path::Path;
use url::Url;

use crate::EngagementError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub target: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeVerdict {
    InScope,
    OutOfScope,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeRuleMatch {
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeDecision {
    pub input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_url: Option<String>,
    pub decision: ScopeVerdict,
    #[serde(default)]
    pub matched_allow: Vec<ScopeRuleMatch>,
    #[serde(default)]
    pub matched_deny: Vec<ScopeRuleMatch>,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounty_eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_eligible: Option<bool>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Scope {
    // Build a default scope allowing the apex domain and all subdomains
    pub fn default_for(target: &str) -> Self {
        Self {
            target: target.to_string(),
            in_scope: vec![target.to_string(), format!("*.{target}")],
            out_of_scope: Vec::new(),
            notes: None,
        }
    }

    // Return true if target is in-scope; out_of_scope list takes priority
    pub fn is_in_scope(&self, target: &str) -> bool {
        matches!(self.explain(target).decision, ScopeVerdict::InScope)
    }

    // Explain how a target matched the engagement scope
    pub fn explain(&self, target: &str) -> ScopeDecision {
        let input = target.to_string();
        let normalized = normalize_target(target);
        let (normalized_host, normalized_url) = match normalized {
            Ok(values) => values,
            Err(reason) => {
                return ScopeDecision {
                    input,
                    normalized_host: None,
                    normalized_url: None,
                    decision: ScopeVerdict::Ambiguous,
                    matched_allow: Vec::new(),
                    matched_deny: Vec::new(),
                    reason,
                    asset_type: None,
                    bounty_eligible: None,
                    submission_eligible: None,
                    notes: Vec::new(),
                };
            }
        };

        let host = normalized_host.as_deref().unwrap_or_default();
        let matched_deny = matching_rules(&self.out_of_scope, host);
        let matched_allow = matching_rules(&self.in_scope, host);
        let (decision, reason) = if !matched_deny.is_empty() {
            (ScopeVerdict::OutOfScope, "explicit deny rule matched")
        } else if !matched_allow.is_empty() {
            (ScopeVerdict::InScope, "allow rule matched")
        } else {
            (ScopeVerdict::OutOfScope, "no allow rule matched")
        };

        ScopeDecision {
            input,
            normalized_host,
            normalized_url,
            decision,
            matched_allow,
            matched_deny,
            reason: reason.into(),
            asset_type: None,
            bounty_eligible: None,
            submission_eligible: None,
            notes: Vec::new(),
        }
    }

    // Deserialize scope rules from a JSON file
    pub fn load(path: &Path) -> Result<Self, EngagementError> {
        let raw = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&raw)?)
    }

    // Serialize scope rules to a pretty-printed JSON file
    pub fn save(&self, path: &Path) -> Result<(), EngagementError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

// Match rules against a normalized host
fn matching_rules(patterns: &[String], host: &str) -> Vec<ScopeRuleMatch> {
    patterns
        .iter()
        .filter(|pattern| matches_pattern(pattern, host))
        .map(|pattern| ScopeRuleMatch {
            pattern: pattern.clone(),
        })
        .collect()
}

// Normalize a URL or host into a lower-case host plus optional normalized URL
fn normalize_target(target: &str) -> Result<(Option<String>, Option<String>), String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("target is empty".into());
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(format!("target contains whitespace: {target}"));
    }

    if let Ok(url) = Url::parse(trimmed) {
        let host = url
            .host_str()
            .map(normalize_host)
            .filter(|host| !host.is_empty())
            .ok_or_else(|| "URL does not contain a host".to_string())?;
        return Ok((Some(host), Some(url.to_string())));
    }

    let without_scheme = trimmed.strip_prefix("//").unwrap_or(trimmed);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let host = authority
        .rsplit_once('@')
        .map(|(_, host)| host)
        .unwrap_or(authority);
    let host = if host.starts_with('[') {
        host.trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or(host)
    } else {
        host.split_once(':').map(|(host, _)| host).unwrap_or(host)
    };
    let host = normalize_host(host);
    if host.is_empty() {
        return Err("target host is empty".into());
    }
    Ok((Some(host), None))
}

// Normalize host casing and trailing dot
fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_lowercase()
}

// Match a single pattern against a target name.
// `*.foo.com` matches `bar.foo.com` and `a.b.foo.com` but NOT `foo.com` itself
// or `evilfoo.com`. Bare `foo.com` matches only itself.
fn matches_pattern(pattern: &str, target: &str) -> bool {
    let pattern = normalize_host(pattern);
    if let Some(suffix) = pattern.strip_prefix("*.") {
        target.ends_with(&format!(".{suffix}"))
    } else {
        pattern == target
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope_with(in_scope: &[&str], out: &[&str]) -> Scope {
        Scope {
            target: "example.com".into(),
            in_scope: in_scope.iter().map(|s| s.to_string()).collect(),
            out_of_scope: out.iter().map(|s| s.to_string()).collect(),
            notes: None,
        }
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_apex() {
        let s = scope_with(&["*.example.com"], &[]);
        assert!(s.is_in_scope("api.example.com"));
        assert!(s.is_in_scope("a.b.example.com"));
        assert!(!s.is_in_scope("example.com"));
    }

    #[test]
    fn wildcard_does_not_match_lookalike() {
        let s = scope_with(&["*.example.com"], &[]);
        assert!(!s.is_in_scope("evilexample.com"));
        assert!(!s.is_in_scope("notexample.com"));
    }

    #[test]
    fn out_of_scope_overrides_in_scope() {
        let s = scope_with(&["*.example.com"], &["staging.example.com"]);
        assert!(s.is_in_scope("api.example.com"));
        assert!(!s.is_in_scope("staging.example.com"));
    }

    #[test]
    fn default_deny_when_no_match() {
        let s = scope_with(&["*.example.com"], &[]);
        assert!(!s.is_in_scope("other.com"));
    }

    #[test]
    fn case_insensitive() {
        let s = scope_with(&["*.Example.COM"], &[]);
        assert!(s.is_in_scope("API.example.com"));
    }

    #[test]
    fn default_for_includes_apex_and_wildcard() {
        let s = Scope::default_for("example.com");
        assert!(s.is_in_scope("example.com"));
        assert!(s.is_in_scope("api.example.com"));
        assert!(!s.is_in_scope("other.com"));
    }

    #[test]
    fn scope_decision_normalizes_url_and_bare_host_equally() {
        let s = scope_with(&["admin.shopify.com"], &[]);
        let bare = s.explain("admin.shopify.com");
        let url = s.explain("https://admin.shopify.com/");

        assert_eq!(bare.decision, ScopeVerdict::InScope);
        assert_eq!(url.decision, ScopeVerdict::InScope);
        assert_eq!(bare.normalized_host, url.normalized_host);
        assert_eq!(bare.normalized_url, None);
        assert_eq!(
            url.normalized_url.as_deref(),
            Some("https://admin.shopify.com/")
        );
    }

    #[test]
    fn scope_decision_reports_deny_precedence() {
        let s = scope_with(&["*.example.com"], &["admin.example.com"]);
        let decision = s.explain("https://admin.example.com/settings");

        assert_eq!(decision.decision, ScopeVerdict::OutOfScope);
        assert_eq!(decision.matched_allow.len(), 1);
        assert_eq!(decision.matched_deny.len(), 1);
        assert_eq!(decision.reason, "explicit deny rule matched");
    }

    #[test]
    fn scope_decision_wildcard_rejects_unrelated_domains() {
        let s = scope_with(&["*.example.com"], &[]);
        let decision = s.explain("https://evilexample.com/");

        assert_eq!(decision.decision, ScopeVerdict::OutOfScope);
        assert!(decision.matched_allow.is_empty());
        assert!(decision.matched_deny.is_empty());
    }

    #[test]
    fn scope_decision_marks_empty_target_ambiguous() {
        let s = scope_with(&["*.example.com"], &[]);
        let decision = s.explain("   ");

        assert_eq!(decision.decision, ScopeVerdict::Ambiguous);
        assert_eq!(decision.normalized_host, None);
        assert!(decision.reason.contains("empty"));
    }
}
