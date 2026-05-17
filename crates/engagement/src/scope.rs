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

use crate::EngagementError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub target: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
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
        let target = target.to_lowercase();
        if self.out_of_scope.iter().any(|p| matches_pattern(p, &target)) {
            return false;
        }
        self.in_scope.iter().any(|p| matches_pattern(p, &target))
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

// Match a single pattern against a target name.
// `*.foo.com` matches `bar.foo.com` and `a.b.foo.com` but NOT `foo.com` itself
// or `evilfoo.com`. Bare `foo.com` matches only itself.
fn matches_pattern(pattern: &str, target: &str) -> bool {
    let pattern = pattern.to_lowercase();
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
}
