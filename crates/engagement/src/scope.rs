/*******************************************************************
 * Filename:        scope.rs
 * Author:          Jeff
 * Date:            2026-05-02
 * Description:     Scope rules for an engagement — wildcard match, default-deny
 * Notes:           out_of_scope wins over in_scope.
 *                  Wildcard pattern *.foo.com matches subdomains but not the apex.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;
use url::Url;

use crate::EngagementError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    pub target: String,
    pub in_scope: Vec<String>,
    pub out_of_scope: Vec<String>,
    #[serde(default)]
    pub program_assets: Vec<ProgramAsset>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramAsset {
    pub identifier: String,
    pub asset_type: String,
    pub platform: String,
    pub in_scope: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounty_eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_eligible: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
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
            program_assets: Vec::new(),
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
        let matched_asset = self.asset_for_host(host);
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
            asset_type: matched_asset.map(|asset| asset.asset_type.clone()),
            bounty_eligible: matched_asset.and_then(|asset| asset.bounty_eligible),
            submission_eligible: matched_asset.and_then(|asset| asset.submission_eligible),
            notes: matched_asset
                .and_then(|asset| asset.instructions.clone())
                .into_iter()
                .collect(),
        }
    }

    // Return the first platform asset matching a normalized or raw host
    pub fn asset_for_host(&self, target: &str) -> Option<&ProgramAsset> {
        let host = normalize_target(target)
            .ok()
            .and_then(|(host, _)| host)
            .unwrap_or_else(|| normalize_host(target));
        self.program_assets
            .iter()
            .filter(|asset| matches_pattern(&asset.identifier, &host))
            .max_by_key(|asset| (if asset.in_scope { 0 } else { 1 }, asset.identifier.len()))
    }

    // Import HackerOne-style CSV into platform-neutral scope assets
    pub fn from_hackerone_csv(target: &str, raw: &str) -> Result<Self, EngagementError> {
        Self::from_program_csv("hackerone", target, raw)
    }

    // Import generic CSV into platform-neutral scope assets
    pub fn from_program_csv(
        platform: &str,
        target: &str,
        raw: &str,
    ) -> Result<Self, EngagementError> {
        let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
        let header = lines
            .next()
            .ok_or_else(|| EngagementError::Invalid("program CSV is empty".into()))?;
        let headers: Vec<String> = header.split(',').map(normalize_key).collect();
        let mut assets = Vec::new();
        for line in lines {
            let values: Vec<&str> = line.split(',').map(str::trim).collect();
            let mut row = HashMap::new();
            for (index, header) in headers.iter().enumerate() {
                row.insert(
                    header.as_str(),
                    values.get(index).copied().unwrap_or_default(),
                );
            }
            assets.push(asset_from_map(platform, &row)?);
        }
        Ok(scope_from_assets(target, assets))
    }

    // Import generic JSON into platform-neutral scope assets
    pub fn from_program_json(
        platform: &str,
        target: &str,
        raw: &str,
    ) -> Result<Self, EngagementError> {
        let value: Value = serde_json::from_str(raw)?;
        let rows = if let Some(items) = value.as_array() {
            items.clone()
        } else if let Some(items) = value.get("assets").and_then(Value::as_array) {
            items.clone()
        } else {
            return Err(EngagementError::Invalid(
                "program JSON must be an array or object with assets".into(),
            ));
        };

        let mut assets = Vec::new();
        for row in rows {
            let object = row.as_object().ok_or_else(|| {
                EngagementError::Invalid("program asset must be an object".into())
            })?;
            assets.push(asset_from_json(platform, object)?);
        }
        Ok(scope_from_assets(target, assets))
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

// Build a scope from normalized program assets
fn scope_from_assets(target: &str, assets: Vec<ProgramAsset>) -> Scope {
    let mut in_scope = Vec::new();
    let mut out_of_scope = Vec::new();
    for asset in &assets {
        if asset.in_scope {
            push_unique(&mut in_scope, asset.identifier.clone());
        } else {
            push_unique(&mut out_of_scope, asset.identifier.clone());
        }
    }

    Scope {
        target: target.into(),
        in_scope,
        out_of_scope,
        program_assets: assets,
        notes: None,
    }
}

// Convert a CSV row map into a platform-neutral asset
fn asset_from_map(
    platform: &str,
    row: &HashMap<&str, &str>,
) -> Result<ProgramAsset, EngagementError> {
    let identifier = first_present(row, &["asset_identifier", "identifier", "target", "asset"])
        .ok_or_else(|| EngagementError::Invalid("program asset missing identifier".into()))?;
    let asset_type = first_present(row, &["asset_type", "type"])
        .unwrap_or("unknown")
        .to_string();
    let bounty_eligible = first_present(row, &["eligible_for_bounty", "bounty_eligible"])
        .and_then(parse_optional_bool);
    let submission_eligible = first_present(
        row,
        &[
            "eligible_for_submission",
            "submission_eligible",
            "eligible_for_report",
        ],
    )
    .and_then(parse_optional_bool);
    let in_scope = first_present(row, &["in_scope", "eligible_for_submission"])
        .and_then(parse_optional_bool)
        .unwrap_or_else(|| bounty_eligible.unwrap_or(false));

    Ok(ProgramAsset {
        identifier: identifier.to_string(),
        asset_type,
        platform: platform.to_string(),
        in_scope,
        bounty_eligible,
        submission_eligible,
        max_severity: first_present(row, &["max_severity", "max_severity_rating"])
            .filter(|value| !value.is_empty() && *value != "none")
            .map(str::to_string),
        instructions: first_present(row, &["instructions", "instruction", "notes"])
            .map(str::to_string),
        metadata: HashMap::new(),
    })
}

// Convert a JSON object into a platform-neutral asset
fn asset_from_json(
    platform: &str,
    row: &serde_json::Map<String, Value>,
) -> Result<ProgramAsset, EngagementError> {
    let identifier = json_string(row, &["identifier", "target", "asset_identifier", "asset"])
        .ok_or_else(|| EngagementError::Invalid("program asset missing identifier".into()))?;
    let asset_type = json_string(row, &["asset_type", "type"]).unwrap_or_else(|| "unknown".into());
    let bounty_eligible = json_bool(row, &["eligible_for_bounty", "bounty_eligible"]);
    let submission_eligible = json_bool(
        row,
        &[
            "eligible_for_submission",
            "submission_eligible",
            "eligible_for_report",
        ],
    );
    let in_scope = json_bool(row, &["in_scope"])
        .or(submission_eligible)
        .unwrap_or_else(|| bounty_eligible.unwrap_or(false));

    Ok(ProgramAsset {
        identifier,
        asset_type,
        platform: platform.into(),
        in_scope,
        bounty_eligible,
        submission_eligible,
        max_severity: json_string(row, &["max_severity", "max_severity_rating"])
            .filter(|value| value != "none"),
        instructions: json_string(row, &["instructions", "instruction", "notes"]),
        metadata: HashMap::new(),
    })
}

// Return the first non-empty CSV value for candidate keys
fn first_present<'a>(row: &'a HashMap<&str, &str>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| row.get(key).copied())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// Return a string field from a JSON object
fn json_string(row: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        row.get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
}

// Return a boolean field from a JSON object
fn json_bool(row: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    keys.iter().find_map(|key| {
        row.get(*key).and_then(|value| {
            value
                .as_bool()
                .or_else(|| value.as_str().and_then(parse_optional_bool))
        })
    })
}

// Parse common program eligibility booleans
fn parse_optional_bool(value: &str) -> Option<bool> {
    match value.trim().to_lowercase().as_str() {
        "true" | "yes" | "eligible" | "in_scope" | "1" => Some(true),
        "false" | "no" | "not_eligible" | "out_of_scope" | "0" => Some(false),
        _ => None,
    }
}

// Normalize CSV/JSON keys to snake_case-ish lookup keys
fn normalize_key(value: &str) -> String {
    value.trim().to_lowercase().replace([' ', '-'], "_")
}

// Push a value if it is not already present
fn push_unique(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
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
            program_assets: Vec::new(),
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

    #[test]
    fn imports_hackerone_csv_into_common_program_assets() {
        let csv = "asset_identifier,asset_type,eligible_for_bounty,eligible_for_submission,max_severity\n*.example.com,url,true,true,high\nold.example.com,url,false,false,none\n";

        let scope = Scope::from_hackerone_csv("example", csv).unwrap();

        assert!(scope.in_scope.contains(&"*.example.com".into()));
        assert!(scope.out_of_scope.contains(&"old.example.com".into()));
        let asset = scope.asset_for_host("api.example.com").unwrap();
        assert_eq!(asset.platform, "hackerone");
        assert_eq!(asset.asset_type, "url");
        assert_eq!(asset.bounty_eligible, Some(true));
        assert_eq!(asset.max_severity.as_deref(), Some("high"));
    }

    #[test]
    fn imports_bugcrowd_json_into_common_program_assets() {
        let raw = r#"[
            {"target":"*.example.org","type":"website","in_scope":true,"eligible_for_bounty":true},
            {"target":"staging.example.org","type":"website","in_scope":false,"eligible_for_bounty":false}
        ]"#;

        let scope = Scope::from_program_json("bugcrowd", "example", raw).unwrap();

        assert!(scope.in_scope.contains(&"*.example.org".into()));
        assert!(scope.out_of_scope.contains(&"staging.example.org".into()));
        let decision = scope.explain("staging.example.org");
        assert_eq!(decision.decision, ScopeVerdict::OutOfScope);
        assert_eq!(decision.bounty_eligible, Some(false));
    }

    #[test]
    fn imports_manual_json_without_platform_assumptions() {
        let raw = r#"{
            "assets": [
                {"identifier":"api.private.test","asset_type":"api","in_scope":true,"submission_eligible":true,"instructions":"private program notes"}
            ]
        }"#;

        let scope = Scope::from_program_json("manual", "private", raw).unwrap();

        let decision = scope.explain("https://api.private.test/v1/me");
        assert_eq!(decision.decision, ScopeVerdict::InScope);
        assert_eq!(decision.asset_type.as_deref(), Some("api"));
        assert_eq!(decision.submission_eligible, Some(true));
        assert!(decision
            .notes
            .iter()
            .any(|note| note.contains("private program notes")));
    }
}
