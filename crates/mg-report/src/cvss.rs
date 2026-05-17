/*******************************************************************
 * Filename:        cvss.rs
 * Author:          Jeff
 * Date:            2026-05-15
 * Description:     CVSS 3.1 base-score parser and calculator
 * Notes:           Report severity uses locally computed scores instead of
 *                  trusting model-generated numbers.
 *******************************************************************/

use std::collections::HashMap;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CvssError {
    #[error("invalid CVSS vector: {0}")]
    InvalidVector(String),
    #[error("missing CVSS metric: {0}")]
    MissingMetric(&'static str),
    #[error("invalid CVSS metric {0}:{1}")]
    InvalidMetric(&'static str, String),
}

// Compute a CVSS 3.1 base score from a vector string
pub fn score_vector(vector: &str) -> Result<f64, CvssError> {
    let metrics = parse_metrics(vector)?;
    let scope_changed = metric(&metrics, "S")? == "C";
    let impact_sub_score = 1.0
        - (1.0 - cia_weight(metric(&metrics, "C")?, "C")?)
            * (1.0 - cia_weight(metric(&metrics, "I")?, "I")?)
            * (1.0 - cia_weight(metric(&metrics, "A")?, "A")?);
    let impact = if scope_changed {
        7.52 * (impact_sub_score - 0.029) - 3.25 * (impact_sub_score - 0.02).powi(15)
    } else {
        6.42 * impact_sub_score
    };
    if impact <= 0.0 {
        return Ok(0.0);
    }
    let exploitability = 8.22
        * av_weight(metric(&metrics, "AV")?)?
        * ac_weight(metric(&metrics, "AC")?)?
        * pr_weight(metric(&metrics, "PR")?, scope_changed)?
        * ui_weight(metric(&metrics, "UI")?)?;
    let raw = if scope_changed {
        1.08 * (impact + exploitability)
    } else {
        impact + exploitability
    };
    Ok(round_up_1(raw.min(10.0)))
}

// Return a conservative default vector for a finding severity label
pub fn default_vector_for_severity(severity: &str) -> &'static str {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "high" => "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "medium" => "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N",
        "low" => "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N",
        _ => "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
    }
}

// Map numeric CVSS score to a report severity label
pub fn severity_label(score: f64) -> &'static str {
    if score >= 9.0 {
        "Critical"
    } else if score >= 7.0 {
        "High"
    } else if score >= 4.0 {
        "Medium"
    } else if score > 0.0 {
        "Low"
    } else {
        "Informational"
    }
}

// Find the first CVSS 3.1 vector embedded in model output or markdown
pub fn find_vector(text: &str) -> Option<String> {
    text.split_whitespace()
        .map(|token| {
            token.trim_matches(|c: char| {
                matches!(
                    c,
                    '`' | '\'' | '"' | ')' | '(' | ',' | '.' | ';' | ':' | '>' | '<' | '-'
                )
            })
        })
        .find(|token| token.starts_with("CVSS:3.1/"))
        .map(str::to_string)
}

// Parse vector metrics into a lookup table
fn parse_metrics(vector: &str) -> Result<HashMap<&str, &str>, CvssError> {
    let raw = vector
        .strip_prefix("CVSS:3.1/")
        .ok_or_else(|| CvssError::InvalidVector(vector.into()))?;
    let mut metrics = HashMap::new();
    for part in raw.split('/') {
        let Some((key, value)) = part.split_once(':') else {
            return Err(CvssError::InvalidVector(vector.into()));
        };
        metrics.insert(key, value);
    }
    Ok(metrics)
}

// Fetch a required metric value
fn metric<'a>(
    metrics: &'a HashMap<&'a str, &'a str>,
    key: &'static str,
) -> Result<&'a str, CvssError> {
    metrics
        .get(key)
        .copied()
        .ok_or(CvssError::MissingMetric(key))
}

// Return attack-vector weight
fn av_weight(value: &str) -> Result<f64, CvssError> {
    match value {
        "N" => Ok(0.85),
        "A" => Ok(0.62),
        "L" => Ok(0.55),
        "P" => Ok(0.20),
        other => Err(CvssError::InvalidMetric("AV", other.into())),
    }
}

// Return attack-complexity weight
fn ac_weight(value: &str) -> Result<f64, CvssError> {
    match value {
        "L" => Ok(0.77),
        "H" => Ok(0.44),
        other => Err(CvssError::InvalidMetric("AC", other.into())),
    }
}

// Return privilege-required weight, accounting for changed scope
fn pr_weight(value: &str, scope_changed: bool) -> Result<f64, CvssError> {
    match (value, scope_changed) {
        ("N", _) => Ok(0.85),
        ("L", false) => Ok(0.62),
        ("L", true) => Ok(0.68),
        ("H", false) => Ok(0.27),
        ("H", true) => Ok(0.50),
        (other, _) => Err(CvssError::InvalidMetric("PR", other.into())),
    }
}

// Return user-interaction weight
fn ui_weight(value: &str) -> Result<f64, CvssError> {
    match value {
        "N" => Ok(0.85),
        "R" => Ok(0.62),
        other => Err(CvssError::InvalidMetric("UI", other.into())),
    }
}

// Return confidentiality, integrity, or availability impact weight
fn cia_weight(value: &str, key: &'static str) -> Result<f64, CvssError> {
    match value {
        "H" => Ok(0.56),
        "L" => Ok(0.22),
        "N" => Ok(0.00),
        other => Err(CvssError::InvalidMetric(key, other.into())),
    }
}

// Round up to one decimal according to CVSS base-score rules
fn round_up_1(value: f64) -> f64 {
    (value * 10.0).ceil() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_critical_vector_scores_9_8() {
        let score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H").unwrap();
        assert_eq!(score, 9.8);
    }

    #[test]
    fn no_impact_scores_zero() {
        let score = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N").unwrap();
        assert_eq!(score, 0.0);
    }

    #[test]
    fn finds_vector_inside_comment() {
        let text = "<!-- cvss_vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N -->";
        assert_eq!(
            find_vector(text).unwrap(),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
        );
    }
}
