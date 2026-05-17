/*******************************************************************
 * Filename:        parse.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Parse the LLM's markdown output into structured Priority records
 * Notes:           The LLM is instructed to emit a strict schema; we still
 *                  handle malformed rows gracefully rather than panicking.
 *                  The raw markdown is also returned for appending to priorities.md.
 *******************************************************************/

use serde::{Deserialize, Serialize};
use std::path::Path;

// One ranked attack-surface entry
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Priority {
    pub rank: u32,
    pub host: String,
    pub bug_class: String,
    pub payout_band: String,
    pub rationale: String,
    pub first_test: String,
    pub skill: String,
    // full path to the skill directory for direct loading
    pub skill_path: String,
}

// Output of parsing one LLM response
pub struct ParsedOutput {
    // structured priorities (empty if parsing failed)
    pub priorities: Vec<Priority>,
    // raw markdown returned by the LLM, for verbatim append to priorities.md
    pub raw_markdown: String,
}

// Parse LLM response markdown into structured priorities
// skills_dir is used to build the full skill_path for each row
pub fn parse_llm_output(llm_response: &str, skills_dir: &Path) -> ParsedOutput {
    let raw_markdown = llm_response.to_string();
    let priorities = extract_table_rows(llm_response, skills_dir);
    ParsedOutput { priorities, raw_markdown }
}

// Walk the markdown looking for pipe-delimited table rows that start with a rank integer
fn extract_table_rows(text: &str, skills_dir: &Path) -> Vec<Priority> {
    let mut priorities = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        // table rows start and end with |; skip header and separator rows
        if !line.starts_with('|') || !line.ends_with('|') { continue; }

        // split on | and trim each cell
        let cells: Vec<&str> = line.split('|')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .collect();

        // expect exactly 7 columns: Rank Host BugClass PayoutBand Rationale FirstTest Skill
        if cells.len() != 7 { continue; }

        // first cell must be a positive integer (the rank)
        let rank = match cells[0].parse::<u32>() {
            Ok(n) if n > 0 => n,
            _ => continue,
        };

        let skill_name = cells[6].to_string();
        // build the absolute path to the skill directory
        let skill_path = skills_dir.join(&skill_name).to_string_lossy().to_string();

        priorities.push(Priority {
            rank,
            host: cells[1].to_string(),
            bug_class: cells[2].to_string(),
            payout_band: cells[3].to_string(),
            rationale: cells[4].to_string(),
            first_test: cells[5].to_string(),
            skill: skill_name,
            skill_path,
        });
    }

    // sort by rank in case the LLM emitted rows out of order
    priorities.sort_by_key(|p| p.rank);
    priorities
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_table_row() {
        let md = "| Rank | Host | Bug Class | Payout Band | Rationale | First Test | Skill |\n\
                  |------|------|-----------|-------------|-----------|------------|-------|\n\
                  | 1 | api.target.com | ssrf | $5k–$30k | nginx + cloud=aws | probe /import | ssrf |";
        let parsed = parse_llm_output(md, Path::new("/skills"));
        assert_eq!(parsed.priorities.len(), 1);
        assert_eq!(parsed.priorities[0].rank, 1);
        assert_eq!(parsed.priorities[0].host, "api.target.com");
        assert_eq!(parsed.priorities[0].bug_class, "ssrf");
        assert_eq!(parsed.priorities[0].skill_path, "/skills/ssrf");
    }

    #[test]
    fn skips_header_and_separator() {
        let md = "| Rank | Host | Bug Class | Payout Band | Rationale | First Test | Skill |\n\
                  |------|------|-----------|-------------|-----------|------------|-------|\n";
        let parsed = parse_llm_output(md, Path::new("/skills"));
        assert!(parsed.priorities.is_empty());
    }

    #[test]
    fn handles_out_of_order_ranks() {
        let md = "| 2 | b.com | xss | $500–$5k | reflected | probe | xss |\n\
                  | 1 | a.com | ssrf | $5k–$30k | aws | probe | ssrf |";
        let parsed = parse_llm_output(md, Path::new("/skills"));
        assert_eq!(parsed.priorities[0].rank, 1);
        assert_eq!(parsed.priorities[1].rank, 2);
    }
}
