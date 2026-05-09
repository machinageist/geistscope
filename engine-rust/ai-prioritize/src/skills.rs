/*******************************************************************
 * Filename:        skills.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Load bug-hunting skill files and extract the sections
 *                  relevant to prioritization (identity, severity map,
 *                  recon hooks, session hooks — not payloads or templates)
 * Notes:           Sections are identified by "## N." headings; we keep
 *                  sections 1, 2, 3, and 12 and drop the rest to keep
 *                  the prompt focused and within budget.
 *******************************************************************/

use std::path::{Path, PathBuf};
use anyhow::Result;

// Parsed representation of one skill relevant to prioritization
pub struct Skill {
    pub name: String,
    #[allow(dead_code)]  // path reserved for future skill-specific tooling
    pub path: PathBuf,
    // compact trigger description from YAML frontmatter
    pub description: String,
    // extracted markdown: sections 1 (identity), 2 (severity), 3 (recon hooks), 12 (session hooks)
    pub context: String,
}

// Discover and load all skills from the given directory
pub fn load_skills(skills_dir: &Path) -> Result<Vec<Skill>> {
    let mut skills = Vec::new();

    // iterate top-level subdirectories; each directory is one skill
    let entries = std::fs::read_dir(skills_dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        // skip files and hidden entries; only process directories that contain SKILL.md
        if !path.is_dir() { continue; }
        let skill_md = path.join("SKILL.md");
        if !skill_md.exists() { continue; }

        let name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let raw = std::fs::read_to_string(&skill_md)?;
        let description = extract_frontmatter_description(&raw);
        let context = extract_priority_sections(&raw);

        skills.push(Skill { name, path, description, context });
    }

    // sort alphabetically so the prompt order is deterministic
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(skills)
}

// Pull the `description:` value out of the YAML frontmatter block (between --- delimiters)
fn extract_frontmatter_description(raw: &str) -> String {
    // find the opening and closing --- markers
    let mut lines = raw.lines();
    if lines.next().map(str::trim) != Some("---") { return String::new(); }

    let mut in_description = false;
    let mut desc_lines: Vec<String> = Vec::new();

    for line in lines {
        if line.trim() == "---" { break; }

        if let Some(after_key) = line.strip_prefix("description:") {
            // the value may be on the same line or as a multi-line YAML block scalar (>)
            let rest = after_key.trim();
            if !rest.is_empty() && rest != ">" {
                desc_lines.push(rest.to_string());
            }
            in_description = true;
            continue;
        }

        if in_description {
            // continuation lines of a YAML block scalar are indented
            if line.starts_with("  ") || line.starts_with('\t') {
                desc_lines.push(line.trim().to_string());
            } else {
                // new key — stop accumulating description
                in_description = false;
            }
        }
    }

    desc_lines.join(" ")
}

// Extract sections 1, 2, 3, and 12 from the skill markdown; skip all others
fn extract_priority_sections(raw: &str) -> String {
    let mut output = Vec::new();
    let mut current_section: Option<u32> = None;
    let mut in_frontmatter = false;
    let mut frontmatter_done = false;
    let mut line_count = 0;

    for line in raw.lines() {
        // skip YAML frontmatter block
        if !frontmatter_done {
            if line.trim() == "---" {
                if !in_frontmatter { in_frontmatter = true; continue; }
                else { frontmatter_done = true; continue; }
            }
            if in_frontmatter { continue; }
        }

        // detect numbered section headings like "## 3. Where To Find It"
        if let Some(section_num) = parse_section_heading(line) {
            current_section = Some(section_num);
        }

        // include lines that belong to sections 1, 2, 3, or 12
        let keep = matches!(current_section, Some(1) | Some(2) | Some(3) | Some(12));

        if keep {
            output.push(line);
            line_count += 1;
            // safety cap: never emit more than 200 lines per skill to bound prompt size
            if line_count >= 200 { break; }
        }
    }

    output.join("\n")
}

// Parse a "## N. Title" heading and return N if matched
fn parse_section_heading(line: &str) -> Option<u32> {
    // must start with "## " followed by a digit
    let rest = line.strip_prefix("## ")?;
    let dot_pos = rest.find('.')?;
    rest[..dot_pos].trim().parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_section_heading_basic() {
        assert_eq!(parse_section_heading("## 3. Where To Find It"), Some(3));
        assert_eq!(parse_section_heading("## 12. Session Mode Hooks"), Some(12));
        assert_eq!(parse_section_heading("### sub"), None);
        assert_eq!(parse_section_heading("# Top level"), None);
    }

    #[test]
    fn extract_frontmatter_description_multiline() {
        let raw = "---\nname: ssrf\ndescription: >\n  Line one\n  line two\n---\n## 1.";
        let desc = extract_frontmatter_description(raw);
        assert!(desc.contains("Line one"));
    }

    #[test]
    fn extract_priority_sections_excludes_section_4() {
        let raw = "---\n---\n## 1. Identity\nkept\n## 4. Detection\ndropped\n## 12. Hooks\nkept2";
        let out = extract_priority_sections(raw);
        assert!(out.contains("kept"));
        assert!(!out.contains("dropped"));
        assert!(out.contains("kept2"));
    }
}
