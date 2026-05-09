/*******************************************************************
 * Filename:        prompt.rs
 * Author:          Jeff
 * Date:            2026-05-08
 * Description:     Build the system and user prompts sent to the LLM
 * Notes:           System prompt fixes the output schema so parse.rs
 *                  can reliably extract structured data.
 *                  User prompt injects recon data + trimmed skill sections.
 *******************************************************************/

use crate::skills::Skill;
use crate::ReconSummary;

// Invariant system prompt — defines role, output format, and ranking rules
pub fn system_prompt() -> &'static str {
    r#"You are a bug bounty prioritization assistant embedded in a recon pipeline.
You receive discovered recon data (subdomains, fingerprints, open ports) and
reference material from bug-hunting skill files. Your job: rank the attack surface
by expected payout × exploitability confidence.

## Output format (strict — do not deviate)

First, a markdown table with exactly these columns in this order:
| Rank | Host | Bug Class | Payout Band | Rationale | First Test | Skill |

Rules:
- Rank 1 is the highest-priority target.
- Rationale must cite specific evidence from the recon data (server header,
  framework, open port, cloud provider, etc.). No generic statements.
- First Test must be a single, concrete, immediately actionable step
  (e.g. "Send GET /api/v1/users/2 logged in as user 1, compare to /users/1").
- Bug Class is the canonical name matching one of the provided skill names
  (e.g. "ssrf", "broken-access-control", "auth-session-flaws").
- Payout Band is a dollar range string (e.g. "$2k–$15k").
- Skill is the bare skill directory name (e.g. "ssrf").

After the table, write exactly:

### Key Observations
2–4 sentences. Summarise the most important patterns across the full host list:
what tech stack dominates, which bug class has the widest surface, what is
the single highest-leverage target and why.

Do not include any other sections, headings, or prose outside this schema."#
}

// Build the per-run user prompt from live recon data and extracted skill sections
pub fn user_prompt(summary: &ReconSummary, skills: &[Skill]) -> String {
    let mut out = String::new();

    // recon data section — one row per host
    out.push_str(&format!(
        "## Engagement: {} — target: {}\n\n",
        summary.engagement, summary.target
    ));
    out.push_str("## Discovered Hosts\n\n");
    out.push_str("| Host | IPs | Source | HTTP | Server | Framework | CDN | CMS | Cloud | Ports | Services |\n");
    out.push_str("|------|-----|--------|------|--------|-----------|-----|-----|-------|-------|----------|\n");

    // one table row per host — compact representation for the LLM
    for host in &summary.hosts {
        let ips = host.ips.join(", ");
        let (server, framework, cdn, cms, cloud) = if let Some(fp) = &host.fingerprint {
            (
                fp.server.as_deref().unwrap_or("-"),
                fp.framework.as_deref().unwrap_or("-"),
                fp.cdn.as_deref().unwrap_or("-"),
                fp.cms.as_deref().unwrap_or("-"),
                fp.cloud.as_deref().unwrap_or("-"),
            )
        } else {
            ("-", "-", "-", "-", "-")
        };
        let http = if host.http_accessible { "yes" } else { "no" };
        let ports = host.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(" ");
        let services = host.services.join(" ");

        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            host.hostname, ips, host.source, http,
            server, framework, cdn, cms, cloud,
            ports, services
        ));
    }

    // skill reference section — trimmed to sections 1, 2, 3, 12 for each skill
    out.push_str("\n## Bug Class Reference\n\n");
    out.push_str("Below are the relevant sections (identity, severity, recon hooks, session hooks) ");
    out.push_str("from each skill. Use them to match recon indicators to bug classes.\n\n");

    for skill in skills {
        out.push_str(&format!("### Skill: {} \n", skill.name));
        if !skill.description.is_empty() {
            out.push_str(&format!("**Trigger:** {}\n\n", skill.description));
        }
        out.push_str(&skill.context);
        out.push_str("\n\n---\n\n");
    }

    // final instruction to stay focused
    out.push_str("Produce the ranked table and Key Observations now. ");
    out.push_str("Every row must map to a real host from the Discovered Hosts table above.");

    out
}
