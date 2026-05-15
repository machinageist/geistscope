# GeistScope Research Sources

Last updated: 2026-05-15

This file records the public sources used to update the GeistScope doctrine,
methodology, endpoint contract, roadmap, and skills. Normative implementation
guidance should prefer official standards, platform docs, and project docs.
Blogs, books, and video transcripts are useful for field workflow, but they
should not override the product doctrine or engagement authorization.

## Standards And Methodology

- OWASP Web Security Testing Guide
  - URL: https://owasp.org/www-project-web-security-testing-guide/
  - Used for: web testing coverage, versioned test references, and methodology
    vocabulary.

- OWASP API Security Top 10
  - URL: https://owasp.org/API-Security/
  - Used for: API risk classes such as BOLA, broken authentication, unrestricted
    resource consumption, BFLA, SSRF, inventory, and unsafe API consumption.

- OWASP Application Security Verification Standard
  - URL: https://owasp.org/www-project-application-security-verification-standard/
  - Used for: verification language and secure-development control framing.

- NIST SP 800-115, Technical Guide to Information Security Testing and Assessment
  - URL: https://csrc.nist.gov/pubs/sp/800/115/final
  - Used for: assessment planning, execution, analysis, mitigation, and reporting
    framing.

- MITRE ATT&CK
  - URL: https://www.mitre.org/focus-areas/cybersecurity/mitre-attack
  - Used for: red-team tactic/technique language and threat-informed extensions.

## Training, Bounty Workflow, And Reporting

- PortSwigger Web Security Academy
  - URL: https://portswigger.net/web-security
  - Used for: practical web vulnerability taxonomy and lab-oriented workflow.

- Bugcrowd University
  - URL: https://github.com/bugcrowd/bugcrowd_university
  - Used for: bug bounty training modules, including submissions, Burp, access
    control, XSS, recon, SSRF, GitHub recon, XXE, and API topics.

- Bugcrowd Vulnerability Rating Taxonomy
  - URL: https://bugcrowd.com/vulnerability-rating-taxonomy/1.7
  - Used for: bounty severity/priority mapping and report triage language.

- Bugcrowd Reporting A Bug
  - URL: https://docs.bugcrowd.com/researchers/reporting-managing-submissions/reporting-a-bug/
  - Used for: required report fields, evidence expectations, and submission
    workflow.

- HackerOne Bug Bounty Maturity Framework
  - URL: https://docs.hackerone.com/en/articles/14048481-bug-bounty-maturity-framework
  - Used for: program operations, consistency, severity frameworks, scope, and
    researcher engagement expectations.

- HackerOne Hacktivity docs
  - URL: https://docs.hackerone.com/en/articles/8410358-hacktivity
  - Used for: disclosed report learning and public-report discovery ideas.

- Bug Bounty Bootcamp by Vickie Li
  - URL: https://nostarch.com/bug-bounty-bootcamp
  - Used for: broad bug bounty workflow topics, including reporting, recon,
    common web vulnerabilities, APIs, mobile, and source review.

## Tooling Patterns

- ProjectDiscovery Katana
  - URL: https://github.com/projectdiscovery/katana
  - Used for: crawler feature inspiration such as standard/headless crawling,
    JavaScript crawling, forms, scope, and output fields.

- ProjectDiscovery Nuclei templates
  - URL: https://docs.projectdiscovery.io/templates/introduction
  - Used for: structured vulnerability template design and low-false-positive
    scanning language.

- ProjectDiscovery Nuclei HTTP fuzzing overview
  - URL: https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview
  - Used for: fuzzing preconditions and request-aware template execution.

- ProjectDiscovery Interactsh
  - URL: https://docs.projectdiscovery.io/opensource/interactsh/overview
  - Used for: out-of-band vulnerability testing architecture and callback-event
    workflow.

## AI Harness And Agent Safety

- OWASP GenAI LLM Top 10
  - URL: https://genai.owasp.org/llm-top-10/
  - Used for: prompt injection, sensitive information disclosure, excessive
    agency, improper output handling, and unbounded consumption controls.

- OWASP MCP Top 10
  - URL: https://owasp.org/www-project-mcp-top-10/
  - Used for: token exposure, tool poisoning, command execution, insufficient
    authorization, audit gaps, and context over-sharing in tool-agent systems.

- OpenAI function calling guide
  - URL: https://developers.openai.com/api/docs/guides/function-calling
  - Used for: strict tool schemas, allowed tools, and provider-compatible tool
    calling concepts.

## Video And Transcript Material

- Bug Hunter's Methodology: Application Analysis, Jason Haddix / HackerOne
  - Transcript mirror: https://glasp.co/youtube/FqnSAa2KmBI
  - Used for: advisory workflow ideas around recon, application analysis,
    content discovery, and focusing on where bugs tend to live.

- Recon to Master: The Complete Bug Bounty Checklist (2025 Edition)
  - Transcript mirror: https://glasp.co/youtube/7hf-WQ0Idhg
  - Used for: advisory recon checklist ideas. Not used as normative source.

- NahamSec and related bug bounty field material surfaced in search
  - Example: https://www.nahamsec.com/posts/hacking-full-time
  - Used for: advisory notes on target selection, consistency, and personal
    methodology. Not used as normative source.

## Local Prior Art

- `~/.claude/projects/REDBROWSER_PROJECT.md`
  - Used for: long-term browser workstation vision, local-first AI/ML triage,
    proxy/traffic storage/API/replay/graph concepts.

- `~/.claude/security/SEC_TOOL_ROADMAP.md`
  - Used for: CLI-first modularity, API-later design, report generation, AI
    summarization, and portfolio-to-product progression.

- `~/.claude/bug-hunting-skills/`
  - Used for: existing skill format, bug-class taxonomy, and operational
    context consumed by `ai-prioritize`.
