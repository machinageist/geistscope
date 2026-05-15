# GeistScope Product Doctrine

Last updated: 2026-05-15

## Purpose

GeistScope is a professional bug hunting workstation for authorized bug bounty,
pentest, and red-team engagements. The near-term product is a TUI-based web
browser and attack-surface console. The core is an AI harness that can call a
dedicated set of scoped security-tool endpoints.

The current implementation is a Rust workspace of CLI tools that share a
file-native engagement directory. That remains the foundation. The next product
layer should expose those tools through explicit endpoint contracts so a human
operator, TUI, and AI agent can all work from the same evidence without giving
the model uncontrolled system access.

## Product Shape

GeistScope should feel like a terminal-native Burp/Caido-style browser for a
solo consultant or bug bounty researcher:

- Open an engagement and browse in-scope assets from the terminal.
- Capture or import traffic into the engagement workspace.
- Send requests to replay, fuzz, crawl, probe, OOB, and reporting tools.
- Let the AI propose next actions, but require tool calls to pass scope,
  safety, rate-limit, and audit checks.
- Keep all evidence local, redacted, reproducible, and ready for bounty or
  client reporting.

This means "AI harness" is not a chat wrapper. It is a tool registry, policy
gate, evidence store, and reasoning loop around the existing Rust engine.

## Non-Negotiable Design Rules

1. Scope is a runtime security boundary.
   Every active action must resolve to an engagement and pass `scope.json`
   before network traffic is sent.

2. The AI never receives raw standing secrets by default.
   Tokens, cookies, API keys, and OOB credentials should be stored in local
   vault-like files or OS keychain-backed storage. Model context gets redacted
   summaries and stable hashes.

3. Web content is untrusted input.
   HTML, JavaScript, HTTP responses, reflected parameters, logs, and imported
   reports can contain prompt injection. The harness must label them as data and
   never allow target-controlled text to redefine system instructions, tool
   policy, scope, or user intent.

4. Tool calls are structured and allowlisted.
   The model may request a named endpoint with JSON arguments. It must not
   construct arbitrary shell commands, paths, SQL, or HTTP clients outside the
   endpoint boundary.

5. Active testing must be attributable.
   Every crawl, scan, fuzz, replay, OOB allocation, report generation, and AI
   recommendation must append an audit event with timestamp, tool name, inputs
   after redaction, target, operator, and output location.

6. Evidence beats assertion.
   Findings should point to raw request/response evidence, replay results,
   OOB callbacks, screenshots or terminal captures, and a short impact chain.
   The AI can draft reports, but should not invent impact.

7. Local-first is the default.
   The system should work with local files and local models. Cloud LLMs are
   optional providers and must receive minimized context.

8. UX is for repeat work.
   The TUI should optimize scanning, comparing, replaying, annotating, and
   reporting. Avoid decorative UI and marketing-style flows inside the tool.

## Coding Doctrine

When adding or changing code, preserve the existing Rust conventions:

- Keep the required block comment header at the top of Rust files.
- Put a `// Verb + noun` comment above functions and major code blocks.
- Keep reusable logic in libraries and thin wrappers in binaries.
- Prefer structured parsers and schemas over ad hoc string scraping.
- Keep engagement writes deterministic and easy to diff.
- Treat path, engagement, host, URL, and finding IDs as untrusted input.
- Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
  for engine changes.

Endpoint and AI-harness code should add these extra constraints:

- Validate all model-provided arguments against JSON Schema or equivalent Rust
  types before dispatch.
- Keep separate types for model requests, validated tool requests, and persisted
  audit records.
- Deny by default when scope, auth context, output path, or risk class is
  ambiguous.
- Use bounded output capture and redact before writing files that the model will
  ingest.
- Keep prompt templates and tool schemas versioned in the repo.

## Current Engine Roles

The current Rust engine already covers the file-native workflow:

- `mg-engagement`: workspace, scope, notes, audit, findings.
- `subdomain-enum`: passive and active subdomain enumeration.
- `mg-scan`: async TCP scan and banner capture.
- `mg-fingerprint`: HTTP tech fingerprinting.
- `mg-recon`: orchestrated recon summary.
- `mg-crawl`: same-origin crawl, pages, JavaScript, endpoints, redacted secrets.
- `mg-probe`: passive posture checks and findings.
- `mg-fuzz`: request-template fuzzing with response diffing.
- `mg-replay`: evidence replay and current verdicts.
- `ai-prioritize`: LLM ranking from recon and skill files.
- `mg-tui`: current file-native terminal dashboard.

These should evolve toward a local endpoint surface, not be replaced.

## Target Architecture

```
TUI browser
  -> local AI harness
       -> policy gate
       -> tool registry
       -> evidence store
       -> model provider adapter
       -> Rust tool endpoints
              -> engagement files
              -> network clients
              -> OOB listener
              -> report generator
```

The TUI should remain usable without an LLM. The AI harness should remain usable
without a TUI. Each Rust tool should remain usable from the CLI.

## Methodology Baseline

GeistScope's methodology should blend:

- OWASP WSTG for web testing coverage and versioned test references.
- OWASP API Security Top 10 for modern API risk categories.
- OWASP ASVS for technical control language and verification rigor.
- NIST SP 800-115 for planning, execution, analysis, and mitigation framing.
- MITRE ATT&CK for red-team tactic/technique language when engagements move
  beyond web app testing.
- PortSwigger Web Security Academy for hands-on web vulnerability practice.
- Bugcrowd and HackerOne guidance for scope, impact, reporting, severity, and
  program operations.
- ProjectDiscovery patterns for crawling, templates, fuzzing preconditions, and
  out-of-band detection.
- OWASP GenAI and MCP guidance for AI-agent tool boundaries, prompt injection,
  excessive agency, secret exposure, and auditability.

The local skill files in `~/.claude/bug-hunting-skills/` provide field notes and
bug-class heuristics. They are useful operational context, but implementation
requirements should trace back to this doctrine, code review, and source-backed
docs.

## Product Boundaries

GeistScope is for authorized testing. It should make good-faith work easier and
more reproducible, not bypass authorization boundaries.

The harness must block or require explicit human confirmation for:

- Out-of-scope targets.
- High-volume fuzzing.
- Authentication attacks and brute force.
- DoS-like payloads.
- Data export beyond harmless-minimum proof.
- Public disclosure or report submission.
- Tool requests that modify, delete, purchase, transfer, or invite unless the
  engagement explicitly authorizes that action.

## Source Anchors

- OWASP WSTG: https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security Top 10: https://owasp.org/API-Security/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- NIST SP 800-115: https://csrc.nist.gov/pubs/sp/800/115/final
- MITRE ATT&CK: https://www.mitre.org/focus-areas/cybersecurity/mitre-attack
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Bugcrowd University: https://github.com/bugcrowd/bugcrowd_university
- Bugcrowd VRT: https://bugcrowd.com/vulnerability-rating-taxonomy/1.7
- HackerOne Bug Bounty Maturity Framework: https://docs.hackerone.com/en/articles/14048481-bug-bounty-maturity-framework
- ProjectDiscovery Interactsh: https://docs.projectdiscovery.io/opensource/interactsh/overview
- ProjectDiscovery Nuclei templates: https://docs.projectdiscovery.io/templates/introduction
- OWASP GenAI LLM Top 10: https://genai.owasp.org/llm-top-10/
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
