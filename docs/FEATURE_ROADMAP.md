# GeistScope Feature Roadmap

Last updated: 2026-05-15

## Current Snapshot

GeistScope has a working Rust engine for engagement setup, recon, crawling,
probing, fuzzing, replay, AI prioritization, and a Ratatui dashboard. The next
major move is to turn the dashboard into a TUI bug-hunting browser and put a
scoped AI harness between the model and the tools.

## P0: Documentation And Harness Contract

Status: in progress.

- Product doctrine for future implementation.
- Bug hunting methodology tied to current tools.
- AI endpoint contract, risk classes, and audit policy.
- Feature roadmap and research source log.
- New operational skills for AI harness and field workflows.

Exit criteria:

- Future code reviews can point to docs for architecture and safety decisions.
- New tool endpoints have a clear schema and risk model.

## P1: TUI Browser Core

Goal: make `mg-tui` the daily driver for a solo researcher.

Status: started. `mg-tui` now includes a Harness tab that displays endpoint
registry status plus harness activity parsed from `audit.log`. The Browser tab
now has a request/response inspector with method, final URL, status, MIME type,
page inventory, redacted cookie/header display, in-page search, and selected
engagement session headers. Hosts can now pivot directly into the Browser tab.

Features:

- Engagement picker with current status, scope, and active risk mode.
- Host/path/parameter browser. Started with host-to-browser pivoting.
- Request and response viewer with search, headers, body, cookies, and diff.
  Started with page search plus redacted response headers and cookies.
- HAR/Burp/Caido import into a request corpus.
- "Send to replay", "Send to fuzz", "Create finding", and "Ask AI" actions.
- Auth profiles for controlled test accounts and roles. Started with the
  `session` crate, `mg-engagement` credential commands, harness `session.*`
  endpoints, TUI browser use, and session header injection for crawl/probe/fuzz.
- Cookie/token redaction and storage outside model-visible context.
- Keyboard-first workflow with stable panes and no layout jumps.

Current-feature improvements:

- Expand `views/browser.rs` from page inspection into request-corpus navigation.
- Add request body capture and response diffing to the Browser inspector.
- Add traffic search and saved filters.
- Add quick links from findings to replay/fuzz output files.
- Expand the Harness tab once `mg-harness` has a daemon queue and live job state.

## P1: AI Harness Core

Goal: route AI assistance through scoped endpoints instead of free-form shell.

Status: started. `mg-harness` now provides a JSON invocation CLI and library
dispatcher with endpoint registry, version/risk checks, confirmation gating,
scope checks, and implemented `engagement.open`, `engagement.status`,
`scope.check`, `recon.run`, `session.set`, `session.get_headers`,
`finding.create`, `finding.read`, and `chain.read`.

Features:

- New `mg-harness` crate for endpoint dispatch. Started.
- Tool registry with endpoint names, versions, risk classes, and schemas. Started.
- Per-turn allowed tools.
- Scope gate before active calls. Started.
- Confirmation prompts for high-active and state-changing calls. Started.
- Audit log entries for dispatches and results. Started.
- Provider-neutral model adapter for Anthropic, Ollama, and OpenAI-compatible APIs.

Current-feature improvements:

- Reuse `llm-client` but separate model messages from tool execution.
- Move `ai-prioritize` skill loading into a reusable library API.
- Use `chain-analysis.md/json` from `ai-prioritize` to drive chained follow-up
  tests. Started.
- Add prompt-injection regression fixtures from crawled HTML and JS comments.

## P1: Recon And Surface Quality

Features:

- CIDR, path, wildcard, mobile, cloud bucket, and API scope types.
- Subdomain takeover checks with CNAME and service-specific fingerprints.
- HTTP fallback when HTTPS fails.
- JS AST extraction using a real parser.
- Source map extraction and endpoint mining.
- OpenAPI import and REST operation inventory.
- GraphQL schema/operation explorer.
- ProjectDiscovery JSONL import/export for Katana/Nuclei interoperability.

Current-feature improvements:

- Keep `mg-crawl` robots and rate-limit behavior, but add better parser coverage.
- Keep `mg-probe` semi-active checks bounded and scope-aware. Started with
  `--active` reflected-marker, single-quote SQL error, and no-follow open
  redirect probes from crawler endpoints.

## P1: OOB And Blind Testing

Features:

- Interactsh-compatible client integration.
- Per-engagement callback allocation.
- Polling loop and TUI callback feed.
- Finding evidence attachment for DNS/HTTP/SMTP callbacks.
- Payload helpers for SSRF, XXE, blind XSS, SSTI, command injection, and webhooks.

Current-feature improvements:

- Add `--oob-token` or `--oob-host` support to `mg-fuzz`.
- Persist OOB events under `engagements/<name>/oob/`.

## P2: Fuzzing And Replay Depth

Features:

- Parameter miner from traffic, crawl, JS, forms, OpenAPI, and GraphQL.
- Stack-aware payload selection. Implemented with `payload-engine` and
  `mg-fuzz --context-aware`.
- ProjectDiscovery-style fuzz preconditions so templates only run where they
  make sense.
- Shared cross-tool rate-limit coordinator.
- Auth-aware replay profiles.
- Two-account access-control diffing.
- Race-condition runner with bounded concurrency and explicit confirmation.
- Nuclei template import/export where safe.
- Response semantic diff for JSON, HTML, and GraphQL.

Current-feature improvements:

- Keep response capture caps.
- Add richer anomaly scoring and false-positive suppression.

## P2: Reporting And Consulting

Features:

- Evidence vault with redaction review.
- Bounty report drafts using platform-specific fields.
- Client report generator with executive summary, scope, methodology, findings,
  evidence appendix, and retest section.
- CVSS, Bugcrowd VRT, and HackerOne-style severity mapping.
- Engagement activity timeline.
- Time notes and deliverable checklist for solo consulting.
- Export bundle that excludes secrets and out-of-scope artifacts.

Current-feature improvements:

- Build on `mg-engagement` findings rather than introducing a separate format.
- Add replay status and OOB evidence references to report frontmatter.

## P3: Red-Team Extensions

Features:

- ATT&CK technique tags for relevant findings and attack paths.
- Attack path graph from external asset to demonstrated impact.
- Detection notes and defensive validation fields.
- Separate bug bounty, pentest, and red-team engagement modes.
- Rules-of-engagement controls for state-changing actions.

Guardrail:

- Do not add social engineering, destructive payloads, persistence, or broad
  brute-force workflows without explicit ROE support and human confirmation.

## Feature Ideas From Research

- Methodology queue: the AI creates one safe next test per hypothesis instead
  of flooding the operator with generic checklists.
- Public report learner: import disclosed Hacktivity/writeups, extract patterns,
  and map them to skills without copying sensitive content.
- Skill effectiveness scoring: record which skill, signal, and test produced a
  valid finding.
- Duplicate-risk hints: compare candidate findings against public reports and
  prior local notes before submission.
- Scope-drift detector: warn when redirects, CNAMEs, APIs, or mobile endpoints
  move outside authorized scope.
- Impact-chain builder: connect low/medium primitives into higher-value chains.
- Prompt-injection lab: fixtures for hostile web pages that try to manipulate
  the AI harness.

## Source Influences

- OWASP WSTG/API/ASVS shape the test and verification model.
- NIST SP 800-115 shapes the assessment lifecycle.
- MITRE ATT&CK shapes red-team language.
- PortSwigger Academy, Bugcrowd University, and bug bounty methodology talks
  shape practical hunting workflows.
- ProjectDiscovery Katana/Nuclei/Interactsh shape automation patterns.
- OWASP GenAI and MCP guidance shape AI-agent safety.
