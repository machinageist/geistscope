# GeistScope Bug Hunting Methodology

Last updated: 2026-05-15

## Operating Model

GeistScope is built for authorized bug bounty, pentest, and red-team work. The
methodology below governs how tools should be designed and how the TUI/AI harness
should guide an operator through an engagement.

The method is cyclical:

```
authorize -> map -> prioritize -> test -> prove -> report -> replay -> learn
```

Each cycle should write structured evidence to the engagement directory and feed
the next cycle.

## 1. Authorization And Scope

Before active traffic:

- Record program/client name, target, platform, authorization notes, and testing
  windows in `engagement.json` or `notes.md`.
- Encode in-scope and out-of-scope assets in `scope.json`.
- Identify forbidden methods: DoS, brute force, social engineering, phishing,
  malware, physical testing, destructive writes, or high-volume scans.
- Record test accounts and roles. Prefer two controlled accounts for access
  control testing and two tenants/orgs when allowed.
- Treat ambiguous scope as blocked until the operator confirms authorization.

Implementation requirement: active tool endpoints must call a shared scope check
before dispatch.

## 2. Attack Surface Mapping

Current coverage:

- `subdomain-enum` discovers domains from CT logs and active DNS brute force.
- `mg-scan` finds open TCP ports and banners.
- `mg-fingerprint` records HTTP stack hints.
- `mg-crawl` maps same-origin pages, JavaScript, forms, endpoints, and redacted
  secret candidates.
- `mg-probe` checks headers, CORS, cookies, debug paths, and stack traces.

TUI browser target behavior:

- Show hosts, paths, parameters, forms, technologies, auth context, and findings
  in one workspace.
- Let the operator pivot from a host to traffic, from traffic to replay, from
  replay to fuzz, and from confirmed behavior to a finding.
- Record every request corpus item once, then reuse it across replay, fuzzing,
  reporting, and AI ranking.

Priority improvements:

- Add CIDR, path, wildcard, mobile, API, and cloud-resource scope types.
- Add passive import from HAR, Burp, Caido, proxy logs, OpenAPI, GraphQL schemas,
  and ProjectDiscovery JSONL.
- Add JS AST endpoint extraction and source-map handling.
- Add subdomain takeover checks.
- Add HTTP fallback when HTTPS is refused, but keep TLS verification enabled by
  default.

## 3. Prioritization

`ai-prioritize` should continue ranking by expected impact and exploitability,
but the harness should move from one-shot ranking to an explainable queue:

- Evidence: what host, tech, port, endpoint, parameter, role, or response pattern
  triggered the idea.
- Hypothesis: what bug class is likely.
- First safe test: one scoped action that proves or disproves the hypothesis.
- Risk: passive, low-volume active, high-volume active, destructive, or blocked.
- Skill: local skill file that informed the test.

Do not optimize for "most tests run." Optimize for high-signal manual paths that
produce valid, non-duplicate findings.

## 4. Browser-Driven Testing Loops

The TUI should support these natural loops:

- Inspect traffic: filter by host, path, method, status, MIME, parameter, cookie,
  and authentication state.
- Replay request: edit headers/body/params safely, resend, compare responses.
- Fuzz request: mark positions, select payload set, run bounded test, diff output.
- Crawl from here: discover links/forms/API calls from an interesting page.
- Probe host: check passive issues without changing application state.
- Allocate OOB callback: insert generated callback in SSRF, XXE, blind XSS, or
  template payloads, then poll events.
- Create finding: attach request/response, replay verdict, OOB transcript, and
  impact notes.

The AI should be able to suggest any of these, but the operator should stay in
control of high-risk actions.

## 5. Bug-Class Coverage

GeistScope should support these bug classes as first-class workflows:

| Area | Current support | Required upgrade |
|---|---|---|
| Broken access control, IDOR, BOLA/BFLA | `mg-fuzz`, `mg-replay`, skills | Auth profiles, two-account diffing, object-ID miner |
| Auth/session/JWT/OAuth | Skills only | Cookie/token vault, session replay, OAuth flow notes |
| API testing | Crawl endpoints, GraphQL skill | OpenAPI import, REST parameter map, GraphQL operation explorer |
| SSRF/OOB/blind bugs | SSRF payloads | Interactsh-compatible callback allocation and polling |
| XSS/client-side | XSS payloads, crawl HTML | DOM sink/source extraction, CSP-aware PoC helper |
| SQLi/SSTI/command injection | Payload sets | Safer baseline probes, DB/template fingerprint hints |
| Race/business logic | Race skill | Parallel replay, single-packet-style timing harness where legal |
| File upload/traversal | Payload sets, skill | Multipart template editor, path traversal corpus |
| Subdomain takeover | Planned | CNAME/service fingerprint, claimability evidence checklist |
| Cloud/config exposure | Probe/debug paths | Cloud metadata and storage-bucket safe checks |

## 6. OOB And Blind Vulnerability Testing

Out-of-band testing should be a core subsystem, not just a payload string.

Required behavior:

- Allocate per-engagement callback domains or tokens.
- Tie each callback to a request, payload, timestamp, and tool run.
- Poll DNS/HTTP/SMTP/etc. interaction logs.
- Redact target data and store only the minimum proof.
- Surface callbacks in TUI and findings.

ProjectDiscovery Interactsh is the model to follow: generated URLs plus a local
client that retrieves interaction logs. Self-hosted mode should be supported for
consulting engagements that require privacy.

## 7. Evidence And Reporting

A reportable finding needs:

- Affected asset and exact endpoint.
- Authentication state and role.
- Steps to reproduce with harmless-minimum proof.
- Raw HTTP request/response evidence with secrets redacted.
- Current replay verdict.
- Impact stated in business terms.
- Severity mapped to program rubric, CVSS when required, and Bugcrowd VRT/HackerOne
  style expectations where relevant.
- Remediation guidance.

`mg-replay` should be used before submission or client delivery whenever possible.
The report generator should never submit automatically.

## 8. Consulting Practice Support

Because GeistScope is also for a solo consulting practice, the docs and product
should support:

- Engagement intake checklist.
- Authorization and rules-of-engagement storage.
- Time notes and activity log.
- Evidence vault and redaction review.
- Draft client report generation.
- Executive summary plus technical appendix.
- Retest/replay history.
- Export bundle that excludes secrets and out-of-scope data.

## 9. Red-Team Extension

For red-team work, map web and cloud findings to ATT&CK tactics and techniques
when useful, but do not turn GeistScope into a generic exploitation framework.

Useful red-team additions:

- Attack path graph from exposed asset to impact.
- Threat-informed notes and technique tags.
- Detection notes for blue-team collaboration.
- Authorized credential and session context management.
- Clear separation between bug bounty mode and red-team mode.

## 10. Learning Loop

Every valid finding should update the local knowledge base:

- What signal first surfaced it.
- Which skill matched it.
- Which first test proved it.
- Which payloads were unnecessary noise.
- Which report language worked with triage.

This is how GeistScope becomes stronger than a static checklist.

## Sources Used

- OWASP WSTG for web test coverage and versioned references.
- OWASP API Security Top 10 for API-specific risk classes.
- OWASP ASVS for verification control language.
- NIST SP 800-115 for assessment lifecycle framing.
- MITRE ATT&CK for red-team technique language.
- PortSwigger Web Security Academy for training-oriented vulnerability coverage.
- Bugcrowd University, VRT, and reporting docs for bounty workflow and severity.
- HackerOne maturity and Hacktivity docs for program operations and public report
  learning.
- ProjectDiscovery Katana, Nuclei, and Interactsh docs for crawler, template, and
  OOB design patterns.
- Public bug bounty methodology talks/transcripts and book pages for field-tested
  workflow ideas, treated as advisory rather than normative.
