# GeistScope — CLAUDE.md

This file orients Claude Code sessions for the GeistScope project.

## What this project is

GeistScope is a professional bug bounty and red-team workstation designed so an
AI operator can assist during authorized engagements without receiving raw shell
access or unbounded authority. The strategic direction is an AI-native
offensive security operating system built around operational memory,
deterministic replay, a persistent security graph, browser-native
instrumentation, and investigation workflows. The current implementation is a
Rust CLI/TUI suite that writes to a shared filesystem layout (the "engagement
directory").

The product direction is a TUI-based bug-hunting browser backed by a local AI
harness. That harness should expose scoped, audited tool endpoints around the
existing Rust engine.

## Repository layout

```
geistscope/
├── engine-rust/           # All tooling — see engine-rust/README.md
│   ├── engagement/        # lib: workspace layout, scope, audit, findings
│   ├── session/           # lib: session.json config + auth header resolution
│   ├── payload-engine/    # lib: stack-aware payload selection
│   ├── security-graph/    # lib: local-first graph model + JSONL store
│   ├── http-client/       # lib: shared reqwest wrapper
│   ├── llm-client/        # lib: Anthropic + Ollama
│   ├── fingerprint/       # lib+bin: tech stack detection
│   ├── corpus-builder/    # lib+bin: crt.sh + Wayback corpus miner
│   ├── subdomain-enum/    # lib+bin: passive + active subdomain enum
│   ├── mg-scan/           # lib+bin: async TCP port scanner
│   ├── mg-recon/          # bin: 4-stage recon orchestrator
│   ├── ai-prioritize/     # bin: LLM-ranked attack surface + chain analysis
│   ├── mg-crawl/          # bin: BFS crawler + JS/API/GraphQL/library extraction
│   ├── mg-probe/          # bin: passive posture + optional active endpoint checks
│   ├── mg-fuzz/           # bin: Burp Intruder-style payload fuzzer
│   ├── mg-replay/         # bin: Burp Repeater-style finding verification
│   ├── mg-report/         # lib+bin: bounty report generation + CVSS scoring
│   ├── mg-recopilot/      # lib+bin: decompiled-pseudocode RE copilot
│   ├── mg-aifuzz/         # lib+bin: adversarial prompt-injection fuzzer
│   ├── mg-exploitgen/     # lib+bin: CVE-driven exploit-project scaffolding
│   └── mg-harness/        # lib+bin: scoped AI/TUI endpoint dispatcher
└── docs/                  # Design notes (currently sparse)
```

Important docs:

```
docs/PRODUCT_DOCTRINE.md       # product definition + coding doctrine
docs/STRATEGIC_HANDOFF.md      # productionization + platform evolution plan
docs/BUG_HUNTING_METHODOLOGY.md # authorized testing methodology
docs/AI_TOOL_ENDPOINTS.md      # model-callable tool endpoint contract
docs/FEATURE_ROADMAP.md        # prioritized implementation roadmap
docs/RESEARCH_SOURCES.md       # web/local sources used for the doctrine
```

## Engagement directory layout (runtime)

```
engagements/<name>/
├── engagement.json     # metadata
├── scope.json          # in_scope / out_of_scope patterns
├── notes.md            # human notes
├── audit.log           # append-only tool invocation log
├── recon/
│   ├── subdomain-enum.json
│   ├── fingerprint.json
│   ├── mg-scan.json
│   ├── summary.json         ← primary AI input
│   ├── probe-report.json
│   └── fuzz-<ts>.json
├── crawl/<host>/
│   ├── pages/<sha256>.html
│   ├── js/<sha256>.js
│   ├── index.json
│   ├── endpoints.json
│   └── secrets.json
├── findings/
│   ├── <id>-<slug>.md
│   └── <id>-<slug>-replay-<date>.json
├── graph/
│   ├── nodes.jsonl        # security-graph nodes
│   └── edges.jsonl        # security-graph edges
├── re/<binary>/
│   ├── manifest.json        # optional: arch, mitigations, notes
│   ├── raw/<func>.c         # operator-supplied decompiled pseudocode
│   ├── <func>.md            # mg-recopilot Markdown analysis
│   └── <func>.json          # mg-recopilot structured analysis
├── aifuzz/
│   ├── CONSENT              # marker file; required before mg-aifuzz run
│   ├── sentinels.txt        # optional: known system-prompt sentinels
│   └── <run-id>.jsonl       # one row per prompt-injection attempt
└── exploits/<cve>/
    ├── Cargo.toml           # generated crate skeleton
    ├── runbook.md           # operator runbook with authorized-testing banner
    ├── src/                 # scanner, validator, payload, cleanup stages
    └── tests/smoke.rs       # scaffold compile-only test
```

## Code conventions (Rust)

All Rust files must have a block comment header:

```rust
/*******************************************************************
 * Filename:        filename.rs
 * Author:          Jeff
 * Date:            YYYY-MM-DD
 * Description:     One-line summary
 * Notes:           Non-obvious context
 *******************************************************************/
```

Function comments: `// Verb + noun` above every function and major code block.
No multi-line docstrings. Constants in `ALL_CAPS_SNAKE_CASE`.
Every crate must pass `cargo clippy -- -D warnings` before commit.

## Active development focus

**`mg-tui` is the foundation for the product UI.** It currently reads engagement
files and renders engagements, hosts, findings, fuzz results, logs, harness
activity, and browser inspection with page search plus redacted response
headers/cookies. When an engagement is selected, browser requests can apply the
env-backed auth headers configured in `session.json` without rendering secret
values. `mg-engagement credentials-set/test` and harness `session.*` endpoints
manage those profiles without exposing secret values. `mg-crawl`, `mg-probe`,
`mg-fuzz`, and the TUI browser now apply configured session headers. Host rows
can pivot directly into the Browser tab. The next UI step is not a marketing
GUI; it is a TUI bug-hunting browser with traffic navigation, replay/fuzz
actions, scope visibility, and AI-assisted next-test suggestions.

**Next engine layer:** `mg-harness`, a local endpoint dispatcher that lets the
AI call scoped tools through typed schemas. The first slice exists with
`endpoint.registry`, `engagement.open`, `engagement.status`, `scope.check`,
confirmed `recon.run`, scoped `finding.create`, bounded `finding.read`, session
endpoints, and graph endpoints (`graph.ingest`, `graph.summary`,
`graph.neighbors`). See `docs/AI_TOOL_ENDPOINTS.md`.

High-priority candidates: Interactsh/OOB integration, request corpus import,
subdomain takeover checks, GraphQL/OpenAPI testing, two-account access-control
diffing, shared rate limits, and evidence/report generation.

## Key reference files

| File | Purpose |
|---|---|
| `docs/PRODUCT_DOCTRINE.md` | Governs product direction, coding decisions, and AI-harness safety |
| `docs/STRATEGIC_HANDOFF.md` | Governs platform evolution toward graph, replay, browser instrumentation, and investigation workflows |
| `docs/AI_TOOL_ENDPOINTS.md` | Endpoint schema, risk classes, scope/audit/redaction policy |
| `docs/BUG_HUNTING_METHODOLOGY.md` | Field workflow for bug bounty, pentest, and red-team use |
| `docs/FEATURE_ROADMAP.md` | Current and suggested feature roadmap |
| `engine-rust/README.md` | Crate table, workflow examples, fuzz template format |
| `engine-rust/ULTRAPLAN.md` | Milestone status, architecture decisions, deferred items |
| `~/.claude/bug-hunting-skills/` | Skill files used by ai-prioritize |

## Workflow

```bash
mg-engagement init <name> --target <domain>
mg-recon <name>
mg-crawl <name> https://<host>
mg-probe <name>
ai-prioritize <name>
mg-fuzz <name> --template tmpl.txt --payloads sqli
mg-replay <name> <finding-id>
```

## Environment variables

| Var | Default | Used by |
|---|---|---|
| `MG_ENGAGEMENTS_DIR` | `engagements` | all tools |
| `MG_SKILLS_DIR` | `~/.claude/bug-hunting-skills` | ai-prioritize |
| `ANTHROPIC_API_KEY` | — | ai-prioritize |
