# GeistScope — CLAUDE.md

This file orients Claude Code sessions for the GeistScope project.

## What this project is

GeistScope is a personal bug bounty toolchain designed so that Claude can act as
an AI co-operator during live engagements. Tools write to a shared filesystem
layout (the "engagement directory") and Claude reads the same files, making the
collaboration file-native with no custom IPC.

## Repository layout

```
geistscope/
├── engine-rust/           # All tooling — see engine-rust/README.md
│   ├── engagement/        # lib: workspace layout, scope, audit, findings
│   ├── http-client/       # lib: shared reqwest wrapper
│   ├── llm-client/        # lib: Anthropic + Ollama
│   ├── fingerprint/       # lib+bin: tech stack detection
│   ├── corpus-builder/    # lib+bin: crt.sh + Wayback corpus miner
│   ├── subdomain-enum/    # lib+bin: passive + active subdomain enum
│   ├── mg-scan/           # lib+bin: async TCP port scanner
│   ├── mg-recon/          # bin: 4-stage recon orchestrator
│   ├── ai-prioritize/     # bin: LLM-ranked attack surface
│   ├── mg-crawl/          # bin: BFS crawler + JS secret extraction
│   ├── mg-probe/          # bin: passive security posture checker
│   ├── mg-fuzz/           # bin: Burp Intruder-style payload fuzzer
│   └── mg-replay/         # bin: Burp Repeater-style finding verification
└── docs/                  # Design notes (currently sparse)
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
└── findings/
    ├── <id>-<slug>.md
    └── <id>-<slug>-replay-<date>.json
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

**Next crate: `mg-tui`** — Ratatui terminal UI
Architecture is specified in `engine-rust/ULTRAPLAN.md` under "Frontend layer".
Build the TUI before the GUI. Data comes from engagement JSON files — no new IPC.

## Key reference files

| File | Purpose |
|---|---|
| `engine-rust/README.md` | Crate table, workflow examples, fuzz template format |
| `engine-rust/ULTRAPLAN.md` | Milestone status, architecture decisions, deferred items |
| `~/.claude/bug-hunting-skills/` | 18 skill files used by ai-prioritize |

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
