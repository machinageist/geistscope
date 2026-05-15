# GeistScope

Professional bug bounty and red-team tooling for human + AI collaboration.
The current system is a Rust CLI/TUI suite that writes to a shared engagement
workspace. The product direction is a TUI-based bug-hunting browser with a
scoped AI harness and dedicated tool endpoints at its core.

## Architecture

```text
engine-rust/          Rust workspace: CLIs, libraries, TUI
docs/                 Product doctrine, methodology, AI endpoint contract, roadmap
CLAUDE.md             AI session orientation (read this first)
```

## Pipeline overview

```
[Target domain]
      │
      ▼
mg-recon              ← subdomain enum + fingerprint + port scan → summary.json
      │
      ├── ai-prioritize   ← LLM ranks attack surface using skill files
      │
      ├── mg-crawl        ← BFS crawler; extracts JS secrets + API endpoints
      │
      ├── mg-probe        ← Passive security posture: headers, CORS, cookies, debug paths
      │
      ├── mg-fuzz         ← Payload fuzzer (Burp Intruder equivalent)
      │
      └── mg-replay       ← Finding verification (Burp Repeater equivalent)
      │
      └── mg-tui          ← Terminal dashboard / TUI browser foundation

Planned:

mg-harness            ← Scoped AI tool endpoint dispatcher
```

## Quick start

```bash
# Build and install everything
cd engine-rust
cargo build --workspace
for crate in engagement subdomain-enum mg-scan fingerprint mg-recon \
             ai-prioritize mg-crawl mg-probe mg-fuzz mg-replay mg-tui mg-harness; do
    cargo install --path $crate
done

# Initialize and run a full engagement
mg-engagement init target-bounty --target target.example.com --platform hackerone
mg-recon target-bounty
mg-crawl target-bounty https://www.target.example.com
mg-probe target-bounty
ai-prioritize target-bounty        # requires ANTHROPIC_API_KEY or local Ollama
```

## Binaries

| Binary           | What it does                                        |
|------------------|-----------------------------------------------------|
| `mg-engagement`  | Init workspaces, manage scope, add notes, findings  |
| `subdomain-enum` | Passive CT log + active DNS brute force enum        |
| `mg-scan`        | Async TCP port scanner                              |
| `mg-fingerprint` | HTTP tech stack detection                           |
| `mg-recon`       | Orchestrates the full 4-stage recon pipeline        |
| `ai-prioritize`  | LLM-ranked attack surface from recon data           |
| `mg-crawl`       | BFS web crawler with JS secret/endpoint extraction  |
| `mg-probe`       | Passive security posture checker                    |
| `mg-fuzz`        | Burp Intruder-style HTTP fuzzer                     |
| `mg-replay`      | Burp Repeater-style finding verification            |
| `mg-tui`         | Ratatui dashboard and browser: engagements, hosts, findings, fuzz, logs, harness status, page rendering, inspector, search, and session headers |
| `mg-harness`     | Scoped JSON endpoint dispatcher for TUI and AI tool calls |

## Core Libraries

| Library | What it does |
|---------|--------------|
| `session` | Engagement auth/session config and header resolution for tools without plaintext token storage |

## Governing docs

| File | Purpose |
|------|---------|
| `docs/PRODUCT_DOCTRINE.md` | Product definition, coding doctrine, AI-harness safety rules |
| `docs/BUG_HUNTING_METHODOLOGY.md` | Authorized testing workflow and bug-class coverage model |
| `docs/AI_TOOL_ENDPOINTS.md` | Provider-neutral endpoint contract for model-callable tools |
| `docs/FEATURE_ROADMAP.md` | Prioritized TUI browser, harness, recon, OOB, reporting roadmap |
| `docs/RESEARCH_SOURCES.md` | Web and local sources used to shape the methodology |

## Requirements

- Rust 1.82+ (edition 2024, let-chain syntax)
- `ANTHROPIC_API_KEY` for ai-prioritize (falls back to Ollama if unset)
- Bug-hunting skill files at `~/.claude/bug-hunting-skills/` (for ai-prioritize)

## License

MIT
