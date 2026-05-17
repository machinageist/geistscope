# GeistScope

Professional bug bounty and red-team tooling for human + AI collaboration.
The current system is a Rust CLI/TUI suite that writes to a shared engagement
workspace. The product direction is an AI-native offensive security operating
system: a TUI-based bug-hunting browser, scoped AI harness, deterministic replay
layer, and persistent security graph around dedicated tool endpoints.

## Architecture

```text
crates/               Rust workspace: CLIs, libraries, TUI
tests/                Integration smoke tests
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
      ├── mg-crawl        ← BFS crawler; extracts JS secrets, endpoints, GraphQL/library signals
      │
      ├── mg-probe        ← Passive security posture: headers, CORS, cookies, debug paths
      │
      ├── mg-fuzz         ← Payload fuzzer (Burp Intruder equivalent)
      ├── mg-replay       ← Finding verification (Burp Repeater equivalent)
      │
      ├── mg-report       ← HackerOne-ready report generation with local CVSS scoring
      │
      └── mg-tui          ← Terminal dashboard / TUI browser foundation

mg-harness            ← Scoped AI tool endpoint dispatcher
```

## Quick start

```bash
# Build and install everything
cd crates
cargo build --workspace
for crate in engagement subdomain-enum mg-scan fingerprint mg-recon \
             ai-prioritize mg-crawl mg-probe mg-fuzz mg-replay mg-report mg-tui mg-harness; do
    cargo install --path $crate
done

# Initialize and run a full engagement
mg-engagement init target-bounty --target target.example.com --platform hackerone
mg-recon target-bounty
mg-crawl target-bounty https://www.target.example.com
mg-probe target-bounty
ai-prioritize target-bounty        # requires ANTHROPIC_API_KEY or local Ollama
mg-report generate target-bounty 2026-05-15-001
```

## Binaries

| Binary           | What it does                                        |
|------------------|-----------------------------------------------------|
| `mg-engagement`  | Init workspaces, manage scope, add notes, findings  |
| `subdomain-enum` | Passive CT log + active DNS brute force enum        |
| `mg-scan`        | Async TCP port scanner                              |
| `mg-fingerprint` | HTTP tech stack detection                           |
| `mg-recon`       | Orchestrates the full 4-stage recon pipeline        |
| `ai-prioritize`  | LLM-ranked attack surface and exploit-chain analysis |
| `mg-crawl`       | BFS crawler with JS secrets, endpoints, internal refs, GraphQL and library signals |
| `mg-probe`       | Passive posture checker with optional low-volume active endpoint probes |
| `mg-fuzz`        | Burp Intruder-style HTTP fuzzer                     |
| `mg-replay`      | Burp Repeater-style finding verification            |
| `mg-report`      | HackerOne-ready report drafts with local CVSS 3.1 scoring |
| `mg-tui`         | Ratatui dashboard/browser: engagements, hosts, findings, fuzz, logs, harness status, host pivoting, page rendering, inspector, search, and session headers |
| `mg-harness`     | Scoped JSON endpoint dispatcher for TUI and AI tool calls |

Credential profiles are stored as environment-variable references, not raw
secrets:

```bash
mg-engagement credentials-set acme-bounty --token-env MG_TOKEN
mg-engagement credentials-test acme-bounty --url https://api.example.com/me
```

`mg-crawl`, `mg-probe`, `mg-fuzz`, and the TUI browser apply those headers when
an engagement has a configured session profile.

## Core Libraries

| Library | What it does |
|---------|--------------|
| `session` | Engagement auth/session config and header resolution for tools without plaintext token storage |
| `payload-engine` | Stack-aware payload selection for fuzzing and harness planning |
| `security-graph` | Local-first operational intelligence graph with deterministic node/edge IDs |
| `mg-report` | Shared report-generation library used by the CLI and harness endpoint |

## Integration Smoke Test

The Docker-backed smoke target lives in `tests/target/`. It exercises crawl,
active probe, and report generation against known local bugs:

```bash
docker compose -f tests/target/docker-compose.yml up -d --wait
bash tests/integration/pipeline-smoke.sh
docker compose -f tests/target/docker-compose.yml down -v
```

## Requirements

- Rust 1.82+ (edition 2024, let-chain syntax)
- `ANTHROPIC_API_KEY` for ai-prioritize (falls back to Ollama if unset)
- Bug-hunting skill files at `~/.claude/bug-hunting-skills/` (for ai-prioritize)

## License

MIT
