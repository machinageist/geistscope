# GeistScope

Automated bug bounty toolchain designed for human + AI collaboration.
Tools write to a shared file layout; an AI operator reads the same files — no custom IPC.

## Architecture

```
engine-rust/          Rust workspace — 10 binaries, 4 libraries
docs/                 Design notes
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
```

## Quick start

```bash
# Build and install everything
cd engine-rust
cargo build --workspace
for crate in engagement subdomain-enum mg-scan fingerprint mg-recon \
             ai-prioritize mg-crawl mg-probe mg-fuzz mg-replay; do
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

## Requirements

- Rust 1.82+ (edition 2024, let-chain syntax)
- `ANTHROPIC_API_KEY` for ai-prioritize (falls back to Ollama if unset)
- Bug-hunting skill files at `~/.claude/bug-hunting-skills/` (for ai-prioritize)

## License

MIT
