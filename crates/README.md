# GeistScope engine — Rust workspace

Recon, web testing, replay, fuzzing, and TUI tooling for authorized bug bounty,
pentest, and red-team work. Tools are designed to be used standalone, chained
through the engagement workspace, and consumed by an AI harness through scoped
tool endpoints.

## Crates

| Crate            | Type     | Binary           | Purpose                                                              |
| ---------------- | -------- | ---------------- | -------------------------------------------------------------------- |
| `engagement`     | lib+bin  | `mg-engagement`  | Bug bounty engagement workspace: scope, audit, findings              |
| `session`        | lib      | —                | Engagement session config and auth header resolution for tools       |
| `payload-engine` | lib      | —                | Stack-aware payload selection for fuzzing and harness planning       |
| `security-graph` | lib      | —                | Local-first operational intelligence graph and JSONL store           |
| `http-client`    | lib      | —                | Shared reqwest wrapper: UA rotation, rate limit, jittered retry      |
| `llm-client`     | lib      | —                | Unified Ollama (local) + Anthropic LLM interface                     |
| `fingerprint`    | lib+bin  | `mg-fingerprint` | HTTP response → tech stack detection                                 |
| `corpus-builder` | lib+bin  | `corpus-builder` | Mine crt.sh + Wayback into a SQLite subdomain/path corpus            |
| `subdomain-enum` | lib+bin  | `subdomain-enum` | Passive (CT logs) + active (DNS brute force) subdomain enum          |
| `mg-scan`        | lib+bin  | `mg-scan`        | Async TCP port scanner with banner grab + stealth controls           |
| `mg-recon`       | bin      | `mg-recon`       | Full recon pipeline: subdomain enum → fingerprint → port scan → summary |
| `ai-prioritize`  | bin      | `ai-prioritize`  | Rank attack surface and write exploit-chain analysis with LLM        |
| `mg-crawl`       | bin      | `mg-crawl`       | BFS crawler: HTML, JS secrets, endpoints, internal refs, GraphQL and library signals |
| `mg-probe`       | bin      | `mg-probe`       | Passive posture plus optional `--active` marker/SQL/open-redirect probes |
| `mg-fuzz`        | bin      | `mg-fuzz`        | Burp Intruder-style payload fuzzer: sniper / battering-ram / pitchfork / cluster-bomb |
| `mg-replay`      | bin      | `mg-replay`      | Replay curl evidence from findings; verdict: still_vulnerable / appears_fixed |
| `mg-report`      | lib+bin  | `mg-report`      | Generate bounty-ready reports from findings with local CVSS 3.1 scoring |
| `mg-tui`         | bin      | `mg-tui`         | Ratatui dashboard/browser with host pivoting, harness status, inspector, search, and session headers |
| `mg-harness`     | lib+bin  | `mg-harness`     | Scoped JSON endpoint dispatcher for TUI and AI tool calls                     |
| `mg-recopilot`   | bin      | `mg-recopilot`   | Decompiled-pseudocode analysis: reads RE output, writes structured findings   |
| `mg-aifuzz`      | bin      | `mg-aifuzz`      | Adversarial LLM-endpoint fuzzer; requires operator consent before sending     |
| `mg-exploitgen`  | bin      | `mg-exploitgen`  | CVE-driven exploit scaffolding from CVE description + target-env JSON         |

`mg-engagement credentials-set` writes `session.json` using env-var references
only. `mg-harness session.get_headers` resolves headers for tools but returns
redacted metadata to model-visible callers. `mg-crawl`, `mg-probe`, `mg-fuzz`,
and `mg-tui` apply configured session headers through their HTTP clients.

## Dependency graph

```
http-client ◄─── fingerprint ◄─── mg-recon ◄─── ai-prioritize
            ◄─── corpus-builder           ◄─── mg-probe (reqwest direct)
            ◄─── mg-crawl (reqwest direct)

engagement ◄─── subdomain-enum
           ◄─── session
           ◄─── mg-scan
           ◄─── fingerprint
           ◄─── mg-recon
           ◄─── ai-prioritize
           ◄─── mg-crawl
           ◄─── mg-probe
           ◄─── mg-fuzz
           ◄─── mg-replay
           ◄─── mg-report
           ◄─── security-graph

llm-client ◄─── ai-prioritize
           ◄─── mg-report

mg-recon ◄─── mg-harness
engagement ◄─── mg-harness
mg-report ◄─── mg-harness
security-graph ◄─── mg-harness
```

Planned harness layer:

```text
mg-harness -> engagement/http-client/llm-client/current tool libraries
mg-tui     -> mg-harness endpoints for replay, fuzz, OOB, reporting, ranking
```

Add typed endpoint wrappers — no arbitrary command execution.

Implemented harness endpoints:

- `endpoint.registry`
- `engagement.open`
- `engagement.status`
- `scope.check`
- `recon.run` (requires `confirmed: true`)
- `session.set` (requires `confirmed: true`)
- `session.get_headers`
- `graph.ingest`
- `graph.summary`
- `graph.neighbors`
- `chain.read`
- `finding.create`
- `finding.read`
- `report.generate`

## Engagement directory layout

```
engagements/<name>/
├── engagement.json        # name, target, platform, url, created_at, tags
├── scope.json             # in_scope / out_of_scope patterns (default-deny)
├── notes.md               # human-editable running notes
├── audit.log              # append-only log of every tool invocation
├── recon/
│   ├── subdomain-enum.json  # discovered subdomains + IPs
│   ├── fingerprint.json     # hostname → tech stack map
│   ├── mg-scan.json         # per-host open ports
│   ├── summary.json         # merged per-host record (primary AI input)
│   ├── probe-report.json    # security header / CORS / cookie check results
│   └── fuzz-<ts>.json       # payload fuzzer results per run
├── crawl/
│   └── <host>/
│       ├── pages/<sha256>.html
│       ├── js/<sha256>.js
│       ├── index.json         # URL → sha256 map
│       ├── endpoints.json     # enriched JS/form API paths
│       ├── secrets.json       # regex-matched secret candidates
│       ├── internal-refs.json # internal hostnames/RFC1918 refs from JS
│       ├── vulnerable-libraries.json # embedded vulnerable JS library hints
│       └── graphql-candidates.json # GraphQL signals, plus graphql-schema.json if introspection succeeds
├── findings/
│   ├── <id>-<slug>.md         # one markdown file per finding
│   ├── <id>-<slug>-report.md  # bounty-ready report generated by mg-report
│   └── <id>-<slug>-replay-<date>.json  # replay verdict
└── graph/
    ├── nodes.jsonl            # local security-graph nodes
    └── edges.jsonl            # local security-graph edges
```

## Typical bug bounty workflow

```bash
# 1. Initialize the engagement
mg-engagement init acme-bounty --target acme.example.com --platform hackerone

# 2. Refine scope (default is target + *.target)
mg-engagement scope-deny acme-bounty '*.dev.acme.example.com'

# 3. Full automated recon (resumable — skips completed stages)
mg-recon acme-bounty

# 4. Crawl HTTP-accessible hosts
mg-crawl acme-bounty https://www.acme.example.com https://api.acme.example.com

# 5. Passive security posture check (headers, CORS, cookies, debug paths, stack traces)
mg-probe acme-bounty

# 6. AI-ranked priority list (Anthropic or Ollama)
ai-prioritize acme-bounty

# 7. Active fuzzing — e.g. IDOR on user ID parameter
mg-fuzz acme-bounty --template idor.txt --payloads numbers:1-200 --mode sniper

# 8. Replay a finding's evidence to confirm it's still exploitable
mg-replay acme-bounty 20260509-probe-001
```

## Fuzz template format

Templates are raw HTTP requests with `§marker§` position markers:

```
GET /api/v1/users/§id§ HTTP/1.1
Host: api.acme.example.com
Authorization: Bearer VALID_TOKEN
```

Built-in payload sets: `sqli`, `xss`, `ssti`, `traversal`, `ssrf`,
`common-passwords`, `http-methods`, `usernames`, `numbers:N-M`.

Attack modes mirror Burp Intruder: `sniper`, `battering-ram`, `pitchfork`, `cluster-bomb`.

## Build / test / install

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings

# Install all binaries system-wide
for crate in engagement subdomain-enum mg-scan fingerprint mg-recon ai-prioritize mg-crawl mg-probe mg-fuzz mg-replay mg-report mg-tui mg-harness; do
    cargo install --path $crate
done
```

## AI harness direction

Future AI-facing code should not add arbitrary command execution. Add typed
endpoint wrappers around existing libraries and CLIs:

- Validate model-provided JSON before dispatch.
- Check engagement scope before active network traffic.
- Redact tokens, cookies, and sensitive response bodies before model ingestion.
- Write audit events for recommendations, dispatches, blocks, and results.
- Keep high-active actions behind explicit user confirmation.

Provider-specific clients belong behind `llm-client` or a harness adapter; tool
policy belongs in the harness.

## Code conventions

- Block comment header at top of every file (Filename / Author / Date / Description / Notes)
- `// Verb + noun` above every function and major code block
- Constants in `ALL_CAPS_SNAKE_CASE`; declare-and-initialize together
- 4-space indentation; section dividers sit above the block they describe
- `-D warnings` passes on every crate before commit
