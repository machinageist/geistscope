# GeistScope engine — Rust workspace

Recon and offensive-security tooling for bug bounty hunting.
Tools are designed to be used standalone, chained through the engagement workspace,
and consumed by Claude as a collaborative AI operator.

## Crates

| Crate            | Type     | Binary           | Purpose                                                              |
| ---------------- | -------- | ---------------- | -------------------------------------------------------------------- |
| `engagement`     | lib+bin  | `mg-engagement`  | Bug bounty engagement workspace: scope, audit, findings              |
| `http-client`    | lib      | —                | Shared reqwest wrapper: UA rotation, rate limit, jittered retry      |
| `llm-client`     | lib      | —                | Unified Ollama (local) + Anthropic LLM interface                     |
| `fingerprint`    | lib+bin  | `mg-fingerprint` | HTTP response → tech stack detection                                 |
| `corpus-builder` | lib+bin  | `corpus-builder` | Mine crt.sh + Wayback into a SQLite subdomain/path corpus            |
| `subdomain-enum` | lib+bin  | `subdomain-enum` | Passive (CT logs) + active (DNS brute force) subdomain enum          |
| `mg-scan`        | lib+bin  | `mg-scan`        | Async TCP port scanner with banner grab + stealth controls           |
| `mg-recon`       | bin      | `mg-recon`       | Full recon pipeline: subdomain enum → fingerprint → port scan → summary |
| `ai-prioritize`  | bin      | `ai-prioritize`  | Rank attack surface with LLM (Anthropic primary, Ollama fallback)    |
| `mg-crawl`       | bin      | `mg-crawl`       | BFS crawler: HTML pages + JS secret/endpoint extraction              |
| `mg-probe`       | bin      | `mg-probe`       | Passive security posture: headers, CORS, cookies, debug path exposure |
| `mg-fuzz`        | bin      | `mg-fuzz`        | Burp Intruder-style payload fuzzer: sniper / battering-ram / pitchfork / cluster-bomb |
| `mg-replay`      | bin      | `mg-replay`      | Replay curl evidence from findings; verdict: still_vulnerable / appears_fixed |

## Dependency graph

```
http-client ◄─── fingerprint ◄─── mg-recon ◄─── ai-prioritize
            ◄─── corpus-builder           ◄─── mg-probe (reqwest direct)
            ◄─── mg-crawl (reqwest direct)

engagement ◄─── subdomain-enum
           ◄─── mg-scan
           ◄─── fingerprint
           ◄─── mg-recon
           ◄─── ai-prioritize
           ◄─── mg-crawl
           ◄─── mg-probe
           ◄─── mg-fuzz
           ◄─── mg-replay

llm-client ◄─── ai-prioritize
```

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
│       ├── endpoints.json     # JS-extracted API paths
│       └── secrets.json       # regex-matched secret candidates
└── findings/
    ├── <id>-<slug>.md         # one markdown file per finding
    └── <id>-<slug>-replay-<date>.json  # replay verdict
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
for crate in engagement subdomain-enum mg-scan fingerprint mg-recon ai-prioritize mg-crawl mg-probe mg-fuzz mg-replay; do
    cargo install --path $crate
done
```

## Code conventions

- Block comment header at top of every file (Filename / Author / Date / Description / Notes)
- `// Verb + noun` above every function and major code block
- Constants in `ALL_CAPS_SNAKE_CASE`; declare-and-initialize together
- 4-space indentation; section dividers sit above the block they describe
- `-D warnings` passes on every crate before commit
