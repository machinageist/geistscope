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
mg-report generate target-bounty YYYYMMDD-001
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
| `mg-harness`     | Scoped JSON endpoint dispatcher + chat REPL (Ollama / OpenAI-compatible / Anthropic) |

### Chat REPL

`mg-harness chat <engagement>` opens an interactive coding-agent loop pinned to
one engagement. The model gets tool-use access to every implemented harness
endpoint — recon, scans, graph queries, report generation — and findings emitted
by the tools land in the engagement workspace automatically.

```bash
# Local Ollama, no API key required
mg-harness chat my-engagement --backend ollama --model qwen2.5-coder

# OpenAI-compatible server (LM Studio, vLLM, OpenRouter, etc.)
mg-harness chat my-engagement --backend openai --base-url http://localhost:1234/v1 \
                                                --model llama-3-70b-instruct

# Anthropic (reads ANTHROPIC_API_KEY)
mg-harness chat my-engagement --backend anthropic --model claude-opus-4-7
```

Active-class endpoints prompt before running. Destructive endpoints (privesc,
loot) are hidden from the catalog unless `--unsafe-mode` is passed.
Slash commands: `/help`, `/tools`, `/reset`, `/quit`.

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

## Extended Tool Suite

69 additional binaries covering every major bug-bounty and pentest surface. All read/write to the engagement workspace and emit standardized findings to `engagements/<name>/findings/`. All are accessible as harness endpoints (`mg-harness`) and via `mg-recon --with <tool>`.

### Active Vulnerability Detection

| Binary | What it does |
|---|---|
| `mg-xss` | Reflected/DOM XSS — 7-payload set, OOB blind mode |
| `mg-sqli` | SQL injection — error-based (6 DB families) and time-based blind |
| `mg-ssrf` | SSRF — cloud metadata payloads with OOB correlation |
| `mg-ssti` | SSTI fingerprinting — Jinja2/Twig/FreeMarker/ERB with RCE probe |
| `mg-xxe` | XXE injection — file disclosure and blind OOB payloads |
| `mg-traversal` | Path traversal/LFI — 9 bypass payloads, OS-keyed detection |
| `mg-redirect` | Open redirect — 20 redirect-prone param names, 7 bypass payloads |
| `mg-csrf` | CSRF — token presence, SameSite, tampered-Origin probe |
| `mg-cmdinject` | OS command injection — error-based, time-based, OOB |
| `mg-smuggle` | HTTP request smuggling — CL.TE, TE.CL, TE.TE via raw TCP/TLS |
| `mg-cache-poison` | Cache poisoning — unkeyed header injection, fat GET, cache detection |
| `mg-proto-pollute` | Prototype pollution — JSON body and URL param injection |
| `mg-deser` | Deserialization detection — Java/PHP/Python magic byte scanner |

### Authentication & Authorization

| Binary | What it does |
|---|---|
| `mg-jwt` | JWT attacks — alg confusion (RS256→HS256), brute force, claim override |
| `mg-oauth` | OAuth 2.0 — state CSRF, redirect_uri bypass, PKCE downgrade |
| `mg-authz` | IDOR/BOLA — multi-role request replay, ownership-scoped URL detection |
| `mg-brute` | Login brute force — rate-limit and lockout detection |
| `mg-session-audit` | Session fixation, entropy, cookie flags, invalidation testing |
| `mg-apikey` | API key extraction — 11-pattern regex scan across crawl corpus |

### Recon & OSINT

| Binary | What it does |
|---|---|
| `mg-takeover` | Subdomain takeover — 13-service fingerprint table |
| `mg-dns-enum` | DNS enumeration — zone transfer, wildcard, DNSSEC, SRV, PTR sweep |
| `mg-dns-history` | Historical DNS — SecurityTrails/HackerTarget; flags forgotten infra |
| `mg-dns-rebind` | DNS rebinding payload generator with TTL-aware HTML attack page |
| `mg-cname-chain` | Full CNAME chain — detects circular refs and hijackable intermediates |
| `mg-vhost` | Virtual host brute force — 50-prefix built-in list, Host injection |
| `mg-whois` | WHOIS, ASN lookup, BGP prefix enumeration |
| `mg-shodan` | Shodan host lookup, CVE correlation, port/banner summary |
| `mg-github` | GitHub org dork search for exposed secrets and config files |
| `mg-cloud-enum` | S3/GCS/Azure bucket enumeration — 36 candidate names |
| `mg-social` | GitHub org member enumeration, email pattern derivation |
| `mg-metadata` | Document metadata extraction from PDF/DOCX/XLSX/JPEG |
| `mg-google-dork` | 14 targeted Google dork queries with optional CSE execution |
| `mg-breach` | HIBP domain breach lookup with password-data classification |

### API & Modern Protocols

| Binary | What it does |
|---|---|
| `mg-graphql` | GraphQL introspection, batch abuse, depth limit testing |
| `mg-openapi` | OpenAPI/Swagger spec parser — auto-replays every endpoint |
| `mg-grpc` | gRPC reflection probe, service enumeration, unauthenticated call detection |
| `mg-websocket` | WebSocket CSWSH test, unauthenticated access, message fuzzing |
| `mg-cors-exploit` | Active CORS — reflection, null-origin, subdomain bypass |
| `mg-csp` | CSP header analyzer — unsafe-inline, wildcards, JSONP bypass domains |

### JavaScript & Client-Side

| Binary | What it does |
|---|---|
| `mg-js-analyze` | Static JS analysis — endpoints, secrets, JWT tokens, source maps |
| `mg-sourcemap` | Source map downloader — reconstructs original source, scans for secrets |

### Infrastructure & Protocol Auditing

| Binary | What it does |
|---|---|
| `mg-tls-scan` | TLS/SSL audit — protocol, cipher, cert validity via rustls |
| `mg-ssh-audit` | SSH config audit — banner, KEX/cipher/MAC weakness detection |
| `mg-udp-scan` | UDP scanner — service probes for DNS/NTP/SNMP/mDNS/SSDP |
| `mg-smtp` | SMTP enumeration — VRFY/EXPN user enum, open relay, header injection |
| `mg-snmp` | SNMP community string brute force and OID walk |
| `mg-smb` | SMB2 NEGOTIATE probe — signing check and null-session detection |
| `mg-http2` | HTTP/2 — h2c upgrade, ALPN check, rapid-reset heuristic |

### Cloud & Container Security

| Binary | What it does |
|---|---|
| `mg-aws` | AWS SSRF chain — IMDSv1/v2 metadata to IAM credential extraction |
| `mg-gcp` | GCP SSRF chain — project ID, service account, OAuth token |
| `mg-azure` | Azure IMDS SSRF — managed identity token, subscription info |
| `mg-k8s` | Kubernetes — API, etcd, kubelet, dashboard exposure checks |
| `mg-docker` | Docker API exposure detection with container/image enumeration |
| `mg-serverless` | Lambda/GCP SSRF chain — runtime API and IAM credential probe |

### Post-Exploitation

| Binary | What it does |
|---|---|
| `mg-privesc-linux` | Linux privesc enumeration — SUID, sudo, caps, cron, NFS |
| `mg-privesc-windows` | Windows privesc enumeration — token privs, unquoted paths, registry |
| `mg-loot` | Post-access credential harvesting — SSH keys, AWS, git, Docker, kubectl |

### Mobile

| Binary | What it does |
|---|---|
| `mg-apk` | Android APK static analysis — manifest flags, DEX secrets, network config |
| `mg-ipa` | iOS IPA static analysis — ATS config, entitlements, binary string extraction |

### OOB & Interoperability

| Binary | What it does |
|---|---|
| `mg-oob` | HTTP OOB callback server — blind SSRF/XXE/CMDi/SQLi detection |
| `mg-secret-validate` | Live secret validation — AWS, GitHub, Stripe, Slack |
| `mg-nuclei-bridge` | Runs Nuclei against scope, imports findings as structured JSON |

### Engagement Workflow

| Binary | What it does |
|---|---|
| `mg-screenshot` | Headless bulk screenshotter with HTML index grid |
| `mg-diff` | Scan-over-scan diff — new subdomains, ports, endpoints, status changes |
| `mg-notify` | Finding webhook push to Slack/Discord/ntfy.sh |
| `mg-timeline` | Chronological engagement timeline reconstructed from workspace files |
| `mg-leak-monitor` | Continuous GitHub secret monitoring with state persistence |

## License

MIT
