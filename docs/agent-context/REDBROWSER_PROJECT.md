# REDBROWSER_PROJECT.md — Red Team Browser Platform

> Flagship long-term project. Open-source offensive security platform.
> Combines an intercepting proxy, recon/attack pipeline, and local AI/ML triage
> into a unified browser-integrated workstation for red teamers and pentesters.
> Companion to SEC_TOOL_ROADMAP.md, RUST_PROJECTS.md, and ENTREPRENEURSHIP.md.
> Last updated: 2026-04

---

## Purpose of This File

When Claude sees this file, it should:
- Walk the user incrementally through the roadmap in order — no skipping stages
- Explain concepts before providing code — educate first, vibe-code only if the user is stuck
- Behave like a senior engineer mentoring a junior engineer
- Connect every component back to its red/blue team security context
- Keep the long-term product vision in mind — every module must be future-productizable

---

## Product Vision

RedBrowser is a privacy-first, local-first offensive security platform that eventually
functions as a full red team browser and workstation. The goal is a tool that red teamers,
pentesters, and security researchers can use instead of Burp Suite — open source,
extensible, and AI-augmented without requiring cloud connectivity.

What makes this different from Burp Suite, Caido, or other existing tools:
- The entire pipeline is automated and AI-mediated — recon output flows directly
  into attack tooling, with an ML layer (trained on CVEs and wordlists) that
  prioritizes the most likely exploitation vectors before the human touches anything
- Local-first AI — no cloud required, no telemetry, models run on-device
- Open source core — the community extends it, which also drives adoption
- Modular architecture — every component can be used standalone or wired together

Long-term: a unified recon → enumerate → prioritize → attack → report workflow,
where AI/ML handles the triage that currently requires hours of manual review.

---

## Architecture Overview

The platform has three major layers. These are built in order.

### Layer 1 — Security Engine (Build First)

This is the core of the project. It runs independently of any browser or UI.
Two languages split by responsibility:
- Go for networking, orchestration, APIs, and session management
- Rust for performance-critical analysis, diffing, and fuzzing

The engine exposes a local REST or gRPC API that every other layer calls.
Keeping the engine headless and API-driven is what makes the platform modular
and eventually productizable.

### Layer 2 — AI/ML Triage Layer (Build in Stage 5-6)

Sits between the recon/enumeration output and the attack tooling.
Consumes findings from the engine and prioritizes them by exploitation likelihood.
Training data: CVE databases, exploit-db, public wordlists, and your own findings over time.

This is the differentiating feature of RedBrowser vs existing tools.
A junior pentester running RedBrowser should be able to get to a high-probability
attack vector in less time than an experienced pentester running Burp manually.

### Layer 3 — Browser Integration (Build Last)

Early development uses Firefox with an extension bridge.
The extension routes traffic through the proxy and adds "Send to RedBrowser" context actions.
A hardened browser wrapper is a long-term consideration only after the engine and
AI layer have traction and contributors.

---

## Repository Structure

```
redbrowser/
├── engine-go/
│   ├── cmd/
│   │   └── proxy/          # CLI entry point — starts the proxy and API server
│   ├── api/                # REST/gRPC endpoints exposed to dashboard and extension
│   ├── storage/            # Traffic database — requests, responses, sessions
│   └── session/            # Session management — groups traffic by target
│
├── engine-rust/
│   ├── diff-engine/        # Response comparison at scale
│   ├── parsers/            # Fast header, body, and parameter parsing
│   └── fuzzing-core/       # Parameter fuzzer with wordlist and anomaly detection
│
├── ml-triage/
│   ├── models/             # Trained models — CVE likelihood scoring, vector prioritization
│   ├── training/           # Training scripts and dataset pipelines
│   └── api/                # Python FastAPI bridge between ML models and Go engine
│
├── ui-dashboard/           # Local web UI — traffic viewer, graph, fuzzer interface
├── browser-extension/      # Firefox extension — proxy bridge and context menus
└── docs/                   # Architecture docs, API reference, writeups
```

---

## Development Roadmap

Build in order. Each stage depends on the previous one working.

---

## Stage 1 — Intercepting Proxy Engine (Foundation)

Everything depends on this. Do not move to Stage 2 until Stage 1 is solid.

### Project 1.1 — Minimal Intercepting Proxy (Go)

Build an HTTP and HTTPS man-in-the-middle proxy.
This means the proxy generates its own CA certificate, installs it as trusted,
and decrypts TLS traffic so it can read and log it before re-encrypting and forwarding.

Concepts covered: TLS MITM fundamentals, HTTP lifecycle, Go networking, certificate generation.

Features to build:
- HTTP + HTTPS interception
- Generate and trust a local CA certificate
- Log requests and responses with timestamps
- CLI startup with configurable port and log output

Deliverable: a runnable proxy that intercepts browser traffic when set as the system proxy.

### Project 1.2 — Traffic Storage Layer

Capture everything the proxy sees and store it in a queryable format.

Store per-request: method, URL, headers, body, timestamp, session ID, response code,
response headers, response body. The schema here becomes the foundation for every
downstream feature — get it right before building on top of it.

Concepts covered: data modeling, serialization, file vs embedded database tradeoffs
(SQLite via `modernc.org/sqlite` is the right default — embedded, no server, zero setup).

### Project 1.3 — Local REST/gRPC API

Expose the engine to external consumers — the dashboard, extension, and eventually the ML layer.

Endpoints needed initially: list traffic, search traffic by host or path,
export sessions as JSON, replay a request.

Concepts covered: API design, separation of concerns, service architecture.
This step is what turns the proxy from a script into a platform.

### Project 1.4 — Request Replay Engine

Take any captured request and resend it, with optional modifications to headers and body.
Compare the response to the original and surface differences.

Concepts covered: HTTP client design, response diffing, the foundation of manual testing workflow.
This is the first feature that makes the tool genuinely useful for pentesting.

---

## Stage 2 — Recon and Mapping Engine

### Project 2.1 — Endpoint Discovery Engine

Automatically extract from captured traffic: domains and subdomains, API routes,
URL parameters, WebSocket connections, auth patterns, and interesting headers.

This consumes the traffic storage layer — no separate recon process needed.
Everything the browser touches flows through the proxy and gets mapped automatically.

Output: a structured inventory of the attack surface, in JSON, updated in real time.

### Project 2.2 — Attack Surface Graph

Take the endpoint inventory and model it as a graph: hosts, paths, parameters, and
the relationships between them. Export as JSON or render in the dashboard.

This graph becomes the input to the ML triage layer. The AI needs a structured
representation of the attack surface to score and prioritize it.

---

## Stage 3 — Rust Performance Modules

Go handles orchestration well but is not the right language for tight loops.
The diff engine and fuzzer need Rust for throughput and memory predictability.

### Project 3.1 — Response Diff Engine (Rust)

Compare two HTTP responses at scale — byte-level, semantic, and structural diffing.
This feeds anomaly detection in the fuzzer: a response that differs significantly
from the baseline is a signal worth surfacing.

Integrate as a shared library called via FFI from Go or as a standalone binary
invoked over stdin/stdout. FFI is the better long-term choice.

### Project 3.2 — Fuzzing Engine (Rust)

Parameter fuzzer with wordlist support, configurable concurrency, and anomaly scoring.

Features: fuzz URL parameters, headers, body fields; support custom wordlists;
detect interesting responses by status code, response length delta, and timing anomaly.

This is the attack-side complement to the recon engine. Recon finds the surface;
the fuzzer probes it.

---

## Stage 4 — Local Web Dashboard

Build a UI that connects to the API and makes the platform usable without a terminal.

Features: traffic viewer with filtering, attack surface graph visualization,
fuzzing interface with live results, session explorer grouped by target.

This is the point where RedBrowser starts to look like a product rather than a collection
of tools. The dashboard is what gets shared in demos and screenshots.

Stack: the same Svelte frontend and Rust JSON API decomposition already planned
for mg-server Phase 3. Build mg-server Phase 3 first — the patterns transfer directly.

---

## Stage 5 — ML Triage Layer

This is the differentiating feature. Build it here, after the data pipeline exists
and there is real traffic to train and test against.

### Project 5.1 — CVE and Exploit Corpus Pipeline

Build a data pipeline that ingests CVE descriptions, CVSS scores, affected technologies,
and public exploit-db entries. Normalize into a format suitable for model training.
This is the knowledge base the triage model learns from.

### Project 5.2 — Vector Scoring Model

Given an attack surface graph and a CVE/exploit corpus, train a model that assigns
a likelihood score to each endpoint and parameter: "how probable is it that this
specific vector leads to a finding, given what CVEs exist for this stack?"

This does not have to be a large model. A gradient boosted classifier (XGBoost or LightGBM)
over structured features — HTTP method, parameter name patterns, response behavior,
detected tech stack — is a reasonable starting point. A transformer is not necessary
and would be harder to run locally.

### Project 5.3 — Triage API

Python FastAPI service that loads the trained model and exposes an endpoint:
take an attack surface JSON object, return a prioritized list of vectors with scores and reasoning.
Go engine calls this API after each recon pass.

---

## Stage 6 — AI Modules (Local-First)

Augment the triage layer with a language model for reasoning and reporting.

Capabilities: explain a captured request and what it suggests about the target,
summarize a pentest session in plain English, suggest fuzz payloads for a specific
endpoint type, generate draft report notes from session findings.

Model integration: Ollama as the default local runtime. The integration is model-agnostic —
cloud APIs work as a fallback for machines that cannot run a local model.

---

## Stage 7 — Browser Extension Bridge

Firefox extension that:
- Routes browser traffic through the RedBrowser proxy automatically
- Adds "Send to Fuzzer" and "Send to Diff" context menu actions
- Highlights discovered endpoints in the browser tab
- Shows a summary of what the engine knows about the current host

---

## Stage 8 — Hardened Browser Wrapper (Long Term)

Only begin this after the engine, ML layer, and dashboard have traction and external contributors.
A browser wrapper without a mature engine is just a skin. The engine is the product.

Paths to evaluate when the time comes: Firefox wrapper with locked-down profile,
WebKitGTK for a fully custom embedding. Decision depends on what the community wants.

---

## How to Interact With This File

When the user asks to start or continue:
1. Identify the current stage and project number
2. State the concepts being introduced before writing any code
3. Provide: concepts → implementation plan → starter code → testing steps → next milestone
4. Never jump multiple stages ahead
5. Every design decision should be explained — not just what to build, but why this approach

