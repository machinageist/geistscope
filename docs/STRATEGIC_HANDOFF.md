# GeistScope Strategic Handoff

Last updated: 2026-05-15

## Executive Direction

GeistScope is moving from a modular offensive security toolkit toward an
AI-native operating system for authorized offensive security investigations.
The key shift is from tools that produce files to a persistent operational
intelligence layer that can support replay, graph reasoning, browser-native
instrumentation, collaboration, and enterprise-grade auditability.

Do not position the project as a Burp replacement, a scanner bundle, or an AI
wrapper around existing tools. The durable value is operational memory,
deterministic replay, attack-surface intelligence, workflow acceleration, and
AI-assisted reasoning over scoped evidence.

## Current Strengths

- The engagement directory model is foundational and should remain local-first.
- Tool separation is healthy: recon, crawl, probe, fuzz, replay, reporting, TUI,
  and harness responsibilities are already reasonably bounded.
- The AI safety model is correct: schema-constrained endpoints, scope checks,
  audit logging, and no unrestricted shell access.

## Current Gaps

- Output is still mostly filesystem-centric, which limits semantic reasoning,
  deduplication, attack-chain analysis, and AI context persistence.
- The UX is still tool-centric; professional operators think in investigations
  such as authentication, authorization, tenant isolation, upload handling, and
  privilege boundaries.
- Replay is not yet a first-class deterministic action ledger.
- There is no unified security graph or persistent entity relationship model.
- The TUI is useful but not yet an operational UI for graph, replay, and
  investigation workflows.

## Platform Architecture

### Unified Security Graph

All meaningful engagement entities should become graph objects. Initial node
kinds include hosts, URLs, parameters, identities, JWTs, sessions, cookies,
APIs, findings, technologies, and replay chains. Initial edge kinds include
calls, authenticates_to, references, discovered_by, vulnerable_to, related_to,
and replayed_from.

The preferred production datastore is Postgres with graph/vector extensions
where practical. The near-term implementation may remain file-backed for CI,
offline, and airgapped use, but must expose an adapter boundary that can later
support Postgres without changing harness endpoint semantics.

### Replay Engine

Every meaningful action should become timestamped, attributable, diffable, and
reproducible. Replay storage should preserve raw requests, raw responses,
cookies, auth state, websocket frames, browser state, DOM snapshots, and timing
metadata when those data are available and authorized.

Required replay capabilities are deterministic replay, sequence replay, partial
replay, environment diffing, and patch validation replay. Browser and attack
chain replay are later platform features.

### Browser-Native Instrumentation

The long-term product direction is Chrome DevTools plus Burp/Caido-style
inspection plus AI plus operational memory. Required capabilities include
request interception, websocket inspection, storage and service-worker
inspection, endpoint extraction, auth-flow recording, event tracing, Playwright
automation, session recording, and authenticated replay.

### Investigation-Centric Workflows

The operator should be able to start an investigation object rather than a tool
run. First-class workflows should include authentication, authorization,
multi-tenancy, upload handling, API schema coverage, and privilege boundaries.
Workflow objects should track plans, checkpoints, evidence, replay chains, and
hypotheses.

### AI Reasoning Layer

AI should correlate findings, reason over attack chains, identify anomalies,
detect auth inconsistencies, compare tenant boundaries, and generate replay
plans. AI must not receive shell access, execute arbitrary commands, operate
outside endpoint constraints, or override scope and risk policy.

Context sources should include the security graph, replay store, engagement
memory, browser telemetry, findings, and bounded methodology skills.

### Plugin Ecosystem

The plugin model should eventually support scanner, browser instrumentation,
AI-tool, workflow, and visualization plugins. WASM sandboxing is the preferred
runtime for untrusted plugins; a Python SDK can be a secondary integration path.

### UI Platform

The TUI remains the near-term operator surface. A future desktop/web UI can be
built with a Rust backend and a graph-capable frontend. Required views are graph
explorer, replay timeline, investigation dashboard, workspace memory, notes,
and collaboration surfaces.

### Collaboration And Enterprise

Design early for shared workspaces, RBAC, SSO, encrypted workspaces, audit
trails, compliance exports, multi-user deployments, airgapped support, comments,
investigation threads, replay sharing, and timeline diffing.

## Engineering Principles

Prioritize deterministic behavior, reproducibility, composability,
observability, auditability, schema-driven systems, transactional state,
resumable scans, append-only logs, cryptographic evidence verification, and
local-first operation.

Avoid shell-script orchestration, uncontrolled agents, opaque automation,
fragile plugin execution, filesystem-only persistence as the long-term model,
and features that bypass authorization or human confirmation.

## Immediate Implementation Priorities

1. Unified datastore and security graph.
   - Add entity schema and graph abstraction.
   - Start with local deterministic JSONL storage.
   - Preserve a clean path to Postgres-backed storage.

2. Replay engine.
   - Capture requests, responses, sessions, timing, and replay lineage.
   - Make action replay deterministic and diffable.

3. Proxy and browser stabilization.
   - Add request interception, websocket support, HTTP/2 support, and browser
     instrumentation hooks.

4. UI shell.
   - Add workspace browser, replay viewer, graph explorer, and investigation
     views.

5. Intelligence layer.
   - Add graph reasoning, attack-path analysis, auth anomaly detection, and
     AI-assisted investigation workflows.

6. Enterprise layer.
   - Add collaboration, cloud sync, RBAC, SSO, audit systems, and deployment
     orchestration only after the local-first evidence model is solid.
