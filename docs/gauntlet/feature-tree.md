# GeistScope Feature Tree

Confirmed execution tree. Details and ordering are in `PLAN.md` Sections 6–7.

- GS-0 Product contract and release boundary
  - GS-0.1 Durable criteria/tree/manifest/handoff protocol
  - GS-0.2 Shipped/prototype/quarantined/deferred inventory
  - GS-0.3 Linux-first install, diagnostics, release gates
- GS-1 Engagement foundation
  - Program/scope/rules; policy/budgets/stops; identities/vault; audit; SQLite/artifacts
- GS-2 Traffic and attack-surface foundation
  - Capture/import; request corpus/search; graph; mutation/replay/diff; continuous discovery
- GS-3 Adaptive hunt engine
  - Observations/hypotheses; immutable plans; policy execution; interpretation; scheduler; coverage; expansion; resume
- GS-4 Capability slices
  - GS-4.1 SSRF
  - GS-4.2 Broken access control/IDOR
  - GS-4.3 Critical server-side injection
  - GS-4.4 Browser/client-side
  - GS-4.5 GraphQL/API
- GS-5 Evidence and reporting
  - Bundles; promotion; runbooks; grouping; report drafts; regression replay
- GS-6 Operator and agent surfaces
  - Versioned API; thin CLI; expert TUI; learning profile; built-in AI; external-agent contract
- GS-7 Consolidation and release
  - Legacy disposition; deduplication; truthful docs; offline campaign; audits; packages/images
- GS-8 Full recon-to-exploit capability packs
  - Passive recon/OSINT; service discovery; web/API; authz/business logic; infrastructure; cloud/container; mobile/artifact/binary; controlled exploitation; policy-gated post-exploitation/cleanup; external interoperability

Every GS-8 pack must implement the common engine contract; standalone scanner output is not completion.
