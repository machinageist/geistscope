# GeistScope Restructure — Adaptive Hunting Engine (Decision Log)

Source: Hermes interview, session `20260723_130546_4e6da8`, 2026-07-23 20:09–21:07.
Prompt that started it: "interview me on how to salvage, improve, or prune this tool... take it
from what i perceive to be a sloppy mess and refine it into the bug bounty
recon-orchestration-exploitation pipeline tool it was intended to be."

This is a record of decisions, not an implementation plan with slices/tasks yet. Use it as the
product/architecture spec to derive a `PLAN.md` from before starting work.

## Product identity

GeistScope is a free, open-source, adaptive hunting system that maintains a persistent model of
an engagement, chooses the next useful test from accumulated evidence, and turns the hunt into
reproducible findings, human-verification runbooks, and report drafts. The competitive core is
closing the reasoning loop (observe → remember → hypothesize → select next test → execute safely
→ interpret evidence → update hunt state → repeat → verify → report), not owning the most
scanners.

Product commitments:
- Entirely open source, no paid edition or feature-gated core, no required cloud service, no
  telemetry by default, no mandatory commercial model provider.
- Functional with deterministic capabilities and local models; cloud AI providers are optional.
- Engagement data stays locally controlled, in exportable/inspectable formats.

Primary v1 user: a technically capable solo bug-bounty hunter, with generated verification
runbooks written to also serve an advancing beginner (progressive disclosure, not a simplified
product — see "Expert vs. learning path" below). Team/enterprise use is explicitly deferred.
Long-term direction: grow into a serious red-team/pentest tool, possibly with a blue/purple team
fork later.

## Operator surfaces (one engine, not four workflows)

- Automatic mode: program description + credentials in, evidence-backed findings/report drafts
  out.
- Interactive mode: same engine pauses at decision points, exposes state via CLI/TUI/chat.
- Embedded-agent mode: Hermes or another agent drives a stable, typed API — no shelling into
  dozens of unrelated binaries.
- Native AI mode: GeistScope's own AI (Claude/OpenAI/local) does hypothesis generation and
  prioritization.
- Manual expert mode: operator can inspect traffic, alter plans, replay requests, approve
  actions, take control.

Core contract:
```
Program rules + scope + credentials
                  ↓
        normalized engagement
                  ↓
 recon → traffic collection → attack-surface model
                  ↓
       hypotheses and test plans
                  ↓
 policy-gated execution and adaptive follow-up
                  ↓
 verified findings + evidence + report drafts
```

## Scope boundary

Near-term core: web applications, HTTP/GraphQL APIs, authenticated and multi-account workflows,
browser/client-side behavior, request capture/mutation/replay/semantic comparison, evidence, and
reporting.

Long-term expansion (not v1): native protocols/raw sockets, infrastructure and cloud/container
exploitation, binary/mobile/firmware analysis, post-exploitation and local privesc.

Target architecture to support that without bloating v1:
```
GeistScope core
├── engagement, scope, policy, credentials
├── asset and request corpus
├── hypothesis and planning engine
├── execution scheduler
├── evidence and finding model
└── operator/agent API

Capability packs
├── web
├── browser
├── API
├── network-protocols       # future
├── cloud-infrastructure    # future
├── mobile/binary           # future
└── post-exploitation       # future
```
Every future pack implements the same contract: observations consumed/produced, hypotheses it
can generate, actions it can execute, risk/authorization metadata, budget accounting, evidence
requirements, verification/cleanup, and how results become structured findings.

Explicit v1 non-goals: team collaboration/shared multi-user deployments, hosted GeistScope SaaS,
native mobile app testing, binary exploitation/reverse engineering, internal network pivoting,
local privesc/post-exploitation, broad cloud-config auditing, generic port/protocol scanning
beyond what supports web targets, stealth/evasion/persistence/destructive actions, automatic
HackerOne submission, dozens of shallow checks for marketing coverage, replacing a general
intercepting proxy for manual workflows.

## Priority vulnerability classes (v1)

In priority order: **1. SSRF, 2. Broken access control / IDOR, 3. RCE and critical
server-side injections.** All three require understanding application behavior and safely
constructing proofs, not payload-spraying — this is the design center for the corpus,
hypothesis engine, replay system, browser automation, and test lab.

Beyond the top 3, the initial high-value capability set (for scheduling priority, not a hard
allowlist — see "Bounty value as scheduling signal"):
- Tier 1 (direct critical/high-impact): RCE/command injection, SQLi, auth bypass/ATO,
  high-impact SSRF, unsafe deserialization, arbitrary file upload to execution/sensitive access,
  XXE with disclosure/internal access/callback evidence.
- Tier 2 (authorization/logic): cross-tenant IDOR/BOLA, privesc, unauthorized state-changing
  actions, admin-function exposure, mass assignment, business-logic/workflow bypass, race
  conditions with financial/entitlement/authz impact.
- Tier 3 (browser/data-impact): stored/DOM XSS with real impact, OAuth/account-linking flaws,
  credential/token leakage, CORS enabling authenticated data access, cache poisoning with durable
  impact, request smuggling where safely testable.

## Automation model

Automation is an engagement-level policy the user selects — never hard-coded into the interface
or decided by the model, and identical regardless of CLI/TUI/built-in-AI/Hermes driving it.

Levels: **Observe** (recon/crawl/fingerprint, no active test traffic) → **Safe** (low-volume
non-mutating read-only tests) → **Guided** (broader authenticated/active tests, approval gates)
→ **Autonomous** (everything the imported program rules + user policy allow) → **Custom**
(per-permission/budget/stop-condition configuration).

Granular controls, not a single unsafe switch: passive vs. active, authenticated testing,
cross-account/cross-role testing, mutation/fuzzing, state-changing actions, OOB callbacks,
exploit confirmation, concurrency/request/byte/time budgets, auto evidence collection, auto
report drafting, stop conditions (rate limits, WAF, instability, scope ambiguity).

At the highest level, automation means **genuine end-to-end hunting**: parse program scope →
find ambiguity/missing authorization → configure engagement/credentials → discover and expand
attack surface → capture/normalize traffic → build hypotheses → select/execute permitted tests →
interpret and adapt → follow signals into exploit chains → independently reproduce → minimize
and preserve proof → assess impact/severity → produce a submission-ready report → retain state to
resume without repeating work. A component survives pruning only if it contributes to this closed
loop.

## Result model (4 layers)

1. **Verified findings** — reproduced by GeistScope with a deterministic test; includes asset,
   preconditions, exact behavior, impact, confidence, evidence; never claims more impact than the
   evidence supports.
2. **Human-verification candidates** — strong signals automation couldn't safely/conclusively
   verify; includes why it matters, what's uncertain, expected secure vs. vulnerable behavior.
3. **Suggested manual verification runbook** — prerequisites/account setup, exact UI nav or HTTP
   requests, which values to substitute, a safe proof payload/marker, expected vulnerable vs.
   secure responses, what evidence to capture, how to rule out false positives (caching, stale
   sessions, authz errors, reflection without execution), cleanup/rollback for state-changing
   tests, program-policy warnings, a clear stopping point. Generated from structured test plans
   and real evidence, not improvised by an LLM afterward. Sensitive values appear as placeholders
   (`<ATTACKER_SESSION>`, `<RESOURCE_ID>`); the local system keeps secure references for replay.
4. **Hunt ledger** — assets examined, hypotheses generated, tests performed and outcomes,
   negative coverage/untested areas, budget/policy stops, remaining opportunities ranked by
   expected value.

This strengthens the case for `request-corpus`, `replay-engine`, `evidence-core`, engagement
policy, and orchestration, and weakens the case for shallow standalone scanners that can't
produce reproducible requests, structured hypotheses, or verification runbooks.

## Identity / multi-account model

Three engagement-specific modes, account creation **disabled by default**, enabled per-engagement:
- Imported identities: user supplies existing controlled accounts/sessions.
- Assisted creation: GeistScope guides the user through creating/labeling accounts.
- Automated creation: GeistScope creates controlled accounts when explicitly enabled and
  permitted by the program.

At setup, GeistScope should detect when multi-identity testing would help and recommend enabling
it, explaining why, how many, role/tenant relationships, verification/invite requirements, which
program rule governs it, and what state-changing actions it performs.

Structured identity metadata (not just "cookie A"/"cookie B"):
```
Identity
├── account label
├── tenant or organization
├── role
├── ownership boundaries
├── session references
├── browser profile
├── creation method
├── test-data permissions
└── lifecycle/cleanup status
```
Secrets stay outside model-visible state — AI/Hermes/TUI see labels and capabilities
(`tenant-a/member`), never raw passwords/cookies/tokens.

## AI vs. deterministic-code boundary (non-negotiable)

```
AI control plane
  proposes, prioritizes, explains, adapts
                 │
                 ▼
Deterministic execution plane
  validates scope, policy, credentials, budgets,
  requests, evidence, verification, and findings
```
AI may: interpret program prose, generate/rank hypotheses, infer input contexts/trust boundaries,
propose test plans/follow-ups, explain evidence, draft verification runbooks/reports.

AI may never: expand scope, override program restrictions, read raw secrets unnecessarily,
change an action's risk class, bypass approval requirements, declare a finding verified without
satisfying its evidence contract, or fabricate requests/responses/OOB callbacks/reproduction
results.

Deterministic Rust code must: establish effective scope, enforce action policy/budgets, resolve
credential references, construct/validate executable requests, record exactly what was sent and
received, correlate OOB interactions, hash/preserve evidence, decide whether an action needs
approval, and prevent the model from claiming unverified findings.

This boundary makes Hermes a clean fit: the built-in model and an external CLI agent are just two
clients of the same typed planning/execution API. Neither gets privileged shell access through
GeistScope.

## Compatibility stance

**No backwards compatibility required. Rewrite from scratch where it helps; the existing repo is
raw material, not the product definition.**

- Salvage: demonstrated behavior, algorithms, tests, safety invariants. Preserve as reference
  implementation/test oracle only when it earns that.
- Rewrite: anything whose interface blocks a coherent pipeline.
- Delete: shallow/redundant tools instead of wrapping them indefinitely.
- Do not salvage architecture merely because it exists.

Likely salvage: scope normalization/deny precedence, program-rule snapshots, action-policy
concepts, named identity/session metadata with secret references, request-corpus concepts,
replay-plan hashing/approval binding, semantic response comparison, immutable evidence bundles,
OOB correlation concepts, audit logging/budget stops, any genuinely tested detection logic.

Likely rewrite: overall orchestration, harness endpoint architecture, engagement storage model,
live proxy/traffic capture, browser automation, finding lifecycle/confidence model, AI planning
loop, CLI/TUI boundaries, SSRF/IDOR/injection capability interfaces.

Likely quarantine/delete: most one-binary-per-technique tools, post-exploitation utilities,
infra/cloud scanners outside v1 scope, dry-run scaffolds that never worked, duplicate HTTP
clients/inconsistent finding emitters, README-only features with no end-to-end integration,
generic scanner checks that can't generate reproducible evidence.

## Technical baseline

- Rust remains the primary implementation language for the core (policy, orchestration, state,
  evidence, public API).
- **Polyglot workers allowed** where a mature open-source ecosystem is substantially stronger
  (e.g. Playwright for browser automation, a proven proxy/interception library, existing
  DNS/HTTP parsers, optional Nuclei interop, externally hosted OOB infra) — rebuilding those in
  Rust would cost years without improving the adaptive-hunt advantage. Motivation: "I wanted to
  use this project to learn Rust... but now I just want a tool that works, gets contributions,
  and helps make supplemental income hunting with."
- Local-first, single-user application. One long-running GeistScope engine/service owns
  engagement state and scheduling.
- SQLite for normalized operational state; immutable files for raw traffic/evidence.
- CLI, TUI, built-in AI, and Hermes all talk to the engine through one versioned local API.
- Browser automation and OOB services run as managed workers.
- No cloud account or hosted GeistScope service required. Containers are optional isolation, not
  the only run mode.
- Linux is the first supported platform; portability later.

## Authentication / session model

Hybrid: direct credential flow when auth is machine-friendly and explicitly configured;
autonomous browser login for ordinary username/password flows; **interactive browser handoff**
for MFA/CAPTCHA/passkeys/SSO/consent screens (no bypass attempts). Session capture after login,
secrets in a local vault, only opaque identity references exposed to AI. Automatic
session-expiry detection triggers a reauth request rather than silently producing misleading
results. Separate isolated browser/HTTP sessions per identity/role/tenant. Optional import from
raw HTTP request, cookie jar, HAR file, or existing proxy session. Post-auth, the autonomous
browser maps workflows and feeds observed requests into the same corpus used by direct HTTP/API
testing, so the HTTP executor can mutate/replay without forcing every test through a browser.

## AI data / privacy policy (configurable per engagement)

- Local-only: only local models process engagement content.
- Redacted cloud: Claude/OpenAI get bounded, structurally redacted observations. **(suggested
  default)**
- Selected cloud: user explicitly permits specified data classes/artifacts.
- Full cloud: broader context allowed, but credentials/raw secrets always blocked.
- No AI: deterministic hunting continues, reduced hypothesis generation.

Raw credentials are never model-visible regardless of mode. Audit ledger records which provider
received which redacted artifact, including hashes and policy decisions.

## Expert vs. learning path

Same engine, same evidence standards, both are **presentation profiles**, not separate capability
or safety systems — factual confidence, evidence requirements, scope enforcement, and what
"verified" means never change between them.

- Expert: raw requests/responses, direct corpus queries, plan editing/replay, policy overrides
  with explicit authorization, detailed semantic diffs, keyboard-first control, scriptable API,
  minimal explanatory noise.
- Learning: explanations of why a hypothesis was generated, vuln-specific verification runbooks,
  expected secure vs. vulnerable behavior, safe proof boundaries, false-positive diagnostics,
  links between observations/tests/evidence/conclusions, warnings before consequential actions.

## Bounty value as scheduling signal

Dollar amount is a **triage/scheduling heuristic, not a hard execution filter** — all bug classes
stay on the table; lower-value bugs are de-prioritized unless cheap enough to pop several for the
cost of one bigger one.

Program-specific opportunity score:
```
expected value
= likely payout for demonstrated severity
× probability the hypothesis is real
× probability it is in scope and eligible
× probability it is not a duplicate
÷ estimated testing cost and risk
```

Scheduler maintains two queues:
1. **Cheap breadth** — low request count, low impact, deterministic checks, little/no model
   cost, tests many assets fast, includes lower-value bugs when marginal cost is small.
2. **High-value depth** — deeper app understanding, authenticated workflows, multi-step
   hypotheses, identity/tenant comparisons, OOB infra, adaptive follow-up, prioritized by
   likely impact and program payout.

Priority combines: program payout range, potential impact, confidence from accumulated evidence,
requests/time/bandwidth/model-token cost, operator-attention cost, risk of state
change/disruption, duplicate likelihood, asset criticality, chaining opportunity, and coverage
value (does a cheap test rule out a large hypothesis class).

Retain minor observations as chain components instead of prematurely emitting low-quality
reports, e.g.: `open redirect + weak OAuth redirect validation + missing account-link
confirmation → possible account takeover chain`.

Initial budget allocation is a **dynamic prior, not a fixed quota** — starts at 20% cheap
breadth / 70% high-value depth / 10% follow-up-reproduction-evidence-hardening, then reallocates
continuously:
- Strong signal → shift budget into that hypothesis family.
- Repeated negative results → reduce spend on similar tests.
- New asset/surface discovered → temporarily increase breadth.
- Possible exploit chain → reserve budget for validation/evidence.
- Confirmed issue → shift effort to independent reproduction and impact-bounded verification.
- Rate limits/WAF/instability/rising errors → reduce active testing.
- Expensive model reasoning used only when deterministic analysis can't rank/refine the next
  action.
- Budget returns to breadth after a promising branch is exhausted.

"Budget" = requests, elapsed time, bytes, model cost, and operator interruptions — not just
money. Every reallocation must be explainable in the hunt ledger, e.g.: "Shifted 35% of
remaining request budget to authorization testing: two endpoints expose stable resource
identifiers, two controlled identities are available, and an ownership-dependent response
difference was observed."

## Finding behavior: expand around success, don't stop

Findings are **reported as soon as found**, not held back — but a confirmed finding means
"hunt harder nearby," not "hunt complete." On confirming/strongly suspecting a vulnerability:
1. Emit the finding immediately.
2. Preserve a reproducible evidence checkpoint immediately.
3. Continue hunting — the first result is not completion.
4. Generate neighboring hypotheses from the successful test.
5. Search for the same root cause across: related endpoints, API versions, alternate HTTP
   methods, similar parameters/object types, other roles/users/tenants, browser and direct-API
   paths, GraphQL operations, mobile/undocumented API routes observable from web assets, sibling
   subdomains/services.
6. Test plausible exploit chains involving the new capability.
7. Group related instances by root cause while retaining asset-specific evidence.
8. Avoid flooding the user with duplicate reports for one systemic flaw.

"Exhaustive" is represented as an inspectable coverage matrix, not an unsupported claim, e.g.:
```
Object: invoice
Actions: list/read/create/update/delete/export
Identities: anonymous/member/manager/admin
Tenants: A/B
Interfaces: browser/REST/GraphQL
Results: secure/vulnerable/untested/blocked/inconclusive
```
New-endpoint discovery runs throughout the hunt, not just as an initial recon phase — responses,
JS, source maps, API docs, links, errors, redirects, browser traffic, and successful findings all
feed back into discovery.

## Stop / pause conditions

- **Hard stop**: scope ambiguity, authorization expiry, program-rule conflict, budget
  exhaustion, target instability, sustained rate limiting, WAF distress, credential
  invalidation, evidence of unintended impact.
- **Finding checkpoint**: emit and continue (see above) rather than pausing the whole hunt.
- **Diminishing-returns stop**: remaining hypotheses fall below a configurable expected-value
  threshold.
- **Coverage stop**: all currently reachable high-priority surfaces/hypothesis families have
  their planned minimum coverage.
- **Idle stop**: no new assets/observations/hypotheses after a defined number of cycles.
- **Scheduled resume**: state is preserved so the hunt can continue later, especially after
  scope, sessions, application state, or program rules change.

## Operating forms

Design the state model for both, but **ship campaign runs first**; gate watch mode until
resume and change detection are trustworthy.
- **Campaign run**: hunt intensively until the current budget or coverage goal is exhausted.
- **Watch mode** (later): stay attached to an engagement, periodically rediscover assets/
  endpoints, diff changes, refresh hypotheses, resume testing under a recurring budget.

Possible future fork: a blue/purple-team variant.

## Vertical slice (first working end-to-end path)

Not yet chosen down to one slice at the point this interview ended — three candidates were
scoped (SSRF, IDOR, critical-injection), with SSRF recommended first because it's the top
priority and proves the whole adaptive loop with the smallest surface. The user then asked to
plan slices for all top bounty categories rather than picking one first slice, which the "bounty
value as scheduling signal" and "expand around success" sections above resolve at the
scheduling/behavior level. **Open item:** decide and record the actual first implementation
vertical slice in a follow-up `PLAN.md` before writing code.

## Status

This document is the architecture/product decision record from the interview. No repo changes
have been made yet. Next step is to derive a dated `PLAN.md` (atomic tasks + verification) for
the first vertical slice, per this repo's own preferred spec hierarchy.
