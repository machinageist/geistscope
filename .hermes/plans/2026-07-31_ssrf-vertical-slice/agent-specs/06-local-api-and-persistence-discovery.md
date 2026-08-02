# Slice 6 — Local API and Persistence Discovery

Status: design task only after Slice 5 passes
Depends on: real campaign state transitions and artifacts from Slice 5
Design checkpoint: Jeff chooses the resulting architecture before production implementation

## Goal

Use the proven campaign runner—not speculative CRUD ideas—to propose the smallest versioned local API and SQLite ownership boundary needed by CLI/TUI/harness clients.

## This agent does not implement production API or SQLite

The output is an ADR and an implementation plan for Jeff's review. Do not add Axum routes, migrations, daemon processes, or persistence dependencies during this task.

## Questions to answer from actual code

1. Which campaign inputs are durable versus per-run ephemeral?
2. Which state transitions must survive process restart?
3. Which artifacts remain filesystem-owned, and which metadata belongs in SQLite?
4. Which component is the single writer?
5. How do workers receive a plan and return bounded records without becoming policy authorities?
6. How do clients observe progress and cancellation without mutating engine state directly?
7. What is the minimal versioned request/response schema for starting a campaign and reading results?
8. What resume identity is required: campaign ID, plan hash, run ID, or all three?
9. How are schema migration, crash recovery, and partially written evidence reconciled?
10. Which secrets are handles only and must never enter SQLite/API payloads?
11. Are callback leases deliberately ephemeral across restart, or stored through an explicitly
    protected restartable mechanism? Plaintext tokens must not silently enter ordinary rows.

## Options to compare

At minimum compare:

- embedded library + SQLite used directly by one CLI process;
- long-lived local engine service over Unix socket/HTTP;
- JSON-RPC or line protocol over stdio for a supervised local process.

Evaluate each against single-writer correctness, TUI observability, worker isolation, testability, restart semantics, packaging, and security—not familiarity.

## Required ADR content

Create a dated ADR under the repo's chosen architecture-doc location containing:

- context and proven state transitions;
- decision drivers and non-goals;
- options table;
- recommended option with rationale;
- proposed API resources/commands and versioning;
- SQLite ownership and transaction boundaries;
- minimal schema sketch;
- filesystem/evidence relationship;
- crash and resume behavior;
- secret-handling rules;
- migration/testing strategy;
- explicit unresolved questions for Jeff;
- rollback/reversibility assessment.

Also produce an atomic implementation plan divided into schema, repository, service/API, client, and migration tests. Do not mark the recommendation accepted.

## Evidence-gathering tasks

- Trace every state type and transition in `SsrfCampaignRunner`.
- List all artifacts written in a successful, negative, blocked, and failed run.
- Identify current engagement/audit filesystem assumptions.
- Inspect existing harness/TUI client boundaries only for requirements, not compatibility.
- Measure which operations need streaming progress versus final responses.

## Acceptance criteria

- Every proposed table/API field maps to a proven Slice 5 need.
- No generic endpoint exists without a named client behavior.
- Raw tokens, cookies, auth headers, bodies, and credentials are excluded.
- Evidence files remain immutable and are not duplicated as SQLite blobs.
- Single-writer and crash-recovery invariants are explicit.
- Jeff can choose among options without needing another code archaeology pass.
- The proposed test plan covers hash revalidation on load, illegal transitions, duplicate/idempotent
  commands, restart during an active lease, atomic state/evidence promotion, and prevention of two
  concurrent executions of one authorized plan.

## Non-goals

- Do not implement a daemon, local HTTP/Unix-socket server, JSON-RPC process, or SQLite schema.
- Do not choose the architecture without Jeff's explicit checkpoint decision.
- Do not preserve old harness/CLI APIs merely for compatibility.
- Do not move immutable evidence bytes into database blobs.
- Do not design remote multi-user authentication, cloud hosting, or report submission.

## Verification

This is documentation-only. Verify links and references with:

```bash
git diff --check
# Confirm every referenced path exists
```

## Done means

Jeff receives an evidence-based ADR and atomic plan, then explicitly approves or changes the local API/persistence boundary before any implementation agent proceeds.
