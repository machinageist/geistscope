# METHODOLOGY — SSRF Vertical Slice (living dev-log)

A running record of *how* this slice was built, written to teach. Each task gets an entry:
**RED** (the failing test and what it asserts) → **what failed** → **GREEN** (the minimal change) →
**what the test revealed** → **plan adjustment** (if any) and why. Intended to distill into a
public writeup later, so it explains reasoning, not just diffs.

## Why this slice, this way

GeistScope is being rebuilt as an *adaptive hunting engine*, not a scanner. The distinguishing
claim is a closed reasoning loop with a hard wall between an **AI control plane** (proposes,
prioritizes, explains) and a **deterministic execution plane** (validates scope/policy/budgets,
constructs requests, records evidence, decides verdicts). SSRF is the first vulnerability class
wired end-to-end because it is priority #1 and forces every part of that loop to exist: candidate
detection, a policy-gated live request, out-of-band confirmation, a deterministic verdict, and
immutable evidence.

The build is strictly test-first. Every capability starts as a failing test that encodes the
desired behavior (including the *refusals* — an out-of-scope or unapproved plan must send nothing),
then the minimum code to make it pass. This is what keeps an autonomous tool honest: the safety
properties are pinned by tests, not by intentions.

---

## Task 0 — Scaffold

**Goal.** Stand up the plan/methodology docs and two new crates (`oob-core`, `replay-runner`)
without changing behavior anywhere else, so later tasks have a home and the workspace still builds.

**Approach.** No test to write yet — this task's gate is `cargo build` from `crates/`. The two
crates are created as empty, header-only libraries and registered as workspace members. Network I/O
and the OOB listener are deliberately *not* added here; they arrive in Tasks 3–4 behind their own
failing tests. Keeping Task 0 inert means the first real RED test in Task 1 fails for the right
reason (missing SSRF logic), not because the tree doesn't compile.

**Design note — why two new crates instead of extending `replay-engine`.** `replay-engine` is
pure: it builds and hashes plans and classifies provided outcomes, with zero network I/O. That
purity is worth protecting — it is trivially testable and safe to call from anywhere. So live
sending goes in a new `replay-runner` crate, and OOB (token minting + a loopback listener) in
`oob-core`. The engine decides *what* is allowed and *what a result means*; the runner is the only
place that actually touches the network, and only for plans the engine already marked executable.

**GREEN.** Created the two crates as header-only libraries, registered them in
`crates/Cargo.toml`, and confirmed the workspace manifest still parses (`cargo metadata`) and both
compile (`cargo build -p oob-core -p replay-runner`).

**What it revealed.** The workspace root is `crates/Cargo.toml` — there is no manifest at the repo
root — so every `cargo` command must run from `crates/` (or with `--manifest-path`). Pinned that as
the working directory. No behavior change anywhere else; the tree is green and ready for the first
real RED test in Task 1.

**Adjustment.** None. Plan unchanged.

---

## Task 1 — SSRF candidate detector

**Goal.** Teach the corpus to notice server-side-request sinks: given captured traffic, emit a
`ServerSideRequestTarget` candidate for any request that exposes a URL/host-shaped parameter — and
emit nothing for benign inputs. This is the "hypothesize" step's raw material for SSRF.

**RED.** Three tests: a `?url=http://169.254.169.254/...` request must yield exactly one SSRF
candidate that `RequiresApproval`, is not `autonomous_safe`, and names `url` as the injection
param; a `?next=https://internal.svc.local/...` request must be caught by its URL-shaped *value*
even though `next` is an unremarkable name; and a `?q=hello` request must produce no SSRF
candidate. Ran `cargo test -p request-corpus` → compile error (`no variant ServerSideRequestTarget`,
`no field injection_params`). That is the RED: the tests encode an API that does not exist yet.

**GREEN.** Added the `ServerSideRequestTarget` variant, a new `injection_params: Vec<String>` field
on `CorpusCandidate` (so the candidate carries *which* parameter a later task will inject), and an
analyzer that runs for every record: it flags a parameter when the name is in a curated
SSRF-prone set (`url, uri, redirect, callback, webhook, fetch, host, …`) **or** its value looks
like a URL. SSRF candidates are always `RequiresApproval` + `autonomous_safe = false`, matching the
decision record's rule that OOB/internal-network tests need explicit approval. Tests pass 9/9;
clippy clean.

**What it revealed.** Two concrete facts that shaped the code:
1. `TrafficRecord.params` holds parameter *names only* — values are not in it. So name-matching
   alone can't see a URL-valued parameter with a boring name (`next=…`). The analyzer therefore
   parses `record.url` query pairs to inspect values, and still consults `params` for name matches
   (which also covers body parameters whose values weren't captured). This is why the crate gained
   a real `url` dependency (previously dev-only).
2. Adding a field to the shared `CorpusCandidate` struct is exactly the ripple the plan warned
   about: two dependent crates construct it directly in test helpers (`replay-engine`,
   `mg-hunt`) and stopped compiling until each got `injection_params: Vec::new()`. No production
   code outside `request-corpus` builds candidates, and nothing matches `CandidateKind`
   exhaustively, so the new variant was otherwise safe.

**Adjustment.** None to the plan. Note for Task 2/4: the injection target now travels on the
candidate as `injection_params`, so the substitution/runner do not need to re-derive it.
