# GeistScope Product-Recovery Decision Record

Status: active interview decisions
Date: September 22, 2026

## Purpose

This is a short record of user-authored decisions made during the GeistScope recovery interview. It prevents old plans, assistant recommendations, package breadth, or sunk work from silently becoming product authority.

A future change may revise a decision only by naming the decision, explaining the new evidence, stating the trade-off in plain language, and receiving explicit user approval.

## 1. Product identity

Decision:

GeistScope is a manual-first systems-security workbench for Jeff. Its purpose is to make Jeff a stronger operator through understandable, inspectable workflows. Autonomous hunting is a possible future capability, not the current product identity or authority.

Why:

The previous feature-led path produced broad, disconnected implementation without a coherent manual operator loop.

Consequence:

No AI, agent, or scheduler may become the primary decision maker for scope, safety, verdicts, or durable state.

## 2. Reference environment

Decision:

Real authorized bug-bounty work is the eventual reference environment. Its constraints win when they conflict with CTF convenience: explicit scope, minimal traffic, web/API focus, reproducible evidence, and report quality.

HTB/CTF is the training and stress-test environment. It does not authorize noisy, destructive, or unsafely generalized production behavior.

Consequence:

The project must distinguish lab-only behavior from any future live-engagement behavior.

## 3. Low-level learning projects

Decision:

The Rust nmap clone, packet-analysis work, shell, and terminal emulator remain separate systems-learning projects. They are not GeistScope dependencies or first-class field tools by default.

They may be considered for later integration only after they have earned it through controlled behavioral comparison, explicit safety boundaries, and a stable import/export contract.

Consequence:

GeistScope does not become a replacement nmap, tcpdump/Wireshark, shell, or terminal project.

## 4. First operator and public-source posture

Decision:

Jeff is the only intended operator for at least the next 12 months. GeistScope is local-first and personal. The public repository is a learn-in-the-open artifact; forks are welcome but do not create a support, compatibility, multi-user, cloud, or hosted-product obligation.

Consequence:

Do not build accounts, team collaboration, public engagement sharing, hosted services, or compatibility layers without a new explicit decision.

## 5. Public/private data boundary

Decision:

Live engagements, target data, traffic, credentials, raw evidence, and operational notes stay in a private local workspace outside the public repository.

The public repository contains only code, synthetic fixtures, redacted schemas, and deliberately sanitized lessons.

Consequence:

A `.gitignore` entry alone is not an acceptable operational-data boundary. Public Git material must be safe if copied, forked, indexed, or accidentally rendered.

## 6. Decision authority

Decision:

Jeff retains all product, architecture, scope, safety, data-model, integration, deletion, and user-workflow decisions.

The assistant may audit, explain, propose bounded options, and implement only explicitly approved slices. It may decide only tiny reversible implementation details inside an accepted specification.

Consequence:

Every consequential decision requires a short record: options, plain-language trade-offs, user choice, and a revisit trigger. A recommendation is not an accepted commitment.

## 7. Evidence source for current product discovery

Decision:

For now, controlled labs and HTB/CTF are the credible source of manual workflow evidence. Jeff is working toward a later staged path of controlled investigations, real program-rule study, and a narrow authorized public-program assessment.

Consequence:

Do not claim that current architecture reflects earned real-world bug-bounty workflow knowledge. Build only to remove friction that appears repeatedly in controlled practice.

## 8. Twelve-week learning vertical

Decision:

The only valid GeistScope learning vertical for the next 12 weeks is authenticated web/API authorization testing, with HTTP/API request and response literacy as the prerequisite.

In plain language: use controlled identities and separately owned objects to determine whether a user can improperly access another user's data or action.

Technical names: IDOR, BOLA, and broken access control.

Consequence:

No scanner, AI, proxy, browser-worker, TUI, campaign-engine, or unrelated vulnerability feature is valid during this period unless it directly removes repeated, observed friction in this one manual learning workflow.

The supporting resource and practice document is:

`docs/WEB_API_AUTHORIZATION_LEARNING_TRACK.md`

## 9. Result-claim ceiling

Decision:

During the 12-week learning vertical, GeistScope may produce only:

- `candidate`
- `negative`
- `invalid`

`verified` is unavailable until Jeff has enough manual experience to define and personally approve a strict proof contract.

Consequence:

No response difference, heuristic, scanner result, or AI assessment may promote a candidate to verified.

## 10. Learning-phase source of truth

Decision:

For the 12-week learning phase, the authoritative record is a private Markdown lab notebook using the standardized redacted observation and runbook template.

Do not commit a durable GeistScope data model, SQLite database, TUI workflow, or campaign engine from unearned assumptions. Derive any future structured model only from repeated, documented manual friction.

Consequence:

The uncommitted `mg-observe`, `campaign-core`, and `mg-engine` prototypes are not the learning-phase source of truth and must not be expanded as a substitute for lab practice.

## 11. Archive and teaching policy

Decision:

Archive and freeze code unrelated to the authenticated web/API authorization learning vertical. Keep relevant code available as a teaching tool, not as a mandate to continue its previous product direction.

The exact archival mechanism and the exact keep/quarantine classification require a separately approved inventory because moving or deleting crates is an irreversible repository-structure decision.

Consequence:

No unrelated legacy capability may remain in the active workspace merely because it is already implemented. Relevant code may be inspected, explained, and exercised in controlled teaching contexts, but no feature expansion is authorized by this decision.

## 12. Archive topology

Decision:

Use a Git-native archive. First preserve a reconciled exact legacy snapshot in a named branch or tag. Then reduce active `main` to the web/API authorization teaching slice.

Legacy code remains public, browsable, and recoverable from the archive reference, but receives no maintenance.

Consequence:

Do not mix archival restructuring with feature work. The archive must retain an accurate status note and the active branch must not continue claiming support for legacy tools.

## 13. Learning-first code posture

Decision:

Labs and private notes come first. After a concept is learned manually, inspect only a small frozen legacy code path as a case study. Write new tiny exercises only when a notebook observation justifies one.

The active branch initially needs documentation and synthetic fixtures, not a product workspace.

Consequence:

Do not preserve or rebuild a Rust product core merely to keep code available. Code must follow demonstrated understanding and repeated manual friction.

## 14. AI role during the learning vertical

Decision:

AI may teach, explain, quiz, review redacted notes, identify assumptions, and propose bounded options.

AI may not choose a target, authorize or execute a test, classify a finding as verified, make a consequential architecture decision, or write or merge code without an explicitly approved slice.

Consequence:

AI is a learning aid and critical reviewer, not an autonomous operator or product owner.

## 15. Controlled identity and secret rule

Decision:

Use two manually operated controlled lab identities whenever the authorization exercise requires comparison. Actual secrets stay in a password manager or the lab's secure mechanism. Separate browser sessions represent `lab-a` and `lab-b`.

The private notebook stores only aliases, role/tenant/ownership facts, expiry or relogin notes, and redacted evidence.

Consequence:

Session cookies, bearer tokens, passwords, and recovery material are never placed in Git, private Markdown notes, synthetic fixtures, shell history, screenshots, chat, or a new GeistScope secret-management feature.

## 16. Learning cadence

Decision:

Protect three approximately 90-minute sessions each week:

1. protocol and study;
2. hands-on controlled lab work; and
3. notebook and retrospective work.

Consequence:

The 12-week vertical is a demanding but realistic practice loop. New project work must not consume the retrospective session or displace the written evidence habit.

## 17. Lab-environment role split

Decision:

PortSwigger Web Security Academy is the primary curriculum and acceptance benchmark. After completing a relevant PortSwigger concept and private notebook artifact, use a carefully selected HTB exercise only as a transfer test.

HTB may not add new GeistScope product requirements during the 12-week learning vertical.

Consequence:

The learning loop remains focused on HTTP/API authorization. HTB may test transfer of learned concepts but cannot pull the active product back into host exploitation, packet analysis, or general CTF-tool development.

## 18. Gate for authorized public-program practice

Decision:

Before any authorized public-program practice:

1. complete the 12-week learning track;
2. produce at least three strong PortSwigger notebook artifacts covering `candidate`, `negative`, and `invalid` outcomes;
3. complete at least one constrained HTB transfer exercise;
4. pass a self-review of scope, secret handling, and evidence; and
5. read one specific program's current rules before performing only low-noise manual exploration.

Prior lab completion is useful background but not automatic proof of retained skill. Existing IDOR/BOLA, SQLi, and unfinished XSS work require deliberate review and revalidation before they count toward this gate.

Consequence:

Do not use past course completion, a scanner result, or a completed CTF as a substitute for current reproducible evidence and disciplined scope handling.

## 19. Prior-learning diagnostic

Decision:

Use prior PortSwigger work as a diagnostic, not a parallel roadmap. Begin by solving one previously completed IDOR/BOLA lab without hints and produce a full private artifact.

SQLi remains a bounded review-only topic. Unfinished XSS is parked until the authorization vertical and its evidence habits are complete.

Consequence:

The learning cycle remains one vertical rather than becoming a three-track vulnerability curriculum or a reason to revive broad scanner development.

## 20. Learning-phase automation ceiling

Decision:

Allow only inert local helpers during the 12-week learning vertical: private-template generation, redaction checks, JSON/schema validation, artifact hashing, and note organization.

All HTTP navigation, account switching, request comparison, and test decisions remain manual.

Consequence:

No crawler, scanner, replay script, browser worker, target-facing code, or autonomous selection logic is authorized for this learning phase, including against controlled labs.

## 21. Private notebook structure

Decision:

Use a private local notebook directory outside the public repository. Create one secret-free Markdown case file per study or lab session and manually maintain `INDEX.md` with concept, classification, time, repeated friction, and case-file links.

Back up the private notebook separately.

Consequence:

The notebook, rather than intuition or an app database, supplies the evidence required to propose a future helper. It must never become a copied dump of credentials, raw tokens, or sensitive target data.

## 22. Public learning-output and publication boundary

Decision:

Keep the public GeistScope repository to code and documentation only. Publish learning reflections and other public artifacts through `mg-server`, not through the GeistScope repository.

Every publication is a separate deliberate editorial act. It must be a sanitized, self-contained retrospective or artifact rather than a copy of a private case file or a session-by-session operational log.

Consequence:

`mg-server` is the public publication authority; GeistScope remains the code/documentation authority; the private notebook remains the investigation-learning authority. Do not create publication pressure that distorts private practice, and do not publish operational detail, identifiers, raw evidence, secrets, or private runbooks.

## 23. Frozen-code study cadence

Decision:

After every two completed private lab artifacts, replace one protocol/study session with one 90-minute walkthrough of a single frozen legacy path that corresponds to a concept already practiced manually.

Begin with scope and identity validation, not complex evidence-authority or AI-harness code.

Consequence:

Source code remains a post-lab case study. It cannot become the primary curriculum or a reason to reactivate unsupported legacy product behavior.

## 24. `mg-server` publication trigger

Decision:

Publish through `mg-server` only after a completed concept milestone: multiple private artifacts and, where useful, a frozen-code case study. Publish one sanitized retrospective or technical artifact, not weekly session logs.

Consequence:

Public work must be a self-contained teaching artifact rather than a chronological trace of private practice. It may not claim that GeistScope is an operator-ready product until the independently applicable publication gate is satisfied.

## 25. Learning-unit document structure

Decision:

Represent each weekly learning unit as documentation containing three 90-minute sessions: protocol/study, controlled lab, and private notebook/retrospective. Break every 90-minute session into three explicit 30-minute chunks.

The public curriculum lives under `docs/learning/web-api-authorization/`. Private case files remain outside the repository.

Consequence:

The curriculum makes time, evidence, and reflection visible. A later code task may not consume the required retrospective or silently collapse several learning activities into an unreviewed marathon.

## 26. Legacy snapshot content

Decision:

Before reducing active `main`, preserve the complete legacy workspace and all pre-interview uncommitted prototypes and plans in one named Git-native legacy snapshot.

Keep the recovery decision record, web/API authorization learning track, and 12-week curriculum on the narrowed active `main`.

Consequence:

The snapshot preserves ideas without allowing them to remain active scope. It is historical source material, not a release, supported product, or authorization to resume legacy feature work.

## 27. Active-branch material during the learning phase

Decision:

After the legacy snapshot is preserved, reduce active `main` to documentation, synthetic fixtures, and future tiny exercises only.

Move all current Rust workspace code, Cargo/CI product scaffolding, broad legacy plans, and tool claims into the preserved legacy snapshot. Use the archive for frozen code case studies.

Consequence:

Active `main` is a learning contract, not a dormant copy of the former product. No legacy crate may remain merely as a temptation, placeholder, or presumed future dependency.

## 28. Future-code admission gate

Decision:

Before any new code is approved on active `main`, require a one-page user-approved change proposal containing:

1. three private case references demonstrating the same friction;
2. the smallest local-only behavior;
3. explicit non-goals;
4. data and safety boundaries;
5. a behavior-level acceptance test; and
6. the condition that would later delete or replace the helper.

Consequence:

No future helper, exercise, schema, database, UI, AI capability, or automation feature may enter the active branch from intuition, a one-off inconvenience, or an assistant-maintained backlog.

## Revisit trigger

Revisit this record after the 12-week learning vertical only when the private lab notebook contains repeated, concrete evidence of workflow friction. A proposed next slice must identify:

1. the repeated manual task;
2. at least three observed instances;
3. the smallest artifact or command that would remove the friction;
4. the behavior it must not automate;
5. a controlled acceptance test; and
6. the user-approved safety and data boundaries it preserves.
