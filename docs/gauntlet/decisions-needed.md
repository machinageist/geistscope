# Decisions Needed

No user decision currently blocks the active slice.

## Upcoming checkpoint: SSRF local API and persistence

Trigger: after the immutable evidence writer and vulnerable/secure/blocked/repeat benchmark pass.

Decision inputs must be observed campaign state transitions, not speculative endpoint design. Compare at least:

- in-process engine API plus SQLite repository;
- local HTTP/Unix-socket service owning state and workers;
- versioning, crash recovery, concurrent-client semantics, migration strategy, and Linux-first packaging.

The implementation owner may recommend a default. Record the selected boundary here before implementing GS-1.5/GS-6.1.

## Upcoming checkpoint: legacy SSRF/OOB disposition

Trigger: after the thin engine client passes.

Inventory `mg-webscan` SSRF behavior and `mg-oob` tests/algorithms. Choose retain, adapt, merge, quarantine, or delete-after-replacement for each. Deletion is forbidden without demonstrated replacement parity or proof that no unique behavior remains.
