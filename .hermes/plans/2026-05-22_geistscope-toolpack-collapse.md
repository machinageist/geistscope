# GeistScope Tool-Pack Collapse Implementation Plan — SUPERSEDED

Superseded 2026-07-23 by `.hermes/plans/2026-07-23_hunting-engine-restructure.md`.

This plan's core rule — "repurpose first, prune only after capability is available under the
target pack" — was a conservative middle ground. The 2026-07-23 restructuring interview replaced
it with a stronger stance: no backwards compatibility is required, salvage proven logic and
architecture only where it earns that, and delete shallow/redundant tools instead of wrapping or
repurposing them indefinitely. See that document's "Compatibility stance" and "Scope boundary"
sections (capability-pack layout, salvage/rewrite/quarantine lists) for the current plan.

Original plan content is preserved in git history (see `git log -- .hermes/plans/2026-05-22_geistscope-toolpack-collapse.md`).
