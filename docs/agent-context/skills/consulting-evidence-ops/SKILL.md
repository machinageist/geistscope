---
name: consulting-evidence-ops
description: >
  Manage evidence and reporting for GeistScope bug bounty, pentest, and solo
  consulting work: rules of engagement, activity logs, redaction, replay,
  severity mapping, client-ready reports, bounty submissions, retest records,
  export bundles, and safe handling of tokens, PII, and screenshots. Use when
  creating findings, reports, wiki docs, or consulting deliverables.
---

# Consulting Evidence Ops Skill

## Workflow

1. Confirm rules of engagement and scope.
2. Keep raw evidence local and organized by engagement.
3. Redact before model ingestion, screenshots, report drafts, and exports.
4. Replay findings before submission or delivery when possible.
5. Map severity to the program/client rubric first, then CVSS/VRT if useful.
6. Export only what the client or platform needs.

## Evidence Minimums

```text
[ ] Affected asset
[ ] Auth state and role
[ ] Exact request and response
[ ] Steps to reproduce
[ ] Harmless-minimum proof
[ ] Impact explanation
[ ] Replay or retest status
[ ] Redaction review
```

## Redaction Rules

- Remove cookies, bearer tokens, API keys, private keys, and session IDs.
- Minimize or mask third-party PII.
- Prefer controlled test account data.
- Store hashes for correlation when the original value should not be shown.
- Keep unredacted originals out of public repos and AI context.

## Report Structure

```markdown
# <Severity> <Bug class> in <asset>

## Summary
## Affected Assets
## Steps To Reproduce
## Evidence
## Impact
## Severity Rationale
## Remediation
## Retest Notes
```

## Consulting Deliverables

- Executive summary.
- Scope and methodology.
- Findings table.
- Technical finding details.
- Evidence appendix.
- Retest status.
- Limitations and assumptions.
- Export manifest.

## Review Checklist

```text
[ ] No out-of-scope assets included.
[ ] No live secrets included.
[ ] No unnecessary third-party data included.
[ ] Replay status is current.
[ ] Impact is factual and not inflated.
[ ] Report language matches platform/client rubric.
```
