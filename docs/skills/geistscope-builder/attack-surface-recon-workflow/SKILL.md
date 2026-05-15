---
name: attack-surface-recon-workflow
description: >
  Run structured attack-surface recon for GeistScope engagements: scope intake,
  subdomains, ports, fingerprints, crawling, traffic import, API/schema discovery,
  technology clustering, public report learning, priority queues, and first safe
  test selection. Use during live bug bounty or consulting recon and when
  improving recon-related code or documentation.
---

# Attack Surface Recon Workflow Skill

## Workflow

1. Confirm authorization and scope.
2. Run or import passive recon before active probes where possible.
3. Build a host/path/parameter inventory.
4. Cluster assets by technology, auth state, business function, and freshness.
5. Identify high-value surfaces: auth, billing, admin, export, upload, import,
   webhook, integration, tenant, and API operations.
6. Convert each hypothesis into one safe first test.
7. Record what worked, what was noise, and what should feed skills.

## GeistScope Commands

```bash
mg-engagement init <name> --target <domain>
mg-recon <name>
mg-crawl <name> https://<host>
mg-probe <name>
ai-prioritize <name>
```

Use `mg-fuzz` and `mg-replay` only after a concrete hypothesis exists.

## Signal Map

- Many subdomains plus varied tech: prioritize inventory, takeover, stale apps.
- API docs/schema: prioritize BOLA/BFLA/mass assignment.
- CDN/cache headers: prioritize cache and edge tests.
- File/import/render features: prioritize OOB and parser tests.
- Auth/session flows: prioritize reset, OAuth, JWT, role and tenant boundaries.
- Debug/admin paths: prioritize exposure, auth boundary, and environment leakage.

## First Safe Test Rule

For every target, ask:

```text
What is the smallest scoped request that can disprove or support this hypothesis
using only controlled accounts and harmless data?
```

Avoid broad scans when one replay can answer the question.

## Evidence Notes

Record:

- Source of discovery.
- Target URL and auth state.
- Why it is in scope.
- Hypothesis.
- First test.
- Result.
- Next action or stop condition.
