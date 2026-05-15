---
name: api-schema-bola
description: >
  Hunt API authorization bugs using OpenAPI, Swagger, Postman collections,
  REST route inventories, GraphQL operation lists, mobile API traces, and
  JavaScript-discovered endpoints. Use when an engagement exposes schema files,
  /swagger, /api-docs, /openapi.json, typed object IDs, tenant IDs, org IDs,
  role fields, admin-only operations, undocumented request properties, or
  request/response shapes that suggest BOLA, BFLA, object-property authorization,
  mass assignment, or cross-tenant access. Prioritize controlled two-account and
  two-tenant tests with harmless-minimum proof.
---

# API Schema BOLA Skill

## 1. Identity and Quick Reference

APIs often reveal their authorization model through schemas, route names, object
IDs, and response shapes. The valuable bug is usually not "schema exposed"; it is
what the schema lets you test: broken object-level authorization, broken function
authorization, property-level authorization, or mass assignment.

One-liner: use schemas and captured traffic to build controlled account-to-account
tests for object, tenant, role, and property boundaries.

Safe proof standard: use accounts, tenants, objects, and roles controlled by the
researcher. Do not enumerate real users or export third-party data.

## 2. Severity and Payout Map

- Critical: cross-tenant admin action, privilege escalation to admin/owner, bulk
  sensitive data access, or account takeover chain.
- High: read/write access to another user's sensitive object, payment/order/PII
  access, role or tenant manipulation, hidden admin function reachable by normal
  user.
- Medium: read-only access to low-sensitivity controlled objects, schema-assisted
  enumeration with limited data exposure, mass assignment of non-critical fields.
- Low/informational: schema exposure alone, version disclosure, unauthenticated
  docs without sensitive operations or exploit path.

Impact language should focus on business function bypass, tenant isolation, PII,
financial actions, and privilege boundary failure.

## 3. Recon Hooks

Look for:

```text
/swagger
/swagger-ui
/api-docs
/openapi.json
/openapi.yaml
/v3/api-docs
/docs
/redoc
/postman.json
/graphql
```

High-signal names:

```text
userId, accountId, customerId, tenantId, orgId, workspaceId, projectId
role, isAdmin, permissions, owner, member, invite, billing, payout
export, report, impersonate, admin, internal, debug, audit, token
```

High-signal response patterns:

- Object IDs are predictable or enumerable.
- Error messages distinguish "not found" from "not authorized".
- Same endpoint behaves differently by role but not by object owner.
- Hidden request properties are accepted even when absent from UI.
- Schema lists operations not reachable from the frontend.
- Mobile or SPA traffic contains richer endpoints than public docs.

## 4. Detection Workflow

1. Import or crawl the schema and captured traffic.
2. Identify object-bearing routes and mutations.
3. Create or choose two controlled accounts. Use two tenants/orgs if the program
   allows cross-tenant tests.
4. Capture a baseline request as account A against account A's object.
5. Replace only the object, tenant, org, or role identifier with account B's
   controlled value.
6. Replay as account A and compare status, body fields, side effects, and audit
   visibility.
7. For mass assignment, add one undocumented field at a time. Prefer harmless
   profile flags over destructive or financial fields unless explicitly allowed.
8. Stop after the minimum proof and write a finding with both controlled accounts.

## 5. GeistScope Tooling Hooks

- `mg-crawl`: collect API paths and schema links from HTML and JavaScript.
- `mg-fuzz`: replace object IDs, tenant IDs, roles, and hidden fields in raw
  request templates.
- `mg-replay`: verify a controlled BOLA/BFLA proof before submission.
- Planned request corpus: tag requests with account, tenant, role, and object
  owner metadata.
- Planned AI harness: propose one controlled object-boundary test at a time.

## 6. Report Evidence Checklist

- Two controlled accounts or tenants named by role.
- Baseline request and response for the owner account.
- Mutated request showing the boundary change.
- Response proving unauthorized read/write/action.
- Business impact in program terms.
- Replay verdict.
- Redacted tokens, cookies, and PII.

## 12. Session Mode Hooks

When recon shows Swagger/OpenAPI/Postman/GraphQL/schema signals, propose:

```text
First safe test: choose one object created by controlled account B and replay a
single account-A request with only that object ID changed. Compare for 200,
field leakage, or state change.
```

When a response contains `tenantId`, `orgId`, `workspaceId`, or `role`, propose a
two-tenant or two-role test only if the engagement permits those accounts.

If scope or test account ownership is unclear, block active testing and ask for
authorization details.
