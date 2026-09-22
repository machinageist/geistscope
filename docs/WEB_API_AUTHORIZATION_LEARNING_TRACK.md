# GeistScope Web/API Authorization Learning Track

Status: accepted learning direction, not an implementation plan
Date: September 22, 2026
Audience: Jeff, working in controlled labs and CTF environments before real bug-bounty work

## Why this exists

GeistScope's next learning vertical is authenticated web/API authorization testing.

In plain English, the question is:

> Can one properly logged-in user read, change, or trigger something that belongs to another user or role?

The technical names are:

- IDOR — Insecure Direct Object Reference
- BOLA — Broken Object Level Authorization
- broken access control — the broader vulnerability family

This track is intentionally manual-first. It teaches how to understand HTTP requests, authentication state, application objects, and evidence before trying to automate anything.

It is not permission to test live systems. Until an individual program's current written policy explicitly allows an action, use only controlled labs, CTFs, or accounts and applications you own.

## The 12-week outcome

By the end of this track, you should be able to take two controlled accounts in a lab and produce one of three honest outcomes:

1. Candidate
   - Account A appears able to access Account B's object or action.
   - You have a minimal, redacted record of the request difference and result.
   - You explicitly state what still needs verification.

2. Negative result
   - The authorization boundary held: Account A was denied or received only its own data.
   - You preserve the observation because knowing what was tested prevents repeated work.

3. Invalid or insufficient result
   - You cannot prove who owns the object, which identity sent the request, or whether the action was safe.
   - You stop rather than inventing a finding.

The desired artifact is not a flashy exploit. It is a reproducible, redacted investigation record and a human verification runbook.

## Ground rules that prevent more technical debt

- Do not build a scanner, proxy, AI loop, TUI pane, or new engine feature before manually performing the exact workflow often enough to identify repeated friction.
- Do not test real programs until their current scope and rules explicitly permit the action.
- Do not use other users' data, accounts, or objects. In labs, create and control both sides of the test.
- Do not treat a changed object ID as proof. Compare the expected authorization rule, the request, the response, and the object ownership.
- Keep real targets, traffic, credentials, raw evidence, and operational notes in a private local workspace outside the public GeistScope repository.
- Keep public Git material limited to synthetic fixtures, schemas, sanitized examples, and deliberately reviewed lessons.

## Vocabulary: plain language paired with the technical term

| Plain language | Technical term | What you must understand |
|---|---|---|
| A browser or script asks a server for something | HTTP request | Method, URL/path, headers, cookies, body |
| The server replies | HTTP response | Status code, headers, body, redirects |
| The action requested | HTTP method / verb | `GET` reads; `POST`, `PUT`, `PATCH`, and `DELETE` may change state |
| A thing in the application | Object / resource | User profile, invoice, document, order, project, API key, message |
| A label used to identify that thing | Object identifier | ID in path, query string, JSON body, header, or encoded value |
| Proving who the user is | Authentication | Login, token, cookie, session, MFA |
| Deciding what that user may do | Authorization | Ownership, role, tenant, feature, workflow state |
| Two users from different organizations | Cross-tenant test | Tests whether tenant boundaries hold |
| A likely issue that is not proven yet | Finding candidate | Requires explicit uncertainty and a next verification step |
| The minimum record needed to repeat a claim | Evidence | Redacted request/response facts, identity labels, scope, and observations |

The critical distinction is authentication versus authorization:

- Authentication answers: "Who are you?"
- Authorization answers: "May you access this object or perform this action?"

A user can be correctly logged in and still be improperly authorized.

## Controlled lab identities: the practical rule

Use two separately controlled lab identities whenever an authorization lab requires comparison:

```text
lab-a  → tenant A / role A / object A
lab-b  → tenant B / role B / object B
```

Use the following boundary:

- Store actual usernames, passwords, recovery codes, session cookies, and tokens only in a password manager or the lab's own secure mechanism.
- Use a distinct browser profile or clearly separate browser session for each controlled identity. Do not casually switch one browser session between accounts.
- Record only aliases, role/tenant labels, ownership facts, session expiry/relogin notes, and redacted evidence in the private Markdown notebook.
- Treat a session cookie or bearer token like a password. It can usually act as the logged-in user for the life of the session, so never place it in Git, a notebook, a screenshot, shell history, chat, or a synthetic fixture.
- If a manual request-analysis tool displays a token, use it only within the private lab session when necessary, redact it before saving evidence, and end or rotate the session when the lab permits.
- Do not build a GeistScope vault, `.env` convention, session-capture feature, or secret-reference system during this learning track. Revisit that only after repeated manual friction proves a real need.

Relevant references:

- OWASP Session Management Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Secrets Management Cheat Sheet
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Required web resources, in learning order

### 1. Learn the HTTP language first

Read these before touching authorization labs. You do not need to memorize every header. You need to be able to explain what a request asks and why a response changed.

1. MDN — Overview of HTTP
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Overview

   Learn: client/server model, requests, responses, headers, proxies, state, and why HTTP is stateless by default.

2. MDN — HTTP messages
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Messages

   Learn: request line, status line, headers, and body. Be able to annotate one request and one response by hand.

3. MDN — HTTP request methods
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods

   Learn: what `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`, and `HEAD` mean. In particular, distinguish a read from a state-changing action.

4. MDN — Using HTTP cookies
   https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies

   Learn: how a server establishes session state even though HTTP itself is stateless. Never copy a real session cookie into notes, screenshots, Git, or chat.

5. RFC 9110 — HTTP Semantics
   https://www.rfc-editor.org/rfc/rfc9110.html

   Use as a reference, not a book to read cover-to-cover. Consult it when a method, status code, or caching behavior is confusing.

Completion check:

- Given a captured lab request, identify method, host, path, query parameters, headers, cookies/session context, and body.
- Given a response, identify status, response headers, body type, and whether it reveals data or changes state.

### 2. Learn access-control models before searching for bugs

1. PortSwigger Web Security Academy — Access control vulnerabilities and privilege escalation
   https://portswigger.net/web-security/access-control

   Learn: horizontal access control (user A versus user B), vertical access control (ordinary user versus administrator), and context-dependent access control (what actions are allowed at a particular workflow step).

2. OWASP Web Security Testing Guide — API Broken Object Level Authorization
   https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization/

   Learn: the testing objective, where object references appear, and why controlled accounts with separately owned objects are better than guessing random IDs.

3. OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization
   https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/

   Learn: why object IDs can appear in paths, query strings, headers, or request bodies, and why the server must enforce ownership rather than trusting the client-provided reference.

Completion check:

- Explain the difference between an IDOR/BOLA issue, a broken function-level authorization issue, and an authentication failure.
- Write an expected rule in plain language, for example: "A member of tenant A may read tenant A's invoice but not tenant B's invoice."

### 3. Learn API behavior and manual request analysis

1. PortSwigger Web Security Academy — API testing
   https://portswigger.net/web-security/api-testing

   Learn: endpoint discovery from normal application behavior, methods, content types, parameters, rate limits, and authentication mechanisms. Stay within the provided labs.

2. PortSwigger Web Security Academy — Getting started
   https://portswigger.net/web-security/getting-started

   Use its guided learning and lab workflow to build manual habits. Learn how to inspect and resend one request at a time before considering any bulk action.

3. PortSwigger Web Security Academy — All labs
   https://portswigger.net/web-security/all-labs

   Use only the Access control, Authentication, and API testing lab categories for this 12-week vertical. Do not turn this into a random-lab marathon.

Completion check:

- Start from normal lab navigation, identify a request that references an object, and explain which account owns it.
- Predict what a secure response should look like before changing any input.
- Make one controlled, minimal change and compare the result without creating unnecessary records or side effects.

### 4. Learn what a useful report and evidence record look like

1. HackerOne — Triage 101
   https://www.hackerone.com/sites/default/files/2025-02/HackerOne-Triage-101.pdf

   Learn: why concise reproduction, relevant impact, scope awareness, and a clear explanation reduce triage ambiguity. This is preparation for later real-program work, not a substitute for each program's current rules.

2. HackerOne Help Center — Post-Submission Guide
   https://docs.hackerone.com/en/articles/15518592-post-submission-guide

   Learn: how a submission moves through triage, validation, severity/scope review, and possible bounty decisions. Treat each live program's current policy as the controlling authority.

Completion check:

- Write a one-page candidate report for a lab with: title, scope/lab identity, expected rule, controlled identities, minimal steps, observed result, evidence references, impact hypothesis, limitations, and safe next step.
- Write a negative report for a secure lab case. Negative coverage is a valid investigation artifact.

## 12-week cadence

### Weeks 1–2: Read HTTP, do not build GeistScope

Goal: understand one request/response pair deeply.

Practice:

- Complete the HTTP resources above.
- Use only a controlled lab.
- Draw the flow: browser/client → request → server → response.
- Keep a private glossary in your own words.

Exit criterion:

- You can explain session state, method semantics, headers, and response status without relying on a tool label.

### Weeks 3–4: Controlled identities and objects

Goal: make authorization visible.

Practice:

- Create or use two controlled lab accounts, A and B.
- Create one object owned by each account when the lab allows it.
- Build an identity/object matrix:

```text
                 Object owned by A    Object owned by B
Account A         allowed              should be denied
Account B         should be denied     allowed
```

- Record the expected rule before performing a test.

Exit criterion:

- You can say which result would be a candidate, a negative, or invalid evidence.

### Weeks 5–7: Access-control and API labs

Goal: learn repetition without automation.

Practice:

- Work through introductory Access control, Authentication, and API testing labs.
- For each lab, preserve only redacted notes:
  - endpoint and method;
  - object reference location;
  - identity/role labels;
  - expected boundary;
  - observed boundary;
  - minimal evidence;
  - why the result is or is not a finding candidate.

Exit criterion:

- Complete at least three cases where the answer is not all the same: one candidate, one negative, and one insufficient/invalid result.

### Weeks 8–9: Build human verification runbooks

Goal: convert learning into reproducible investigation practice.

For each candidate, write:

1. Authorization and safety preconditions.
2. Controlled account/role setup.
3. Exact navigation or request sequence.
4. The one value that changes.
5. Expected secure behavior.
6. Expected vulnerable behavior.
7. Evidence to preserve.
8. False-positive checks.
9. Cleanup or rollback.
10. A hard stop if the test would touch uncontrolled data.

Exit criterion:

- Another careful learner could reproduce the lab result without receiving a credential, raw cookie, or destructive instruction.

### Weeks 10–11: Repeat with variation

Goal: prove understanding rather than memorizing a lab answer.

Practice a different access-control shape:

- horizontal access: user A versus user B;
- vertical access: ordinary user versus administrator;
- context-dependent access: an action allowed only at a specific workflow phase;
- API object reference in path, query parameter, or JSON body.

Exit criterion:

- You can identify the authorization rule before choosing what to inspect.

### Week 12: Retrospective before code

Do not add a feature because it sounds useful. Review your private lab notes and identify only friction observed at least three times.

For each proposed GeistScope feature, write:

```text
Observed repeated friction:
Manual workflow that caused it:
Evidence from three lab sessions:
Smallest artifact or command that would remove it:
What it must not automate:
How it will be tested in a controlled lab:
```

Only then is one narrow GeistScope learning slice eligible for design. The likely first slice is an offline importer for a redacted manual observation, producing a candidate/negative/invalid record, evidence bundle, and human runbook draft. It must remain local-only and execute no network traffic.

## What not to build yet

Explicitly defer these until repeated manual experience proves a need:

- a replacement nmap, tcpdump/Wireshark, shell, or terminal emulator inside GeistScope;
- live proxy interception or HTTPS MITM;
- browser automation;
- autonomous scanning, replay, payload generation, or adaptive scheduling;
- AI-based verdicts, severity decisions, or policy decisions;
- multi-user collaboration, cloud persistence, or public engagement sharing;
- broad vulnerability packs, RCE, brute force, post-exploitation, or destructive testing.

## Private investigation-note template

Keep this in the private engagement workspace, never in the public repository.

```text
Lab / target:
Authorization / scope basis:
Date:

Expected rule:
Identity A:
Identity B:
Object A:
Object B:

Baseline request:
- method:
- path:
- object reference location:
- state-changing? yes/no:

Minimal controlled change:

Expected secure result:
Observed result:

Classification: candidate / negative / invalid
Reason:

Redacted evidence references:
Limitations:
Next safe verification step:
Cleanup performed:
```

## Definition of learning-slice completion

This learning slice is complete when you can demonstrate, in controlled labs:

- correct reading of HTTP requests and responses;
- clear separation of authentication from authorization;
- two-identity, separately owned-object testing;
- candidate, negative, and invalid classifications;
- a redacted evidence record;
- a safe human verification runbook;
- a retrospective showing whether GeistScope removed a real repeated manual friction.

It is not complete because a scanner ran, a model proposed an exploit, a dashboard looked polished, or a new crate compiled.
