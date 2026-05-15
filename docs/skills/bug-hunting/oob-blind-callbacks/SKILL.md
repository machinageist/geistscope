---
name: oob-blind-callbacks
description: >
  Hunt blind vulnerabilities that require out-of-band callbacks: blind SSRF,
  XXE, blind XSS, blind SSTI, blind command injection, unsafe webhooks, URL
  importers, image/PDF renderers, document converters, archive processors,
  deserialization gadgets, and server-side fetch features. Use when inputs accept
  URLs, XML, templates, filenames, callback/webhook URLs, avatar/image imports,
  file conversion jobs, metadata fetches, or integrations that may trigger DNS,
  HTTP, SMTP, LDAP, SMB, or cloud metadata interactions. Focus on scoped,
  harmless callback proof.
---

# OOB Blind Callback Skill

## 1. Identity and Quick Reference

Blind bugs often look like "nothing happened" in the HTTP response. The proof is
an external interaction: DNS lookup, HTTP callback, email, LDAP/SMB, or delayed
job execution. The payload should prove reachability and context without reading
or changing target data.

One-liner: generate a per-test callback, inject it into one plausible server-side
fetch/parser path, then tie the callback event back to the exact request.

Use a self-hosted OOB service or approved callback infrastructure for consulting
engagements with strict data-handling rules.

## 2. Severity and Payout Map

- Critical: OOB primitive chains to internal network access, credential exposure,
  cloud metadata, RCE proof, or cross-tenant data access.
- High: confirmed server-side fetch from sensitive network zone, blind command
  execution with harmless `id`/hostname style proof, webhook SSRF to internal
  control planes.
- Medium: confirmed blind SSRF without sensitive internal access, blind XXE DNS
  proof, blind XSS in admin workflow with limited impact.
- Low/informational: callback from third-party scanner, link preview bot, or
  expected integration with no security boundary impact.

## 3. Recon Hooks

Input names:

```text
url, uri, link, callback, webhook, redirect, next, target, image, avatar,
feed, import, export, pdf, render, fetch, proxy, site, domain, endpoint,
xml, template, file, attachment, document, archive
```

Feature signals:

- Import from URL.
- Generate PDF/screenshot/preview.
- Webhook configuration or test webhook button.
- XML/SOAP/SAML upload.
- Markdown/HTML rendering by background workers.
- Avatar or image fetch from remote URL.
- Link unfurling in comments, chat, tickets, or notifications.
- Cloud integrations and metadata-looking error messages.

## 4. Detection Workflow

1. Allocate a unique callback token for exactly one test.
2. Inject the callback into one input at a time.
3. Include a path that identifies engagement, endpoint, and parameter without
   leaking secrets.
4. Submit the minimum request required to trigger server-side processing.
5. Poll OOB logs for DNS/HTTP/SMTP/etc. events.
6. Record source IP, protocol, timestamp, user agent, path, and original request.
7. If callback fires, stop broad testing and validate impact with the smallest
   next proof allowed by scope.

Do not run internal port scans through SSRF unless the program explicitly allows
it. Do not fetch sensitive metadata unless the rules allow that exact proof.

## 5. GeistScope Tooling Hooks

- Planned `oob.allocate`: create per-engagement tokens.
- Planned `oob.poll`: attach callback events to request IDs.
- `mg-fuzz`: insert callback tokens into SSRF/XXE/template positions.
- `mg-replay`: reproduce one confirmed callback path.
- TUI browser: show live callback feed and link events to findings.

## 6. Report Evidence Checklist

- Exact request that carried the callback.
- Exact callback token and timestamp.
- OOB event protocol, source IP, host header/path, and user agent.
- Explanation of why the callback came from target-controlled processing.
- Harmless-minimum impact proof.
- Redaction of tokens, cookies, and unrelated callback payloads.

## 12. Session Mode Hooks

When an endpoint accepts a URL, XML, webhook, image, document, or render input,
suggest:

```text
First safe test: allocate one OOB token, place it only in the URL-like field,
submit once, then poll for DNS/HTTP callback evidence.
```

When a callback fires, suggest the next smallest impact validation based on
program rules. If the program forbids SSRF/internal testing, stop at callback
proof and document the boundary.
