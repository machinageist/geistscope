---
name: web-cache-and-edge-flaws
description: >
  Hunt CDN, reverse proxy, and web cache flaws: web cache deception, web cache
  poisoning, unkeyed headers, host/header confusion, cacheable authenticated
  responses, edge authorization bypass, path normalization mismatch, and stale
  sensitive content. Use when recon shows Cloudflare, Fastly, Akamai, CloudFront,
  Varnish, nginx proxy caching, cache headers, X-Cache, Age, Via, CDN-specific
  headers, or routes mixing static-looking paths with authenticated content.
  Focus on controlled account proof and cache-buster isolation.
---

# Web Cache And Edge Flaws Skill

## 1. Identity and Quick Reference

CDNs and reverse proxies can disagree with the origin about cache keys, paths,
headers, or authentication. Good findings show that an attacker can poison a
shared cache, retrieve authenticated content from cache, or exploit path/host
normalization differences.

One-liner: find where the edge cache and origin disagree, then prove impact with
controlled content and cache-buster isolation.

Do not poison shared popular pages. Use unique cache busters, controlled paths,
and controlled accounts.

## 2. Severity and Payout Map

- Critical: cache poisoning leading to account takeover, credential theft,
  payment manipulation, or malware delivery on high-traffic pages.
- High: authenticated PII or account data cached and retrievable by another
  controlled user, edge authorization bypass, cache poisoning of sensitive flows.
- Medium: targeted web cache deception exposing controlled account data, unkeyed
  header poisoning on low-traffic/non-sensitive pages.
- Low/informational: cache header misconfiguration without exploitability,
  static asset cache anomalies, CDN fingerprinting only.

## 3. Recon Hooks

Headers:

```text
X-Cache, CF-Cache-Status, Age, Via, Server-Timing, CDN-Cache-Control,
Surrogate-Control, X-Served-By, X-Cache-Hits, Cache-Control, Vary, ETag
```

Edge providers:

```text
Cloudflare, Fastly, Akamai, CloudFront, Varnish, nginx, Envoy, Netlify, Vercel
```

Path and route patterns:

```text
/account
/profile
/settings
/api/me
/download
/export
/invoice
/callback
/*.css
/*.js
/*.png
```

High-signal behaviors:

- Authenticated page returns cache headers.
- `Vary` omits a header that changes content.
- `Host`, `X-Forwarded-Host`, scheme, or port affects generated links.
- Origin treats `/account` and `/account/nonexistent.css` as the same route.
- Cache treats query string, path parameters, or encoded characters differently
  from the origin.

## 4. Detection Workflow

1. Use a unique cache buster for every test.
2. Probe only controlled pages or harmless content first.
3. Compare cache status and body across account A, account B, and logged-out
   sessions.
4. For deception, append static-looking suffixes to authenticated routes and
   check whether controlled account data becomes cached.
5. For poisoning, test one unkeyed header or parameter at a time on a harmless
   route and verify cache hit behavior.
6. Confirm with two requests: one to seed cache, one from a different controlled
   context to retrieve poisoned or sensitive content.
7. Stop after controlled proof.

## 5. GeistScope Tooling Hooks

- `mg-fingerprint`: identify CDN/proxy/cache headers.
- `mg-replay`: compare cache miss/hit sequences.
- `mg-fuzz`: mutate headers and path normalization inputs with tight bounds.
- Planned request corpus: track auth context and cache key candidates.
- Planned TUI: show cache headers and account-context diffs side by side.

## 6. Report Evidence Checklist

- Cache-buster value used for isolation.
- Seed request and retrieval request.
- Account contexts for each request.
- Cache headers proving miss/hit or shared cache behavior.
- Response diff showing sensitive/poisoned controlled content.
- Explanation of edge/origin disagreement.

## 12. Session Mode Hooks

When a host shows CDN/cache headers and authenticated routes, suggest:

```text
First safe test: request one controlled authenticated page with a unique cache
buster, then request the same URL from a second controlled context and compare
cache headers and body.
```

When route normalization looks suspicious, suggest testing a static-looking suffix
on a controlled account page only. Avoid popular public pages and broad poisoning.
