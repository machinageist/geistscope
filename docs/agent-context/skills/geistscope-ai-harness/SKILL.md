---
name: geistscope-ai-harness
description: >
  Build or review GeistScope's AI harness: typed tool endpoints, local dispatch,
  model-provider adapters, strict schemas, scoped active testing, redaction,
  audit logs, prompt-injection defenses, allowed-tool narrowing, and safe
  integration with the Rust engine. Use when adding mg-harness, AI tool calling,
  endpoint schemas, or model-assisted actions in the TUI.
---

# GeistScope AI Harness Skill

## Workflow

1. Read `docs/PRODUCT_DOCTRINE.md` and `docs/AI_TOOL_ENDPOINTS.md`.
2. Identify whether the change is endpoint schema, dispatcher, provider adapter,
   prompt template, TUI action, or existing tool integration.
3. Keep the model boundary strict: the model requests endpoints; Rust validates
   and dispatches endpoints.
4. Add or update audit events for every dispatch, block, and confirmation.
5. Add prompt-injection and malformed-argument tests for any model-visible path.

## Endpoint Rules

- Endpoint names are stable: `domain.action`.
- Inputs and outputs are typed Rust structs.
- Model request, validated request, and persisted audit record are separate.
- Active endpoints require engagement and target.
- Scope check happens before network traffic.
- High-active and state-changing endpoints require user confirmation.
- Raw shell command construction from model-provided text is not allowed.

## Redaction Rules

- Do not send cookies, bearer tokens, API keys, private keys, or third-party PII
  to the model by default.
- Store full evidence locally and send model-visible summaries plus hashes.
- Cap response bodies before model ingestion.
- Preserve enough evidence references for replay and reporting.

## Rust Conventions

- Preserve the required file header comment.
- Add `// Verb + noun` comments above functions and major blocks.
- Keep library logic reusable and binaries thin.
- Run `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`.

## Review Checklist

```text
[ ] Endpoint has risk class and schema.
[ ] Scope gate covers active calls.
[ ] Redaction happens before model-visible output.
[ ] Audit log records dispatch or block.
[ ] Prompt-injection fixture covers untrusted web/log content.
[ ] Tests cover invalid model arguments.
[ ] No raw shell access is exposed to the model.
```
