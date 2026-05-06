# ModSecurity-nginx: Phase 4 Handling (English)

## Purpose of this document

This document describes the currently implemented Phase 4 behavior in the nginx module, including:

- technical limits once headers are already sent,
- behavior of `minimal`, `safe`, and `strict` modes,
- content-type scoping,
- logging (`modsecurity_phase4_log`) and security boundaries,
- a clear split between **production configuration** and **test/demo behavior**.

Only statements supported by the current repository code and tests are included.

---

## 1) Background: request vs response phases

ModSecurity rules run in multiple transaction phases.

- Early phases (for example request phases) make decisions before a response is emitted.
- `phase:4` belongs to **response-body processing**.

This difference is critical: during `phase:4`, nginx may already have sent headers and/or part of the body.

### Why this matters

If a `phase:4` rule triggers an intervention (`deny`, `status`, `redirect`), a clean status/redirect rewrite is only possible while headers are still unsent.

---

## 2) What `phase:4` means operationally

`phase:4` rules inspect response body content. This is useful when security signals are visible only in outgoing payload.

At the same time, this creates a hard technical boundary:

- **Before headers are sent**: status/redirect can still be applied cleanly.
- **After headers are sent**: status/redirect can no longer be reliably changed.

Therefore the module includes dedicated late-intervention handling.

---

## 3) Why headers may already be sent in `phase:4`

nginx processes responses as a stream. Depending on upstream behavior, buffering, and filter timing, headers can already be on the wire before body inspection fully completes.

Result: a `phase:4` `status:403` or `redirect:302` is not guaranteed to become a clean client-visible HTTP status.

> No false guarantee: after headers are sent, `phase:4` cannot guarantee a clean HTTP status rewrite.

---

## 4) New directives in this module

## `modsecurity_phase4_mode`

Configures phase-4 late-intervention behavior.

Supported values:

- `minimal`
- `safe`
- `strict`

Invalid values are rejected by configuration parsing.

## `modsecurity_phase4_content_types_file`

Loads scoped content types from a file.

- one MIME type per line,
- `#` comments supported,
- entries are validated,
- wildcards (`*`) are rejected.

If unset, module defaults are used.

## `modsecurity_phase4_log`

Enables dedicated JSON-lines logging for Phase 4 events.

---

## 5) Mode behavior (`minimal`, `safe`, `strict`)

## `minimal`

Goal: least intrusive behavior.

For interventions after headers were sent:

- action is downgraded to `log_only`,
- no forced connection termination.

Use when delivery continuity is prioritized.

## `safe`

Goal: conservative production baseline (module default merge behavior).

For late interventions:

- also downgraded to `log_only`.

Use as default when you want phase:4 visibility without forced disconnect side effects.

## `strict`

Goal: stricter fallback once clean status rewrite is no longer possible.

For interventions after headers were sent:

- `connection_abort`.

### Risks of `strict`

- Active connections may terminate.
- Clients/proxies may observe transport interruption rather than a clean 4xx/3xx response.
- It does **not** mean “guaranteed 403/401/301/302”.

Use only when those trade-offs are acceptable.

---

## 6) Behavior by header state

## Headers **not sent yet**

If intervention is finalized before header send, normal deny/status behavior remains possible (logged as `deny_status` in code path).

## Headers **already sent**

- `minimal`: `log_only`
- `safe`: `log_only`
- `strict`: `connection_abort`

This is an intentional downgrade to avoid false status guarantees.

---

## 7) Why there is **no global response-body buffering**

Global buffering of all responses could delay decision points, but introduces broad costs:

- additional memory and latency overhead,
- higher complexity in generic response paths,
- increased risk of throughput/stability side effects.

Current implementation instead makes late interventions explicit and controlled (`log_only` or `connection_abort`).

---

## 8) Why there is no `ngx_chain_t` reordering/rewriting

The module does **not** implement synthetic reordering of already flowing body chains to force post-hoc status semantics.

Reasoning:

- high implementation complexity,
- higher fragility,
- difficult correctness guarantees across all filter/upstream combinations.

The documented downgrade model is more robust than pretending hard guarantees.

---

## 9) Content-type scoping: meaning and safe usage

`modsecurity_phase4_content_types_file` limits special phase-4 handling to selected MIME types.

If `Content-Type` is missing or out of scope:

- action is logged as `log_only`,
- reason is typically `content_type_missing` or `content_type_not_in_scope`.

### Why this matters

- reduces side effects on non-target response types,
- improves predictability,
- enforces explicit operator intent.

---

## 10) Logging format and security boundaries

With `modsecurity_phase4_log`, the module emits JSON lines including fields such as:

- `event` (`phase4_intervention`)
- `uri`, `method`
- `response_status`, `waf_status`
- `content_type`
- `header_sent`
- `mode`
- `wanted_action`, `actual_action`
- `reason`
- `intervention`
- `rule_id`

Additionally, nginx `error.log` may contain warnings (especially on strict late-intervention paths).

### Logging boundary

Tests explicitly check that response body payload is not leaked into phase-4 log output.

---

## 11) Production examples

General (non test-path-specific) example configurations:

- `docs/examples/phase4-minimal.conf`
- `docs/examples/phase4-safe.conf`
- `docs/examples/phase4-strict.conf`
- `docs/examples/phase4-content-types.conf`

These use `http` / `server` / `location /` patterns and avoid `/phase4` as a production example path.

---

## 12) Test/demo behavior (explicitly separate)

Repository tests include `/phase4` endpoints, for example in:

- `tests/modsecurity.t`
- `tests/modsecurity-proxy.t`
- `tests/modsecurity-h2.t`
- `tests/modsecurity-proxy-h2.t`
- `tests/modsecurity-phase4-*.t`

Those paths are **test context**, not generic production guidance.

---

## 13) Known limits / no false promises

- `phase:4` cannot **guarantee** clean 301/302/401/403 delivery once headers are already sent.
- For late interventions, only downgraded handling is possible (`log_only` or `connection_abort`).
- `strict` is not “guaranteed block status”; it can mean connection termination.

---

## 14) Operator checklist

1. Place hard block/redirect decisions in earlier phases whenever possible.
2. Start with `safe` unless you have a clear need for `strict`.
3. Use `strict` only when connection abort side effects are acceptable.
4. Enable `modsecurity_phase4_log` and monitor `actual_action` + `reason` fields.
5. Keep content-type scope narrow and review it regularly.

