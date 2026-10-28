# ModSecurity-nginx: Phase 4 Handling (English)

## 1) Scope and provenance

Phase 4 inspects the response body. nginx can already have sent headers or body
bytes when a phase 4 rule requests a deny status or redirect. A late
intervention cannot reliably replace the HTTP status already sent to the
client.

This branch adopts the relevant nginx implementation from
[Easton97-Jens/ModSecurity-conector, commit b0f3bdab429717b5b0311c30c5b4d1153c672ac0](https://github.com/Easton97-Jens/ModSecurity-conector/tree/b0f3bdab429717b5b0311c30c5b4d1153c672ac0/connectors/nginx/src).
The response-limit ownership update follows
[commit 820b6975495bdf0f90aca67eee86e27a3b7d329b](https://github.com/Easton97-Jens/ModSecurity-conector/blob/820b6975495bdf0f90aca67eee86e27a3b7d329b/docs/phase4-mode-budget.md).
Native-result, response completion, and lifecycle corrections follow
[commit f5523da040bd6325b369269ada074be6ba069c4f](https://github.com/Easton97-Jens/ModSecurity-conector/tree/f5523da040bd6325b369269ada074be6ba069c4f/connectors/nginx/src).
These changes are adapted to this standalone module and preserve its phase 4
JSON-lines schema. The source repository's multi-connector runtime and run
evidence are not imported.

This document describes source behavior. It does not claim that runtime,
protocol, or integration tests have passed for this migration.

## 2) Configuration and breaking changes

All three connector directives below are valid in `http`, `server`, and
`location` contexts and inherit from the enclosing context.

| Directive | Values | Default |
| --- | --- | --- |
| `modsecurity_phase4_mode` | `off`, `safe`, `strict` | `off` |
| `modsecurity_phase4_body_limit` | Deprecated, ignored compatibility value; positive bytes or nginx size, e.g. `256k`, `2m` | `1m` (1 MiB), ignored |
| `modsecurity_phase4_log` | File path for phase 4 JSON-lines events | No dedicated log |

When migrating older phase 4 configurations, note:

- `minimal` is no longer valid and is not an alias for `off`.
- The default is `off`; older configurations may have relied on `safe`.
  Set `safe` or `strict` explicitly to enable the additional connector policy.
- `modsecurity_phase4_content_types_file` is removed and causes an nginx
  configuration error. Move MIME selection into ModSecurity rules.
- `modsecurity_phase4_body_limit` is now deprecated and ignored in all valid
  modes. Its positive-value parser, inheritance, and historical 1 MiB default
  remain for compatibility; zero is still invalid. Move inspection limits into
  `SecResponseBodyLimit` and `SecResponseBodyLimitAction`.

Validate the migrated configuration with `nginx -t` in the deployment
environment before reloading nginx.

## 3) Mode behavior and header timing

`off` disables the connector's additional phase 4 intervention policy.
It **does not disable ModSecurity**, response-body inspection, or phase
4 rules. Native intervention handling remains active. If a native intervention
occurs after headers have been committed, the affected transport is failed
without trying to send another HTTP status; `off` is not a promise to deliver
every response or to reproduce every pre-PR intervention control-flow decision.

For the additional policy in `safe` and `strict`:

| Header state | `safe` | `strict` |
| --- | --- | --- |
| Headers not sent | Apply the intervention's status/redirect through the normal path; logged as `deny_status` | Same |
| Headers already sent | Log the rule intervention as `log_only` and continue if logging succeeds | Log `connection_abort` and terminate the response |

`safe` only downgrades late **rule interventions**. An engine API failure, invalid
buffer, failed file read, allocation failure, counter overflow, or final
processing failure remains a failure. It is not converted into successful
forwarding. Native response-limit Reject is not a rule-policy downgrade.

Once a response has failed, later data callbacks and NULL-input flushes cannot
resume forwarding. Before headers are sent, nginx may render its synchronous
core error response once; subsequent callbacks retain the failure. Ordinary
successful downstream `NGX_AGAIN` handling remains unchanged.

`strict` can produce a truncated response or a client/proxy transport error.
It cannot guarantee a clean 403, 401, 301, or 302 after headers have been sent.
Previously forwarded body bytes cannot be recalled.

## 4) Engine inspection limits and streaming

libModSecurity owns the WAF response-inspection byte limit through
`SecResponseBodyLimit` and `SecResponseBodyLimitAction` in every phase 4 mode.
The connector does not add a cumulative inspection ceiling for `safe`,
`strict`, or `off`, and does not reject a response merely because it exceeds
`modsecurity_phase4_body_limit`.

For example, configure this engine policy in your ModSecurity rules:

```apache
SecResponseBodyLimit 1048576
SecResponseBodyLimitAction ProcessPartial
```

The 1 MiB value is an explicit example setting, not a new engine default.
`ProcessPartial` selects inspection of the portion within the engine limit;
`Reject` is the alternative engine action when rejection is required. Mode
selection does not override that engine policy. Native Reject is recognized
by its exact rule-free engine signature while processing a response body. It
produces 403 before headers are sent, or fails the transport after commitment,
in all modes including `safe`. It does not produce a `phase4_intervention`
rule-policy event; a fixed diagnostic is written to the nginx error log.

The deprecated connector setting remains parseable and inherited, but its
value has no enforcement effect in any valid mode. A successful configuration
load therefore does not establish the old connector inspection limit. Migrate
that policy to the engine settings above.

Checked cumulative byte accounting still rejects overflow beyond `SIZE_MAX`
in all modes. Genuine processing and file-read failures remain failures;
nonfatal engine `ProcessPartial` ingestion is not a connector failure.

The connector does not globally buffer responses or reorder nginx body
chains. Memory buffers are inspected directly. File-only buffers are read
through a bounded 32 KiB scratch buffer, without loading the entire file into
memory or replacing the original outgoing chain. Pending interventions are
checked after every file chunk so Reject stops further reads immediately.
Genuine processing or I/O failures stop the affected response.

The response body is finalized once per transaction: a main request uses
`last_buf`; a subrequest uses `last_in_chain`. Repeated filter calls after
finalization do not run phase 4 again. Empty memory/EOS buffers with both data
pointers NULL are valid; a missing single pointer or inverted range remains an
error. Native byte appends accept only 0/1 (`ProcessPartial` may return 0),
phase evaluation succeeds only with 1, and native intervention collection
accepts only 0/1 and honors the disruptive flag.

## 5) MIME selection belongs to ModSecurity

The engine decides response-body inspection using `SecResponseBodyAccess`,
`SecResponseBodyMimeType`, and `SecResponseBodyMimeTypesClear`. There is no
connector content-type allowlist or connector MIME-based downgrade.

For example, reset the MIME list in one rule load, then add the selected types
in a separate load:

```nginx
modsecurity_rules 'SecResponseBodyMimeTypesClear';
modsecurity_rules '
    SecResponseBodyAccess On
    SecResponseBodyMimeType text/html text/plain application/json
';
```

The reset is separate because libModSecurity's
[merge implementation](https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/headers/modsecurity/rules_set_properties.h)
can clear MIME values added in the same rule load.

The standalone [engine MIME example](examples/phase4-engine-mime.conf) contains
MIME additions, response-body access, and an explicit engine limit policy.
It is a ModSecurity rules
file, not an nginx include. To replace the engine's MIME list with this file,
load the reset first, then the file, alongside your other rules:

```nginx
modsecurity_rules 'SecResponseBodyMimeTypesClear';
modsecurity_rules_file /etc/modsecurity/phase4-engine-mime.conf;
```

The complete nginx examples below configure MIME selection inline using the
same separate-load sequence.

Engine MIME selection and inspection limits apply in every phase 4 mode;
there is no additional connector inspection budget.

## 6) Logging format and security boundary

`modsecurity_phase4_log` preserves the existing JSON-lines intervention schema:

- `event` (`phase4_intervention`), `uri`, `method`;
- `response_status`, `waf_status`, `content_type`, `header_sent`, `mode`;
- `wanted_action`, `actual_action`, `reason`;
- `intervention`, `rule_id`.

The `actual_action` values remain `deny_status`, `log_only`, and
`connection_abort`; `mode` uses the current mode names. The intervention
message is redacted rather than copied from the engine, and response-body
payload is not added to this event. nginx's error log may also contain
diagnostics.

`off` uses native intervention handling and does not produce these dedicated
policy events. A dedicated intervention event is not a complete inventory of
all engine, buffer, or I/O errors.

Native audit logging is attempted once, including re-entry, and its return
value is checked. A failed audit attempt is retained as a failure without
trying to generate a new HTTP response. Request inspection also preserves
deny/redirect decisions across `error_page` routing; a new internal target
location starts its own transaction rather than reusing processed state.

## 7) Configuration examples and verification

- [off](examples/phase4-off.conf): native intervention handling with explicit
  engine inspection policy.
- [safe](examples/phase4-safe.conf): explicit late `log_only` policy.
- [strict](examples/phase4-strict.conf): late connection termination.

- [engine MIME selection](examples/phase4-engine-mime.conf): ModSecurity
  response-body configuration.

All three examples configure the same 1 MiB engine limit with `ProcessPartial`;
that limit policy is independent of the connector mode.

The nginx examples use `location /` and an example upstream at
`127.0.0.1:8081`. Adapt the listen address, upstream, log path, and rules to
your environment. The `sensitive-marker` rule is illustrative.

Repository test endpoints such as `/phase4` are test fixtures, not required
production paths. Runtime checks should cover late deny/redirect behavior,
HTTP/1.1 and HTTP/2, file-backed responses, subrequests, repeated finalization,
engine-limit boundaries, responses above the ignored legacy setting, and
failure paths. Results from another repository or build
do not establish those behaviors for the deployed module.
