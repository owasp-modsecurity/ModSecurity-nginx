# Security Policy

## Supported Versions

Only the latest v1.0.x release of the ModSecurity-nginx connector is
supported. Security fixes land on `master` and ship in the next v1.0.x
release.

## Reporting a Vulnerability

Please do not report security issues publicly (no GitHub issues, pull
requests or mailing lists).

Report them privately with GitHub's
[Report a vulnerability](https://github.com/owasp-modsecurity/ModSecurity-nginx/security/advisories/new)
button. The maintainers triage the report there, coordinate a fix with you
and publish the advisory together with the fixed release. Reporters are
credited in the published advisory.

If you cannot use GitHub, email modsecurity@owasp.org instead.

When reporting, include the versions of the connector, libmodsecurity and
nginx you are running, and the relevant nginx and ModSecurity configuration.

## Scope

This repository covers the nginx connector only. Please report issues in the
related projects to them directly:

- **libmodsecurity** (rule engine, operators, transformations, body parsers):
  [owasp-modsecurity/ModSecurity](https://github.com/owasp-modsecurity/ModSecurity/security/advisories/new)
- **OWASP CRS** (rule false negatives/bypasses):
  [coreruleset/coreruleset](https://github.com/coreruleset/coreruleset/security/policy)

If you are not sure which component is at fault, report it here and we will
route it.

## Hardening Notes

- `modsecurity_rules_remote`: always use an `https://` URL. The key is a
  credential for the rules server; keep the nginx configuration that holds it
  readable only by the users that need it.
- `modsecurity_rules_file` and any files it includes: these are loaded by
  nginx and control what is blocked. Make sure only trusted users can write to
  them, their directories and any of their parent directories.
- `SecDebugLog` / `SecAuditLog`: debug and audit logs can contain full request
  and response data, including credentials and cookies. Write them to a
  directory that is not world-readable (not `/tmp`), make the log files
  themselves readable only by the users that need them, and do not leave a
  high `SecDebugLogLevel` enabled in production. The debug log and the audit
  log files named by `SecAuditLog`/`SecAuditLog2` are opened by the nginx
  master process (usually root), so neither their directory nor any of its
  parent directories may be writable by anyone but trusted users (root and
  the user nginx is started as), in particular not by the nginx worker user
  nor through a group or ACL; otherwise whoever can write there can replace a
  log file, or a directory on its path, with a symlink and have root append
  request data to any file. Concurrent audit logging is different: the
  per-transaction files in `SecAuditLogStorageDir` are created by the worker
  processes, so that directory must be writable by the worker user, but by no
  other untrusted user, and its parent directories only by trusted users;
  otherwise another user can replace the directory, or one of its parents,
  with a symlink.
- `modsecurity on` is an nginx-level switch only. Whether rules actually block
  is controlled by `SecRuleEngine` in the loaded rules. With `SecRuleEngine
  DetectionOnly`, or with `SecRuleEngine` not set at all, rules are evaluated
  but never block; only `SecRuleEngine On` enforces disruptive actions. Note
  that libmodsecurity's `modsecurity.conf-recommended` sets
  `SecRuleEngine DetectionOnly`: loading it, or CRS without any
  `SecRuleEngine` line, does not block. Set `SecRuleEngine On` explicitly when
  you want enforcement. These describe the configured mode: a rule with
  `ctl:ruleEngine` can change it for a single transaction, either way.
  Whether a match is logged depends on the rules and the logging
  configuration (for example, rules with `nolog` are not logged).
