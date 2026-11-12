# Security Policy

## Supported Versions

Only the latest v1.0.x release of the ModSecurity-nginx connector is
supported. Security fixes land on `master` and ship in the next v1.0.x
release.

## Reporting a Vulnerability

Please do not report security issues publicly (no GitHub issues, pull
requests or mailing lists).

Report them privately by opening a
[draft security advisory](https://github.com/owasp-modsecurity/ModSecurity-nginx/security/advisories/new)
on GitHub. The maintainers triage the report there, coordinate a fix with you
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
  them.
- `SecDebugLog` / `SecAuditLog`: debug and audit logs can contain full request
  and response data, including credentials and cookies. Write them to a
  directory that is not world-readable (not `/tmp`), and do not leave a high
  `SecDebugLogLevel` enabled in production.
- `modsecurity on` is an nginx-level switch only. Whether rules actually block
  is controlled by `SecRuleEngine` in the loaded rules; `SecRuleEngine
  DetectionOnly` logs but never blocks.
