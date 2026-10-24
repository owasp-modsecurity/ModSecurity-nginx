# Threat model

This file is read by Anthropic's OSS Scanner before it analyses ModSecurity-nginx, the nginx
connector of libModSecurity (ModSecurity v3). How to report: see the
[security policy](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/SECURITY.md).

## What this project does and where untrusted input enters

ModSecurity-nginx is an nginx module (`src/`, about 2000 lines of C) that connects nginx to
libModSecurity, the WAF engine. It adds the directives `modsecurity`, `modsecurity_rules`,
`modsecurity_rules_file`, `modsecurity_rules_remote`, `modsecurity_transaction_id` and
`modsecurity_use_error_log`, and for every request it:

- creates a libModSecurity `Transaction` (`ngx_http_modsecurity_create_ctx` in
  `src/ngx_http_modsecurity_module.c`), tied to the request pool by a cleanup handler;
- in the access phase (`src/ngx_http_modsecurity_access.c`) passes the connection, the
  request line, the headers and the request body (from memory buffers or from the temporary
  file nginx spooled it to) and acts on the intervention (`ngx_http_modsecurity_process_intervention`
  in `src/ngx_http_modsecurity_module.c`): a status or a redirect;
- in the header and body filters (`src/ngx_http_modsecurity_header_filter.c`,
  `src/ngx_http_modsecurity_body_filter.c`) passes the response headers and buffers the
  response body for inspection;
- in the log phase (`src/ngx_http_modsecurity_log.c`) runs the logging phase.

The library is not in this repository. Its sources, at the `v3/master` revision this image
was built with, are in `/opt/ModSecurity` for reference; findings in the library itself
belong to the ModSecurity enrolment, unless the connector feeds it something the API does not
allow.

**Every byte of the request and of the response is attacker-controlled**: the request line,
headers, cookies, the request body (also chunked, also over HTTP/2, also spooled to disk), and
the response headers and body from the upstream. The attacker also controls the timing:
when the client closes the connection, how slowly the body arrives, and whether the request
triggers internal redirects, subrequests or error pages.

**Configuration and rules are trusted**: the nginx configuration, the `modsecurity_*`
directives, the rule files and `modsecurity_rules_remote` sources, and the rules' own
actions (including the target of a `redirect`).

## Components that matter most / least

Most:

1. The request lifecycle and memory: the module context and transaction cleanup, request
   reference counting (`r->main->count`) around reading the body, internal redirects
   (`error_page`, `try_files`, `X-Accel-Redirect`), subrequests (`auth_request`, SSI),
   HTTP/2 streams, and client aborts. A use-after-free or double free of the transaction or
   the context across these paths is the most serious class here.
2. Completeness of inspection: a request or response part that nginx processes but the
   connector never hands to the library (a body that is not read, part of a chunked or
   HTTP/2 body, a header that is skipped, a response body that bypasses the filter), or an
   intervention that is returned but not enforced. Either is a WAF bypass.
3. The header filter's resolvers for headers nginx keeps in dedicated fields (`Server`,
   `Date`, `Content-Length`, `Content-Type`, `Last-Modified`, `Connection`,
   `Transfer-Encoding`, `Vary`), and the response body buffering in the body filter.
4. Configuration merging between `http`, `server` and `location` blocks: config is
   trusted, but a merge that silently applies the wrong rule set or none is in scope.

Less: `ngx-modsec.stp` (a SystemTap script), `release.sh`, `win32/`, `tests/` (the harness
itself), `.github/`.

Out of scope: nginx itself, libModSecurity itself (`/opt/ModSecurity`, enrolled separately),
nginx-tests (`/opt/nginx-tests`), the CRS's own detection logic.

## How to exercise it

- nginx with the connector built in is `/opt/nginx/objs/nginx` (built with `--with-debug`,
  HTTP/2 and `auth_request`). Rebuild after a change with `make -C /opt/nginx`.
- The connector's tests are `tests/modsecurity*.t`, written for nginx-tests' `Test::Nginx`
  (linked into `tests/lib`). Run them as the unprivileged user `builder`, as in CI:
  `cd /src/tests && runuser -u builder -- env TEST_NGINX_BINARY=/opt/nginx/objs/nginx prove
  modsecurity*.t` (or one file). Add `TEST_NGINX_LEAVE=1` to keep the test directory and its
  logs.
- **A reproducer as a `Test::Nginx` test case in the style of `tests/modsecurity*.t` is what
  we need in a report**: the nginx configuration, the rules and the request.
- The OWASP CRS v4 (latest release) is in `/opt/coreruleset`, and the library's
  `modsecurity.conf-recommended` in `/opt/ModSecurity`. Score against that configuration,
  not against a bare `SecRuleEngine On`.
- The image is built without sanitizers. To build with ASan offline, rebuild nginx with
  `./auto/configure ... --with-cc-opt="-g -O1 -fno-omit-frame-pointer -fsanitize=address"
  --with-ld-opt="-fsanitize=address" --add-module=/src` in `/opt/nginx`; nginx's own pool
  allocator hides some errors unless the configuration uses small pools. `gdb` and
  `valgrind` are installed.

## How you rate severity

We score with CVSS 3.1 and re-score every report during triage.

- **Memory corruption** (use-after-free, double free, buffer overflow) reachable by a
  remote client: High at a minimum, Critical when it is a controlled write. A crash takes
  down an nginx worker and every connection it serves.
- **WAF bypass** (request or response data that nginx processes but the library never
  inspects, or an intervention that is not enforced): Scope Changed, Integrity Low, which
  gives Medium for most. High when it bypasses inspection for a whole class of requests
  (for example every HTTP/2 request body) under a default configuration.
- **Denial of service** (a worker stuck, unbounded memory per request beyond what nginx's
  and the library's limits bound): Medium; High when a small request reliably exhausts a
  worker.
- **Crash without memory corruption** (null dereference, assertion) reachable by a remote
  client: Medium.
- Anything that requires control of the nginx configuration or the rules is not a
  vulnerability.

## How we want reports and patches

- A reproducer as a `Test::Nginx` test case, the nginx version, and the configuration.
- Patches against `master`, in nginx's coding style as used in `src/`, one fix per patch,
  with the test case in the same patch.
- The connector supports the nginx versions CI tests (currently 1.28.x to 1.30.x); a patch
  must not rely on an API only newer nginx versions have without a version guard.
