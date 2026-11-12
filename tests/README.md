# Tests

Those are nginx test files. You can copy those files into yours nginx test
tree, to perform the tests using the "prove" utility.

For more information about those tests, read the subsection "Testing your
patch" on the project's README file.

For more about nginx tests, check their repository:
http://hg.nginx.org/nginx-tests/

## Standalone Phase4 helper regressions

Run from the repository root with Python 3 and GCC or Clang:

```sh
CC=gcc python3 -m unittest discover -s tests -p 'test_*runtime.py' -v
CC=clang python3 -m unittest discover -s tests -p 'test_*runtime.py' -v
```

The suites compile the production body-filter functions, request-context
creation/lookup/cleanup, intervention helpers, and request/audit handlers with
small NGINX and libModSecurity doubles.
They check forwarding above the deprecated connector limit in every mode,
checked accounting, overflow, memory/file buffers, bounded file reads and allocation/read
errors, finalization at EOS, native failures, late interventions, downstream
`NGX_AGAIN`, request ownership, and internal redirect recovery. They need no
Common connector library. The intervention cases run with sanity checks enabled
and disabled and cover redirect ownership, status values, and cleanup. These
are helper behavior tests; they do not replace
the native HTTP integration tests.

Further regressions exercise invalid native result values, nondisruptive
outputs, exact native response-limit rejection, valid empty EOS markers,
failed filter re-entry (including NULL-input flushes), a synchronous core
error response, and early rejection after a single file chunk. Request tests
exercise internal target-location isolation, error-page P1/P2 continuation,
once-only audit logging, failed context creation and custom-ID termination.

## Native Phase4 integration tests

Copy `tests/*.t` and `tests/*.pl` into an nginx-tests checkout after building
NGINX with this connector and libModSecurity. From that checkout, run:

```sh
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity-phase4-*.t
TEST_NGINX_BINARY=/absolute/path/to/nginx prove modsecurity*.t
```

The Phase4 suites cover `off` (the default), `safe`, and `strict`, JSON event
logging, engine-owned `SecResponseBodyMimeType` selection, complete response
delivery above the deprecated connector limit in every mode, and engine-owned
`SecResponseBodyLimit` behavior with `Reject` and `ProcessPartial`. They also
reject the removed `minimal` mode and connector
MIME directive. Late deny/redirect assertions check transport interruption,
because headers have already been committed; they do not promise a clean 403.
Native engine Reject is an error in every mode, including safe; it does not
emit a rule-policy JSON event or attempt a second response header. The error
page suite also verifies target-location P1/P2 blocking after internal routing.

A separate GitHub workflow job runs the standalone suite immediately with
both Linux compilers, independently of the libModSecurity build. The native
Perl suites run in the Linux and Windows build jobs.

`modsecurity-phase4-subrequest.t` checks that a disabled, header-only
`auth_request` response cannot consume the main transaction's response headers
or MIME selection. The main response must still run its Phase3 header rule and
Phase4 body rule. Direct subrequest EOS ownership is exercised separately by
the compiled helper suite; the auth fixture does not claim to emit a body EOS.
