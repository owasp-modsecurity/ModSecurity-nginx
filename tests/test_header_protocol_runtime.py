"""Exercise the actual synthetic Transfer-Encoding resolver across build modes.

The C fixture models NGINX callback boundaries only. It checks that HTTP/2 and
HTTP/3 bypass context/sanity/native mutations even when the host chunked flag
is set, while HTTP/1.x preserves the existing resolver result.
"""

from __future__ import annotations

import itertools
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HEADER_FILTER = ROOT / "src" / "ngx_http_modsecurity_header_filter.c"


def resolver_definition(source: str) -> str:
    name = "ngx_http_modsecurity_resolv_header_transfer_encoding"
    for match in re.finditer(rf"\b{name}\s*\(", source):
        cursor = source.index(")", match.end()) + 1
        while source[cursor].isspace():
            cursor += 1
        if source[cursor] != "{":
            continue
        start = source.rfind("\n", 0, match.start()) + 1
        start = source.rfind("\n", 0, start - 1) + 1
        depth = 0
        for index in range(cursor, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[start:index + 1]
    raise AssertionError("production Transfer-Encoding resolver was not found")


PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct {
    int chunked;
    int http_version;
#if (NGX_HTTP_V2)
    void *stream;
#endif
} ngx_http_request_t;
typedef struct { void *modsec_transaction; } ngx_http_modsecurity_ctx_t;
#define ngx_string(value) { sizeof(value) - 1, (u_char *) value }
#if nginx_version >= 1025000
#define NGX_HTTP_VERSION_30 3000
#endif

static int transaction;
static ngx_http_modsecurity_ctx_t context = { &transaction };
static unsigned context_calls, native_calls, sanity_calls;
static int native_result;

static ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    (void) r;
    context_calls++;
    return &context;
}

#if (MODSECURITY_SANITY_CHECKS)
static int ngx_http_modsecurity_store_ctx_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value)
{
    (void) r;
    if (name->len != 17 || value->len != 7) abort();
    sanity_calls++;
    return 1;
}
#endif

static int msc_add_n_response_header(void *owner, const unsigned char *name,
    size_t name_size, const unsigned char *value, size_t value_size)
{
    if (owner != &transaction || name_size != 17 || value_size != 7 ||
        memcmp(name, "Transfer-Encoding", 17) != 0 ||
        memcmp(value, "chunked", 7) != 0) abort();
    native_calls++;
    return native_result;
}
"""

MAIN = r"""
int main(int argc, char **argv)
{
    ngx_http_request_t request;
    ngx_str_t name = ngx_string("Transfer-Encoding");
    ngx_int_t result;

    if (argc != 5) return 2;
    memset(&request, 0, sizeof(request));
    request.http_version = atoi(argv[1]);
    request.chunked = atoi(argv[2]);
#if (NGX_HTTP_V2)
    request.stream = atoi(argv[3]) ? &transaction : NULL;
#endif
    native_result = atoi(argv[4]);
    result = ngx_http_modsecurity_resolv_header_transfer_encoding(&request,
        name, 0);
    printf("%ld %u %u %u\n", (long) result, native_calls, sanity_calls,
        context_calls);
    return 0;
}
"""


class HeaderProtocolRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise unittest.SkipTest("A C compiler is needed for header protocol regressions")
        cls.directory = tempfile.TemporaryDirectory(prefix="modsec-header-protocol-")
        cls.addClassCleanup(cls.directory.cleanup)
        source = PREAMBLE + resolver_definition(HEADER_FILTER.read_text(encoding="utf-8")) + MAIN
        path = Path(cls.directory.name) / "header-protocol.c"
        path.write_text(source, encoding="utf-8")
        cls.binaries = {}
        for v2, sanity, version in itertools.product((0, 1), (0, 1), (1024000, 1031000)):
            key = v2, sanity, version
            binary = Path(cls.directory.name) / f"header-{v2}-{sanity}-{version}"
            completed = subprocess.run(
                # NGINX builds with -Wno-unused-parameter too; resolvers share
                # one signature and need not use their offset.
                compiler + ["-std=c99", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter",
                            f"-DNGX_HTTP_V2={v2}",
                            f"-DMODSECURITY_SANITY_CHECKS={sanity}",
                            f"-Dnginx_version={version}", str(path), "-o", str(binary)],
                capture_output=True, text=True, check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stdout + completed.stderr)
            cls.binaries[key] = binary

    def execute(self, key, protocol, chunked, stream=0, result=73):
        completed = subprocess.run(
            [str(self.binaries[key]), str(protocol), str(chunked), str(stream), str(result)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        return tuple(map(int, completed.stdout.split()))

    def test_http1_chunked_preserves_native_and_sanity_callbacks(self):
        for key in self.binaries:
            with self.subTest(build=key):
                self.assertEqual(self.execute(key, 1001, 1), (73, 1, key[1], 1))

    def test_http1_unchunked_never_synthesizes_transfer_encoding(self):
        for key in self.binaries:
            with self.subTest(build=key):
                self.assertEqual(self.execute(key, 1001, 0), (1, 0, 0, 0))

    def test_http2_stream_bypasses_even_a_stale_chunked_flag(self):
        for key in self.binaries:
            if not key[0]:
                continue
            for chunked in (0, 1):
                with self.subTest(build=key, chunked=chunked):
                    self.assertEqual(self.execute(key, 2000, chunked, stream=1), (1, 0, 0, 0))

    def test_http3_bypasses_without_requiring_an_http2_stream_field(self):
        for key in self.binaries:
            if key[2] < 1025000:
                continue
            for chunked in (0, 1):
                with self.subTest(build=key, chunked=chunked):
                    self.assertEqual(self.execute(key, 3000, chunked), (1, 0, 0, 0))

    def test_http1_propagates_native_header_result(self):
        for key in self.binaries:
            for native_result in (-1, 0, 1):
                with self.subTest(build=key, result=native_result):
                    self.assertEqual(self.execute(key, 1001, 1, result=native_result),
                                     (native_result, 1, key[1], 1))


if __name__ == "__main__":
    unittest.main()
