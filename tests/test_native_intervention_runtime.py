"""Check ngx_http_modsecurity_process_intervention() against msc_intervention().

msc_intervention() returns the C++ bool of Transaction::intervention(), so 0
or 1, and writes to the structure only when it returns 1. "url" and "log"
are strdup() copies the caller frees. Up to libModSecurity 3.0.12 it returns
the "disruptive" field it was given and writes "url" and "log" only when the
rule set them.

The function and ngx_http_modsecurity_get_module_ctx() are compiled from
src/ with NGINX and libModSecurity doubles, with and without
MODSECURITY_SANITY_CHECKS. The nginx-tests suites cover the module in NGINX.

The double allocates "url" and "log" with malloc() and counts what is not
freed, so a leak, a double free or a free of another pointer fails a case. The
cases also run built with AddressSanitizer and UndefinedBehaviorSanitizer when
the compiler supports them, which catches a Location header that still points
at the freed "url". Set INTERVENTION_RUNNER to run the plain builds under a
tool, for example INTERVENTION_RUNNER="valgrind --error-exitcode=99
--leak-check=full".
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "ngx_http_modsecurity_module.c"


def function_definition(source: str, name: str) -> str:
    """Return the definition of name from its line to its closing brace."""
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
        cursor = source.index("(", match.start())
        depth = 0
        for cursor in range(cursor, len(source)):
            depth += {"(": 1, ")": -1}.get(source[cursor], 0)
            if depth == 0:
                break
        body = re.compile(r"\s*\{").match(source, cursor + 1)
        if body is None:
            continue
        depth = 0
        for end in range(body.end() - 1, len(source)):
            depth += {"{": 1, "}": -1}.get(source[end], 0)
            if depth == 0:
                start = source.rfind("\n", 0, match.start()) + 1
                return source[start:end + 1]
    raise AssertionError(f"{name} definition was not found")

PREAMBLE = r"""
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define nginx_version 1031010
#define dd(...)

typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct ngx_table_elt_s ngx_table_elt_t;
struct ngx_table_elt_s {
    ngx_uint_t hash;
    ngx_str_t key, value;
    u_char *lowcase_key;
    ngx_table_elt_t *next;
};
typedef struct { ngx_table_elt_t elts[4]; ngx_uint_t nelts; } ngx_list_t;
typedef struct ngx_pool_cleanup_s {
    void (*handler)(void *);
    void *data;
    struct ngx_pool_cleanup_s *next;
} ngx_pool_cleanup_t;
typedef struct {
    ngx_pool_cleanup_t *cleanup;
    u_char storage[1024];
    size_t used;
} ngx_pool_t;
typedef struct { int unused; } ngx_log_t;
typedef struct { ngx_log_t *log; } ngx_connection_t;
typedef struct { int unused; } Transaction;
/* The layout of libModSecurity's headers/modsecurity/intervention.h */
typedef struct {
    int status;
    int pause;
    char *url;
    char *log;
    int disruptive;
} ModSecurityIntervention;
typedef struct {
    Transaction *modsec_transaction;
    unsigned logged:1;
} ngx_http_modsecurity_ctx_t;
typedef struct { ngx_int_t use_error_log; } ngx_http_modsecurity_conf_t;
typedef struct {
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
    unsigned header_sent:1;
    struct { ngx_list_t headers; ngx_table_elt_t *location; } headers_out;
} ngx_http_request_t;

#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_LOG_ERR 4
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define ngx_inline inline
#define ngx_http_modsecurity_module 0
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define ngx_memzero(buf, n) (void) memset(buf, 0, n)
#define ngx_memcpy(dst, src, n) (void) memcpy(dst, src, n)
#define ngx_strlen(s) strlen((const char *) (s))
#define ngx_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
static int clear_calls;
#define ngx_http_clear_location(r) \
    ++clear_calls; \
    if ((r)->headers_out.location) { \
        (r)->headers_out.location->hash = 0; \
        (r)->headers_out.location = NULL; \
    }

/* libModSecurity double, see Transaction::intervention() */
#define NO_OVERRIDE INT_MIN
static int lib_pending, lib_status = 403, lib_legacy;
static int lib_return = NO_OVERRIDE, lib_disruptive = 1;
static const char *lib_url;
static const char *lib_log = "native intervention message";
static Transaction *expected_transaction;
static int native_calls, native_initialized;
static uintptr_t native_url, native_log;
/* Live copies, stored inverted so that leak checkers do not see them. */
static uintptr_t live[8];
static int live_count, free_calls, bad_free;

static char *native_strdup(const char *s)
{
    char *copy = malloc(strlen(s) + 1);
    if (copy == NULL || live_count == 8) abort();
    strcpy(copy, s);
    live[live_count++] = ~(uintptr_t) copy;
    return copy;
}
static void tracked_free(void *p)
{
    int i;
    for (i = 0; i < live_count; ++i) {
        if (live[i] == ~(uintptr_t) p) {
            live[i] = live[--live_count];
            ++free_calls;
            free(p);
            return;
        }
    }
    ++bad_free;
}
#define free(p) tracked_free(p)

static int msc_intervention(Transaction *transaction, ModSecurityIntervention *it)
{
    int disruptive = lib_pending;
    ++native_calls;
    if (transaction != expected_transaction) abort();
    native_initialized = it->status == 200 && it->pause == 0 &&
        it->url == NULL && it->log == NULL && it->disruptive == 0;
    if (lib_pending) {
        if (lib_url != NULL) it->url = native_strdup(lib_url);
        else if (!lib_legacy) it->url = NULL;
        it->disruptive = lib_disruptive;
        it->status = lib_status;
        if (lib_log != NULL) it->log = native_strdup(lib_log);
        else if (!lib_legacy) it->log = NULL;
        native_url = (uintptr_t) it->url;
        native_log = (uintptr_t) it->log;
        lib_pending = 0;
    }
    if (lib_return != NO_OVERRIDE) return lib_return;
    return lib_legacy ? it->disruptive != 0 : disruptive;
}
static int status_calls, updated_status;
static void msc_update_status_code(Transaction *transaction, int status)
{
    if (transaction != expected_transaction) abort();
    ++status_calls;
    updated_status = status;
}

/* NGINX and connector doubles */
static int alloc_calls, fail_alloc, push_calls, fail_push;
static void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    ++alloc_calls;
    if (fail_alloc || size > sizeof(pool->storage) - pool->used) return NULL;
    p = pool->storage + pool->used;
    pool->used += size;
    return p;
}
static void *ngx_list_push(ngx_list_t *list)
{
    ngx_table_elt_t *elt;
    ++push_calls;
    if (fail_push || list->nelts == 4) return NULL;
    elt = &list->elts[list->nelts++];
    memset(elt, 0xa5, sizeof(*elt));
    return elt;
}
static int log_calls, error_calls;
static char last_log[256], last_error[256];
static void ngx_log_error(ngx_uint_t level, ngx_log_t *log, int err, const char *fmt, ...)
{
    va_list args;
    (void) level; (void) log; (void) err;
    va_start(args, fmt);
    if (strcmp(fmt, "%s") == 0) {
        ++log_calls;
        vsnprintf(last_log, sizeof(last_log), fmt, args);
    } else {
        ++error_calls;
        vsnprintf(last_error, sizeof(last_error), fmt, args);
    }
    va_end(args);
}
static int early_log_calls;
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    (void) r;
    ++early_log_calls;
    return NGX_OK;
}
static void ngx_http_modsecurity_cleanup(void *data) { (void) data; }
#if MODSECURITY_SANITY_CHECKS
static int sanity_calls;
static ngx_int_t ngx_http_modsecurity_store_ctx_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value)
{
    (void) r;
    if (name->len != 8 || memcmp(name->data, "Location", 8) != 0) abort();
    if (value->len != strlen(lib_url) || memcmp(value->data, lib_url, value->len) != 0) abort();
    ++sanity_calls;
    return NGX_OK;
}
#endif
"""

CASES = r"""
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "%s line %d: %s\n", name, __LINE__, #condition); return 1; \
} } while (0)

static void reset_counters(void)
{
    native_calls = 0; native_initialized = 0; status_calls = 0; updated_status = 0;
    alloc_calls = 0; push_calls = 0; clear_calls = 0; log_calls = 0; error_calls = 0;
    early_log_calls = 0; free_calls = 0;
    last_log[0] = '\0'; last_error[0] = '\0';
}

static void arm(int status, const char *url, const char *log)
{
    lib_pending = 1; lib_status = status; lib_url = url; lib_log = log;
}

int main(int argc, char **argv)
{
    /* static: the doubles keep pointers to them */
    static ngx_pool_t pool;
    static ngx_log_t log;
    static ngx_connection_t connection = {&log};
    static Transaction transaction;
    static ngx_http_modsecurity_ctx_t ctx;
    static ngx_http_modsecurity_conf_t conf;
    static ngx_http_request_t request;
    static ngx_table_elt_t previous;
    static ngx_pool_cleanup_t cleanup = {ngx_http_modsecurity_cleanup, &ctx, NULL};
    const char *message = "native intervention message";
    const char *target = "https://example.test/new-location";
    const char *name;
    ngx_table_elt_t *location;
    int result;

    if (argc != 2) return 2;
    name = argv[1];
    request.pool = &pool;
    request.connection = &connection;
    request.ctx = &ctx;
    request.conf = &conf;
    ctx.modsec_transaction = &transaction;
    expected_transaction = &transaction;
    conf.use_error_log = 1;
    previous.hash = 1;
    ngx_str_set(&previous.key, "Location");
    ngx_str_set(&previous.value, "/previous");
    request.headers_out.location = &previous;

#define UNCHANGED_RESPONSE() do { \
    CHECK(request.headers_out.location == &previous && previous.hash == 1); \
    CHECK(alloc_calls == 0 && push_calls == 0 && clear_calls == 0); \
} while (0)
#define NO_ACTION() do { \
    UNCHANGED_RESPONSE(); \
    CHECK(status_calls == 0 && early_log_calls == 0 && !ctx.logged); \
} while (0)

    if (strcmp(name, "no-intervention") == 0) {
        int early_log;
        for (early_log = 0; early_log <= 1; ++early_log) {
            result = ngx_http_modsecurity_process_intervention(&transaction, &request, early_log);
            CHECK(result == 0);
        }
        CHECK(native_calls == 2 && native_initialized);
        CHECK(log_calls == 0 && error_calls == 0 && free_calls == 0);
        NO_ACTION();
    } else if (strcmp(name, "deny-precommit") == 0) {
        arm(403, NULL, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 403 && native_initialized);
        CHECK(status_calls == 1 && updated_status == 403);
        CHECK(early_log_calls == 1 && ctx.logged);
        CHECK(log_calls == 1 && strcmp(last_log, message) == 0 && error_calls == 0);
        CHECK(free_calls == 1);
        UNCHANGED_RESPONSE();
    } else if (strcmp(name, "deny-committed") == 0) {
        request.header_sent = 1;
        arm(403, NULL, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_ERROR);
        CHECK(status_calls == 1 && updated_status == 403 && early_log_calls == 0);
        CHECK(log_calls == 1 && error_calls == 0 && free_calls == 1);
        UNCHANGED_RESPONSE();
    } else if (strcmp(name, "status-200") == 0) {
        arm(200, NULL, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 0 && log_calls == 1 && free_calls == 1);
        NO_ACTION();
    } else if (strcmp(name, "nondisruptive-result") == 0) {
        arm(302, target, message);
        lib_return = 1; lib_disruptive = 0;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 0 && native_calls == 1);
        CHECK(log_calls == 0 && error_calls == 0 && free_calls == 2);
        NO_ACTION();
    } else if (strcmp(name, "no-result-owned-outputs") == 0) {
        arm(302, target, message);
        lib_return = 0;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 0 && native_calls == 1);
        CHECK(log_calls == 0 && error_calls == 0 && free_calls == 2);
        NO_ACTION();
    } else if (strcmp(name, "invalid-native-results") == 0) {
        const int invalid[] = {INT_MIN + 1, -2, -1, 2, 99, INT_MAX};
        size_t i;
        int committed, outputs;
        char expected[64];
        for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
            for (committed = 0; committed <= 1; ++committed) {
                for (outputs = 0; outputs <= 1; ++outputs) {
                    reset_counters();
                    request.header_sent = committed;
                    lib_return = invalid[i];
                    if (outputs) arm(302, target, message);
                    result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
                    CHECK(result == (committed ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR));
                    CHECK(native_calls == 1 && native_initialized);
                    snprintf(expected, sizeof(expected),
                             "ModSecurity: invalid intervention result %d", invalid[i]);
                    CHECK(error_calls == 1 && strcmp(last_error, expected) == 0);
                    CHECK(log_calls == 0 && free_calls == 2 * outputs);
                    NO_ACTION();
                }
            }
        }
    } else if (strcmp(name, "redirect-owned") == 0) {
        arm(302, target, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 302);
        location = request.headers_out.location;
        CHECK(location != NULL && location != &previous && previous.hash == 0);
        CHECK(location == &request.headers_out.headers.elts[0]);
        CHECK(location->hash == 1 && location->next == NULL && clear_calls == 1);
        CHECK(location->key.len == 8 && memcmp(location->key.data, "Location", 8) == 0);
        CHECK((uintptr_t) location->value.data != native_url);
        CHECK(location->value.data >= pool.storage && location->value.data < pool.storage + pool.used);
        CHECK(location->value.len == strlen(target));
        CHECK(memcmp(location->value.data, target, location->value.len) == 0);
        /* the redirect path keeps its status and does not run the log phase */
        CHECK(status_calls == 0 && early_log_calls == 0);
        CHECK(log_calls == 1 && strcmp(last_log, message) == 0 && error_calls == 0);
        CHECK(free_calls == 2);
#if MODSECURITY_SANITY_CHECKS
        CHECK(sanity_calls == 1);
#endif
    } else if (strcmp(name, "redirect-status") == 0) {
        arm(301, target, NULL);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 301 && free_calls == 1);
        CHECK(strcmp(last_log, "(no log message was specified)") == 0);
        CHECK(memcmp(request.headers_out.location->value.data, target, strlen(target)) == 0);
    } else if (strcmp(name, "redirect-committed") == 0) {
        request.header_sent = 1;
        arm(302, target, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_ERROR && free_calls == 2 && log_calls == 1);
        NO_ACTION();
    } else if (strcmp(name, "redirect-allocation-failure") == 0) {
        fail_alloc = 1;
        arm(302, target, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_HTTP_INTERNAL_SERVER_ERROR && alloc_calls == 1);
        CHECK(push_calls == 0 && clear_calls == 0 && free_calls == 2);
        CHECK(request.headers_out.location == &previous && previous.hash == 1);
    } else if (strcmp(name, "redirect-list-failure") == 0) {
        fail_push = 1;
        arm(302, target, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_HTTP_INTERNAL_SERVER_ERROR);
        CHECK(alloc_calls == 1 && push_calls == 1 && clear_calls == 0 && free_calls == 2);
        CHECK(request.headers_out.location == &previous && previous.hash == 1);
    } else if (strcmp(name, "missing-log") == 0) {
        arm(403, NULL, NULL);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && free_calls == 0);
        CHECK(log_calls == 1 && strcmp(last_log, "(no log message was specified)") == 0);
    } else if (strcmp(name, "error-log-disabled") == 0) {
        conf.use_error_log = 0;
        arm(403, NULL, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && log_calls == 0 && error_calls == 0 && free_calls == 1);
    } else if (strcmp(name, "missing-config-precommit") == 0 ||
               strcmp(name, "missing-config-committed") == 0 ||
               strcmp(name, "missing-context-precommit") == 0 ||
               strcmp(name, "missing-context-committed") == 0 ||
               strcmp(name, "missing-transaction-precommit") == 0 ||
               strcmp(name, "missing-transaction-committed") == 0) {
        Transaction *argument = &transaction;
        request.header_sent = strstr(name, "-committed") != NULL;
        if (strncmp(name, "missing-config", 14) == 0) request.conf = NULL;
        else if (strncmp(name, "missing-context", 15) == 0) request.ctx = NULL;
        else argument = NULL;
        arm(403, target, message);
        result = ngx_http_modsecurity_process_intervention(argument, &request, 1);
        CHECK(result == (request.header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR));
        CHECK(native_calls == 0 && error_calls == 1 && log_calls == 0);
        CHECK(strncmp(last_error, "ModSecurity: no context", 23) == 0);
        NO_ACTION();
        lib_pending = 0;
    } else if (strcmp(name, "context-recovery") == 0) {
        request.ctx = NULL;
        pool.cleanup = &cleanup;
        arm(403, NULL, message);
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 403 && native_calls == 1 && ctx.logged && free_calls == 1);
    } else if (strcmp(name, "repeated-calls") == 0) {
        arm(403, NULL, message);
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 403);
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 0);
        CHECK(native_initialized && free_calls == 1 && status_calls == 1);
        reset_counters();
        arm(302, target, message);
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 302);
        location = request.headers_out.location;
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 0);
        CHECK(native_initialized && native_calls == 2 && free_calls == 2);
        CHECK(request.headers_out.location == location && push_calls == 1);
        CHECK(memcmp(location->value.data, target, strlen(target)) == 0);
    } else if (strcmp(name, "legacy-library") == 0) {
        /* libModSecurity 3.0.12 and older */
        lib_legacy = 1;
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 0);
        CHECK(native_initialized && log_calls == 0);
        arm(403, NULL, message);
        CHECK(ngx_http_modsecurity_process_intervention(&transaction, &request, 0) == 403);
        CHECK(native_initialized && native_url == 0 && free_calls == 1);
        CHECK(request.headers_out.location == &previous && push_calls == 0);
    } else {
        return 2;
    }

    CHECK(live_count == 0 && bad_free == 0 && !lib_pending);
    return 0;
}
"""


def unit_program(module: str) -> str:
    return (
        PREAMBLE
        + "\nstatic ngx_http_modsecurity_ctx_t *\n"
        + function_definition(module, "ngx_http_modsecurity_get_module_ctx")
        + "\nstatic int\n"
        + function_definition(module, "ngx_http_modsecurity_process_intervention")
        + CASES
    )


SANITIZERS = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
              "-fno-omit-frame-pointer", "-g"]


class NativeInterventionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-native-intervention-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = directory / "native_intervention.c"
        source.write_text(unit_program(MODULE.read_text(encoding="utf-8")), encoding="utf-8")
        suffix = ".exe" if os.name == "nt" else ""
        cls.binaries = {}
        cls.sanitized = {}
        cls.sanitizer_error = ""
        for sanity in (0, 1):
            flags = ["-std=c17", "-Wall", "-Wextra", "-Werror",
                     f"-DMODSECURITY_SANITY_CHECKS={sanity}", str(source)]
            binary = directory / f"native-intervention-{sanity}{suffix}"
            build = subprocess.run([*compiler, *flags, "-o", str(binary)],
                                   capture_output=True, text=True, timeout=60, check=False)
            if build.returncode:
                raise AssertionError(f"build (sanity={sanity}) failed:\n{build.stderr}")
            cls.binaries[sanity] = binary
            binary = directory / f"native-intervention-asan-{sanity}{suffix}"
            build = subprocess.run([*compiler, *flags, *SANITIZERS, "-o", str(binary)],
                                   capture_output=True, text=True, timeout=60, check=False)
            if build.returncode:
                cls.sanitizer_error = build.stderr
            else:
                cls.sanitized[sanity] = binary

    def run_binary(self, command: list[str], name: str) -> None:
        result = subprocess.run([*command, name], capture_output=True, text=True,
                                timeout=60, check=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_case(self, name: str) -> None:
        runner = shlex.split(os.environ.get("INTERVENTION_RUNNER", ""))
        for sanity, binary in self.binaries.items():
            with self.subTest(sanity=sanity, build="plain"):
                self.run_binary([*runner, str(binary)], name)
        for sanity, binary in self.sanitized.items():
            with self.subTest(sanity=sanity, build="sanitizers"):
                self.run_binary([str(binary)], name)

    def test_sanitizer_builds(self) -> None:
        if not self.sanitized:
            self.skipTest("no AddressSanitizer/UBSan build:\n" + self.sanitizer_error)


def case_test(name: str):
    def test(self: NativeInterventionRuntimeTests) -> None:
        self.run_case(name)
    return test


for case in (
    "no-intervention", "deny-precommit", "deny-committed", "status-200",
    "nondisruptive-result", "no-result-owned-outputs", "invalid-native-results",
    "redirect-owned", "redirect-status", "redirect-committed",
    "redirect-allocation-failure", "redirect-list-failure",
    "missing-log", "error-log-disabled",
    "missing-config-precommit", "missing-config-committed",
    "missing-context-precommit", "missing-context-committed",
    "missing-transaction-precommit", "missing-transaction-committed",
    "context-recovery", "repeated-calls", "legacy-library",
):
    setattr(NativeInterventionRuntimeTests, "test_" + case.replace("-", "_"), case_test(case))


if __name__ == "__main__":
    unittest.main()
