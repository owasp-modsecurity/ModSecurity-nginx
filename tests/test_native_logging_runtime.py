"""Exercise the native logging phase through the production source.

ngx_http_modsecurity_log_handler(), ngx_http_modsecurity_process_intervention(),
the PCRE1 memory helpers and the context struct are compiled from src/ with
small NGINX and libModSecurity doubles. The doubles let msc_process_logging()
return any value and re-enter the handler, which a real libModSecurity does
not do; modsecurity-audit-log-once.t covers the native NGINX behaviour.

Run: python3 -m unittest discover -s tests -p 'test_native_logging_runtime.py'
CC selects the compiler, CFLAGS adds flags (for example -fsanitize=address)
and TEST_RUNTIME_WRAPPER runs each case through a tool such as valgrind.
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


def matching_delimiter(source: str, opening: int, left: str, right: str) -> int:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == left:
            depth += 1
        elif source[index] == right:
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError(f"unterminated {left}{right} pair")


def function_definition(source: str, name: str) -> str:
    for match in re.finditer(rf"\b{re.escape(name)}\s*\(", source):
        opening = source.index("(", match.start())
        closing = matching_delimiter(source, opening, "(", ")")
        cursor = closing + 1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != "{":
            continue
        end = matching_delimiter(source, cursor, "{", "}")
        start = source.rfind("\n", 0, match.start()) + 1
        return source[start:end + 1]
    raise AssertionError(f"{name} definition was not found")


def context_struct(header: str) -> str:
    end = header.index("} ngx_http_modsecurity_ctx_t;")
    start = header.rindex("typedef struct {", 0, end)
    return header[start:end] + "} ngx_http_modsecurity_ctx_t;\n"


PREAMBLE = r"""
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MODSECURITY_SANITY_CHECKS 0
typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef uintptr_t ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_log_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct {
    int status; int pause; char *url; char *log; int disruptive;
} ModSecurityIntervention;
typedef struct { ngx_uint_t hash; ngx_str_t key; ngx_str_t value; } ngx_table_elt_t;
typedef struct { ngx_table_elt_t *elts; ngx_uint_t nelts; } ngx_list_t;
typedef struct { ngx_log_t *log; int error; } ngx_connection_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct { int use_error_log; } ngx_http_modsecurity_conf_t;
"""

DOUBLES = r"""
struct ngx_http_request_s {
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_request_t *main;
    unsigned header_sent:1;
    struct { ngx_list_t headers; ngx_table_elt_t *location; } headers_out;
    /* the module context slot, and what the pool cleanup scan would find */
    ngx_http_modsecurity_ctx_t *ctx, *pool_ctx;
    ngx_http_modsecurity_conf_t *conf;
};
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_LOG_ERR 4
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define dd(...) ((void) 0)
#define ngx_string(str) { sizeof(str) - 1, (u_char *) str }
#define ngx_str_set(str, text) \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define ngx_http_clear_location(r) ((r)->headers_out.location = NULL)
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

static Transaction transaction;
static ngx_table_elt_t pushed_header;
static ngx_http_request_t *active_request;
static int log_result = 1, log_calls, log_reenter, error_calls, failure_messages;
static int intervention_status, update_calls, updated_status;
static const char *intervention_url;
static ngx_int_t nested_log_result = 12345;

static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r);

static ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    return r->ctx != NULL ? r->ctx : r->pool_ctx;
}

static void
ngx_log_error(ngx_uint_t level, ngx_log_t *log, int err, const char *fmt, ...)
{
    char message[256];
    va_list args;
    (void) level; (void) log; (void) err;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    ++error_calls;
    if (strncmp(message, "ModSecurity: the logging phase ", 31) == 0
        || strncmp(message, "ModSecurity: no transaction ", 28) == 0)
    {
        ++failure_messages;
    }
}

static void *ngx_list_push(ngx_list_t *list) { (void) list; return &pushed_header; }

static int
msc_intervention(Transaction *t, ModSecurityIntervention *it)
{
    (void) t;
    if (intervention_status == 0) return 0;
    it->status = intervention_status;
    it->disruptive = 1;
    it->log = malloc(8);
    if (it->log != NULL) memcpy(it->log, "matched", 8);
    if (intervention_url != NULL) {
        it->url = malloc(strlen(intervention_url) + 1);
        if (it->url != NULL) strcpy(it->url, intervention_url);
    }
    return 1;
}

static int
msc_update_status_code(Transaction *t, int status)
{
    (void) t; ++update_calls; updated_status = status;
    return 1;
}
"""

PCRE1 = r"""
static void *(*pcre_malloc)(size_t) = malloc;
static void (*pcre_free)(void *) = free;
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static ngx_pool_t *ngx_http_modsec_pcre_pool = NULL;
static int pcre_swapped_during_call;
static void *ngx_palloc(ngx_pool_t *pool, size_t size) { (void) pool; (void) size; return NULL; }
static void ngx_pfree(ngx_pool_t *pool, void *p) { (void) pool; (void) p; }
"""

PCRE2 = r"""
#define ngx_http_modsecurity_pcre_malloc_init(x) NULL
#define ngx_http_modsecurity_pcre_malloc_done(x) (void)x
"""

NATIVE = r"""
static int
msc_process_logging(Transaction *t)
{
    (void) t; ++log_calls;
#if TEST_PCRE1
    pcre_swapped_during_call = pcre_malloc == ngx_http_modsec_pcre_malloc
        && pcre_free == ngx_http_modsec_pcre_free
        && ngx_http_modsec_pcre_pool == active_request->pool;
#endif
    if (log_reenter && log_calls == 1) {
        nested_log_result = ngx_http_modsecurity_log_handler(active_request);
    }
    return log_result;
}
"""

CASES = r"""
static int
pcre_restored(void)
{
#if TEST_PCRE1
    CHECK(pcre_malloc == malloc && pcre_free == free);
    CHECK(ngx_http_modsec_pcre_pool == NULL);
    CHECK(log_calls == 0 || pcre_swapped_during_call);
#endif
    return 0;
}

static void
setup(ngx_http_request_t *request, ngx_pool_t *pool, ngx_connection_t *connection,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *conf)
{
    memset(ctx, 0, sizeof(*ctx));
    request->pool = pool; request->connection = connection;
    request->main = request; request->ctx = ctx; request->conf = conf;
    ctx->modsec_transaction = &transaction;
    active_request = request;
}

static int
run_logging(const char *scenario, int parameter)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {1};
    ngx_http_modsecurity_ctx_t ctx;
    ngx_http_request_t request = {0};
    ngx_int_t result;
    setup(&request, &pool, &connection, &ctx, &conf);
    log_result = parameter;
    if (strcmp(scenario, "log-missing") == 0) ctx.modsec_transaction = NULL;
    if (strcmp(scenario, "log-no-context") == 0) request.ctx = NULL;
    if (strcmp(scenario, "log-reenter") == 0) log_reenter = 1;
    result = ngx_http_modsecurity_log_handler(&request);
    if (strcmp(scenario, "log-no-context") == 0) {
        CHECK(result == NGX_OK && log_calls == 0 && error_calls == 0);
        CHECK(!ctx.logged && !ctx.native_logging_failed);
        return pcre_restored();
    }
    CHECK(ctx.logged && result == (parameter == 1 && ctx.modsec_transaction != NULL ? NGX_OK : NGX_ERROR));
    CHECK(ctx.native_logging_failed == (result != NGX_OK));
    CHECK(log_calls == (ctx.modsec_transaction != NULL ? 1 : 0));
    CHECK(failure_messages == (result != NGX_OK) && error_calls == failure_messages);
    if (log_reenter) CHECK(nested_log_result == NGX_ERROR);
    CHECK(pcre_restored() == 0);
    /* a repeated call returns the stored result without a native call */
    CHECK(ngx_http_modsecurity_log_handler(&request) == result);
    CHECK(log_calls == (ctx.modsec_transaction != NULL ? 1 : 0));
    CHECK(failure_messages == (result != NGX_OK) && error_calls == failure_messages);
    CHECK(ctx.logged && ctx.native_logging_failed == (result != NGX_OK));
    CHECK(!connection.error && !request.header_sent && request.headers_out.location == NULL);
    return pcre_restored();
}

static int
run_subrequest(void)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {1};
    ngx_http_modsecurity_ctx_t ctx;
    ngx_http_request_t request = {0}, subrequest = {0};
    setup(&request, &pool, &connection, &ctx, &conf);
    /* a subrequest shares the pool, so the cleanup scan finds the main context */
    subrequest = request; subrequest.main = &request;
    subrequest.ctx = NULL; subrequest.pool_ctx = &ctx;
    CHECK(ngx_http_modsecurity_log_handler(&subrequest) == NGX_OK);
    CHECK(log_calls == 0 && !ctx.logged);
    CHECK(ngx_http_modsecurity_log_handler(&request) == NGX_OK);
    CHECK(ngx_http_modsecurity_log_handler(&subrequest) == NGX_OK);
    CHECK(log_calls == 1 && ctx.logged && !ctx.native_logging_failed);
    return pcre_restored();
}

static int
run_nested_pool(void)
{
#if TEST_PCRE1
    ngx_pool_t pool = {0}, outer = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {1};
    ngx_http_modsecurity_ctx_t ctx;
    ngx_http_request_t request = {0};
    ngx_pool_t *saved;
    setup(&request, &pool, &connection, &ctx, &conf);
    saved = ngx_http_modsecurity_pcre_malloc_init(&outer);
    CHECK(saved == NULL && ngx_http_modsec_pcre_pool == &outer);
    CHECK(ngx_http_modsecurity_log_handler(&request) == NGX_OK);
    /* the handler puts back the pool that was active before it */
    CHECK(pcre_swapped_during_call && log_calls == 1);
    CHECK(ngx_http_modsec_pcre_pool == &outer && pcre_malloc == ngx_http_modsec_pcre_malloc);
    ngx_http_modsecurity_pcre_malloc_done(saved);
    log_calls = 0;
#endif
    return pcre_restored();
}

static int
run_intervention(const char *scenario, int parameter)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {1};
    ngx_http_modsecurity_ctx_t ctx;
    ngx_http_request_t request = {0};
    int result, early = 1, expected = 403, logged_early = 1;
    setup(&request, &pool, &connection, &ctx, &conf);
    log_result = parameter;
    intervention_status = 403;
    if (strcmp(scenario, "early-sent") == 0) { request.header_sent = 1; expected = -1; }
    else if (strcmp(scenario, "late") == 0) { early = 0; logged_early = 0; }
    else if (strcmp(scenario, "redirect") == 0) {
        intervention_status = 302; intervention_url = "http://example.test/";
        expected = 302; logged_early = 0;
    } else if (strcmp(scenario, "none") == 0) {
        intervention_status = 0; expected = 0; logged_early = 0;
    } else if (strcmp(scenario, "early") != 0) return 2;

    result = ngx_http_modsecurity_process_intervention(&transaction, &request, early);
    /* the logging result never changes the intervention */
    CHECK(result == expected);
    CHECK(log_calls == logged_early && ctx.logged == logged_early);
    CHECK(ctx.native_logging_failed == (logged_early && parameter != 1));
    CHECK(failure_messages == (logged_early && parameter != 1));
    if (intervention_status == 403) CHECK(update_calls == 1 && updated_status == 403);
    else CHECK(update_calls == 0);
    if (intervention_url != NULL) {
        CHECK(request.headers_out.location == &pushed_header);
        CHECK(pushed_header.value.len == strlen(intervention_url));
        free(pushed_header.value.data);
    } else {
        CHECK(request.headers_out.location == NULL);
    }
    CHECK(pcre_restored() == 0);
    /* a second intervention check logs nothing more */
    if (intervention_status == 403) {
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, early);
        CHECK(result == expected && log_calls == logged_early);
    }
    /* the LOG phase runs the logging phase only if early logging did not */
    result = (int) ngx_http_modsecurity_log_handler(&request);
    CHECK(result == (parameter == 1 ? NGX_OK : NGX_ERROR));
    CHECK(log_calls == 1 && ctx.logged && ctx.native_logging_failed == (parameter != 1));
    CHECK(failure_messages == (parameter != 1));
    return pcre_restored();
}

int
main(int argc, char **argv)
{
    CHECK(argc == 3);
    if (strcmp(argv[1], "log-subrequest") == 0) return run_subrequest();
    if (strcmp(argv[1], "log-nested-pool") == 0) return run_nested_pool();
    if (strncmp(argv[1], "log-", 4) == 0) return run_logging(argv[1], atoi(argv[2]));
    return run_intervention(argv[1], atoi(argv[2]));
}
"""


def program(pcre1: bool) -> str:
    header = (ROOT / "src/ngx_http_modsecurity_common.h").read_text(encoding="utf-8")
    module = (ROOT / "src/ngx_http_modsecurity_module.c").read_text(encoding="utf-8")
    logging = (ROOT / "src/ngx_http_modsecurity_log.c").read_text(encoding="utf-8")
    source = PREAMBLE + context_struct(header) + DOUBLES
    if pcre1:
        source += "#define TEST_PCRE1 1\n" + PCRE1
        for name, result in (
            ("ngx_http_modsec_pcre_malloc", "static void *"),
            ("ngx_http_modsec_pcre_free", "static void"),
            ("ngx_http_modsecurity_pcre_malloc_init", "static ngx_pool_t *"),
            ("ngx_http_modsecurity_pcre_malloc_done", "static void"),
        ):
            source += "\n" + result + "\n" + function_definition(module, name) + "\n"
    else:
        source += "#define TEST_PCRE1 0\n" + PCRE2
    source += NATIVE
    source += "\nstatic ngx_int_t\n" + function_definition(
        logging, "ngx_http_modsecurity_log_handler") + "\n"
    source += "\nstatic int\n" + function_definition(
        module, "ngx_http_modsecurity_process_intervention") + "\n"
    return source + CASES


class NativeLoggingRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        flags = shlex.split(os.environ.get("CFLAGS", ""))
        cls.wrapper = shlex.split(os.environ.get("TEST_RUNTIME_WRAPPER", ""))
        workspace = tempfile.TemporaryDirectory(prefix="nginx-native-logging-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        cls.binaries = {}
        for variant in ("pcre1", "pcre2"):
            source = directory / f"logging-{variant}.c"
            source.write_text(program(variant == "pcre1"), encoding="utf-8")
            binary = directory / (f"logging-{variant}.exe" if os.name == "nt" else f"logging-{variant}")
            build = subprocess.run(
                [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror", *flags,
                 str(source), "-o", str(binary)],
                capture_output=True, text=True, check=False, timeout=60,
            )
            if build.returncode:
                raise AssertionError(f"Native logging helper build failed:\n{build.stderr}")
            cls.binaries[variant] = binary

    def case(self, name: str, parameter: int = 1) -> None:
        for variant, binary in self.binaries.items():
            with self.subTest(variant=variant):
                result = subprocess.run(
                    [*self.wrapper, str(binary), name, str(parameter)],
                    capture_output=True, text=True, check=False, timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # The four cases below are the native logging cases of #377's
    # tests/test_lifecycle_runtime.py, without its transaction owner changes.

    def test_audit_result_is_checked_and_attempted_once(self):
        for result in (-1, 0, 1, 2):
            with self.subTest(result=result):
                self.case("log-result", result)

    def test_audit_reentry_cannot_repeat_native_call(self):
        for result in (0, 1):
            with self.subTest(result=result):
                self.case("log-reenter", result)

    def test_missing_native_transaction_does_not_call_audit(self):
        self.case("log-missing", 1)

    def test_disabled_context_does_not_call_audit(self):
        self.case("log-no-context", 1)

    def test_subrequest_does_not_use_up_the_main_attempt(self):
        self.case("log-subrequest")

    def test_pcre_pool_of_the_caller_is_restored(self):
        self.case("log-nested-pool")

    def test_early_logging_runs_once_and_keeps_the_status(self):
        for scenario in ("early", "early-sent"):
            for result in (-1, 0, 1, 2):
                with self.subTest(scenario=scenario, result=result):
                    self.case(scenario, result)

    def test_late_redirect_and_no_intervention_log_in_the_log_phase(self):
        for scenario in ("late", "redirect", "none"):
            for result in (0, 1):
                with self.subTest(scenario=scenario, result=result):
                    self.case(scenario, result)


if __name__ == "__main__":
    unittest.main()
