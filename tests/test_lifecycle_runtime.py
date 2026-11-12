"""Exercise access routing and native audit completion through production code.

The complete access and log handlers run with small NGINX/SDK doubles. These
tests prove their control flow, not live error_page or client transport behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_phase4_runtime import function_definition

ROOT = Path(__file__).resolve().parents[1]

PREAMBLE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_list_part_s {
    void *elts;
    ngx_uint_t nelts;
    struct ngx_list_part_s *next;
} ngx_list_part_t;
typedef struct { ngx_list_part_t part; } ngx_list_t;
typedef struct { ngx_str_t key, value; } ngx_table_elt_t;
typedef struct { u_char *pos, *last; int last_buf; } ngx_buf_t;
typedef struct ngx_chain_s { ngx_buf_t *buf; struct ngx_chain_s *next; } ngx_chain_t;
typedef struct { struct { ngx_str_t name; } file; } ngx_temp_file_t;
typedef struct { ngx_temp_file_t *temp_file; ngx_chain_t *bufs; } ngx_http_request_body_t;
typedef struct { void *sockaddr, *local_sockaddr, *log; ngx_str_t addr_text; int error; } ngx_connection_t;
typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
    int waiting_more_body, body_requested, request_body_processed;
    int intervention_triggered, intervention_failed;
    int logged, native_logging_failed;
} ngx_http_modsecurity_ctx_t;
typedef struct { int enable; } ngx_http_modsecurity_conf_t;
struct ngx_http_request_s {
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_request_t *main;
    int count, method, http_version, header_sent, error_page;
    ngx_str_t http_protocol, unparsed_uri, method_name;
    struct { ngx_str_t server; ngx_list_t headers; } headers_in;
    ngx_http_request_body_t *request_body;
    int request_body_in_single_buf, request_body_in_persistent_file;
    int request_body_in_file_only, request_body_in_clean_file;
    void (*write_event_handler)(ngx_http_request_t *);
    ngx_http_modsecurity_ctx_t *ctx, *recovered;
    ngx_http_modsecurity_conf_t *conf;
};
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_AGAIN (-2)
#define NGX_DONE (-4)
#define NGX_DECLINED (-5)
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_SPECIAL_RESPONSE 300
#define NGX_HTTP_VERSION_9 9
#define NGX_HTTP_VERSION_10 1000
#define NGX_HTTP_VERSION_11 1001
#define NGX_SOCKADDR_STRLEN 64
#define NGX_LOG_ERR 3
#define dd(...) ((void)0)
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

static Transaction transaction;
static ngx_http_modsecurity_ctx_t created;
static int created_calls, recovered_calls, error_calls;
static int native_results[4] = {1, 1, 1, 1};
static int native_calls[4], intervention_results[5], intervention_calls[5];
static int active_phase, append_result = 1, append_calls, file_result = 1;
static int log_result = 1, log_calls, log_reenter, nested_log_result;
static ngx_http_request_t *active_request;
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r);
static void ngx_http_core_run_phases(ngx_http_request_t *r) { (void)r; }
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    ++recovered_calls;
    if (r->ctx != NULL && r->ctx->r == r) return r->ctx;
    return r->recovered != NULL && r->recovered->r == r ? r->recovered : NULL;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    ++created_calls;
    memset(&created, 0, sizeof(created));
    created.r = r;
    created.modsec_transaction = &transaction;
    r->ctx = &created;
    return &created;
}
static char *ngx_str_to_char(ngx_str_t value, ngx_pool_t *pool)
{
    (void)pool;
    return value.len == 0 ? NULL : (char *)value.data;
}
static int ngx_inet_get_port(void *address) { (void)address; return 80; }
static ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *connection, ngx_str_t *out, int port)
{
    (void)connection; (void)port;
    out->data = (u_char *)"127.0.0.1"; out->len = 9;
    return NGX_OK;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...)
{
    (void)level; (void)log; (void)error; (void)format;
    ++error_calls;
}
static int phase_result(int phase)
{
    active_phase = phase;
    ++native_calls[phase];
    return native_results[phase];
}
static int msc_process_connection(Transaction *t, const char *client, int cp, const char *server, int sp)
{
    (void)t; (void)client; (void)cp; (void)server; (void)sp;
    return phase_result(0);
}
static int msc_process_uri(Transaction *t, const char *uri, const char *method, const char *version)
{
    (void)t; (void)uri; (void)method; (void)version;
    return phase_result(1);
}
static int msc_add_n_request_header(Transaction *t, const u_char *name, size_t nl, const u_char *value, size_t vl)
{
    (void)t; (void)name; (void)nl; (void)value; (void)vl;
    return 1;
}
static int msc_process_request_headers(Transaction *t) { (void)t; return phase_result(2); }
static int msc_process_request_body(Transaction *t) { (void)t; return phase_result(3); }
static int msc_append_request_body(Transaction *t, const u_char *data, size_t size)
{
    (void)t; (void)data; (void)size;
    active_phase = 4;
    ++append_calls;
    return append_result;
}
static int msc_request_body_from_file(Transaction *t, const char *name)
{
    (void)t; (void)name;
    return file_result;
}
static int ngx_http_modsecurity_process_intervention(Transaction *t, ngx_http_request_t *r, int early)
{
    (void)t; (void)r; (void)early;
    ++intervention_calls[active_phase];
    return intervention_results[active_phase];
}
static ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r, void (*callback)(ngx_http_request_t *))
{
    (void)r; (void)callback;
    return NGX_OK;
}
static int msc_process_logging(Transaction *t)
{
    (void)t;
    ++log_calls;
    if (log_reenter && log_calls == 1)
        nested_log_result = ngx_http_modsecurity_log_handler(active_request);
    return log_result;
}
"""

CASES = r"""
static int run_access(const char *scenario, int parameter)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {1};
    ngx_http_modsecurity_ctx_t previous = {0};
    ngx_http_request_t other_request = {0};
    ngx_http_request_body_t body = {0};
    ngx_http_request_t request = {0};
    u_char bytes[] = "abc";
    ngx_buf_t buffer = {bytes, bytes + 3, 0};
    ngx_chain_t chain = {&buffer, NULL};
    ngx_temp_file_t file = {{{0, NULL}}};
    int phase, before_calls, after_calls;
    ngx_int_t result;
    request.pool = &pool; request.connection = &connection;
    request.main = &request; request.conf = &conf; request.request_body = &body;
    request.http_version = NGX_HTTP_VERSION_11;
    request.unparsed_uri.data = (u_char *)"/protected"; request.unparsed_uri.len = 10;
    request.method_name.data = (u_char *)"POST"; request.method_name.len = 4;
    connection.addr_text.data = (u_char *)"127.0.0.1"; connection.addr_text.len = 9;
    request.error_page = 1;

    if (strcmp(scenario, "fresh-error-page") == 0 ||
        strcmp(scenario, "foreign-direct") == 0) {
        previous.r = strcmp(scenario, "foreign-direct") == 0 ? &other_request : &request;
        previous.modsec_transaction = &transaction;
        previous.request_body_processed = 1; previous.intervention_triggered = 1;
        if (strcmp(scenario, "foreign-direct") == 0) request.ctx = &previous;
        else request.recovered = &previous;
        intervention_results[3] = parameter;
    } else if (strcmp(scenario, "p1-status") == 0) {
        intervention_results[2] = parameter;
    } else if (strcmp(scenario, "p2-status") == 0) {
        intervention_results[3] = parameter;
    } else if (strcmp(scenario, "intervention-error") == 0) {
        intervention_results[parameter] = -1;
        if (parameter == 4) body.bufs = &chain;
    } else if (strcmp(scenario, "native-error") == 0) {
        phase = parameter / 10;
        native_results[phase] = parameter % 10 - 1;
    } else if (strcmp(scenario, "append") == 0) {
        body.bufs = &chain; append_result = parameter;
    } else if (strcmp(scenario, "file") == 0) {
        file.file.name.data = (u_char *)"body.tmp"; file.file.name.len = 8;
        body.temp_file = &file; file_result = parameter;
    } else {
        return 2;
    }

    result = ngx_http_modsecurity_access_handler(&request);
    if (strcmp(scenario, "fresh-error-page") == 0 ||
        strcmp(scenario, "foreign-direct") == 0) {
        CHECK(created_calls == 1 && recovered_calls == 0);
        CHECK(native_calls[2] == 1 && native_calls[3] == 1);
        CHECK(previous.request_body_processed && previous.intervention_triggered);
        CHECK(result == (parameter > 0 ? parameter : NGX_DECLINED));
    } else if (strcmp(scenario, "p1-status") == 0) {
        CHECK(result == parameter && created.intervention_triggered);
        CHECK(native_calls[3] == 0);
    } else if (strcmp(scenario, "p2-status") == 0) {
        CHECK(result == parameter && created.intervention_triggered);
        CHECK(native_calls[3] == 1 && created.request_body_processed);
    } else if ((strcmp(scenario, "append") == 0 && (parameter == 0 || parameter == 1)) ||
               (strcmp(scenario, "file") == 0 && parameter == 1)) {
        CHECK(result == NGX_DECLINED && native_calls[3] == 1);
        CHECK(!created.intervention_failed && created.request_body_processed);
    } else {
        CHECK(result == 500 && created.intervention_failed);
        CHECK(created.intervention_triggered);
        if (strcmp(scenario, "native-error") == 0) {
            phase = parameter / 10;
            CHECK(intervention_calls[phase] == 0);
        }
        if (strcmp(scenario, "append") == 0 || strcmp(scenario, "file") == 0)
            CHECK(native_calls[3] == 0);
        before_calls = append_calls + log_calls;
        for (phase = 0; phase < 4; ++phase) before_calls += native_calls[phase];
        result = ngx_http_modsecurity_access_handler(&request);
        after_calls = append_calls + log_calls;
        for (phase = 0; phase < 4; ++phase) after_calls += native_calls[phase];
        CHECK(result == 500 && before_calls == after_calls);
        request.header_sent = 1;
        CHECK(ngx_http_modsecurity_access_handler(&request) == NGX_ERROR);
        CHECK(connection.error);
    }
    return 0;
}

static int run_logging(const char *scenario, int parameter)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_request_t request = {0};
    ngx_int_t result;
    request.pool = &pool; request.connection = &connection; request.ctx = &ctx;
    ctx.r = &request; ctx.modsec_transaction = &transaction;
    active_request = &request; log_result = parameter;
    if (strcmp(scenario, "log-missing") == 0) ctx.modsec_transaction = NULL;
    if (strcmp(scenario, "log-no-context") == 0) request.ctx = NULL;
    if (strcmp(scenario, "log-reenter") == 0) log_reenter = 1;
    result = ngx_http_modsecurity_log_handler(&request);
    if (strcmp(scenario, "log-no-context") == 0) {
        CHECK(result == NGX_OK && log_calls == 0);
        return 0;
    }
    CHECK(ctx.logged);
    CHECK(result == (parameter == 1 && ctx.modsec_transaction != NULL ? NGX_OK : NGX_ERROR));
    CHECK(ctx.native_logging_failed == (result != NGX_OK));
    CHECK(log_calls == (ctx.modsec_transaction != NULL ? 1 : 0));
    if (log_reenter) CHECK(nested_log_result == NGX_ERROR);
    CHECK(ngx_http_modsecurity_log_handler(&request) == result);
    CHECK(log_calls == (ctx.modsec_transaction != NULL ? 1 : 0));
    CHECK(!connection.error && !request.header_sent);
    return 0;
}

int main(int argc, char **argv)
{
    CHECK(argc == 3);
    return strncmp(argv[1], "log-", 4) == 0
        ? run_logging(argv[1], atoi(argv[2]))
        : run_access(argv[1], atoi(argv[2]));
}
"""


def unit_program(access: str, logging: str) -> str:
    helpers = ""
    if "ngx_http_modsecurity_request_failure(" in access:
        helpers += "\nstatic ngx_int_t\n" + function_definition(
            access, "ngx_http_modsecurity_request_failure"
        )
    helpers += "\nvoid\n" + function_definition(
        access, "ngx_http_modsecurity_request_read"
    )
    helpers += "\nngx_int_t\n" + function_definition(
        access, "ngx_http_modsecurity_access_handler"
    )
    helpers += "\nstatic ngx_int_t\n" + function_definition(
        logging, "ngx_http_modsecurity_log_handler"
    )
    return PREAMBLE + helpers + CASES


OWNERSHIP_PREAMBLE = r"""
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } Transaction;
typedef struct { int unused; } ngx_array_t;
typedef struct { int unused; } ngx_http_modsecurity_header_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
    ngx_array_t *sanity_headers_out;
} ngx_http_modsecurity_ctx_t;
typedef struct { void (*handler)(void *); void *data; } ngx_pool_cleanup_t;
typedef struct {
    unsigned char storage[1024]; size_t used; ngx_pool_cleanup_t cleanup;
} ngx_pool_t;
typedef struct { void *rules_set, *transaction_id; } ngx_http_modsecurity_conf_t;
typedef struct { void *modsec; } ngx_http_modsecurity_main_conf_t;
typedef struct { void *log; } ngx_connection_t;
struct ngx_http_request_s {
    ngx_pool_t *pool; ngx_connection_t *connection;
    ngx_http_modsecurity_conf_t *conf; ngx_http_modsecurity_main_conf_t *main_conf;
    ngx_http_modsecurity_ctx_t *ctx;
};
#define NGX_OK 0
#define NGX_CONF_ERROR ((void *)-1)
#define dd(...) ((void)0)
#define ngx_http_get_module_main_conf(r, module) ((r)->main_conf)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define ngx_http_set_ctx(r, value, module) ((r)->ctx = (value))
#define ngx_memcpy(dst, src, size) memcpy((dst), (src), (size))
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
static Transaction transaction;
static int allocation_calls, fail_allocation_at, complex_failure, native_failure;
static int registration_failure, registration_calls, native_calls, cleanup_calls;
static int sanity_failure, sanity_allocations, sanity_destroys;
static int custom_id_copied, custom_id_terminated;
static char custom_id[4] = {'i', 'd', '7', '!'};
static void ngx_http_modsecurity_cleanup(void *data);
static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes)
{
    void *result;
    ++allocation_calls;
    if (allocation_calls == fail_allocation_at || bytes > sizeof(pool->storage) - pool->used)
        return NULL;
    result = pool->storage + pool->used;
    pool->used += bytes;
    return result;
}
static void *ngx_pcalloc(ngx_pool_t *pool, size_t bytes)
{
    void *result = ngx_pnalloc(pool, bytes);
    if (result != NULL) memset(result, 0, bytes);
    return result;
}
static int ngx_http_complex_value(ngx_http_request_t *r, void *expression, ngx_str_t *out)
{
    (void)r; (void)expression;
    out->data = (u_char *)custom_id; out->len = 3;
    return complex_failure ? -1 : NGX_OK;
}
static Transaction *msc_new_transaction(void *modsec, void *rules, void *log)
{
    (void)modsec; (void)rules; (void)log;
    ++native_calls;
    return native_failure ? NULL : &transaction;
}
static Transaction *msc_new_transaction_with_id(void *modsec, void *rules, char *id, void *log)
{
    custom_id_copied = id != custom_id && memcmp(id, custom_id, 3) == 0;
    custom_id_terminated = id[3] == '\0';
    return msc_new_transaction(modsec, rules, log);
}
static void msc_transaction_cleanup(Transaction *value)
{
    if (value != &transaction) abort();
    ++cleanup_calls;
}
static ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *pool, size_t size)
{
    (void)size;
    ++registration_calls;
    return registration_failure ? NULL : &pool->cleanup;
}
#if MODSECURITY_SANITY_CHECKS
static ngx_array_t sanity_array;
static ngx_array_t *ngx_array_create(ngx_pool_t *pool, unsigned count, size_t bytes)
{
    (void)pool; (void)count; (void)bytes;
    ++sanity_allocations;
    return sanity_failure ? NULL : &sanity_array;
}
static void ngx_array_destroy(ngx_array_t *array)
{
    if (array != &sanity_array) abort();
    ++sanity_destroys;
}
#endif
"""

OWNERSHIP_CASES = r"""
int main(int argc, char **argv)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t conf = {0};
    ngx_http_modsecurity_main_conf_t main_conf = {0};
    ngx_http_request_t request = {0};
    ngx_http_modsecurity_ctx_t *ctx;
    int expected_failure = 1;
    CHECK(argc == 2);
    request.pool = &pool; request.connection = &connection;
    request.conf = &conf; request.main_conf = &main_conf;
    conf.rules_set = &transaction; main_conf.modsec = &transaction;
    if (strcmp(argv[1], "context-allocation") == 0) fail_allocation_at = 1;
    else if (strcmp(argv[1], "complex-value") == 0) {
        conf.transaction_id = &conf; complex_failure = 1;
    } else if (strcmp(argv[1], "custom-id-allocation") == 0) {
        conf.transaction_id = &conf; fail_allocation_at = 2;
    } else if (strcmp(argv[1], "native-allocation") == 0) native_failure = 1;
    else if (strcmp(argv[1], "cleanup-registration") == 0) registration_failure = 1;
    else if (strcmp(argv[1], "sanity-allocation") == 0) {
        sanity_failure = 1; expected_failure = MODSECURITY_SANITY_CHECKS;
    } else if (strcmp(argv[1], "custom-id-owned") == 0) {
        conf.transaction_id = &conf; expected_failure = 0;
    } else if (strcmp(argv[1], "cleanup-once") == 0) expected_failure = 0;
    else return 2;

    ctx = ngx_http_modsecurity_create_ctx(&request);
    if (expected_failure) {
        CHECK(ctx == NULL && request.ctx == NULL);
        CHECK(pool.cleanup.handler == NULL && pool.cleanup.data == NULL);
        if (registration_failure || sanity_failure) CHECK(cleanup_calls == 1);
        else CHECK(cleanup_calls == 0);
        if (fail_allocation_at || complex_failure) CHECK(native_calls == 0);
        return 0;
    }
    CHECK(ctx != NULL && ctx != NGX_CONF_ERROR && ctx == request.ctx);
    CHECK(native_calls == 1 && registration_calls == 1 && cleanup_calls == 0);
    CHECK(pool.cleanup.handler == ngx_http_modsecurity_cleanup && pool.cleanup.data == ctx);
    if (conf.transaction_id != NULL) CHECK(custom_id_copied && custom_id_terminated);
    ngx_http_modsecurity_cleanup(NULL);
    pool.cleanup.handler(pool.cleanup.data);
    pool.cleanup.handler(pool.cleanup.data);
    CHECK(ctx->modsec_transaction == NULL && cleanup_calls == 1);
    CHECK(sanity_allocations == MODSECURITY_SANITY_CHECKS);
    CHECK(sanity_destroys == MODSECURITY_SANITY_CHECKS);
    return 0;
}
"""


def ownership_program(module: str) -> str:
    helpers = "\nstatic void\n" + function_definition(
        module, "ngx_http_modsecurity_cleanup"
    )
    helpers += "\nngx_http_modsecurity_ctx_t *\n" + function_definition(
        module, "ngx_http_modsecurity_create_ctx"
    )
    return OWNERSHIP_PREAMBLE + helpers + OWNERSHIP_CASES


class LifecycleRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        workspace = tempfile.TemporaryDirectory(prefix="nginx-lifecycle-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        source = directory / "lifecycle.c"
        source.write_text(unit_program(
            (ROOT / "src/ngx_http_modsecurity_access.c").read_text(encoding="utf-8"),
            (ROOT / "src/ngx_http_modsecurity_log.c").read_text(encoding="utf-8"),
        ), encoding="utf-8")
        cls.binary = directory / ("lifecycle.exe" if os.name == "nt" else "lifecycle")
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if build.returncode:
            raise AssertionError(f"Lifecycle helper build failed:\n{build.stderr}")

    def case(self, name: str, parameter: int) -> None:
        result = subprocess.run(
            [str(self.binary), name, str(parameter)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_internal_error_page_uses_fresh_location_context(self):
        for status in (0, 403):
            with self.subTest(status=status):
                self.case("fresh-error-page", status)

    def test_foreign_direct_context_does_not_skip_access_processing(self):
        self.case("foreign-direct", 403)

    def test_error_page_preserves_p1_and_p2_status_decisions(self):
        for scenario in ("p1-status", "p2-status"):
            for status in (302, 403, 451):
                with self.subTest(scenario=scenario, status=status):
                    self.case(scenario, status)

    def test_negative_interventions_fail_and_remain_terminal(self):
        for phase in range(5):
            with self.subTest(phase=phase):
                self.case("intervention-error", phase)

    def test_native_phase_requires_exact_success(self):
        for phase in range(4):
            for result in (-1, 0, 2):
                with self.subTest(phase=phase, result=result):
                    self.case("native-error", phase * 10 + result + 1)

    def test_native_append_partial_is_not_phase_failure(self):
        for result in (-1, 0, 1, 2):
            with self.subTest(result=result):
                self.case("append", result)

    def test_native_file_result_is_not_append_partial(self):
        for result in (-1, 0, 1, 2):
            with self.subTest(result=result):
                self.case("file", result)

    def test_audit_result_is_checked_and_attempted_once(self):
        for result in (-1, 0, 1, 2):
            with self.subTest(result=result):
                self.case("log-result", result)

    def test_audit_reentry_cannot_repeat_native_call(self):
        self.case("log-reenter", 1)

    def test_missing_native_transaction_does_not_call_audit(self):
        self.case("log-missing", 1)

    def test_disabled_context_does_not_call_audit(self):
        self.case("log-no-context", 1)


class LifecycleOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        workspace = tempfile.TemporaryDirectory(prefix="nginx-ownership-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        source = directory / "ownership.c"
        source.write_text(ownership_program(
            (ROOT / "src/ngx_http_modsecurity_module.c").read_text(encoding="utf-8")
        ), encoding="utf-8")
        cls.binaries = {}
        for sanity in (0, 1):
            binary = directory / (f"ownership-{sanity}.exe" if os.name == "nt" else f"ownership-{sanity}")
            build = subprocess.run(
                [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                 f"-DMODSECURITY_SANITY_CHECKS={sanity}", str(source), "-o", str(binary)],
                capture_output=True, text=True, check=False, timeout=60,
            )
            if build.returncode:
                raise AssertionError(f"Ownership helper build failed:\n{build.stderr}")
            cls.binaries[sanity] = binary

    def case(self, name: str) -> None:
        for sanity, binary in self.binaries.items():
            with self.subTest(sanity=sanity):
                result = subprocess.run(
                    [str(binary), name], capture_output=True, text=True,
                    check=False, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_context_and_native_allocation_failures_are_null(self):
        for name in ("context-allocation", "native-allocation"):
            with self.subTest(name=name):
                self.case(name)

    def test_custom_id_failures_do_not_create_native_transaction(self):
        for name in ("complex-value", "custom-id-allocation"):
            with self.subTest(name=name):
                self.case(name)

    def test_partial_creation_failure_cleans_native_owner(self):
        for name in ("cleanup-registration", "sanity-allocation"):
            with self.subTest(name=name):
                self.case(name)

    def test_custom_id_copy_is_terminated_before_native_call(self):
        self.case("custom-id-owned")

    def test_cleanup_is_null_safe_and_idempotent(self):
        self.case("cleanup-once")


if __name__ == "__main__":
    unittest.main()
