"""Exercise production intervention dispatch and retained allocation lifetimes.

The actual module wrapper, redirect/log helpers, and request-context lookup are
compiled with host doubles. Both sanity-check build variants run each case.
Native NGINX/libModSecurity integration remains the Perl suites' responsibility.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from test_phase4_runtime import function_definition

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "src" / "ngx_http_modsecurity_module.c"

PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
typedef unsigned char u_char;
typedef int ngx_int_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct {
    ngx_str_t key, value;
    unsigned hash;
} ngx_table_elt_t;
typedef struct {
    ngx_table_elt_t entries[4];
    unsigned count;
} ngx_list_t;
typedef struct ngx_pool_cleanup_s {
    void (*handler)(void *);
    void *data;
    struct ngx_pool_cleanup_s *next;
} ngx_pool_cleanup_t;
typedef struct {
    ngx_pool_cleanup_t *cleanup;
    u_char storage[4096];
    size_t used;
} ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct {
    int status;
    char *url, *log;
    int disruptive;
    double pause;
} ModSecurityIntervention;
typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
    ngx_str_t last_intervention_log;
    int last_intervention_status, intervention_late, intervention_failed;
    int intervention_redirect_location_installed, logged;
    int phase4_failed, phase4_error_emitting, phase4_started, phase4_processed, intervention_body_limit;
} ngx_http_modsecurity_ctx_t;
typedef struct {
    void *phase4_log_file;
    int use_error_log, phase4_mode;
} ngx_http_modsecurity_conf_t;
typedef struct { void *log; } ngx_connection_t;
struct ngx_http_request_s {
    int header_sent;
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
    struct { ngx_list_t headers; ngx_table_elt_t *location; } headers_out;
};
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_DECLINED (-5)
#define NGX_HTTP_MODSEC_PHASE4_MODE_OFF 0
#define NGX_HTTP_BAD_REQUEST 400
#define NGX_HTTP_FORBIDDEN 403
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_LOG_ERR 3
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define ngx_memzero(data, size) memset((data), 0, (size))
#define ngx_memcpy(dst, src, size) memcpy((dst), (src), (size))
#define ngx_strlen(data) strlen((const char *)(data))
#define ngx_str_null(str) do { (str)->len = 0; (str)->data = NULL; } while (0)
#define ngx_str_set(str, literal) do { \
    (str)->len = sizeof(literal) - 1; (str)->data = (u_char *)(literal); \
} while (0)

static int native_available = 1, native_status = 403, native_calls;
static int native_return = 1, native_disruptive = 1;
static int native_has_log = 1, native_has_url, native_initialized;
static char native_log[256] = "native intervention message";
static char native_url[256] = "https://example.test/new-location";
static int freed_log, freed_url, bad_free, allocation_calls, fail_allocation_at;
static int list_calls, fail_list, clear_calls, error_log_calls;
static int status_calls, updated_status, early_log_calls, sanity_calls, fail_sanity;
static int early_log_result;
static char captured_error[256];
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r);
static void ngx_http_modsecurity_cleanup(void *data) { (void)data; }

static int msc_intervention(Transaction *transaction, ModSecurityIntervention *out)
{
    (void)transaction;
    ++native_calls;
    native_initialized = out->status == 200 && out->log == NULL &&
        out->url == NULL && out->disruptive == 0 && out->pause == 0.0;
    if (!native_available) return 0;
    out->status = native_status;
    out->log = native_has_log ? native_log : NULL;
    out->url = native_has_url ? native_url : NULL;
    out->disruptive = native_disruptive;
    return native_return;
}
/* Poison released native memory without releasing storage: a retained native
 * pointer remains readable but differs from the expected pool-owned value. */
static void tracked_free(void *pointer)
{
    if (pointer == native_log) ++freed_log;
    else if (pointer == native_url) ++freed_url;
    else ++bad_free;
    memset(pointer, '!', strlen((const char *)pointer));
}
#define free(pointer) tracked_free(pointer)
static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes)
{
    u_char *result;
    ++allocation_calls;
    if (allocation_calls == fail_allocation_at || bytes > sizeof(pool->storage) - pool->used)
        return NULL;
    result = pool->storage + pool->used;
    pool->used += bytes == 0 ? 1 : bytes;
    return result;
}
static ngx_table_elt_t *ngx_list_push(ngx_list_t *list)
{
    ++list_calls;
    if (fail_list || list->count == 4U) return NULL;
    return &list->entries[list->count++];
}
static void ngx_http_clear_location(ngx_http_request_t *r)
{
    ++clear_calls;
    if (r->headers_out.location != NULL) r->headers_out.location->hash = 0;
    r->headers_out.location = NULL;
}
static void ngx_log_error(int level, void *log, int error, const char *format, ...)
{
    va_list args;
    (void)level; (void)log; (void)error;
    ++error_log_calls;
    va_start(args, format);
    if (strcmp(format, "%s") == 0)
        snprintf(captured_error, sizeof(captured_error), "%s", va_arg(args, const char *));
    va_end(args);
}
static void msc_update_status_code(Transaction *transaction, int status)
{
    (void)transaction;
    ++status_calls;
    updated_status = status;
}
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx != NULL) ctx->logged = 1;
    ++early_log_calls;
    return early_log_result;
}
#if MODSECURITY_SANITY_CHECKS
static ngx_int_t ngx_http_modsecurity_store_ctx_header(ngx_http_request_t *r,
    ngx_str_t *name, ngx_str_t *value)
{
    (void)r; (void)name; (void)value;
    ++sanity_calls;
    return fail_sanity ? NGX_ERROR : NGX_OK;
}
#endif
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
"""

CASES = r"""
int main(int argc, char **argv)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    Transaction transaction = {0};
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_modsecurity_conf_t conf = {0};
    ngx_http_request_t request = {0};
    ngx_table_elt_t previous_location = {0};
    ngx_pool_cleanup_t cleanup = {ngx_http_modsecurity_cleanup, &ctx, NULL};
    const char *expected_log = "native intervention message";
    const char *expected_url = "https://example.test/new-location";
    const char *limit_message = "Response body limit is marked to reject the request";
    int result;
    CHECK(argc == 2);
    request.pool = &pool; request.connection = &connection;
    request.ctx = &ctx; request.conf = &conf;
    ctx.r = &request; ctx.modsec_transaction = &transaction;
    conf.phase4_log_file = &transaction; conf.use_error_log = 1;
    previous_location.hash = 1;
    request.headers_out.location = &previous_location;
    ctx.intervention_late = 1; ctx.intervention_failed = 1;
    ctx.intervention_redirect_location_installed = 1;

    if (strcmp(argv[1], "no-intervention") == 0) {
        native_available = 0;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 0 && native_initialized && native_calls == 1);
        CHECK(!ctx.intervention_late && !ctx.intervention_failed);
        CHECK(!ctx.intervention_redirect_location_installed);
        CHECK(allocation_calls == 0 && error_log_calls == 0);
        CHECK(freed_log == 0 && freed_url == 0 && bad_free == 0);
    } else if (strcmp(argv[1], "invalid-native-results") == 0) {
        const int invalid[] = {-2, -1, 2, 99};
        size_t index;
        int mode, committed;
        native_has_url = 1; native_status = 302;
        for (mode = 0; mode <= 2; ++mode) {
            conf.phase4_mode = mode;
            for (committed = 0; committed <= 1; ++committed) {
                request.header_sent = committed;
                for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); ++index) {
                    strcpy(native_log, expected_log); strcpy(native_url, expected_url);
                    native_return = invalid[index]; freed_log = 0; freed_url = 0;
                    ctx.last_intervention_status = 451;
                    ctx.last_intervention_log.data = (u_char *)"stale";
                    ctx.last_intervention_log.len = 5U;
                    ctx.intervention_body_limit = 1;
                    result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
                    CHECK(result == (committed ? NGX_ERROR : 500));
                    CHECK(ctx.intervention_failed && !ctx.intervention_late);
                    CHECK(!ctx.intervention_body_limit && !ctx.intervention_redirect_location_installed);
                    CHECK(ctx.last_intervention_status == 0);
                    CHECK(ctx.last_intervention_log.data == NULL && ctx.last_intervention_log.len == 0U);
                    CHECK(freed_log == 1 && freed_url == 1 && bad_free == 0);
                    CHECK(allocation_calls == 0 && status_calls == 0 && list_calls == 0);
                    CHECK(early_log_calls == 0 && captured_error[0] == '\0');
                    CHECK(request.headers_out.location == &previous_location && previous_location.hash == 1);
                }
            }
        }
    } else if (strcmp(argv[1], "nondisruptive-result") == 0 ||
               strcmp(argv[1], "no-result-owned-outputs") == 0) {
        native_has_url = 1; native_status = 302;
        if (strcmp(argv[1], "nondisruptive-result") == 0) native_disruptive = 0;
        else native_return = 0;
        ctx.last_intervention_status = 451;
        ctx.last_intervention_log.data = (u_char *)"stale";
        ctx.last_intervention_log.len = 5U; ctx.intervention_body_limit = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 0 && native_calls == 1);
        CHECK(!ctx.intervention_failed && !ctx.intervention_late && !ctx.intervention_body_limit);
        CHECK(!ctx.intervention_redirect_location_installed && ctx.last_intervention_status == 0);
        CHECK(ctx.last_intervention_log.data == NULL && ctx.last_intervention_log.len == 0U);
        CHECK(freed_log == 1 && freed_url == 1 && bad_free == 0);
        CHECK(allocation_calls == 0 && status_calls == 0 && list_calls == 0);
        CHECK(early_log_calls == 0 && error_log_calls == 0);
        CHECK(request.headers_out.location == &previous_location && previous_location.hash == 1);
    } else if (strcmp(argv[1], "body-limit-rejection") == 0) {
        int mode, committed;
        for (mode = 0; mode <= 2; ++mode) {
            conf.phase4_mode = mode;
            for (committed = 0; committed <= 1; ++committed) {
                strcpy(native_log, limit_message); freed_log = 0;
                request.header_sent = committed; ctx.phase4_started = 1;
                result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
                CHECK(result == (committed ? NGX_ERROR : 403));
                CHECK(ctx.intervention_failed && ctx.intervention_body_limit && !ctx.intervention_late);
                CHECK(ctx.last_intervention_status == 403);
                CHECK(!ctx.intervention_redirect_location_installed && freed_log == 1 && freed_url == 0);
                CHECK(status_calls == 0 && list_calls == 0 && early_log_calls == 0);
            }
        }
    } else if (strcmp(argv[1], "body-limit-other-phase") == 0 ||
               strcmp(argv[1], "body-limit-rule-lookalike") == 0) {
        if (strcmp(argv[1], "body-limit-other-phase") == 0) strcpy(native_log, limit_message);
        else {
            ctx.phase4_started = 1; ctx.phase4_processed = 1;
            strcpy(native_log, "[client 127.0.0.1] ModSecurity: Access denied with code 403 (phase 4). [id \"12345\"] [msg \"Response body limit is marked to reject the request\"]");
        }
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && !ctx.intervention_failed && !ctx.intervention_body_limit);
        CHECK(ctx.last_intervention_status == 403 && status_calls == 1);
        CHECK(freed_log == 1 && freed_url == 0 && early_log_calls == 0);
    } else if (strcmp(argv[1], "uncorrelated-append-intervention") == 0) {
        int mode, committed;
        ctx.phase4_started = 1; native_has_log = 0;
        for (mode = 0; mode <= 2; ++mode) {
            conf.phase4_mode = mode;
            for (committed = 0; committed <= 1; ++committed) {
                request.header_sent = committed;
                result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
                CHECK(result == (committed ? NGX_ERROR : 500));
                CHECK(ctx.intervention_failed && !ctx.intervention_body_limit && !ctx.intervention_late);
                CHECK(ctx.last_intervention_status == 0 && ctx.last_intervention_log.data == NULL);
                CHECK(status_calls == 0 && early_log_calls == 0 && list_calls == 0);
                CHECK(freed_log == 0 && freed_url == 0 && allocation_calls == 0);
            }
        }
    } else if (strcmp(argv[1], "early-log-failure") == 0) {
        early_log_result = NGX_ERROR;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 500 && ctx.intervention_failed && !ctx.intervention_late);
        CHECK(early_log_calls == 1 && freed_log == 1 && freed_url == 0);
        CHECK(list_calls == 0 && !ctx.intervention_redirect_location_installed);
    } else if (strcmp(argv[1], "status-precommit") == 0) {
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 403 && native_initialized);
        CHECK(ctx.last_intervention_status == 403 && updated_status == 403);
        CHECK(status_calls == 1 && early_log_calls == 1 && ctx.logged);
        CHECK(!ctx.intervention_failed && !ctx.intervention_late);
        CHECK(freed_log == 1 && freed_url == 0 && bad_free == 0);
        CHECK(ctx.last_intervention_log.data != (u_char *)native_log);
        CHECK(ctx.last_intervention_log.len == strlen(expected_log));
        CHECK(strcmp((const char *)ctx.last_intervention_log.data, expected_log) == 0);
        CHECK(strcmp(captured_error, expected_log) == 0);
    } else if (strcmp(argv[1], "status-committed") == 0 ||
               strcmp(argv[1], "status-native-committed") == 0) {
        request.header_sent = 1;
        conf.phase4_mode = strcmp(argv[1], "status-native-committed") == 0 ? 0 : 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_ERROR && ctx.intervention_late && !ctx.intervention_failed);
        CHECK(ctx.last_intervention_status == 403 && updated_status == 403);
        CHECK(!ctx.intervention_redirect_location_installed);
        CHECK(status_calls == 1 && early_log_calls == 0);
        CHECK(freed_log == 1 && freed_url == 0);
        CHECK(strcmp((const char *)ctx.last_intervention_log.data, expected_log) == 0);
    } else if (strcmp(argv[1], "late-phase4-policy-deferral") == 0) {
        int mode;
        request.header_sent = 1;
        ctx.phase4_started = 1; ctx.phase4_processed = 1;
        for (mode = 0; mode <= 2; ++mode) {
            conf.phase4_mode = mode;
            strcpy(native_log, expected_log); freed_log = 0;
            status_calls = 0; early_log_calls = 0; updated_status = 0;
            ctx.logged = 0;
            result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
            CHECK(result == NGX_ERROR && ctx.intervention_late && !ctx.intervention_failed);
            CHECK(ctx.last_intervention_status == 403 && !ctx.intervention_body_limit);
            CHECK(status_calls == (mode == 0) && early_log_calls == (mode == 0));
            CHECK(updated_status == (mode == 0 ? 403 : 0));
            CHECK(ctx.logged == (mode == 0) && list_calls == 0);
            CHECK(freed_log == 1 && freed_url == 0 && !ctx.intervention_redirect_location_installed);
        }
    } else if (strcmp(argv[1], "status-log-only") == 0) {
        native_status = 200;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 0 && ctx.last_intervention_status == 200);
        CHECK(!ctx.intervention_failed && !ctx.intervention_late);
        CHECK(status_calls == 0 && early_log_calls == 0 && !ctx.logged);
        CHECK(freed_log == 1 && freed_url == 0);
    } else if (strcmp(argv[1], "redirect-owned") == 0) {
        native_status = 302; native_has_url = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 1);
        CHECK(result == 302 && !ctx.intervention_failed && !ctx.intervention_late);
        CHECK(ctx.intervention_redirect_location_installed);
        CHECK(freed_log == 1 && freed_url == 1 && bad_free == 0);
        CHECK(request.headers_out.location != &previous_location && previous_location.hash == 0);
        CHECK(request.headers_out.location->hash == 1 && clear_calls == 1);
        CHECK(request.headers_out.location->key.len == 8U);
        CHECK(memcmp(request.headers_out.location->key.data, "Location", 8U) == 0);
        CHECK(request.headers_out.location->value.data != (u_char *)native_url);
        CHECK(request.headers_out.location->value.len == strlen(expected_url));
        CHECK(memcmp(request.headers_out.location->value.data, expected_url, strlen(expected_url)) == 0);
        CHECK(strcmp((const char *)ctx.last_intervention_log.data, expected_log) == 0);
        CHECK(status_calls == 0 && early_log_calls == 0);
        CHECK(sanity_calls == MODSECURITY_SANITY_CHECKS);
    } else if (strcmp(argv[1], "redirect-committed") == 0) {
        native_status = 302; native_has_url = 1; request.header_sent = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == NGX_ERROR && ctx.intervention_late && !ctx.intervention_failed);
        CHECK(!ctx.intervention_redirect_location_installed);
        CHECK(request.headers_out.location == &previous_location && previous_location.hash == 1);
        CHECK(list_calls == 0 && clear_calls == 0 && allocation_calls == 1);
        CHECK(freed_log == 1 && freed_url == 1 && sanity_calls == 0);
    } else if (strcmp(argv[1], "redirect-crlf") == 0) {
        native_status = 302; native_has_url = 1;
        strcpy(native_url, "https://example.test/\r\nInjected: yes");
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 400 && ctx.intervention_failed && !ctx.intervention_late);
        CHECK(!ctx.intervention_redirect_location_installed);
        CHECK(request.headers_out.location == &previous_location && list_calls == 0);
        CHECK(freed_log == 1 && freed_url == 1 && bad_free == 0);
        CHECK(allocation_calls == 1 && error_log_calls == 2);
    } else if (strcmp(argv[1], "redirect-list-failure") == 0) {
        native_status = 302; native_has_url = 1; fail_list = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 500 && ctx.intervention_failed && !ctx.intervention_late);
        CHECK(!ctx.intervention_redirect_location_installed);
        CHECK(request.headers_out.location == &previous_location && clear_calls == 0);
        CHECK(freed_log == 1 && freed_url == 1 && list_calls == 1);
    } else if (strcmp(argv[1], "redirect-allocation-failure") == 0) {
        native_status = 302; native_has_url = 1; fail_allocation_at = 2;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 500 && ctx.intervention_failed && !ctx.intervention_late);
        CHECK(!ctx.intervention_redirect_location_installed && list_calls == 0);
        CHECK(freed_log == 1 && freed_url == 1 && allocation_calls == 2);
        CHECK(strcmp((const char *)ctx.last_intervention_log.data, expected_log) == 0);
    } else if (strcmp(argv[1], "redirect-sanity-failure") == 0) {
        native_status = 302; native_has_url = 1; fail_sanity = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == (MODSECURITY_SANITY_CHECKS ? 500 : 302));
        CHECK(ctx.intervention_failed == MODSECURITY_SANITY_CHECKS);
        CHECK(ctx.intervention_redirect_location_installed == !MODSECURITY_SANITY_CHECKS);
        CHECK(!ctx.intervention_late && sanity_calls == MODSECURITY_SANITY_CHECKS);
        CHECK(freed_log == 1 && freed_url == 1 && bad_free == 0);
        CHECK(request.headers_out.location->value.len == strlen(expected_url));
        CHECK(memcmp(request.headers_out.location->value.data, expected_url, strlen(expected_url)) == 0);
    } else if (strcmp(argv[1], "log-allocation-precommit") == 0 ||
               strcmp(argv[1], "log-allocation-committed") == 0) {
        request.header_sent = strcmp(argv[1], "log-allocation-committed") == 0;
        native_has_url = 1; native_status = 302; fail_allocation_at = 1;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == (request.header_sent ? NGX_ERROR : 500));
        CHECK(ctx.intervention_failed && !ctx.intervention_late);
        CHECK(!ctx.intervention_redirect_location_installed && error_log_calls == 0);
        CHECK(ctx.last_intervention_log.len == 0U && ctx.last_intervention_log.data == NULL);
        CHECK(freed_log == 1 && freed_url == 1 && list_calls == 0);
    } else if (strcmp(argv[1], "disabled-log-retention") == 0) {
        conf.phase4_log_file = NULL; conf.use_error_log = 0;
        ctx.last_intervention_log.data = (u_char *)"old message";
        ctx.last_intervention_log.len = 11;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && !ctx.intervention_failed);
        CHECK(ctx.last_intervention_log.data == NULL && ctx.last_intervention_log.len == 0U);
        CHECK(allocation_calls == 0 && error_log_calls == 0);
        CHECK(freed_log == 1 && freed_url == 0);
    } else if (strcmp(argv[1], "missing-log") == 0) {
        native_has_log = 0;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && allocation_calls == 0);
        CHECK(ctx.last_intervention_log.data == NULL && ctx.last_intervention_log.len == 0U);
        CHECK(strcmp(captured_error, "(no log message was specified)") == 0);
        CHECK(freed_log == 0 && freed_url == 0);
    } else if (strcmp(argv[1], "missing-config-precommit") == 0 ||
               strcmp(argv[1], "missing-config-committed") == 0) {
        request.conf = NULL;
        request.header_sent = strcmp(argv[1], "missing-config-committed") == 0;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == (request.header_sent ? NGX_ERROR : 500));
        CHECK(ctx.intervention_failed && !ctx.intervention_late);
        CHECK(native_calls == 0 && freed_log == 0 && freed_url == 0);
    } else if (strcmp(argv[1], "redirect-context-recovery") == 0) {
        pool.cleanup = &cleanup; request.ctx = NULL;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 403 && native_calls == 1 && !ctx.intervention_failed);
        CHECK(freed_log == 1 && ctx.last_intervention_status == 403);
    } else if (strcmp(argv[1], "foreign-context-rejected") == 0) {
        ngx_http_request_t other_request = {0};
        ctx.r = &other_request; pool.cleanup = &cleanup;
        result = ngx_http_modsecurity_process_intervention(&transaction, &request, 0);
        CHECK(result == 500 && native_calls == 0);
        CHECK(freed_log == 0 && freed_url == 0);
    } else {
        return 2;
    }
    CHECK(bad_free == 0 && freed_log <= 1 && freed_url <= 1);
    return 0;
}
"""


def unit_program(module: str) -> str:
    helpers = "\nstatic ngx_http_modsecurity_ctx_t *\n" + function_definition(
        module, "ngx_http_modsecurity_get_module_ctx"
    )
    helpers += "\nstatic ngx_int_t\n" + function_definition(
        module, "ngx_http_modsecurity_log_intervention"
    )
    helpers += "\nstatic int\n" + function_definition(
        module, "ngx_http_modsecurity_process_intervention_redirect"
    )
    for helper in (
        "ngx_http_modsecurity_is_response_body_limit_rejection",
        "ngx_http_modsecurity_intervention_failure_status",
        "ngx_http_modsecurity_collect_native_intervention",
        "ngx_http_modsecurity_defer_late_phase4_intervention",
    ):
        if re.search(rf"\b{helper}\s*\(", module):
            helpers += "\nstatic ngx_int_t\n" + function_definition(module, helper)
    reset = "ngx_http_modsecurity_reset_intervention"
    if re.search(rf"\b{reset}\s*\(", module):
        helpers += "\nstatic void\n" + function_definition(module, reset)
    helpers += "\nint\n" + function_definition(
        module, "ngx_http_modsecurity_process_intervention"
    )
    return PREAMBLE + helpers + CASES


class InterventionRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        temporary = tempfile.TemporaryDirectory(prefix="nginx-intervention-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        source = directory / "intervention.c"
        source.write_text(unit_program(MODULE.read_text(encoding="utf-8")), encoding="utf-8")
        cls.binaries = {}
        for sanity in (0, 1):
            binary = directory / (f"intervention-{sanity}.exe" if os.name == "nt" else f"intervention-{sanity}")
            build = subprocess.run(
                [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                 f"-DMODSECURITY_SANITY_CHECKS={sanity}", str(source), "-o", str(binary)],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if build.returncode:
                raise AssertionError(f"intervention helper build (sanity={sanity}) failed:\n{build.stderr}")
            cls.binaries[sanity] = binary

    def run_case(self, name: str) -> None:
        for sanity, binary in self.binaries.items():
            with self.subTest(sanity=sanity):
                result = subprocess.run(
                    [str(binary), name], capture_output=True, text=True,
                    timeout=10, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def case_test(name: str):
    def test(self: InterventionRuntimeTests) -> None:
        self.run_case(name)
    return test


for case in (
    "no-intervention", "status-precommit", "status-committed", "status-native-committed",
    "status-log-only",
    "late-phase4-policy-deferral",
    "invalid-native-results", "nondisruptive-result", "no-result-owned-outputs",
    "body-limit-rejection", "body-limit-other-phase", "body-limit-rule-lookalike",
    "early-log-failure",
    "uncorrelated-append-intervention",
    "redirect-owned", "redirect-committed", "redirect-crlf", "redirect-list-failure",
    "redirect-allocation-failure", "redirect-sanity-failure",
    "log-allocation-precommit", "log-allocation-committed", "disabled-log-retention",
    "missing-log", "missing-config-precommit", "missing-config-committed",
    "redirect-context-recovery", "foreign-context-rejected",
):
    setattr(InterventionRuntimeTests, "test_" + case.replace("-", "_"), case_test(case))


if __name__ == "__main__":
    unittest.main()
