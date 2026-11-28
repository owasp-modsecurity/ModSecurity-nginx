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
#include <stdint.h>
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef long off_t;
typedef long ssize_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_list_part_s { void *elts; ngx_uint_t nelts; struct ngx_list_part_s *next; } ngx_list_part_t;
typedef struct { ngx_list_part_t part; } ngx_list_t;
typedef struct { ngx_str_t key, value; } ngx_table_elt_t;
typedef struct { u_char *pos, *last; int last_buf; } ngx_buf_t;
typedef struct ngx_chain_s { ngx_buf_t *buf; struct ngx_chain_s *next; } ngx_chain_t;
typedef struct { int fd; ngx_str_t name; } ngx_file_t;
typedef struct { off_t size; int regular; } ngx_file_info_t;
typedef struct { ngx_file_t file; off_t offset; } ngx_temp_file_t;
typedef struct { ngx_temp_file_t *temp_file; ngx_chain_t *bufs; } ngx_http_request_body_t;
typedef struct { void *sockaddr, *local_sockaddr, *log; ngx_str_t addr_text; int error; } ngx_connection_t;
typedef struct {
    ngx_http_request_t *r;
    struct { ngx_pool_t *pool; const void *conf; } lifetime;
    Transaction *modsec_transaction;
    int waiting_more_body, body_requested, request_body_processed;
    int intervention_triggered, intervention_failed, request_intervention_active;
    int request_intervention_pending, logged, native_logging_failed;
    u_char *request_file_scratch;
} ngx_http_modsecurity_ctx_t;
typedef struct { int enable; } ngx_http_modsecurity_conf_t;
struct ngx_http_request_s {
    ngx_pool_t *pool; ngx_connection_t *connection; ngx_http_request_t *main;
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
#define NGX_INVALID_FILE (-1)
#define NGX_FILE_ERROR (-1)
#define ngx_is_file(info) ((info)->regular)
#define ngx_file_size(info) ((info)->size)
#define ngx_buf_special(buf) ((buf)->pos == NULL && (buf)->last == NULL)
#define dd(...) ((void)0)
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_get_module_loc_conf(r, module) ((r)->conf)
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
static Transaction transaction;
static ngx_http_modsecurity_ctx_t created;
static int created_calls, recovered_calls, error_calls, prepare_calls, prepare_failure, recover_allowed;
static int native_results[4] = {1, 1, 1, 1};
static int native_calls[4], intervention_results[5], intervention_calls[5];
static int active_phase, append_result = 1, append_calls, capture_calls, pending_limit;
static int log_result = 1, log_calls, log_reenter, nested_log_result;
static int stat_calls, read_calls, short_read, fail_read, bad_stat, regular_file = 1, changed_file, fail_scratch;
static size_t max_read;
static off_t actual_file_size = 3;
static u_char file_bytes[65537], scratch[32768];
static ngx_http_request_t *active_request;
static ngx_int_t ngx_http_modsecurity_log_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_modsecurity_log_context(ngx_http_modsecurity_ctx_t *ctx);
static void ngx_http_core_run_phases(ngx_http_request_t *r) { (void)r; }
static ngx_int_t ngx_http_modsecurity_prepare_location(ngx_http_request_t *r, const ngx_http_modsecurity_conf_t *conf)
{
    (void)r; (void)conf; ++prepare_calls;
    return prepare_failure ? NGX_ERROR : NGX_OK;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    ++recovered_calls;
    if (r->ctx != NULL && r->ctx->r == r) return r->ctx;
    return recover_allowed && r->recovered != NULL && r->recovered->r == r ? r->recovered : NULL;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    ++created_calls; memset(&created, 0, sizeof(created));
    created.r = r; created.modsec_transaction = &transaction;
    created.lifetime.pool = r->pool; created.lifetime.conf = r->conf;
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
    (void)connection; (void)port; out->data = (u_char *)"127.0.0.1"; out->len = 9;
    return NGX_OK;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool) { return pool; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...)
{
    (void)level; (void)log; (void)error; (void)format; ++error_calls;
}
static int phase_result(int phase) { active_phase = phase; ++native_calls[phase]; return native_results[phase]; }
static int msc_process_connection(Transaction *t, const char *client, int cp, const char *server, int sp)
{
    (void)t; (void)client; (void)cp; (void)server; (void)sp; return phase_result(0);
}
static int msc_process_uri(Transaction *t, const char *uri, const char *method, const char *version)
{
    (void)t; (void)uri; (void)method; (void)version; return phase_result(1);
}
static int msc_add_n_request_header(Transaction *t, const u_char *name, size_t nl, const u_char *value, size_t vl)
{
    (void)t; (void)name; (void)nl; (void)value; (void)vl; return 1;
}
static int msc_process_request_headers(Transaction *t) { (void)t; return phase_result(2); }
static int msc_process_request_body(Transaction *t) { (void)t; return phase_result(3); }
static int msc_append_request_body(Transaction *t, const u_char *data, size_t size)
{
    (void)t; (void)data; (void)size; active_phase = 4; ++append_calls; return append_result;
}
static ngx_int_t ngx_http_modsecurity_capture_request_body_intervention(ngx_http_request_t *r)
{
    ++capture_calls;
    if (intervention_results[4] < 0) return NGX_ERROR;
    if (pending_limit) r->ctx->request_intervention_pending = 1;
    return NGX_OK;
}
static int ngx_http_modsecurity_process_intervention(Transaction *t, ngx_http_request_t *r, int early)
{
    (void)t; (void)early; ++intervention_calls[active_phase];
    if (!r->ctx->request_intervention_active) abort();
    if (active_phase == 3 && r->ctx->request_intervention_pending) {
        r->ctx->request_intervention_pending = 0;
        return 413;
    }
    return intervention_results[active_phase];
}
static ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r, void (*callback)(ngx_http_request_t *))
{
    (void)r; (void)callback; return NGX_OK;
}
static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes)
{
    (void)pool; return !fail_scratch && bytes == sizeof(scratch) ? scratch : NULL;
}
static int ngx_fd_info(int fd, ngx_file_info_t *info)
{
    ++stat_calls;
    if (fd != 7 || bad_stat) return NGX_FILE_ERROR;
    info->size = actual_file_size - (changed_file && stat_calls > 1 ? 1 : 0);
    info->regular = regular_file;
    return 0;
}
static ssize_t ngx_read_file(ngx_file_t *file, u_char *out, size_t amount, off_t offset)
{
    (void)file; ++read_calls;
    if (amount > max_read) max_read = amount;
    if (fail_read || offset < 0 || (uintmax_t)offset + amount > sizeof(file_bytes)) return -1;
    if (short_read) return (ssize_t)amount - 1;
    memcpy(out, file_bytes + offset, amount);
    return (ssize_t)amount;
}
static int msc_process_logging(Transaction *t)
{
    (void)t; ++log_calls;
    if (log_reenter && log_calls == 1) nested_log_result = ngx_http_modsecurity_log_handler(active_request);
    return log_result;
}
static ngx_int_t ngx_http_modsecurity_log_request_contexts(ngx_http_request_t *r)
{
    if (r == NULL || r->pool == NULL) return NGX_ERROR;
    return r->ctx != NULL ? ngx_http_modsecurity_log_context(r->ctx) : NGX_OK;
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
    ngx_temp_file_t file = {{7, {8, (u_char *)"body.tmp"}}, 3};
    int phase, before_calls, after_calls, allowed = 0;
    ngx_int_t result;
    request.pool = &pool; request.connection = &connection;
    request.main = &request; request.conf = &conf; request.request_body = &body;
    request.http_version = NGX_HTTP_VERSION_11;
    request.unparsed_uri.data = (u_char *)"/protected"; request.unparsed_uri.len = 10;
    request.method_name.data = (u_char *)"POST"; request.method_name.len = 4;
    connection.addr_text.data = (u_char *)"127.0.0.1"; connection.addr_text.len = 9;
    request.error_page = 1;
    if (strcmp(scenario, "body-callback-no-context") == 0) {
        ngx_http_modsecurity_request_read(&request);
        CHECK(created_calls == 0 && native_calls[3] == 0);
        return 0;
    }
    if (strcmp(scenario, "fresh-error-page") == 0 || strcmp(scenario, "foreign-direct") == 0) {
        previous.r = strcmp(scenario, "foreign-direct") == 0 ? &other_request : &request;
        previous.modsec_transaction = &transaction;
        previous.request_body_processed = 1; previous.intervention_triggered = 1;
        if (strcmp(scenario, "foreign-direct") == 0) request.ctx = &previous;
        else request.recovered = &previous;
        intervention_results[3] = parameter;
    } else if (strcmp(scenario, "same-policy") == 0 || strcmp(scenario, "block-page") == 0) {
        previous.r = &request; previous.modsec_transaction = &transaction;
        previous.request_body_processed = 1;
        previous.intervention_triggered = strcmp(scenario, "block-page") == 0;
        request.recovered = &previous; recover_allowed = 1;
    } else if (strcmp(scenario, "p1-status") == 0) intervention_results[2] = parameter;
    else if (strcmp(scenario, "p2-status") == 0) intervention_results[3] = parameter;
    else if (strcmp(scenario, "intervention-error") == 0) {
        intervention_results[parameter] = -1;
        if (parameter == 4) body.bufs = &chain;
    } else if (strcmp(scenario, "native-error") == 0) native_results[parameter / 10] = parameter % 10 - 1;
    else if (strcmp(scenario, "append") == 0) {
        body.bufs = &chain; append_result = parameter; allowed = parameter == 0 || parameter == 1;
    } else if (strcmp(scenario, "file") == 0 || strcmp(scenario, "file-large") == 0 || strcmp(scenario, "file-reject") == 0) {
        body.temp_file = &file; append_result = parameter; allowed = parameter == 0 || parameter == 1;
        if (strcmp(scenario, "file-large") == 0) file.offset = actual_file_size = sizeof(file_bytes);
        if (strcmp(scenario, "file-reject") == 0) pending_limit = 1;
    } else if (strcmp(scenario, "file-error") == 0) {
        body.temp_file = &file;
        if (parameter == 0) file.file.fd = NGX_INVALID_FILE;
        if (parameter == 1) file.offset = -1;
        if (parameter == 2) bad_stat = 1;
        if (parameter == 3) regular_file = 0;
        if (parameter == 4) actual_file_size = 2;
        if (parameter == 5) short_read = 1;
        if (parameter == 6) fail_read = 1;
        if (parameter == 7) changed_file = 1;
        if (parameter == 8) fail_scratch = 1;
    } else if (strcmp(scenario, "disabled") == 0) conf.enable = 0;
    else if (strcmp(scenario, "prepare-error") == 0) prepare_failure = 1;
    else return 2;
    result = ngx_http_modsecurity_access_handler(&request);
    CHECK(prepare_calls == 1);
    CHECK(created.request_intervention_active == 0);
    if (strcmp(scenario, "fresh-error-page") == 0 || strcmp(scenario, "foreign-direct") == 0) {
        CHECK(created_calls == 1 && recovered_calls == 1);
        CHECK(native_calls[2] == 1 && native_calls[3] == 1);
        CHECK(previous.request_body_processed && previous.intervention_triggered);
        CHECK(result == (parameter > 0 ? parameter : NGX_DECLINED));
    } else if (strcmp(scenario, "same-policy") == 0 || strcmp(scenario, "block-page") == 0) {
        CHECK(result == NGX_DECLINED && created_calls == 0);
        CHECK(native_calls[0] == 0 && native_calls[2] == 0 && native_calls[3] == 0);
    } else if (strcmp(scenario, "disabled") == 0 || strcmp(scenario, "prepare-error") == 0) {
        CHECK(result == (prepare_failure ? 500 : NGX_DECLINED) && created_calls == 0);
    } else if (strcmp(scenario, "p1-status") == 0) {
        CHECK(result == parameter && created.intervention_triggered && native_calls[3] == 0);
    } else if (strcmp(scenario, "p2-status") == 0 || strcmp(scenario, "file-reject") == 0) {
        CHECK(result == (pending_limit ? 413 : parameter) && created.intervention_triggered);
        CHECK(native_calls[3] == 1 && created.request_body_processed);
        CHECK(!created.request_intervention_pending);
    } else if (allowed) {
        CHECK(result == NGX_DECLINED && native_calls[3] == 1 && created.request_body_processed);
        CHECK(!created.intervention_failed);
        if (body.temp_file != NULL) CHECK(stat_calls == 2 && read_calls == append_calls && capture_calls == append_calls);
        if (strcmp(scenario, "file-large") == 0) CHECK(append_calls == 3 && max_read == 32768U);
        else CHECK(append_calls == 1 && capture_calls == 1 && read_calls == (body.temp_file != NULL));
    } else {
        CHECK(result == 500 && created.intervention_failed && created.intervention_triggered);
        if (strcmp(scenario, "native-error") == 0) CHECK(intervention_calls[parameter / 10] == 0);
        if (body.temp_file != NULL || strcmp(scenario, "append") == 0) CHECK(native_calls[3] == 0);
        before_calls = append_calls + log_calls;
        for (phase = 0; phase < 4; ++phase) before_calls += native_calls[phase];
        CHECK(ngx_http_modsecurity_access_handler(&request) == 500);
        after_calls = append_calls + log_calls;
        for (phase = 0; phase < 4; ++phase) after_calls += native_calls[phase];
        CHECK(before_calls == after_calls);
        request.header_sent = 1;
        CHECK(ngx_http_modsecurity_access_handler(&request) == NGX_ERROR && connection.error);
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
    ctx.r = &request; ctx.modsec_transaction = &transaction; ctx.lifetime.pool = &pool;
    active_request = &request; log_result = parameter;
    if (strcmp(scenario, "log-missing") == 0) ctx.modsec_transaction = NULL;
    if (strcmp(scenario, "log-no-context") == 0) request.ctx = NULL;
    if (strcmp(scenario, "log-reenter") == 0) log_reenter = 1;
    result = ngx_http_modsecurity_log_handler(&request);
    if (strcmp(scenario, "log-no-context") == 0) { CHECK(result == NGX_OK && log_calls == 0); return 0; }
    CHECK(ctx.logged && result == (parameter == 1 && ctx.modsec_transaction != NULL ? NGX_OK : NGX_ERROR));
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
    return strncmp(argv[1], "log-", 4) == 0 ? run_logging(argv[1], atoi(argv[2])) : run_access(argv[1], atoi(argv[2]));
}
"""


def unit_program(access: str, logging: str) -> str:
    helpers = ""
    for name, result in (
        ("ngx_http_modsecurity_request_failure", "static ngx_int_t"),
        ("ngx_http_modsecurity_request_intervention", "static int"),
        ("ngx_http_modsecurity_append_request_chunk", "static ngx_int_t"),
        ("ngx_http_modsecurity_append_request_body", "static ngx_int_t"),
        ("ngx_http_modsecurity_inspect_request_body_file", "static ngx_int_t"),
        ("ngx_http_modsecurity_request_read", "void"),
        ("ngx_http_modsecurity_access_handler", "ngx_int_t"),
    ):
        helpers += "\n" + result + "\n" + function_definition(access, name)
    for name in ("ngx_http_modsecurity_log_context", "ngx_http_modsecurity_log_handler"):
        helpers += "\nstatic ngx_int_t\n" + function_definition(logging, name)
    return PREAMBLE + helpers + CASES


OWNERSHIP_PREAMBLE = r"""
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } Transaction;
typedef long ngx_int_t;
typedef struct { int unused; } ngx_array_t;
typedef struct { int unused; } ngx_http_modsecurity_header_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
    struct { void *pool; const void *conf; } lifetime;
    struct { char *log, *url; } pending_request_intervention;
    int request_intervention_pending, logged;
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
#define ngx_memzero(dst, size) memset((dst), 0, (size))
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
static Transaction transaction;
static int allocation_calls, fail_allocation_at, complex_failure, native_failure;
static int registration_failure, registration_calls, native_calls, cleanup_calls;
static int sanity_failure, sanity_allocations, sanity_destroys;
static int custom_id_copied, custom_id_terminated, audit_attempts;
static char custom_id[4] = {'i', 'd', '7', '!'};
static void ngx_http_modsecurity_cleanup(void *data);
static ngx_int_t ngx_http_modsecurity_log_context(ngx_http_modsecurity_ctx_t *ctx)
{
    if (!ctx->logged) { ctx->logged = 1; ++audit_attempts; }
    return NGX_OK;
}
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
        if (registration_failure || sanity_failure) CHECK(cleanup_calls == 1 && audit_attempts == 1);
        else CHECK(cleanup_calls == 0);
        if (fail_allocation_at || complex_failure) CHECK(native_calls == 0);
        return 0;
    }
    CHECK(ctx != NULL && ctx != NGX_CONF_ERROR && ctx == request.ctx);
    CHECK(native_calls == 1 && registration_calls == 1 && cleanup_calls == 0);
    CHECK(ctx->lifetime.pool == &pool && ctx->lifetime.conf == &conf);
    CHECK(pool.cleanup.handler == ngx_http_modsecurity_cleanup && pool.cleanup.data == ctx);
    if (conf.transaction_id != NULL) CHECK(custom_id_copied && custom_id_terminated);
    ngx_http_modsecurity_cleanup(NULL);
    pool.cleanup.handler(pool.cleanup.data);
    pool.cleanup.handler(pool.cleanup.data);
    CHECK(ctx->modsec_transaction == NULL && cleanup_calls == 1 && audit_attempts == 1);
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


POLICY_PREAMBLE = r"""
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int result, logs, cleanups; } Transaction;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_pool_cleanup_s {
    void (*handler)(void *); void *data; struct ngx_pool_cleanup_s *next;
} ngx_pool_cleanup_t;
typedef struct { ngx_pool_cleanup_t *cleanup; } ngx_pool_t;
typedef struct { void *elts; ngx_uint_t nelts; } ngx_array_t;
typedef struct { ngx_str_t literal; int failed; } ngx_http_complex_value_t;
typedef struct { ngx_int_t status, overwrite; ngx_http_complex_value_t value; } ngx_http_err_page_t;
typedef struct { ngx_array_t *error_pages; int named; ngx_str_t name; } ngx_http_core_loc_conf_t;
typedef struct ngx_http_modsecurity_conf_s {
    void *rules_set; const void *rules_identity;
    int enable, use_error_log, sanity_checks_enabled;
    void *transaction_id, *phase4_log_file; ngx_uint_t phase4_mode;
} ngx_http_modsecurity_conf_t;
typedef struct {
    ngx_http_request_t *r;
    struct { ngx_pool_t *pool; const ngx_http_modsecurity_conf_t *conf; } lifetime;
    struct { ngx_str_t target; ngx_int_t status, response_status; } error_page;
    Transaction *modsec_transaction;
    struct { char *log, *url; } pending_request_intervention;
    int logged, native_logging_failed, request_policy_superseded;
    int request_intervention_active, request_intervention_pending, native_request_body_limit_rejection;
    int intervention_triggered, intervention_failed, phase4_failed;
    ngx_int_t last_intervention_status;
    ngx_array_t *sanity_headers_out;
} ngx_http_modsecurity_ctx_t;
typedef struct { void *log; int error; } ngx_connection_t;
struct ngx_http_request_s {
    ngx_pool_t *pool; ngx_connection_t *connection;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
    ngx_http_core_loc_conf_t *core;
    int internal, error_page, err_status, header_sent; ngx_str_t uri;
};
enum { ngx_http_modsecurity_module = 1, ngx_http_core_module = 2 };
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_HTTP_BAD_REQUEST 400
#define NGX_LOG_ERR 3
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_set_ctx(r, value, module) ((r)->ctx = (value))
#define ngx_http_get_module_loc_conf(r, module) \
    ((module) == ngx_http_core_module ? (void *)(r)->core : (void *)(r)->conf)
#define ngx_strncmp(a, b, n) strncmp((const char *)(a), (const char *)(b), (n))
#define ngx_memzero(dst, size) memset((dst), 0, (size))
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
static ngx_pool_t *last_pool_seen;
static void ngx_http_modsecurity_cleanup(void *data);
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    last_pool_seen = pool;
    return pool;
}
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool) { (void)pool; }
static void ngx_log_error(int level, void *log, int error, const char *format, ...)
{
    (void)level; (void)log; (void)error; (void)format;
}
static int msc_process_logging(Transaction *transaction)
{
    ++transaction->logs;
    return transaction->result;
}
static void msc_transaction_cleanup(Transaction *transaction)
{
    ++transaction->cleanups;
    if (transaction->cleanups != 1) abort();
}
static int ngx_http_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *value, ngx_str_t *out)
{
    (void)r; *out = value->literal; return value->failed ? NGX_ERROR : NGX_OK;
}
static u_char *ngx_strlchr(u_char *first, u_char *last, u_char value)
{
    return memchr(first, value, (size_t)(last - first));
}
#if MODSECURITY_SANITY_CHECKS
static void ngx_array_destroy(ngx_array_t *array) { (void)array; }
#endif
"""

POLICY_CASES = r"""
int main(int argc, char **argv)
{
    Transaction first = {1, 0, 0}, second = {1, 0, 0}, foreign_transaction = {1, 0, 0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t original = {0}, destination;
    ngx_http_core_loc_conf_t core = {0};
    ngx_http_request_t request = {0}, other = {0};
    ngx_http_modsecurity_ctx_t origin = {0}, target = {0}, foreign = {0};
    ngx_pool_cleanup_t source_cleanup = {ngx_http_modsecurity_cleanup, &origin, NULL};
    ngx_pool_cleanup_t target_cleanup = {ngx_http_modsecurity_cleanup, &target, &source_cleanup};
    ngx_pool_cleanup_t foreign_cleanup = {ngx_http_modsecurity_cleanup, &foreign, NULL};
    ngx_pool_t pool = {&source_cleanup};
    ngx_http_err_page_t error_page = {403, -1, {{24, (u_char *)"/block.html?observation=1"}, 0}};
    ngx_array_t pages = {&error_page, 1};
    ngx_http_modsecurity_ctx_t *selected;
    int parameter, expected;
    CHECK(argc == 3);
    parameter = atoi(argv[2]);
    original.enable = 1; original.rules_set = &first; original.rules_identity = &first;
    destination = original; destination.rules_set = &second;
    request.pool = &pool; request.connection = &connection;
    request.conf = &destination; request.core = &core;
    request.uri.data = (u_char *)"/block.html"; request.uri.len = 11;
    origin.r = &request; origin.lifetime.pool = &pool; origin.lifetime.conf = &original;
    origin.modsec_transaction = &first;
    target.r = &request; target.lifetime.pool = &pool; target.lifetime.conf = &destination;
    target.modsec_transaction = &second;
    foreign.r = &other; foreign.lifetime.pool = &pool; foreign.lifetime.conf = &original;
    foreign.modsec_transaction = &foreign_transaction;
    source_cleanup.next = &foreign_cleanup;

    if (strcmp(argv[1], "same-policy") == 0) {
        CHECK(ngx_http_modsecurity_same_policy(&original, &destination));
        CHECK(ngx_http_modsecurity_prepare_location(&request, &destination) == NGX_OK);
        CHECK(!origin.request_policy_superseded);
        CHECK(ngx_http_modsecurity_get_module_ctx(&request) == &origin && request.ctx == &origin);
        CHECK(ngx_http_modsecurity_log_handler(&request) == NGX_OK);
        CHECK(ngx_http_modsecurity_log_handler(&request) == NGX_OK);
        CHECK(first.logs == 1 && second.logs == 0 && foreign_transaction.logs == 0);
    } else if (strcmp(argv[1], "policy-key") == 0) {
        if (parameter == 0) destination.rules_identity = &second;
        if (parameter == 1) destination.enable = 0;
        if (parameter == 2) destination.use_error_log = 1;
        if (parameter == 3) destination.transaction_id = &second;
        if (parameter == 4) destination.phase4_mode = 1;
        if (parameter == 5) destination.phase4_log_file = &second;
        if (parameter == 6) destination.sanity_checks_enabled = 1;
        expected = parameter != 6 || MODSECURITY_SANITY_CHECKS;
        CHECK(ngx_http_modsecurity_prepare_location(&request, &destination) == NGX_OK);
        CHECK(origin.request_policy_superseded == expected);
        CHECK(ngx_http_modsecurity_get_module_ctx(&request) == (expected ? NULL : &origin));
    } else if (strcmp(argv[1], "changed-policy") == 0 || strcmp(argv[1], "failed-audit") == 0
               || strcmp(argv[1], "failed-target-audit") == 0 || strcmp(argv[1], "disabled-target") == 0) {
        destination.rules_identity = &second;
        if (strcmp(argv[1], "disabled-target") == 0) destination.enable = 0;
        CHECK(ngx_http_modsecurity_prepare_location(&request, &destination) == NGX_OK);
        CHECK(origin.request_policy_superseded && ngx_http_modsecurity_get_module_ctx(&request) == NULL);
        if (destination.enable) { pool.cleanup = &target_cleanup; request.ctx = &target; }
        /* The failing owner comes first, so the owner after it must still be audited. */
        if (strcmp(argv[1], "failed-audit") == 0) {
            pool.cleanup = &source_cleanup;
            source_cleanup.next = &target_cleanup; target_cleanup.next = &foreign_cleanup;
            first.result = 0;
        }
        if (strcmp(argv[1], "failed-target-audit") == 0) second.result = 0;
        expected = first.result == 1 && second.result == 1 ? NGX_OK : NGX_ERROR;
        CHECK(ngx_http_modsecurity_log_handler(&request) == expected);
        CHECK(ngx_http_modsecurity_log_handler(&request) == expected);
        CHECK(first.logs == 1 && second.logs == (destination.enable ? 1 : 0));
        CHECK(foreign_transaction.logs == 0 && !connection.error && !request.header_sent);
    } else if (strcmp(argv[1], "cleanup-fallback") == 0) {
        request.pool = NULL;
        ngx_http_modsecurity_cleanup(&origin);
        ngx_http_modsecurity_cleanup(&origin);
        CHECK(first.logs == 1 && first.cleanups == 1 && origin.modsec_transaction == NULL);
        CHECK(last_pool_seen == &pool && foreign_transaction.logs == 0);
    } else if (strcmp(argv[1], "block-page") == 0) {
        destination.rules_identity = &second;
        core.error_pages = &pages;
        origin.request_intervention_active = 1;
        origin.intervention_triggered = 1; origin.last_intervention_status = 403;
        request.internal = 1; request.error_page = 1; request.err_status = 403;
        if (parameter == 6) origin.native_request_body_limit_rejection = 1;
        if (parameter == 7) origin.request_intervention_active = 0;
        if (parameter == 8 || parameter == 9) {
            error_page.value.literal.data = (u_char *)"@block"; error_page.value.literal.len = 6;
            core.named = parameter == 8; core.name = error_page.value.literal;
        }
        if (parameter == 10 || parameter == 11) {
            error_page.overwrite = parameter == 10 ? 200 : 0;
            request.err_status = error_page.overwrite;
        }
        if (parameter == 14) {
            error_page.value.literal.data = (u_char *)"https://example.test/error";
            error_page.value.literal.len = 26;
        }
        if (parameter == 15) error_page.value.failed = 1;
        if (parameter != 13) ngx_http_modsecurity_capture_error_page(&request, &origin, 403);
        origin.request_intervention_active = 0;
        if (parameter == 1) { request.uri.data = (u_char *)"/different"; request.uri.len = 10; }
        if (parameter == 2) request.err_status = 451;
        if (parameter == 3) request.internal = 0;
        if (parameter == 4) origin.intervention_failed = 1;
        if (parameter == 5) origin.last_intervention_status = 451;
        if (parameter == 12) origin.r = &other;
        expected = parameter == 0 || parameter == 8 || parameter == 10 || parameter == 11;
        selected = ngx_http_modsecurity_get_module_ctx(&request);
        CHECK(selected == (expected ? &origin : NULL));
        CHECK(first.logs == 0 && second.logs == 0 && foreign_transaction.logs == 0);
    } else return 2;
    return 0;
}
"""


def policy_program(module: str, logging: str) -> str:
    helpers = "\nngx_int_t\n" + function_definition(logging, "ngx_http_modsecurity_log_context")
    for name, result in (
        ("ngx_http_modsecurity_same_policy", "static int"),
        ("ngx_http_modsecurity_capture_error_page", "static void"),
        ("ngx_http_modsecurity_is_block_error_page", "static int"),
        ("ngx_http_modsecurity_prepare_location", "ngx_int_t"),
        ("ngx_http_modsecurity_get_module_ctx", "ngx_http_modsecurity_ctx_t *"),
        ("ngx_http_modsecurity_log_request_contexts", "ngx_int_t"),
        ("ngx_http_modsecurity_cleanup", "static void"),
    ):
        helpers += "\n" + result + "\n" + function_definition(module, name)
    helpers += "\nngx_int_t\n" + function_definition(logging, "ngx_http_modsecurity_log_handler")
    return POLICY_PREAMBLE + helpers + POLICY_CASES


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

    def test_body_callback_without_a_recoverable_context_is_safe(self):
        self.case("body-callback-no-context", 0)

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

    def test_file_and_memory_partial_results_have_equal_semantics(self):
        for result in (-1, 0, 1, 2):
            with self.subTest(result=result):
                self.case("file", result)

    def test_file_chunks_are_bounded_and_partial_inspection_continues(self):
        self.case("file-large", 0)

    def test_file_descriptor_read_and_allocation_failures_remain_errors(self):
        for failure in range(9):
            with self.subTest(failure=failure):
                self.case("file-error", failure)

    def test_file_native_reject_is_dispatched_after_successful_eos(self):
        self.case("file-reject", 1)

    def test_same_policy_and_native_block_page_do_not_repeat_request_phases(self):
        for scenario in ("same-policy", "block-page"):
            with self.subTest(scenario=scenario):
                self.case(scenario, 0)

    def test_location_preparation_runs_before_disabled_or_failed_entry(self):
        for scenario in ("disabled", "prepare-error"):
            with self.subTest(scenario=scenario):
                self.case(scenario, 0)

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


class LifecyclePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        workspace = tempfile.TemporaryDirectory(prefix="nginx-policy-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        source = directory / "policy.c"
        source.write_text(policy_program(
            (ROOT / "src/ngx_http_modsecurity_module.c").read_text(encoding="utf-8"),
            (ROOT / "src/ngx_http_modsecurity_log.c").read_text(encoding="utf-8"),
        ), encoding="utf-8")
        cls.binaries = {}
        for sanity in (0, 1):
            binary = directory / (f"policy-{sanity}.exe" if os.name == "nt" else f"policy-{sanity}")
            build = subprocess.run(
                [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
                 f"-DMODSECURITY_SANITY_CHECKS={sanity}", str(source), "-o", str(binary)],
                capture_output=True, text=True, check=False, timeout=60,
            )
            if build.returncode:
                raise AssertionError(f"Policy helper build failed:\n{build.stderr}")
            cls.binaries[sanity] = binary

    def case(self, name: str, parameter: int = 0) -> None:
        for sanity, binary in self.binaries.items():
            with self.subTest(sanity=sanity):
                result = subprocess.run(
                    [str(binary), name, str(parameter)], capture_output=True,
                    text=True, check=False, timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_inherited_equivalent_policy_reuses_one_audited_owner(self):
        self.case("same-policy")

    def test_semantic_policy_changes_require_a_new_owner(self):
        for parameter in range(7):
            with self.subTest(parameter=parameter):
                self.case("policy-key", parameter)

    def test_changed_or_disabled_target_retains_source_audit(self):
        for name in ("changed-policy", "disabled-target"):
            with self.subTest(name=name):
                self.case(name)

    def test_owner_audit_failure_is_sticky_without_skipping_other_owners(self):
        for name in ("failed-audit", "failed-target-audit"):
            with self.subTest(name=name):
                self.case(name)

    def test_cleanup_audits_once_with_the_retained_pool(self):
        self.case("cleanup-fallback")

    def test_exact_native_block_destination_can_reuse_its_origin(self):
        for parameter in (0, 8, 10, 11):
            with self.subTest(parameter=parameter):
                self.case("block-page", parameter)

    def test_unrelated_routes_cannot_claim_the_block_page_exemption(self):
        for parameter in (1, 2, 3, 4, 5, 6, 7, 9, 12, 13, 14, 15):
            with self.subTest(parameter=parameter):
                self.case("block-page", parameter)


if __name__ == "__main__":
    unittest.main()
