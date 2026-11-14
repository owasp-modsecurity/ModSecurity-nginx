"""Compile and exercise the production Phase4 helpers with small host doubles.

These tests cover accounting, buffer representations, EOS, and intervention
dispatch. Native NGINX/libModSecurity HTTP tests remain in modsecurity*.t.
There is no dependency on the Common connector or its runtime framework.
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
BODY = ROOT / "src" / "ngx_http_modsecurity_body_filter.c"
MODULE = ROOT / "src" / "ngx_http_modsecurity_module.c"


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


PREAMBLE = r"""
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef _MSC_VER
typedef intptr_t ssize_t;
#endif
typedef unsigned char u_char;
typedef int ngx_int_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_http_modsecurity_conf_s ngx_http_modsecurity_conf_t;
typedef struct { int named; ngx_str_t name; } ngx_http_core_loc_conf_t;
typedef struct ngx_pool_cleanup_s {
    void (*handler)(void *);
    void *data;
    struct ngx_pool_cleanup_s *next;
} ngx_pool_cleanup_t;
typedef struct { ngx_pool_cleanup_t *cleanup; } ngx_pool_t;
typedef struct { int error; void *log; int buffered; } ngx_connection_t;
typedef struct { u_char *data; size_t length; } ngx_file_t;
typedef struct {
    u_char *pos, *last;
    off_t file_pos, file_last;
    ngx_file_t *file;
    unsigned memory, in_file, last_buf, last_in_chain;
    unsigned flush, sync;
} ngx_buf_t;
typedef struct ngx_chain_s {
    ngx_buf_t *buf;
    struct ngx_chain_s *next;
} ngx_chain_t;
typedef struct {
    size_t response_body_bytes_seen, response_body_bytes_inspected;
    int response_body_seen, response_body_truncated, phase4_processed;
    int phase4_strict_abort, phase4_headers_checked, intervention_triggered;
    int intervention_late, intervention_failed, response_replaced, last_intervention_status;
    int phase4_failed, phase4_error_emitting, phase4_started, intervention_body_limit;
    int phase4_append_active, replacement_body_terminal_sent;
    int logged, request_policy_superseded;
    struct { ngx_pool_t *pool; const ngx_http_modsecurity_conf_t *conf; } lifetime;
    struct { ngx_str_t target; ngx_int_t status, response_status; } error_page;
    ngx_http_request_t *r;
    void *modsec_transaction;
    u_char *phase4_file_scratch;
} ngx_http_modsecurity_ctx_t;
struct ngx_http_modsecurity_conf_s {
    unsigned phase4_mode;
    size_t phase4_body_limit;
    int enable, use_error_log;
    void *rules_identity, *transaction_id, *phase4_log_file;
};
struct ngx_http_request_s {
    int header_sent, filter_finalize;
    int buffered, internal, err_status;
    ngx_str_t uri;
    ngx_http_core_loc_conf_t *core_conf;
    struct ngx_http_request_s *main;
    ngx_pool_t *pool;
    ngx_connection_t *connection;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
};
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_AGAIN (-2)
#define NGX_DECLINED (-5)
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_FORBIDDEN 403
#define NGX_HTTP_MODSEC_PHASE4_MODE_OFF 0
#define NGX_HTTP_MODSEC_PHASE4_MODE_SAFE 1
#define NGX_HTTP_MODSEC_PHASE4_MODE_STRICT 2
#define NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK 32768U
#define ngx_buf_in_memory(buffer) ((buffer)->memory)
#define ngx_http_get_module_ctx(r, module) ((r)->ctx)
#define ngx_http_core_module 1
#define ngx_http_get_module_loc_conf(r, module) \
    ((module) == ngx_http_core_module ? (void *)(r)->core_conf : (void *)(r)->conf)
#define ngx_http_set_ctx(r, value, module) ((r)->ctx = (value))
#define ngx_strncmp(a, b, n) strncmp((const char *)(a), (const char *)(b), (n))
#define ngx_log_error(...) (++diagnostic_calls)
static int ngx_http_modsecurity_module;
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r);
static void ngx_http_modsecurity_cleanup(void *data) { (void)data; }
static int allocation_calls, read_calls, append_calls, process_calls;
static int fail_allocation, fail_read, short_read, fail_append, append_result = 1;
static int engine_result = 1, native_result, native_late, native_failed, native_body_limit;
static int log_result, event_calls, pcre_enter, pcre_leave;
static int diagnostic_calls, native_only_after_eos, append_collections, eos_with_append_active;
static int forward_calls, forwarded_links, forward_result;
static int verify_writer, writer_rejected_zero, forwarded_controls, forwarded_eos;
static int control_link_calls, control_buffer_calls, fail_control_link, fail_control_buffer;
static ngx_chain_t control_links[16];
static ngx_buf_t control_buffers[16];
static int finalize_calls, emulate_core_response, core_response_result;
static ngx_chain_t *core_response;
ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *, ngx_chain_t *);
static size_t read_max, appended_bytes;
static u_char scratch[32768], inspected[200000];
static const char *last_action, *last_reason;

static ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool)
{
    (void)pool;
    if (fail_control_link || control_link_calls >= 16) return NULL;
    return &control_links[control_link_calls++];
}
static ngx_buf_t *ngx_calloc_buf(ngx_pool_t *pool)
{
    (void)pool;
    if (fail_control_buffer || control_buffer_calls >= 16) return NULL;
    return &control_buffers[control_buffer_calls++];
}
static void *ngx_pnalloc(ngx_pool_t *pool, size_t bytes)
{
    (void)pool;
    ++allocation_calls;
    return !fail_allocation && bytes <= sizeof(scratch) ? scratch : NULL;
}
static ssize_t ngx_read_file(ngx_file_t *file, u_char *out,
    size_t bytes, off_t offset)
{
    ++read_calls;
    if (bytes > read_max) read_max = bytes;
    if (fail_read || offset < 0) return -1;
    if ((size_t)offset > file->length || bytes > file->length - (size_t)offset)
        return 0;
    if (short_read && bytes != 0U) --bytes;
    memcpy(out, file->data + offset, bytes);
    return (ssize_t)bytes;
}
static int msc_append_response_body(void *transaction, u_char *data, size_t bytes)
{
    (void)transaction;
    ++append_calls;
    if (fail_append || bytes > sizeof(inspected) - appended_bytes) return -1;
    memcpy(inspected + appended_bytes, data, bytes);
    appended_bytes += bytes;
    return append_result;
}
static int msc_process_response_body(void *transaction)
{
    ngx_http_modsecurity_ctx_t *ctx = transaction;
    if (ctx->phase4_append_active) ++eos_with_append_active;
    ++process_calls;
    return engine_result;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ++pcre_enter;
    return pool;
}
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *pool)
{
    (void)pool;
    ++pcre_leave;
}
static int ngx_http_modsecurity_process_intervention(void *transaction,
    ngx_http_request_t *r, int early)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    (void)transaction; (void)early;
    if (ctx == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if (ctx->phase4_append_active) ++append_collections;
    if (native_only_after_eos && !ctx->phase4_processed) return 0;
    ctx->intervention_late = native_late;
    ctx->intervention_failed = native_failed;
    ctx->intervention_body_limit = native_body_limit;
    return native_result;
}
static ngx_int_t ngx_http_filter_finalize_request(ngx_http_request_t *r,
    int *module, int status)
{
    (void)module;
    ++finalize_calls;
    if (!r->header_sent && emulate_core_response) {
        int previous = r->filter_finalize;
        r->filter_finalize = 1;
        core_response_result = ngx_http_modsecurity_body_filter(r, core_response);
        r->filter_finalize = previous;
    }
    return r->header_sent ? NGX_ERROR : status;
}
static ngx_int_t ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r,
    ngx_http_modsecurity_conf_t *conf, const char *wanted,
    const char *actual, const char *reason)
{
    (void)r; (void)conf; (void)wanted;
    ++event_calls;
    last_action = actual; last_reason = reason;
    return log_result;
}
static ngx_int_t ngx_http_next_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    (void)r;
    ++forward_calls;
    for (; in != NULL; in = in->next) {
        ngx_buf_t *buffer = in->buf;
        int special = buffer != NULL && !buffer->memory && !buffer->in_file &&
            (buffer->flush || buffer->sync || buffer->last_buf);
        int empty = buffer == NULL || (buffer->memory
            ? buffer->pos == buffer->last
            : (!buffer->in_file || buffer->file_pos == buffer->file_last));
        if (verify_writer && empty && !special) {
            ++writer_rejected_zero;
            return NGX_ERROR;
        }
        ++forwarded_links;
        if (special) ++forwarded_controls;
        if (buffer != NULL && (buffer->last_buf ||
            (r != r->main && buffer->last_in_chain))) ++forwarded_eos;
    }
    return forward_result;
}
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)
"""

CASES = r"""
int main(int argc, char **argv)
{
    ngx_http_modsecurity_ctx_t ctx = {0};
    ngx_http_modsecurity_conf_t conf = {
        .phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_SAFE,
        .phase4_body_limit = 1048576U, .enable = 1
    };
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_request_t request = {0};
    ngx_http_request_t main_request = {0};
    u_char payload[70000];
    ngx_file_t file = {payload, sizeof(payload)};
    ngx_buf_t buffer = {0};
    ngx_buf_t final = {0};
    ngx_chain_t tail = {&final, NULL};
    ngx_chain_t chain = {&buffer, &tail};
    size_t allowed = 999U;
    size_t i;
    CHECK(argc == 2);
    memset(payload, 'A', sizeof(payload));
    request.pool = &pool; request.connection = &connection;
    request.ctx = &ctx; request.conf = &conf; request.main = &request; ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
    buffer.file = &file; buffer.in_file = 1; buffer.file_last = sizeof(payload);

    if (strcmp(argv[1], "request-ownership") == 0) {
        ngx_http_modsecurity_ctx_t other_ctx = {0};
        ngx_http_request_t subrequest = {0};
        ngx_pool_cleanup_t owner_cleanup = {ngx_http_modsecurity_cleanup, &ctx, NULL};
        ngx_pool_cleanup_t other_cleanup = {ngx_http_modsecurity_cleanup, &other_ctx, &owner_cleanup};
        other_ctx.r = &subrequest; other_ctx.modsec_transaction = &other_ctx;
        other_ctx.lifetime.pool = &pool; other_ctx.lifetime.conf = &conf;
        subrequest.conf = &conf;
        subrequest.pool = &pool; subrequest.main = &request;
        pool.cleanup = &other_cleanup;
        CHECK(ngx_http_modsecurity_get_module_ctx(&request) == &ctx);
        request.ctx = NULL; /* Same-request internal redirect clears module context. */
        CHECK(ngx_http_modsecurity_get_module_ctx(&request) == &ctx);
        CHECK(ngx_http_modsecurity_get_module_ctx(&subrequest) == &other_ctx);
        subrequest.ctx = &ctx; /* Reject a foreign direct context too. */
        CHECK(ngx_http_modsecurity_get_module_ctx(&subrequest) == &other_ctx);
        pool.cleanup = &owner_cleanup; /* Auth subrequest has no own transaction. */
        subrequest.ctx = NULL;
        CHECK(ngx_http_modsecurity_get_module_ctx(&subrequest) == NULL);
        subrequest.ctx = NULL; subrequest.connection = &connection;
        final.last_in_chain = 1;
        CHECK(ngx_http_modsecurity_body_filter(&subrequest, &tail) == NGX_OK);
        CHECK(process_calls == 0 && !ctx.phase4_processed && forward_calls == 1);
        final.last_in_chain = 0; final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &tail) == NGX_OK);
        CHECK(process_calls == 1 && ctx.phase4_processed && forward_calls == 2);
    } else if (strcmp(argv[1], "all-modes-large") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1048577U, &allowed) == NGX_OK);
            CHECK(allowed == 1048577U && ctx.response_body_bytes_seen == allowed);
            CHECK(ctx.response_body_seen && !ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_inspected == 0U);
        }
    } else if (strcmp(argv[1], "all-modes-multiple") == 0) {
        size_t chunk;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            for (chunk = 0; chunk < 3; ++chunk) {
                CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                    1048576U, &allowed) == NGX_OK);
                CHECK(allowed == 1048576U);
                ctx.response_body_bytes_inspected += allowed;
            }
            CHECK(ctx.response_body_bytes_seen == 3U * 1048576U);
            CHECK(ctx.response_body_bytes_inspected == ctx.response_body_bytes_seen);
            CHECK(!ctx.response_body_truncated);
        }
    } else if (strcmp(argv[1], "legacy-boundary") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1048575U, &allowed) == NGX_OK);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1U, &allowed) == NGX_OK);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1U, &allowed) == NGX_OK);
            ctx.response_body_bytes_inspected += allowed;
            CHECK(allowed == 1U && !ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_seen == 1048577U);
            CHECK(ctx.response_body_bytes_inspected == 1048577U);
        }
    } else if (strcmp(argv[1], "memory-over-legacy-limit") == 0) {
        conf.phase4_body_limit = 65536U;
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + sizeof(payload);
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            append_calls = 0; appended_bytes = 0;
            CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
                &conf, &buffer) == NGX_OK);
            CHECK(append_calls == 1 && appended_bytes == sizeof(payload));
            CHECK(read_calls == 0 && allocation_calls == 0);
            CHECK(ctx.response_body_bytes_seen == sizeof(payload));
            CHECK(ctx.response_body_bytes_inspected == sizeof(payload));
            CHECK(!ctx.response_body_truncated);
            CHECK(memcmp(inspected, payload, sizeof(payload)) == 0);
            CHECK(buffer.pos == payload && buffer.last == payload + sizeof(payload));
        }
    } else if (strcmp(argv[1], "overflow") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            ctx.response_body_bytes_seen = SIZE_MAX - 1U;
            ctx.response_body_bytes_inspected = SIZE_MAX - 1U;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                2U, &allowed) == NGX_OK);
            CHECK(allowed == 2U && !ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_seen == SIZE_MAX);
            CHECK(ctx.response_body_bytes_inspected == SIZE_MAX - 1U);
            CHECK(ngx_http_modsecurity_append_response_body_chunk(&ctx,
                payload, 2U) == NGX_OK);
            CHECK(ctx.response_body_bytes_inspected == SIZE_MAX);
            CHECK(append_calls == (int)i + 1 && ctx.phase4_append_active);
        }
    } else if (strcmp(argv[1], "invalid-accounting") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            ctx.response_body_bytes_inspected = 1U;
            CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
                1U, &allowed) == NGX_ERROR);
            CHECK(allowed == 0U && ctx.response_body_truncated);
            CHECK(ctx.response_body_bytes_seen == 0U);
        }
    } else if (strcmp(argv[1], "null-empty-mode") == 0) {
        CHECK(ngx_http_modsecurity_plan_limited_response_body(NULL, &conf,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, NULL,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1U, NULL) == NGX_ERROR);
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            0U, &allowed) == NGX_OK && allowed == 0U);
        CHECK(!ctx.response_body_seen);
        conf.phase4_mode = 99U;
        CHECK(ngx_http_modsecurity_plan_limited_response_body(&ctx, &conf,
            1U, &allowed) == NGX_ERROR && allowed == 0U);
    } else if (strcmp(argv[1], "file-chunks") == 0) {
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(read_calls == 3 && append_calls == 3 && read_max == 32768U);
        CHECK(allocation_calls == 1 && appended_bytes == sizeof(payload));
        CHECK(memcmp(inspected, payload, sizeof(payload)) == 0);
        CHECK(buffer.file_pos == 0 && buffer.file_last == sizeof(payload));
        buffer.file_last = 1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_OK);
        CHECK(allocation_calls == 1 && appended_bytes == sizeof(payload) + 1U);
    } else if (strcmp(argv[1], "mixed-over-legacy-limit") == 0) {
        conf.phase4_body_limit = 65536U;
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + sizeof(payload);
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            append_calls = 0; appended_bytes = 0;
            CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
                &conf, &buffer) == NGX_OK);
            CHECK(appended_bytes == sizeof(payload) && append_calls == 1);
            CHECK(read_calls == 0 && allocation_calls == 0);
            CHECK(ctx.response_body_bytes_seen == sizeof(payload));
            CHECK(ctx.response_body_bytes_inspected == sizeof(payload));
            CHECK(!ctx.response_body_truncated);
            CHECK(memcmp(inspected, payload, sizeof(payload)) == 0);
            CHECK(buffer.pos == payload && buffer.last == payload + sizeof(payload));
            CHECK(buffer.file_pos == 0 && buffer.file_last == sizeof(payload));
        }
    } else if (strcmp(argv[1], "file-over-legacy-limit") == 0) {
        conf.phase4_body_limit = 65536U;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            read_calls = 0; append_calls = 0; allocation_calls = 0;
            appended_bytes = 0; read_max = 0;
            CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
                &conf, &buffer) == NGX_OK);
            CHECK(read_calls == 3 && append_calls == 3 && read_max == 32768U);
            CHECK(allocation_calls == 1 && appended_bytes == sizeof(payload));
            CHECK(ctx.response_body_bytes_seen == sizeof(payload));
            CHECK(ctx.response_body_bytes_inspected == sizeof(payload));
            CHECK(!ctx.response_body_truncated);
            CHECK(memcmp(inspected, payload, sizeof(payload)) == 0);
            CHECK(buffer.file_pos == 0 && buffer.file_last == sizeof(payload));
        }
    } else if (strcmp(argv[1], "file-invalid") == 0) {
        buffer.file_pos = -1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        buffer.file_pos = 10; buffer.file_last = 9;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        buffer.file_pos = 0; buffer.file_last = 10; buffer.file = NULL;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, NULL) == NGX_ERROR);
        buffer.memory = 1; buffer.pos = NULL; buffer.last = payload + 10;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        buffer.pos = payload + 10; buffer.last = payload;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(ngx_http_modsecurity_append_response_body_chunk(&ctx,
            NULL, 1U) == NGX_ERROR);
        CHECK(read_calls == 0 && append_calls == 0);
    } else if (strcmp(argv[1], "allocation-failure") == 0) {
        fail_allocation = 1;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 0 && appended_bytes == 0U);
    } else if (strcmp(argv[1], "short-read") == 0 || strcmp(argv[1], "read-error") == 0) {
        short_read = strcmp(argv[1], "short-read") == 0;
        fail_read = !short_read;
        CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
            &conf, &buffer) == NGX_ERROR);
        CHECK(read_calls == 1 && append_calls == 0 && appended_bytes == 0U);
    } else if (strcmp(argv[1], "append-error") == 0) {
        fail_append = 1;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
                &conf, &buffer) == NGX_ERROR);
            CHECK(ctx.response_body_bytes_inspected == 0U);
        }
    } else if (strcmp(argv[1], "append-zero") == 0) {
        append_result = 0;
        conf.phase4_body_limit = 1U;
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            append_calls = 0; appended_bytes = 0;
            CHECK(ngx_http_modsecurity_append_response_body_buffer(&request, &ctx,
                &conf, &buffer) == NGX_OK);
            CHECK(ctx.response_body_bytes_inspected == 10U && append_calls == 1);
            CHECK(!ctx.response_body_truncated);
        }
    } else if (strcmp(argv[1], "final-once") == 0) {
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_OK);
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_OK);
        CHECK(process_calls == 1 && pcre_enter == 1 && pcre_leave == 1);
        CHECK(ctx.phase4_processed);
    } else if (strcmp(argv[1], "engine-error") == 0) {
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            request.header_sent = 1; connection.error = 0; engine_result = -1;
            CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == NGX_ERROR);
            CHECK(ctx.phase4_processed && ctx.intervention_triggered && connection.error);
        }
        CHECK(process_calls == 3 && pcre_enter == pcre_leave);
    } else if (strcmp(argv[1], "process-zero") == 0) {
        engine_result = 0;
        CHECK(ngx_http_modsecurity_process_final_response_body(&request, &ctx, &conf) == 500);
        CHECK(ctx.intervention_triggered && ctx.phase4_processed);
        CHECK(process_calls == 1 && pcre_enter == pcre_leave);
    } else if (strcmp(argv[1], "main-eos") == 0 || strcmp(argv[1], "subrequest-eos") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; buffer.last_in_chain = 1;
        chain.next = NULL;
        if (strcmp(argv[1], "subrequest-eos") == 0) request.main = &main_request;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(appended_bytes == 10U && process_calls == (request.main != &request));
        chain.buf = &final; final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && appended_bytes == 10U);
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && forward_calls == 3);
    } else if (strcmp(argv[1], "chain-restored") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(chain.next == &tail && tail.next == NULL);
        CHECK(forward_calls == 1 && forwarded_links == 2 && process_calls == 1);
        CHECK(appended_bytes == 10U && buffer.pos == payload);
    } else if (strcmp(argv[1], "forward-again") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; final.last_buf = 1;
        forward_result = NGX_AGAIN;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_AGAIN);
        CHECK(chain.next == &tail && forwarded_links == 2 && process_calls == 1);
        CHECK(buffer.pos == payload && appended_bytes == 10U);
        forward_result = NGX_OK;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(forwarded_links == 4 && appended_bytes == 10U && process_calls == 1);
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_OK);
        CHECK(process_calls == 1 && chain.next == &tail);
    } else if (strcmp(argv[1], "terminal-trailing") == 0) {
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10; buffer.last_buf = 1;
        final.memory = 1; final.pos = payload + 10; final.last = payload + 20;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(process_calls == 1 && appended_bytes == 10U);
        CHECK(chain.next == &tail && forwarded_links == 2);
    } else if (strcmp(argv[1], "replaced-body") == 0) {
        ctx.response_replaced = 1;
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + 10;
        final.last_buf = 1; verify_writer = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(buffer.pos == buffer.last && buffer.in_file);
        CHECK(buffer.file_last == buffer.file_pos);
        CHECK(append_calls == 0 && process_calls == 0 && forwarded_links == 1);
        CHECK(forwarded_controls == 1 && forwarded_eos == 1 && writer_rejected_zero == 0);
        CHECK(ctx.replacement_body_terminal_sent && chain.next == &tail);
    } else if (strcmp(argv[1], "replaced-data-only") == 0) {
        ctx.response_replaced = 1; verify_writer = 1; chain.next = NULL;
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + 10;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(buffer.pos == buffer.last && buffer.file_pos == buffer.file_last);
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_OK);
        CHECK(forward_calls == 0 && control_link_calls == 0 && writer_rejected_zero == 0);
        CHECK(append_calls == 0 && process_calls == 0 && !ctx.replacement_body_terminal_sent);
    } else if (strcmp(argv[1], "replaced-buffered-drain") == 0) {
        ctx.response_replaced = 1; verify_writer = 1; chain.next = NULL;
        request.buffered = 1; forward_result = NGX_AGAIN;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_AGAIN);
        CHECK(forward_calls == 1 && forwarded_links == 0 && writer_rejected_zero == 0);
        request.buffered = 0; connection.buffered = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_AGAIN);
        CHECK(forward_calls == 2 && forwarded_links == 0);
        connection.buffered = 0;
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_OK);
        CHECK(forward_calls == 2 && control_link_calls == 0);
    } else if (strcmp(argv[1], "replaced-terminal-again") == 0) {
        ctx.response_replaced = 1; verify_writer = 1; chain.next = NULL;
        buffer.memory = 1; buffer.pos = payload; buffer.last = payload + 10;
        buffer.last_buf = 1; request.buffered = 1; forward_result = NGX_AGAIN;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_AGAIN);
        CHECK(ctx.replacement_body_terminal_sent && forwarded_eos == 1);
        CHECK(control_link_calls == 1 && forwarded_controls == 1 && writer_rejected_zero == 0);
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_AGAIN);
        CHECK(forward_calls == 2 && forwarded_eos == 1 && forwarded_links == 1);
        request.buffered = 0;
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_OK);
        CHECK(forward_calls == 2 && control_link_calls == 1 && chain.next == NULL);
    } else if (strcmp(argv[1], "replaced-subrequest-eos") == 0) {
        ctx.response_replaced = 1; verify_writer = 1; request.main = &main_request;
        chain.next = NULL; buffer.last_in_chain = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(forwarded_controls == 1 && forwarded_eos == 1 && writer_rejected_zero == 0);
        CHECK(ctx.replacement_body_terminal_sent && control_buffers[0].sync);
        CHECK(!control_buffers[0].last_buf && control_buffers[0].last_in_chain);
    } else if (strcmp(argv[1], "replaced-main-chain-marker") == 0) {
        ctx.response_replaced = 1; verify_writer = 1; chain.next = NULL;
        buffer.last_in_chain = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(!ctx.replacement_body_terminal_sent && forwarded_eos == 0);
        CHECK(control_buffers[0].sync && control_buffers[0].last_in_chain);
        final.last_buf = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &tail) == NGX_OK);
        CHECK(ctx.replacement_body_terminal_sent && forwarded_eos == 1);
        CHECK(forwarded_controls == 2 && writer_rejected_zero == 0);
    } else if (strcmp(argv[1], "replaced-control-allocation-failure") == 0) {
        for (i = 0; i < 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx;
            ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
            ctx.response_replaced = 1; request.header_sent = 1; connection.error = 0;
            buffer.file_pos = 0; buffer.last_buf = 1; chain.next = NULL;
            fail_control_link = i == 0; fail_control_buffer = i != 0;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
            CHECK(ctx.phase4_failed && connection.error && forward_calls == 0);
            CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_ERROR);
        }
    } else if (strcmp(argv[1], "counter-saturation-stream") == 0) {
        chain.next = NULL; request.header_sent = 1;
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx;
            ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf; conf.phase4_mode = (unsigned)i;
            ctx.response_body_bytes_seen = SIZE_MAX - 1U;
            ctx.response_body_bytes_inspected = SIZE_MAX - 1U;
            append_calls = 0; appended_bytes = 0; process_calls = 0; forward_calls = 0;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
            CHECK(ctx.response_body_bytes_seen == SIZE_MAX && ctx.response_body_bytes_inspected == SIZE_MAX);
            CHECK(append_calls == 1 && appended_bytes == 10U && process_calls == 1 && forward_calls == 1);
            CHECK(!ctx.phase4_failed && !ctx.response_body_truncated && !connection.error);
        }
    } else if (strcmp(argv[1], "large-file-first-chunk") == 0) {
        if (sizeof(off_t) < 8) return 0;
        buffer.file_last = (off_t)UINT32_MAX + (off_t)sizeof(payload);
        native_result = 403; native_failed = 1; native_body_limit = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == 403);
        CHECK(read_calls == 1 && append_calls == 1 && appended_bytes == 32768U);
        CHECK(ctx.intervention_body_limit && process_calls == 0 && forward_calls == 0);
    } else if (strcmp(argv[1], "append-boundary") == 0) {
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        buffer.pos = payload; buffer.last = payload + 10; chain.next = NULL;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
        CHECK(append_collections == 1 && eos_with_append_active == 0);
        CHECK(!ctx.phase4_append_active && ctx.phase4_processed && forward_calls == 1);
    } else if (strcmp(argv[1], "empty-memory-eos") == 0) {
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        chain.next = NULL;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
            conf.phase4_mode = (unsigned)i;
            process_calls = 0; forward_calls = 0;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
            CHECK(process_calls == 1 && append_calls == 0 && forward_calls == 1);
            CHECK(ctx.phase4_processed && !ctx.phase4_failed);
            CHECK(ctx.response_body_bytes_seen == 0U && !ctx.response_body_seen);
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_OK);
            CHECK(process_calls == 1 && forward_calls == 2);
        }
    } else if (strcmp(argv[1], "memory-missing-end") == 0) {
        buffer.in_file = 0; buffer.memory = 1; buffer.pos = payload;
        request.header_sent = 1;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
        CHECK(append_calls == 0 && forward_calls == 0 && ctx.phase4_failed);
    } else if (strcmp(argv[1], "invalid-append-results") == 0) {
        const int invalid[] = {-2, -1, 2, 99};
        size_t invalid_index;
        request.header_sent = 1; chain.next = NULL;
        buffer.in_file = 0; buffer.memory = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        for (i = 0; i <= 2; ++i) {
            conf.phase4_mode = (unsigned)i;
            for (invalid_index = 0; invalid_index < sizeof(invalid) / sizeof(invalid[0]); ++invalid_index) {
                memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
                append_calls = 0; appended_bytes = 0; connection.error = 0;
                append_result = invalid[invalid_index];
                CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
                CHECK(append_calls == 1 && process_calls == 0 && forward_calls == 0);
                CHECK(ctx.phase4_failed && connection.error);
            }
        }
    } else if (strcmp(argv[1], "failure-reentry") == 0) {
        request.header_sent = 1; chain.next = NULL;
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
            conf.phase4_mode = (unsigned)i;
            process_calls = 0; append_calls = 0; appended_bytes = 0;
            engine_result = 0; connection.error = 0;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
            CHECK(ctx.phase4_failed && connection.error);
            engine_result = 1;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
            CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_ERROR);
            CHECK(process_calls == 1 && append_calls == 1 && forward_calls == 0);
        }
    } else if (strcmp(argv[1], "strict-reentry") == 0 ||
               strcmp(argv[1], "sink-failure-reentry") == 0) {
        request.header_sent = 1; chain.next = NULL;
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        native_result = -1; native_late = 1; ctx.last_intervention_status = 403;
        native_only_after_eos = 1;
        if (strcmp(argv[1], "strict-reentry") == 0) conf.phase4_mode = 2;
        else log_result = NGX_ERROR;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) ==
            (conf.phase4_mode == 2 ? NGX_ERROR : NGX_OK));
        CHECK(ctx.phase4_failed == (conf.phase4_mode == 2));
        CHECK(connection.error == (conf.phase4_mode == 2) && event_calls == 1);
        native_result = 0; log_result = NGX_OK;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) ==
            (conf.phase4_mode == 2 ? NGX_ERROR : NGX_OK));
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) ==
            (conf.phase4_mode == 2 ? NGX_ERROR : NGX_OK));
        CHECK(append_calls == 1 && process_calls == 1);
        CHECK(forward_calls == (conf.phase4_mode == 2 ? 0 : 3));
        CHECK(event_calls == 1);
    } else if (strcmp(argv[1], "core-error-once") == 0) {
        buffer.in_file = 0; buffer.memory = 1; buffer.last_buf = 1;
        buffer.pos = payload; buffer.last = payload + 10;
        chain.next = NULL; final.last_buf = 1;
        engine_result = 0; emulate_core_response = 1; core_response = &tail;
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == 500);
        CHECK(finalize_calls == 1 && core_response_result == NGX_OK);
        CHECK(process_calls == 1 && append_calls == 1 && forward_calls == 1);
        CHECK(ctx.phase4_failed && !ctx.phase4_error_emitting);
        CHECK(ngx_http_modsecurity_body_filter(&request, NULL) == NGX_ERROR);
        CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
        CHECK(finalize_calls == 1 && forward_calls == 1);
    } else if (strcmp(argv[1], "file-chunk-rejection") == 0) {
        request.header_sent = 1;
        native_result = 403; native_failed = 1; native_body_limit = 1;
        for (i = 0; i <= 2; ++i) {
            memset(&ctx, 0, sizeof(ctx)); ctx.r = &request; ctx.modsec_transaction = &ctx; ctx.lifetime.pool = &pool; ctx.lifetime.conf = &conf;
            conf.phase4_mode = (unsigned)i;
            read_calls = 0; append_calls = 0; appended_bytes = 0;
            CHECK(ngx_http_modsecurity_body_filter(&request, &chain) == NGX_ERROR);
            CHECK(ctx.phase4_failed && ctx.intervention_body_limit);
            CHECK(read_calls == 1 && append_calls == 1 && appended_bytes == 32768U);
            CHECK(process_calls == 0 && forward_calls == 0 && event_calls == 0);
        }
    } else if (strcmp(argv[1], "late-safe") == 0 || strcmp(argv[1], "late-strict") == 0 || strcmp(argv[1], "late-off") == 0) {
        request.header_sent = 1; native_result = -1; native_late = 1;
        ctx.last_intervention_status = 403;
        if (strcmp(argv[1], "late-off") == 0) conf.phase4_mode = 0;
        if (strcmp(argv[1], "late-strict") == 0) conf.phase4_mode = 2;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) ==
            (conf.phase4_mode == 1 ? NGX_OK : NGX_ERROR));
        CHECK(event_calls == (conf.phase4_mode != 0));
        CHECK(ctx.intervention_triggered == (conf.phase4_mode != 1));
        if (conf.phase4_mode == 1) CHECK(strcmp(last_action, "log_only") == 0);
        if (conf.phase4_mode == 2) {
            CHECK(strcmp(last_action, "connection_abort") == 0);
            CHECK(ctx.phase4_strict_abort && connection.error);
        }
    } else if (strcmp(argv[1], "native-failure-safe") == 0) {
        request.header_sent = 1; native_result = 500; native_failed = 1;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == NGX_ERROR);
        CHECK(connection.error && ctx.intervention_triggered && event_calls == 0);
    } else if (strcmp(argv[1], "native-failure-uncommitted") == 0) {
        native_result = 500; native_failed = 1;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == 500);
        CHECK(ctx.intervention_triggered && event_calls == 0);
    } else if (strcmp(argv[1], "uncommitted-deny") == 0) {
        const ngx_int_t statuses[] = {403, 302};
        for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
            ctx.phase4_headers_checked = 0; ctx.intervention_triggered = 0;
            event_calls = 0; native_result = statuses[i];
            ctx.last_intervention_status = statuses[i];
            CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == statuses[i]);
            CHECK(ctx.intervention_triggered && event_calls == 1);
            CHECK(strcmp(last_action, "deny_status") == 0);
            CHECK(strcmp(last_reason, "response_not_committed") == 0);
        }
    } else if (strcmp(argv[1], "log-failure-safe") == 0) {
        request.header_sent = 1; native_result = -1; native_late = 1; log_result = NGX_ERROR;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == NGX_OK);
        CHECK(!ctx.intervention_triggered && !ctx.phase4_failed && !connection.error);
        CHECK(event_calls == 1 && diagnostic_calls == 1);
    } else if (strcmp(argv[1], "log-failure-strict") == 0) {
        conf.phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_STRICT;
        request.header_sent = 1; native_result = -1; native_late = 1; log_result = NGX_ERROR;
        CHECK(ngx_http_modsecurity_process_response_intervention(&request, &ctx, &conf) == NGX_ERROR);
        CHECK(ctx.phase4_failed && ctx.phase4_strict_abort && connection.error && event_calls == 1);
    } else {
        return 2;
    }
    return 0;
}
"""


def unit_program(body: str, module: str) -> str:
    functions = (
        "response_body_failure", "plan_limited_response_body",
        "append_response_body_chunk", "append_limited_response_body",
        "append_file_response_body", "append_response_body_buffer",
        "phase4_handle_intervention", "process_response_intervention",
        "process_final_response_body",
    )
    definitions = [
        "\nstatic ngx_int_t\n" + function_definition(body, "ngx_http_modsecurity_" + name)
        + "\n" for name in functions
    ]
    gate = "ngx_http_modsecurity_phase4_error_gate"
    if re.search(rf"\b{gate}\s*\(", body):
        definitions.insert(0, "\nstatic ngx_int_t\n" + function_definition(body, gate) + "\n")
    discard_type = "void" if re.search(
        r"static\s+void\s+ngx_http_modsecurity_discard_replaced_response_body\s*\(", body
    ) else "ngx_int_t"
    definitions.append("\nstatic " + discard_type + "\n" + function_definition(
        body, "ngx_http_modsecurity_discard_replaced_response_body"
    ))
    definitions.append("\nngx_int_t\n" + function_definition(
        body, "ngx_http_modsecurity_body_filter"
    ))
    declarations = "\n".join(definition[:definition.index("{")] + ";" for definition in definitions)
    context_lookup = "".join(
        "\nstatic ngx_int_t\n" + function_definition(module, name) + "\n"
        for name in ("ngx_http_modsecurity_same_policy", "ngx_http_modsecurity_is_block_error_page")
    )
    context_lookup += "\nstatic ngx_http_modsecurity_ctx_t *\n" + function_definition(
        module, "ngx_http_modsecurity_get_module_ctx"
    ) + "\n"
    return PREAMBLE + declarations + context_lookup + "".join(definitions) + CASES


class Phase4RuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        directory = tempfile.TemporaryDirectory(prefix="nginx-phase4-")
        cls.addClassCleanup(directory.cleanup)
        source = Path(directory.name) / "phase4.c"
        cls.binary = Path(directory.name) / ("phase4.exe" if os.name == "nt" else "phase4")
        source.write_text(unit_program(BODY.read_text(encoding="utf-8"), MODULE.read_text(encoding="utf-8")), encoding="utf-8")
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, timeout=60, check=False,
        )
        if build.returncode:
            raise AssertionError("Phase4 helper compilation failed:\n" + build.stderr)

    def run_case(self, name: str) -> None:
        result = subprocess.run(
            [str(self.binary), name], capture_output=True, text=True,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


def case_test(name: str):
    def test(self: Phase4RuntimeTests) -> None:
        self.run_case(name)
    return test


for case in (
    "request-ownership", "all-modes-large", "all-modes-multiple", "legacy-boundary", "memory-over-legacy-limit",
    "overflow", "invalid-accounting", "null-empty-mode", "file-chunks",
    "mixed-over-legacy-limit", "file-over-legacy-limit", "file-invalid", "allocation-failure",
    "short-read", "read-error", "append-error", "append-zero", "final-once",
    "engine-error", "process-zero",
    "main-eos", "subrequest-eos", "chain-restored", "forward-again",
    "terminal-trailing", "replaced-body",
    "replaced-data-only", "replaced-buffered-drain", "replaced-terminal-again",
    "replaced-subrequest-eos", "replaced-main-chain-marker", "replaced-control-allocation-failure",
    "counter-saturation-stream", "large-file-first-chunk", "append-boundary",
    "empty-memory-eos", "memory-missing-end", "invalid-append-results",
    "failure-reentry", "strict-reentry", "sink-failure-reentry",
    "core-error-once", "file-chunk-rejection",
    "late-safe", "late-strict", "late-off", "native-failure-safe",
    "native-failure-uncommitted", "uncommitted-deny", "log-failure-safe", "log-failure-strict",
):
    setattr(Phase4RuntimeTests, "test_" + case.replace("-", "_"), case_test(case))


if __name__ == "__main__":
    unittest.main()
