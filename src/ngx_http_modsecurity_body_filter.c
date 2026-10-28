/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 *
 * You may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * If any of the files related to licensing are missing or if you have any
 * other questions related to licensing please contact Trustwave Holdings, Inc.
 * directly using the email address security@modsecurity.org.
 *
 */

#include <ngx_config.h>
#include <stdint.h>

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"

/* Bounded, reusable materialization for file-only response buffers. */
#define NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK 32768U

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_int_t ngx_http_modsecurity_process_response_intervention(ngx_http_request_t *r, ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf);
static ngx_int_t ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf, const char *wanted, const char *actual, const char *reason);
static ngx_int_t ngx_http_modsecurity_phase4_handle_intervention(ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf);
static void ngx_http_modsecurity_json_escape(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst);
static void ngx_http_modsecurity_extract_rule_id(ngx_pool_t *pool, ngx_str_t *intervention, ngx_str_t *rule_id);
static ngx_str_t ngx_http_modsecurity_normalize_content_type(ngx_pool_t *pool, ngx_str_t in);
static ngx_str_t ngx_http_modsecurity_sanitize_intervention(ngx_pool_t *pool, ngx_str_t in);

/* XXX: check behaviour on few body filters installed */
ngx_int_t
ngx_http_modsecurity_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;

    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_phase4_error_gate(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    if (!ctx->phase4_failed) {
        return NGX_OK;
    }
    /* Only the synchronous core-generated error body may pass the gate.
     * A subsequent flush or data callback cannot resume the failed chain. */
    if (ctx->phase4_error_emitting && r->filter_finalize) {
        return NGX_DECLINED;
    }
    r->connection->error = 1;
    return NGX_ERROR;
}

static ngx_int_t
ngx_http_modsecurity_response_body_failure(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_int_t ret;

    if (ctx->phase4_failed) {
        r->connection->error = 1;
        return NGX_ERROR;
    }
    ctx->phase4_failed = 1;
    ctx->intervention_triggered = 1;
    if (r->header_sent) {
        r->connection->error = 1;
        return NGX_ERROR;
    }
    ctx->phase4_error_emitting = 1;
    ret = ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,
        ctx->intervention_body_limit ? NGX_HTTP_FORBIDDEN :
            NGX_HTTP_INTERNAL_SERVER_ERROR);
    ctx->phase4_error_emitting = 0;
    return ret;
}

/* libModSecurity owns response inspection limits in every Phase-4 mode.
 * Keep checked accounting without imposing the legacy connector budget;
 * independent host, file-buffer and allocation limits remain active. */
static ngx_int_t
ngx_http_modsecurity_plan_limited_response_body(
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf,
    size_t len, size_t *allowed)
{
    if (allowed == NULL) {
        return NGX_ERROR;
    }
    *allowed = 0U;
    if (ctx == NULL || mcf == NULL) {
        return NGX_ERROR;
    }
    if (len == 0U) {
        return NGX_OK;
    }
    ctx->response_body_seen = 1;
    if (mcf->phase4_mode != NGX_HTTP_MODSEC_PHASE4_MODE_OFF &&
        mcf->phase4_mode != NGX_HTTP_MODSEC_PHASE4_MODE_SAFE &&
        mcf->phase4_mode != NGX_HTTP_MODSEC_PHASE4_MODE_STRICT) {
        return NGX_ERROR;
    }
    if (ctx->response_body_bytes_inspected > ctx->response_body_bytes_seen) {
        ctx->response_body_truncated = 1;
        return NGX_ERROR;
    }
    if (len > SIZE_MAX - ctx->response_body_bytes_seen) {
        ctx->response_body_bytes_seen = SIZE_MAX;
        ctx->response_body_truncated = 1;
        return NGX_ERROR;
    }
    ctx->response_body_bytes_seen += len;
    *allowed = len;
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_append_response_body_chunk(
    ngx_http_modsecurity_ctx_t *ctx, u_char *data, size_t bytes)
{
    int ret;

    if (bytes == 0U) {
        return NGX_OK;
    }
    if (data == NULL || ctx->response_body_bytes_inspected > SIZE_MAX - bytes) {
        return NGX_ERROR;
    }
    ret = msc_append_response_body(ctx->modsec_transaction, data, bytes);
    if (ret != 0 && ret != 1) {
        return NGX_ERROR;
    }
    ctx->response_body_bytes_inspected += bytes;
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_append_limited_response_body(
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf,
    u_char *data, size_t len)
{
    size_t allowed;

    if (ngx_http_modsecurity_plan_limited_response_body(ctx, mcf, len,
            &allowed) != NGX_OK) {
        return NGX_ERROR;
    }
    return ngx_http_modsecurity_append_response_body_chunk(ctx, data, allowed);
}

static ngx_int_t
ngx_http_modsecurity_append_file_response_body(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf,
    ngx_buf_t *buffer)
{
    uintmax_t file_length;
    size_t allowed;
    size_t remaining;
    size_t chunk;
    off_t file_offset;
    ssize_t read_count;
    ngx_int_t ret;

    if (buffer == NULL || buffer->file_pos < 0 ||
        buffer->file_last < buffer->file_pos) {
        return NGX_ERROR;
    }
    file_length = (uintmax_t)buffer->file_last - (uintmax_t)buffer->file_pos;
    if (file_length > (uintmax_t)SIZE_MAX ||
        ngx_http_modsecurity_plan_limited_response_body(ctx, mcf,
            (size_t)file_length, &allowed) != NGX_OK) {
        return NGX_ERROR;
    }
    if (allowed == 0U) {
        return NGX_OK;
    }
    if (buffer->file == NULL) {
        return NGX_ERROR;
    }
    if (ctx->phase4_file_scratch == NULL) {
        ctx->phase4_file_scratch = ngx_pnalloc(r->pool,
            NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK);
        if (ctx->phase4_file_scratch == NULL) {
            return NGX_ERROR;
        }
    }
    file_offset = buffer->file_pos;
    remaining = allowed;
    while (remaining > 0U) {
        chunk = remaining > NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK
            ? NGX_HTTP_MODSECURITY_PHASE4_FILE_READ_CHUNK : remaining;
        read_count = ngx_read_file(buffer->file, ctx->phase4_file_scratch,
            chunk, file_offset);
        if (read_count < 0 || (size_t)read_count != chunk) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log,
                read_count < 0 ? ngx_errno : 0,
                "ModSecurity: file-backed response body read is short or failed");
            return NGX_ERROR;
        }
        if (ngx_http_modsecurity_append_response_body_chunk(ctx,
                ctx->phase4_file_scratch, chunk) != NGX_OK) {
            return NGX_ERROR;
        }
        /* Native Reject may return a successful append with a pending
         * intervention. Collect it before reading the next file chunk. */
        ret = ngx_http_modsecurity_process_response_intervention(r, ctx, mcf);
        if (ret != NGX_OK || ctx->intervention_triggered) {
            return ret;
        }
        file_offset += (off_t)chunk;
        remaining -= chunk;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_append_response_body_buffer(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf,
    ngx_buf_t *buffer)
{
    if (buffer == NULL) {
        return NGX_ERROR;
    }
    /* Buffers backed by both memory and a file describe the same bytes. */
    if (ngx_buf_in_memory(buffer)) {
        if (buffer->pos == NULL && buffer->last == NULL) {
            return NGX_OK;
        }
        if (buffer->pos == NULL || buffer->last == NULL ||
            buffer->last < buffer->pos) {
            return NGX_ERROR;
        }
        return ngx_http_modsecurity_append_limited_response_body(ctx, mcf,
            buffer->pos, (size_t)(buffer->last - buffer->pos));
    }
    if (buffer->in_file) {
        return ngx_http_modsecurity_append_file_response_body(r, ctx, mcf,
            buffer);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_process_response_intervention(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    int ret;

    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r,
        0);
    if (ret == 0) {
        return NGX_OK;
    }
    if (ctx->intervention_failed || (ret < 0 && !ctx->intervention_late)) {
        return ngx_http_modsecurity_response_body_failure(r, ctx);
    }
    if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_OFF) {
        if (r->header_sent) {
            return ngx_http_modsecurity_response_body_failure(r, ctx);
        }
        ctx->intervention_triggered = 1;
        /* Retain the native intervention failure path in off. */
        return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,
            ret < 0 ? NGX_HTTP_INTERNAL_SERVER_ERROR : ret);
    }
    ret = ngx_http_modsecurity_phase4_handle_intervention(r, mcf);
    if (ctx->intervention_triggered || ret != NGX_OK) {
        return ret;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_process_final_response_body(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    ngx_pool_t *old_pool;
    int ret;

    if (ctx->phase4_processed) {
        return NGX_OK;
    }
    ctx->phase4_processed = 1;
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    ret = msc_process_response_body(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    if (ret != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ModSecurity: response body phase processing failed");
        return ngx_http_modsecurity_response_body_failure(r, ctx);
    }
    return ngx_http_modsecurity_process_response_intervention(r, ctx, mcf);
}

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
static ngx_int_t
ngx_http_modsecurity_response_header_sanity(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_http_modsecurity_header_t *headers;
    ngx_uint_t i = 0;
    ngx_uint_t j;

    if (mcf->sanity_checks_enabled == NGX_CONF_UNSET) {
        return NGX_OK;
    }
    if (ctx->sanity_headers_out == NULL) {
        return ngx_http_modsecurity_response_body_failure(r, ctx);
    }
    headers = ctx->sanity_headers_out->elts;
    for (;;) {
        while (i >= part->nelts) {
            if (part->next == NULL) {
                return NGX_OK;
            }
            part = part->next;
            data = part->elts;
            i = 0;
        }
        for (j = 0; j < ctx->sanity_headers_out->nelts; j++) {
            if (data[i].key.len == headers[j].name.len &&
                ngx_strncmp(data[i].key.data, headers[j].name.data,
                    data[i].key.len) == 0 &&
                data[i].value.len == headers[j].value.len &&
                ngx_strncmp(data[i].value.data, headers[j].value.data,
                    data[i].value.len) == 0) {
                break;
            }
        }
        if (j == ctx->sanity_headers_out->nelts) {
            return ngx_http_modsecurity_response_body_failure(r, ctx);
        }
        i++;
    }
}
#endif

static void
ngx_http_modsecurity_discard_replaced_response_body(ngx_chain_t *in)
{
    ngx_chain_t *chain;

    for (chain = in; chain != NULL; chain = chain->next) {
        if (chain->buf == NULL) {
            continue;
        }
        chain->buf->pos = chain->buf->last;
        chain->buf->in_file = 0;
        chain->buf->file_last = chain->buf->file_pos;
    }
}

ngx_int_t
ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *chain;
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *mcf;
    ngx_int_t ret;

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    ret = ngx_http_modsecurity_phase4_error_gate(r, ctx);
    if (ret != NGX_OK) {
        return ret == NGX_DECLINED ? ngx_http_next_body_filter(r, in) : ret;
    }
    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    if (ctx->response_replaced) {
        ngx_http_modsecurity_discard_replaced_response_body(in);
        return ngx_http_next_body_filter(r, in);
    }
    if (ctx->intervention_triggered || ctx->phase4_processed) {
        return ngx_http_next_body_filter(r, in);
    }
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL) {
        return ngx_http_modsecurity_response_body_failure(r, ctx);
    }
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ret = ngx_http_modsecurity_response_header_sanity(r, ctx, mcf);
    if (ret != NGX_OK) {
        return ret;
    }
#endif
    ctx->phase4_started = 1;
    for (chain = in; chain != NULL; chain = chain->next) {
        ret = ngx_http_modsecurity_append_response_body_buffer(r, ctx, mcf,
            chain->buf);
        if (ctx->intervention_triggered) {
            return ret;
        }
        if (ret != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ModSecurity: response body inspection append failed");
            return ngx_http_modsecurity_response_body_failure(r, ctx);
        }
        ret = ngx_http_modsecurity_process_response_intervention(r, ctx, mcf);
        if (ret != NGX_OK || ctx->intervention_triggered) {
            return ret;
        }
        /* A main response may contain last_in_chain before the real EOS.
         * Subrequests finish with last_in_chain instead of last_buf. */
        if (!(chain->buf->last_buf ||
              (r != r->main && chain->buf->last_in_chain))) {
            continue;
        }
        ret = ngx_http_modsecurity_process_final_response_body(r, ctx, mcf);
        if (ret != NGX_OK || ctx->intervention_triggered) {
            return ret;
        }
        /* Subsequent flush/terminal links still belong to NGINX; never
         * append bytes after the transaction has completed. */
        break;
    }
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_modsecurity_phase4_handle_intervention(ngx_http_request_t *r,
    ngx_http_modsecurity_conf_t *mcf)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    const char *wanted = "deny";
    ngx_int_t log_result;
    ngx_int_t status;

    if (mcf == NULL || ctx == NULL) {
        return NGX_ERROR;
    }
    if (ctx->last_intervention_status >= 300 &&
        ctx->last_intervention_status < 400) {
        wanted = "redirect";
    }
    if (ctx->phase4_headers_checked) {
        return NGX_OK;
    }
    ctx->phase4_headers_checked = 1;
    if (!r->header_sent) {
        status = ctx->last_intervention_status >= 300
            ? ctx->last_intervention_status : NGX_HTTP_FORBIDDEN;
        log_result = ngx_http_modsecurity_phase4_log_event(r, mcf, wanted,
            "deny_status",
            "response_not_committed");
        ctx->intervention_triggered = 1;
        if (log_result != NGX_OK) {
            return ngx_http_modsecurity_response_body_failure(r, ctx);
        }
        return ngx_http_filter_finalize_request(r, &ngx_http_modsecurity_module,
            status);
    }
    if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_STRICT) {
        ctx->phase4_strict_abort = 1;
        ctx->phase4_failed = 1;
        ctx->intervention_triggered = 1;
        r->connection->error = 1;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "modsecurity phase4 intervention after headers sent, action=connection_abort, uri=\"%V\"", &r->uri);
        (void)ngx_http_modsecurity_phase4_log_event(r, mcf, wanted,
            "connection_abort", "response_committed_strict");
        return NGX_ERROR;
    }
    log_result = ngx_http_modsecurity_phase4_log_event(r, mcf, wanted,
        "log_only", "response_committed_safe");
    if (log_result != NGX_OK) {
        return ngx_http_modsecurity_response_body_failure(r, ctx);
    }
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf, const char *wanted, const char *actual, const char *reason)
{
    u_char *p;
    ngx_str_t euri;
    ngx_str_t emethod;
    ngx_str_t ect;
    ngx_str_t elog;
    ngx_str_t erule;
    ngx_str_t raw_log;
    ngx_str_t slog;
    const char *mode = "off";
    const char *header_sent = r->header_sent ? "true" : "false";
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (mcf == NULL || mcf->phase4_log_file == NULL || mcf->phase4_log_file->fd == NGX_INVALID_FILE) return NGX_OK;
    ngx_http_modsecurity_json_escape(r->pool, &r->uri, &euri);
    ngx_http_modsecurity_json_escape(r->pool, &r->method_name, &emethod);
    ngx_str_t nct = ngx_http_modsecurity_normalize_content_type(r->pool, r->headers_out.content_type);
    ngx_http_modsecurity_json_escape(r->pool, &nct, &ect);
    if (ctx) {
        raw_log = ctx->last_intervention_log;
        ngx_http_modsecurity_extract_rule_id(r->pool, &raw_log, &erule);
        slog = ngx_http_modsecurity_sanitize_intervention(r->pool, raw_log);
        ngx_http_modsecurity_json_escape(r->pool, &slog, &elog);
    } else {
        raw_log.len = 0; raw_log.data = (u_char *)"";
        elog.len = 0; elog.data=(u_char*)"";
        erule.len = 0; erule.data=(u_char*)"";
    }
    if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_SAFE) mode = "safe";
    else if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_STRICT) mode = "strict";
    size_t need = 256 + euri.len + emethod.len + ect.len + elog.len + erule.len + ngx_strlen(mode) + ngx_strlen(wanted) + ngx_strlen(actual) + ngx_strlen(reason);
    u_char *dbuf = ngx_pnalloc(r->pool, need);
    if (dbuf == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "modsecurity phase4 log allocation failed");
        return NGX_ERROR;
    }
    p = ngx_snprintf(dbuf, need,
        "{\"event\":\"phase4_intervention\",\"uri\":\"%V\",\"method\":\"%V\",\"response_status\":%ui,\"waf_status\":%i,\"content_type\":\"%V\",\"header_sent\":%s,\"mode\":\"%s\",\"wanted_action\":\"%s\",\"actual_action\":\"%s\",\"reason\":\"%s\",\"intervention\":\"%V\",\"rule_id\":\"%V\"}\n",
        &euri, &emethod, (ngx_uint_t) r->headers_out.status,
        ctx ? ctx->last_intervention_status : (ngx_int_t) 0,
        &ect, header_sent, mode, wanted, actual, reason, &elog, &erule);
    ssize_t n = ngx_write_fd(mcf->phase4_log_file->fd, dbuf, p - dbuf);
    if (n < 0 || (size_t) n != (size_t) (p - dbuf)) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, ngx_errno,
            "modsecurity phase4 log write failed");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_str_t
ngx_http_modsecurity_normalize_content_type(ngx_pool_t *pool, ngx_str_t in)
{
    ngx_str_t out;
    size_t i;
    u_char *semi;
    out = in;
    if (out.data == NULL || out.len == 0) return out;
    semi = (u_char *)ngx_strlchr(out.data, out.data + out.len, ';');
    if (semi) out.len = semi - out.data;
    while (out.len > 0) {
        u_char c = out.data[out.len - 1];
        if (c != ' ' && c != '\t' && c != '\n' &&
            c != '\r' && c != '\f' && c != '\v') {
            break;
        }
        out.len--;
    }
    out.data = ngx_pnalloc(pool, out.len);
    if (out.data == NULL) { out.len = 0; return out; }
    for (i = 0; i < out.len; i++) out.data[i] = ngx_tolower(in.data[i]);
    return out;
}

static ngx_str_t
ngx_http_modsecurity_sanitize_intervention(ngx_pool_t *pool, ngx_str_t in)
{
    static ngx_str_t redacted = { sizeof("redacted") - 1, (u_char *) "redacted" };
    ngx_str_t out = redacted;
    u_char *id, *msg, *op;
    size_t len = 0;
    if (in.data == NULL || in.len == 0) {
        return redacted;
    }
    id = (u_char *)ngx_strstr(in.data, "id \"");
    msg = (u_char *)ngx_strstr(in.data, "msg \"");
    op = (u_char *)ngx_strstr(in.data, "Operator");
    if (id == NULL && msg == NULL && op == NULL) {
        return redacted;
    }
    len = 9 + (id ? 10 : 0) + (msg ? 12 : 0) + (op ? 10 : 0);
    out.data = ngx_pnalloc(pool, len);
    if (out.data == NULL) return redacted;
    out.len = ngx_snprintf(out.data, len, "id:%s msg:%s op:%s",
        id ? "present" : "-", msg ? "present" : "-", op ? "present" : "-") - out.data;
    return out;
}

static void
ngx_http_modsecurity_json_escape(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    size_t i;
    size_t extra = 0;
    u_char *d;
    if (src == NULL || src->data == NULL) { dst->len=0; dst->data=(u_char*)""; return; }
    for (i = 0; i < src->len; i++) {
        if (src->data[i] < 0x20 || src->data[i] == '"' || src->data[i] == '\\') {
            extra++;
        }
    }
    dst->data = ngx_pnalloc(pool, src->len + extra + 1);
    if (dst->data == NULL) {
        dst->len = 0;
        dst->data = (u_char *)"";
        return;
    }
    d = dst->data;
    for (i = 0; i < src->len; i++) {
        u_char c = src->data[i];
        if (c == '"' || c == '\\') { *d++='\\'; *d++=c; }
        else if (c < 0x20) { *d++=' '; }
        else *d++=c;
    }
    dst->len = d - dst->data;
}

static void
ngx_http_modsecurity_extract_rule_id(ngx_pool_t *pool, ngx_str_t *intervention, ngx_str_t *rule_id)
{
    size_t i;
    rule_id->data = (u_char *)"";
    rule_id->len = 0;
    if (intervention == NULL || intervention->data == NULL) return;
    for (i = 0; i + 4 < intervention->len; i++) {
        size_t j;

        if (ngx_strncasecmp(intervention->data + i, (u_char *)"id \"", 4) != 0) continue;

        j = i + 4;
        while (j < intervention->len && intervention->data[j] >= '0' && intervention->data[j] <= '9') j++;
        if (j <= i + 4 || j >= intervention->len || intervention->data[j] != '"') continue;

        rule_id->len = j - (i + 4);
        rule_id->data = ngx_pnalloc(pool, rule_id->len);
        if (rule_id->data == NULL) {
            rule_id->len = 0;
            rule_id->data = (u_char *)"";
            return;
        }
        ngx_memcpy(rule_id->data, intervention->data + i + 4, rule_id->len);
        return;
    }
}
