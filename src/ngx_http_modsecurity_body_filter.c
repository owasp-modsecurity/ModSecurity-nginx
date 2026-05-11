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
#include <ctype.h>

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
static ngx_int_t ngx_http_modsecurity_phase4_in_scope(ngx_http_request_t *r);
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

ngx_int_t
ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t *chain = in;
    ngx_http_modsecurity_ctx_t *ctx = NULL;
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_conf_t *mcf;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
#endif

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_modsecurity_get_module_ctx(r);

    dd("body filter, recovering ctx: %p", ctx);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->intervention_triggered) {
        return ngx_http_next_body_filter(r, in);
    }

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf != NULL && mcf->sanity_checks_enabled != NGX_CONF_UNSET)
    {
#if 0
        dd("dumping stored ctx headers");
        for (i = 0; i < ctx->sanity_headers_out->nelts; i++)
        {
            ngx_http_modsecurity_header_t *vals = ctx->sanity_headers_out->elts;
            ngx_str_t *s2 = &vals[i].name, *s3 = &vals[i].value;
            dd(" dump[%d]: name = '%.*s', value = '%.*s'", (int)i,
                (int)s2->len, (char*)s2->data,
                (int)s3->len, (char*)s3->data);
        }
#endif
        /*
         * Identify if there is a header that was not inspected by ModSecurity.
         */
        int worth_to_fail = 0;

        for (i = 0; ; i++)
        {
            int found = 0;
            ngx_uint_t j = 0;
            ngx_table_elt_t *s1;
            ngx_http_modsecurity_header_t *vals;

            if (i >= part->nelts)
            {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            vals = ctx->sanity_headers_out->elts;
            s1 = &data[i];

            /*
             * Headers that were inspected by ModSecurity.
             */
            while (j < ctx->sanity_headers_out->nelts)
            {
                ngx_str_t *s2 = &vals[j].name;
                ngx_str_t *s3 = &vals[j].value;

                if (s1->key.len == s2->len && ngx_strncmp(s1->key.data, s2->data, s1->key.len) == 0)
                {
                    if (s1->value.len == s3->len && ngx_strncmp(s1->value.data, s3->data, s1->value.len) == 0)
                    {
                        found = 1;
                        break;
                    }
                }
                j++;
            }
            if (!found) {
                dd("header: `%.*s' with value: `%.*s' was not inspected by ModSecurity",
                    (int) s1->key.len,
                    (const char *) s1->key.data,
                    (int) s1->value.len,
                    (const char *) s1->value.data);
                worth_to_fail++;
            }
        }

        if (worth_to_fail)
        {
            dd("%d header(s) were not inspected by ModSecurity, so exiting", worth_to_fail);
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }
#endif

    int is_request_processed = 0;
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    for (; chain != NULL; chain = chain->next)
    {
        u_char *data = chain->buf->pos;
        int ret;

        msc_append_response_body(ctx->modsec_transaction, data, chain->buf->last - data);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (ret > 0) {
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, ret);
        } else if (ret < 0) {
            ret = ngx_http_modsecurity_phase4_handle_intervention(r, mcf);
            if (ret == NGX_ERROR) return NGX_ERROR;
        }

/* XXX: chain->buf->last_buf || chain->buf->last_in_chain */
        is_request_processed = chain->buf->last_buf;

        if (is_request_processed) {
            ngx_pool_t *old_pool;

            old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
            msc_process_response_body(ctx->modsec_transaction);
            ngx_http_modsecurity_pcre_malloc_done(old_pool);

/* XXX: I don't get how body from modsec being transferred to nginx's buffer.  If so - after adjusting of nginx's
   XXX: body we can proceed to adjust body size (content-length).  see xslt_body_filter() for example */
            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
            if (ret > 0) {
                if (!ctx->phase4_headers_checked) {
                    ngx_http_modsecurity_phase4_log_event(r, mcf, "deny", "deny_status", "headers_not_sent");
                    ctx->phase4_headers_checked = 1;
                }
                return ret;
            }
            else if (ret < 0) {
                ret = ngx_http_modsecurity_phase4_handle_intervention(r, mcf);
                if (ret == NGX_ERROR) return NGX_ERROR;
                return ngx_http_next_body_filter(r, in);

            }
        }
    }
    if (!is_request_processed)
    {
        dd("buffer was not fully loaded! ctx: %p", ctx);
    }

/* XXX: xflt_filter() -- return NGX_OK here */
    return ngx_http_next_body_filter(r, in);
}

static ngx_int_t
ngx_http_modsecurity_phase4_handle_intervention(ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf)
{
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    ngx_int_t in_scope = ngx_http_modsecurity_phase4_in_scope(r);
    if (ctx && ctx->phase4_headers_checked) return NGX_OK;
    if (ctx) ctx->phase4_headers_checked = 1;

    if (in_scope == 0) {
        ngx_http_modsecurity_phase4_log_event(r, mcf, "deny", "log_only", r->headers_out.content_type.len ? "content_type_not_in_scope" : "content_type_missing");
        return NGX_OK;
    }
    if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_STRICT) {
        ngx_http_modsecurity_phase4_log_event(r, mcf, "deny", "connection_abort", "headers_already_sent");
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "modsecurity phase4 intervention after headers sent, action=connection_abort, uri=\"%V\"", &r->uri);
        r->connection->error = 1;
        return NGX_ERROR;
    }
    ngx_http_modsecurity_phase4_log_event(r, mcf, "deny", "log_only",
        mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_MINIMAL ? "mode_minimal" : "mode_safe");
    return NGX_OK;
}

static ngx_int_t
ngx_http_modsecurity_phase4_in_scope(ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    ngx_uint_t i;
    ngx_str_t ct;
    u_char *semi;
    if (r->headers_out.content_type.len == 0 || mcf->phase4_content_types == NULL) return 0;
    ct = r->headers_out.content_type;
    semi = (u_char *)ngx_strlchr(ct.data, ct.data + ct.len, ';');
    if (semi != NULL) ct.len = semi - ct.data;
    while (ct.len > 0 && isspace((unsigned char)ct.data[ct.len - 1])) ct.len--;
    for (i = 0; i < mcf->phase4_content_types->nelts; i++) {
        ngx_str_t *arr = mcf->phase4_content_types->elts;
        if (arr[i].len == ct.len && ngx_strncasecmp(arr[i].data, ct.data, ct.len) == 0) return 1;
    }
    return 0;
}

static ngx_int_t
ngx_http_modsecurity_phase4_log_event(ngx_http_request_t *r, ngx_http_modsecurity_conf_t *mcf, const char *wanted, const char *actual, const char *reason)
{
    u_char *p;
    ngx_str_t euri, emethod, ect, elog, erule, raw_log, slog;
    const char *mode = "safe";
    const char *header_sent = r->header_sent ? "true" : "false";
    ngx_http_modsecurity_ctx_t *ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (mcf->phase4_log_file == NULL || mcf->phase4_log_file->fd == NGX_INVALID_FILE) return NGX_OK;
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
    if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_MINIMAL) mode = "minimal";
    else if (mcf->phase4_mode == NGX_HTTP_MODSEC_PHASE4_MODE_STRICT) mode = "strict";
    size_t need = 256 + euri.len + emethod.len + ect.len + elog.len + erule.len + ngx_strlen(mode) + ngx_strlen(wanted) + ngx_strlen(actual) + ngx_strlen(reason);
    u_char *dbuf = ngx_pnalloc(r->pool, need);
    if (dbuf == NULL) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "modsecurity phase4 log allocation failed");
        return NGX_ERROR;
    }
    p = ngx_snprintf(dbuf, need,
        "{\"event\":\"phase4_intervention\",\"uri\":\"%V\",\"method\":\"%V\",\"response_status\":%ui,\"waf_status\":%i,\"content_type\":\"%V\",\"header_sent\":%s,\"mode\":\"%s\",\"wanted_action\":\"%s\",\"actual_action\":\"%s\",\"reason\":\"%s\",\"intervention\":\"%V\",\"rule_id\":\"%V\"}\n",
        &euri,&emethod,(ngx_uint_t)r->headers_out.status,ctx ? (int) ctx->last_intervention_status : 0,&ect,header_sent,mode,wanted,actual,reason,&elog,&erule);
    ngx_write_fd(mcf->phase4_log_file->fd, dbuf, p - dbuf);
    return NGX_OK;
}

static ngx_str_t
ngx_http_modsecurity_normalize_content_type(ngx_pool_t *pool, ngx_str_t in)
{
    ngx_str_t out; size_t i;
    u_char *semi;
    out = in;
    if (out.data == NULL || out.len == 0) return out;
    semi = (u_char *)ngx_strlchr(out.data, out.data + out.len, ';');
    if (semi) out.len = semi - out.data;
    while (out.len > 0 && isspace((unsigned char) out.data[out.len - 1])) out.len--;
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
    size_t i, extra = 0; u_char *d;
    if (src == NULL || src->data == NULL) { dst->len=0; dst->data=(u_char*)""; return; }
    for (i = 0; i < src->len; i++) if (src->data[i] < 0x20 || src->data[i] == '"' || src->data[i] == '\\') extra++;
    dst->data = ngx_pnalloc(pool, src->len + extra + 1); if (dst->data == NULL) { dst->len=0; dst->data=(u_char*)""; return; }
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
        if (ngx_strncasecmp(intervention->data + i, (u_char *)"id \"", 4) == 0) {
            size_t j = i + 4;
            while (j < intervention->len && intervention->data[j] >= '0' && intervention->data[j] <= '9') j++;
            if (j > i + 4 && j < intervention->len && intervention->data[j] == '"') {
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
    }
}
