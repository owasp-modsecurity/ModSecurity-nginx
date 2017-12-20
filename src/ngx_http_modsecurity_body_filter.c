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

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"

static ngx_http_output_body_filter_pt ngx_http_next_body_filter;

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

    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_chain_t *chain = in;
    ngx_int_t ret;
    ngx_pool_t *old_pool;
    ngx_int_t is_request_processed = 0;
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_http_modsecurity_conf_t *loc_cf = NULL;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
#endif

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    /* get context for request */
    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    dd("body filter, recovering ctx: %p", ctx);
										   
    if (ctx == NULL || r->filter_finalize) {
        return ngx_http_next_body_filter(r, in);
    }


#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (loc_cf != NULL && loc_cf->sanity_checks_enabled != NGX_CONF_UNSET)
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

    for (chain = in; chain != NULL; chain = chain->next) {

        ngx_buf_t *copy_buf;
        ngx_chain_t* copy_chain;
        is_request_processed = chain->buf->last_buf;
        ngx_int_t data_size = chain->buf->end - chain->buf->start;
        ngx_int_t data_offset = chain->buf->pos - chain->buf->start;
        u_char *data = chain->buf->start;
        msc_append_response_body(ctx->modsec_transaction, data,
                chain->buf->end - data);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction,
                r);
        if (ret > 0) {
            return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, ret);
        }
        if (data_size > 0){
            copy_chain = ngx_alloc_chain_link(r->pool);
            if (copy_chain == NULL) {
                return NGX_ERROR;
            }

            copy_buf = ngx_calloc_buf(r->pool);
            if (copy_buf == NULL) {
                return NGX_ERROR;
            }
            copy_buf->start = ngx_pcalloc(r->pool, data_size);
            if (copy_buf->start == NULL) {
                return NGX_ERROR;
            }
            ngx_memcpy(copy_buf->start, chain->buf->start, data_size);
            copy_buf->pos = copy_buf->start + data_offset;
            copy_buf->end = copy_buf->start + data_size;
            copy_buf->last = copy_buf->pos + ngx_buf_size(chain->buf);
            copy_buf->temporary = (chain->buf->temporary == 1) ? 1 : 0;
            copy_buf->memory = (chain->buf->memory == 1) ? 1 : 0;
            copy_chain->buf = copy_buf;
            copy_chain->buf->last_buf = 1;
            copy_chain->next = NULL;
            chain->buf->pos = chain->buf->last;
        }
        else
            copy_chain = chain;
        if (ctx->temp_chain == NULL) {
            ctx->temp_chain = copy_chain;
        } else {
            if (ctx->current_chain == NULL) {
                ctx->temp_chain->next = copy_chain;
                ctx->temp_chain->buf->last_buf = 0;
            } else {
                ctx->current_chain->next = copy_chain;
                ctx->current_chain->buf->last_buf = 0;
            }
            ctx->current_chain = copy_chain;
        }
    }

    if (is_request_processed) {
        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_response_body(ctx->modsec_transaction);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r);
        if (ret > 0) {
            if (ret < NGX_HTTP_BAD_REQUEST && ctx->header_pt != NULL)
                ctx->header_pt(r);
            return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, ret);
        } else if (ret < 0) {
            return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        ctx->response_body_filtered = 1;
        if (ctx->header_pt != NULL)
            ctx->header_pt(r);
        return ngx_http_next_body_filter(r, ctx->temp_chain);
    } else {
        return NGX_AGAIN;
    }
}
