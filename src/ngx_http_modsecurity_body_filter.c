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
    for (; chain != NULL; chain = chain->next)
    {
        u_char *data = chain->buf->pos;
        int ret;

        if (msc_append_response_body(ctx->modsec_transaction, data,
            chain->buf->last - data) != 1)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "ModSecurity: failed to append response body chunk "
                "for inspection");
            ctx->intervention_triggered = 1;
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }

        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity_module, ret);
        }
        else if (ret < 0) {
            /*
             * process_intervention() returns -1 specifically when
             * r->header_sent is already true (it wanted to intervene but
             * can't safely rewrite headers). By the time the body filter
             * runs, header_sent is *always* true -- header_filter() already
             * ran. ngx_http_filter_finalize_request() would call
             * ngx_http_clean_header() and try to send a fresh status line
             * and headers anyway, producing nginx's own "header already
             * sent" alert and a truncated response instead of a clean
             * abort. NGX_ERROR is the correct signal here: it triggers
             * ngx_http_terminate_request(), which closes the connection
             * without attempting to resend anything.
             */
            ctx->intervention_triggered = 1;
            return NGX_ERROR;
        }

/* XXX: chain->buf->last_buf || chain->buf->last_in_chain */
        is_request_processed = chain->buf->last_buf;

        if (is_request_processed) {
            ngx_pool_t *old_pool;

            old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
            ret = msc_process_response_body(ctx->modsec_transaction);
            ngx_http_modsecurity_pcre_malloc_done(old_pool);

            if (ret != 1) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "ModSecurity: response body phase processing failed");
                ctx->intervention_triggered = 1;
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity_module, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }

/* XXX: I don't get how body from modsec being transferred to nginx's buffer.  If so - after adjusting of nginx's
   XXX: body we can proceed to adjust body size (content-length).  see xslt_body_filter() for example */
            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
            if (ret > 0) {
                ctx->intervention_triggered = 1;
                return ret;
            }
            else if (ret < 0) {
                /* See the comment on the identical check above. */
                ctx->intervention_triggered = 1;
                return NGX_ERROR;
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
