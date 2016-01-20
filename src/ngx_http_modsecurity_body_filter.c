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


#include "ddebug.h"
#ifndef DDEBUG
#define DDEBUG 0
#endif


#include <nginx.h>
#include "ngx_http_modsecurity_body_filter.h"


static ngx_http_output_body_filter_pt ngx_http_next_body_filter;


ngx_int_t ngx_http_modsecurity_body_filter_init(void)
{
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;

    return NGX_OK;
}


ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    int buffer_fully_loadead = 0;
    ngx_chain_t *chain = in;
    ngx_http_modsecurity_ctx_t *ctx = NULL;

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("body filter, recovering ctx: %p", ctx);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    for (; chain != NULL; chain = chain->next)
    {
        if (chain->buf->last_buf)
        {
            buffer_fully_loadead = 1;
        }
    }

    if (buffer_fully_loadead == 1)
    {
        int ret;

        for (chain = in; chain != NULL; chain = chain->next)
        {
            u_char *data = chain->buf->start;

            msc_append_response_body(ctx->modsec_transaction, data, chain->buf->end - data);
            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r);
            if (ret > 0)
            {
                return ngx_http_filter_finalize_request(r,
                    &ngx_http_modsecurity, ret);
            }
        }

        msc_process_response_body(ctx->modsec_transaction);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r);
        if (ret > 0)
        {
            return ret;
        }
        else if (ret < 0)
        {
            return ngx_http_filter_finalize_request(r,
                &ngx_http_modsecurity, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
    }
    else
    {
        dd("buffer was not fully loaded! ctx: %p", ctx);
    }

    return ngx_http_next_body_filter(r, in);
}
