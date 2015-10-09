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


#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


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
    ngx_chain_t *chain = in;
    int buffer_fully_loadead = 0;
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_modsecurity_loc_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);
    if (cf == NULL || cf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return ngx_http_next_body_filter(r, in);
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_POST) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST or GET");
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("body filter, recovering ctx: %p", ctx);

    if (r != r->main || ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    for (chain = in; chain != NULL; chain = chain->next)
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

            msc_append_response_body(ctx->modsec_assay, data, chain->buf->end - data);
            /**
             * FIXME: Body size also matters. check for intervention.
             */
        }

        msc_process_response_body(ctx->modsec_assay);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
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
