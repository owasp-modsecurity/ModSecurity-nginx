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
#include "ngx_http_modsecurity_header_filter.h"
#include "ngx_http_modsecurity_common.h"


static ngx_http_output_header_filter_pt ngx_http_next_header_filter;


ngx_int_t ngx_http_modsecurity_header_filter_init(void)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;

    return NGX_OK;
}


ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    int ret = 0;
    ngx_uint_t status;
    const char *response_proto;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("header filter, recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("something really bad happened or ModSecurity is disabled. going to the next filter.");
        return ngx_http_next_header_filter(r);;
    }

    if (ctx && ctx->processed)
    {
        /**
         *FIXME: verify if this request is already processed.
         *
         */
        dd("Already processed... going to the next header...");
        return ngx_http_next_header_filter(r);
    }

    ctx->processed = 1;

    for (i = 0 ;; i++)
    {
        if (i >= part->nelts)
        {
            if (part->next == NULL)
            {
                break;
            }

            part = part->next;
            data = part->elts;
            i = 0;
        }
        /**
         * Doing this ugly cast here, explanation on the request_header
         * 
         */

        msc_add_n_response_header(ctx->modsec_transaction,
            (const unsigned char *) data[i].key.data,
            data[i].key.len,
            (const unsigned char *) data[i].value.data,
            data[i].value.len);
    }

    if (r->err_status) {
        status = r->err_status;
    } else {
        status = r->headers_out.status;
    }

    response_proto = "HTTP 1.1";
#if (NGX_HTTP_V2)
    if (r->stream) {
        response_proto = "HTTP 2.0";
    }
#endif

    msc_process_response_headers(ctx->modsec_transaction, status, response_proto);
    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r);
    if (ret > 0)
    {
        return ret;
    }

    /**
     * Proxies will not like this... but it is necessary to unset
     * the content length in order to manipulate the content of
     * response body in ModSecurity.
     *
     * This header may arrive at the client before ModSecurity had
     * a change to make any modification. That is why it is necessary
     * to set this to -1 here.
     *
     * We need to have some kind of flag the decide if ModSecurity
     * will make a modification or not. If not, keep the content and
     * make the proxy servers happy.
     *
     */
    /**
     * The line below is commented to make the spdy test to work
     *
     */
     //r->headers_out.content_length_n = -1;

    return ngx_http_next_header_filter(r);
}
