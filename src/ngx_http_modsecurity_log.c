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


void
ngx_http_modsecurity_log(void *log, const void* data)
{
    const char *msg;
    if (log == NULL) {
        return;
    }
    msg = (const char *) data;

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)log, 0, "%s", msg);
}


ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_ctx_t   *ctx;

    dd("catching a new _log_ phase handler");

    /*
    if (r->method != NGX_HTTP_GET &&
        r->method != NGX_HTTP_POST && r->method != NGX_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NGX_OK;
    }
    */
    ctx = ngx_http_modsecurity_get_module_ctx(r);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL) {
        dd("ModSecurity not enabled or error occurred");
        return NGX_OK;
    }

    if (ctx->logged) {
        dd("already logged earlier");
        return NGX_OK;
    }

    dd("calling msc_process_logging for %p", ctx);
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    ctx->logged = 1;

    return NGX_OK;
}
