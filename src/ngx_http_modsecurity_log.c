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
ngx_http_modsecurity_log_context(ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_pool_t                   *old_pool;
    ngx_http_request_t           *r;
    int                          result;

    if (ctx == NULL || ctx->r == NULL || ctx->r->connection == NULL ||
        ctx->lifetime.pool == NULL) {
        return NGX_ERROR;
    }
    r = ctx->r;
    if (ctx->logged) {
        return ctx->native_logging_failed ? NGX_ERROR : NGX_OK;
    }

    /* Claim the attempt before native callbacks can re-enter this owner. */
    ctx->logged = 1;
    ctx->native_logging_failed = 1;
    if (ctx->modsec_transaction == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ModSecurity: native logging transaction is unavailable");
        return NGX_ERROR;
    }
    /* Pool cleanup can run after NGINX clears r->pool. Retain its real owner. */
    old_pool = ngx_http_modsecurity_pcre_malloc_init(ctx->lifetime.pool);
    result = msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
    if (result != 1) {
        /* The log phase cannot replace the response or retry the audit sink. */
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ModSecurity: native logging phase processing failed");
        return NGX_ERROR;
    }
    ctx->native_logging_failed = 0;
    return NGX_OK;
}


ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    /* Every transaction owner for this request gets one native audit attempt,
     * including prior locations and disabled/different target policies. */
    return ngx_http_modsecurity_log_request_contexts(r);
}
