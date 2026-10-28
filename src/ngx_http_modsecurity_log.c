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
    int                          result;

    if (r == NULL || r->connection == NULL) {
        return NGX_ERROR;
    }
    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL) {
        return NGX_OK;
    }
    if (ctx->logged) {
        return ctx->native_logging_failed ? NGX_ERROR : NGX_OK;
    }

    /* Claim the attempt before a native callback can re-enter this handler. */
    ctx->logged = 1;
    ctx->native_logging_failed = 1;
    if (ctx->modsec_transaction == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "ModSecurity: native logging transaction is unavailable");
        return NGX_ERROR;
    }
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
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
