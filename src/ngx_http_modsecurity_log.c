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


/*
 * Runs the native logging phase (phase 5 rules and the audit log) of the
 * request's transaction. It is called from the NGINX LOG phase and, for an
 * intervention in the access phase, from
 * ngx_http_modsecurity_process_intervention() ("early logging").
 *
 * msc_process_logging() runs at most once per transaction, whether the first
 * attempt succeeded or not; later calls return the stored result. NGX_ERROR
 * means that the native logging phase did not report success. NGX_OK only
 * means that it returned 1: libModSecurity does not report whether an audit
 * log record was written. NGINX ignores the result of LOG phase handlers, so
 * a failure here never changes a response.
 */
ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    int                           ret;
    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_ctx_t   *ctx;

    dd("catching a new _log_ phase handler");

    /*
     * Subrequests share the pool of the main request, so the cleanup scan in
     * ngx_http_modsecurity_get_module_ctx() finds its context. With
     * "log_subrequest on" their LOG phase must not use up the single logging
     * attempt of a transaction whose response is still being sent; the main
     * request logs it.
     */
    if (r != r->main) {
        dd("subrequest, the main request logs the transaction");
        return NGX_OK;
    }

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
        return ctx->native_logging_failed ? NGX_ERROR : NGX_OK;
    }

    /*
     * Claim the attempt before the native call, so that a call re-entering
     * from a libModSecurity callback cannot run the logging phase again. Until
     * msc_process_logging() returns 1 the attempt counts as failed.
     */
    ctx->logged = 1;
    ctx->native_logging_failed = 1;

    if (ctx->modsec_transaction == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ModSecurity: no transaction to run the logging "
                      "phase for");
        return NGX_ERROR;
    }

    dd("calling msc_process_logging for %p", ctx);
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    ret = msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    /* 1 is success and 0 failure; anything else is outside the API contract */
    if (ret != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ModSecurity: the logging phase %s (%d)",
                      ret == 0 ? "failed" : "returned an unexpected result",
                      ret);
        return NGX_ERROR;
    }

    ctx->native_logging_failed = 0;

    return NGX_OK;
}
