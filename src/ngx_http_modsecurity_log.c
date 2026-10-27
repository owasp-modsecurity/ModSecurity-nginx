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
ngx_http_modsecurity_log(void *data, const void* msg)
{
    ngx_http_modsecurity_msclog_t  *msclog = data;

    if (msclog == NULL || msclog->log == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, msclog->log, 0, "%s", (const char *) msg);
}


static ngx_int_t
ngx_http_modsecurity_log_transaction(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_pool_t  *old_pool;

    dd("calling msc_process_logging for %p", ctx);
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    return NGX_OK;
}


#if (NGX_THREADS) && (NGX_PCRE2)

typedef struct {
    ngx_pool_t                     *pool;
    Transaction                    *transaction;
    ngx_http_modsecurity_msclog_t  *msclog;
} ngx_http_modsecurity_log_task_t;


static void
ngx_http_modsecurity_log_thread_handler(void *data, ngx_log_t *log)
{
    ngx_http_modsecurity_log_task_t  *lt = data;

    /* the request and its connection log may be gone by now */
    lt->msclog->log = log;

    msc_process_logging(lt->transaction);
}


static void
ngx_http_modsecurity_log_thread_event_handler(ngx_event_t *ev)
{
    ngx_http_modsecurity_log_task_t  *lt = ev->data;

    msc_transaction_cleanup(lt->transaction);
    ngx_free(lt->msclog);
    ngx_destroy_pool(lt->pool);
}


static ngx_int_t
ngx_http_modsecurity_log_offload(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_thread_pool_t *tp)
{
    ngx_pool_t                       *pool;
    ngx_thread_task_t                *task;
    ngx_http_modsecurity_log_task_t  *lt;

    pool = ngx_create_pool(512, ngx_cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    task = ngx_thread_task_alloc(pool, sizeof(ngx_http_modsecurity_log_task_t));
    if (task == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    lt = task->ctx;
    lt->pool = pool;
    lt->transaction = ctx->modsec_transaction;
    lt->msclog = ctx->msclog;

    task->handler = ngx_http_modsecurity_log_thread_handler;
    task->event.data = lt;
    task->event.handler = ngx_http_modsecurity_log_thread_event_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ModSecurity: posting logging to the thread pool");

    if (ngx_thread_task_post(tp, task) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    /* the task now owns the transaction and the log holder */
    ctx->modsec_transaction = NULL;
    ctx->msclog = NULL;

    return NGX_OK;
}

#endif


ngx_int_t
ngx_http_modsecurity_log_phase_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t   *ctx;
#if (NGX_THREADS) && (NGX_PCRE2)
    ngx_http_modsecurity_conf_t  *mcf;
#endif

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL || ctx->logged || ctx->modsec_transaction == NULL) {
        return NGX_OK;
    }

#if (NGX_THREADS) && (NGX_PCRE2)
    /*
     * Subrequests do not own a context of their own -- the access phase is
     * skipped for them -- so their log phase, which runs while the main
     * request is still being processed, must not detach the main request's
     * transaction.
     */
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    if (r == r->main && mcf->log_thread_pool != NULL && ctx->msclog_heap) {
        if (ngx_http_modsecurity_log_offload(r, ctx, mcf->log_thread_pool)
            == NGX_OK)
        {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                      "ModSecurity: could not post logging to thread pool, "
                      "processing inline");
    }
#endif

    return ngx_http_modsecurity_log_transaction(r, ctx);
}


ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
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

    return ngx_http_modsecurity_log_transaction(r, ctx);
}
