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


#if (NGX_THREADS) && (NGX_PCRE2)

/* logging tasks of this worker posted and not yet completed */
static ngx_uint_t          ngx_http_modsecurity_log_pending;
static time_t              ngx_http_modsecurity_log_inline_warned;

/* keeps a gracefully exiting worker alive while tasks are pending */
static ngx_event_t         ngx_http_modsecurity_log_drain;
static ngx_connection_t    ngx_http_modsecurity_log_drain_dumb;

/* serialises msc_process_logging() within the worker */
static ngx_thread_mutex_t  ngx_http_modsecurity_log_mutex;
static ngx_flag_t          ngx_http_modsecurity_log_mutex_created;


ngx_int_t
ngx_http_modsecurity_log_init_process(ngx_cycle_t *cycle)
{
    ngx_http_modsecurity_main_conf_t  *mmcf;

    mmcf = ngx_http_cycle_get_module_main_conf(cycle,
                                               ngx_http_modsecurity_module);

    if (mmcf == NULL || !mmcf->log_thread_pool_used) {
        return NGX_OK;
    }

    if (ngx_thread_mutex_create(&ngx_http_modsecurity_log_mutex, cycle->log)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_http_modsecurity_log_mutex_created = 1;

    return NGX_OK;
}


static ngx_flag_t
ngx_http_modsecurity_log_lock(ngx_log_t *log)
{
    if (!ngx_http_modsecurity_log_mutex_created) {
        return 0;
    }

    return ngx_thread_mutex_lock(&ngx_http_modsecurity_log_mutex, log)
           == NGX_OK;
}


static void
ngx_http_modsecurity_log_unlock(ngx_flag_t locked, ngx_log_t *log)
{
    if (locked) {
        (void) ngx_thread_mutex_unlock(&ngx_http_modsecurity_log_mutex, log);
    }
}

#endif


static ngx_int_t
ngx_http_modsecurity_log_transaction(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_pool_t  *old_pool;
#if (NGX_THREADS) && (NGX_PCRE2)
    ngx_flag_t   locked;

    locked = ngx_http_modsecurity_log_lock(r->connection->log);
#endif

    dd("calling msc_process_logging for %p", ctx);
    old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_logging(ctx->modsec_transaction);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

#if (NGX_THREADS) && (NGX_PCRE2)
    ngx_http_modsecurity_log_unlock(locked, r->connection->log);
#endif

    return NGX_OK;
}


#if (NGX_THREADS) && (NGX_PCRE2)

static void
ngx_http_modsecurity_log_thread_handler(void *data, ngx_log_t *log)
{
    ngx_flag_t                        locked;
    ngx_http_modsecurity_log_task_t  *lt = data;

    /* the request and its connection log may be gone by now */
    lt->msclog.log = log;

    locked = ngx_http_modsecurity_log_lock(log);
    msc_process_logging(lt->transaction);
    ngx_http_modsecurity_log_unlock(locked, log);

    /* the completion handler does not run if the worker exits first */
    msc_transaction_cleanup(lt->transaction);
    lt->transaction = NULL;
}


static void
ngx_http_modsecurity_log_thread_event_handler(ngx_event_t *ev)
{
    ngx_http_modsecurity_log_task_t  *lt = ev->data;

    ngx_free(lt);

    ngx_http_modsecurity_log_pending--;

    if (ngx_http_modsecurity_log_pending == 0
        && ngx_http_modsecurity_log_drain.timer_set)
    {
        ngx_del_timer(&ngx_http_modsecurity_log_drain);
    }
}


static void
ngx_http_modsecurity_log_drain_handler(ngx_event_t *ev)
{
    if (ngx_http_modsecurity_log_pending) {
        ngx_add_timer(ev, 1000);
    }
}


static ngx_int_t
ngx_http_modsecurity_log_offload(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, ngx_http_modsecurity_conf_t *mcf)
{
    ngx_http_modsecurity_log_task_t  *lt;

    if (ngx_http_modsecurity_log_pending >= mcf->log_max_pending) {
        return NGX_DECLINED;
    }

    lt = ctx->log_task;

    lt->transaction = ctx->modsec_transaction;

    lt->task.ctx = lt;
    lt->task.handler = ngx_http_modsecurity_log_thread_handler;
    lt->task.event.data = lt;
    lt->task.event.handler = ngx_http_modsecurity_log_thread_event_handler;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "ModSecurity: posting logging to the thread pool");

    if (ngx_thread_task_post(mcf->log_thread_pool, &lt->task) != NGX_OK) {
        return NGX_ERROR;
    }

    /* the task now owns the transaction and itself */
    ctx->modsec_transaction = NULL;
    ctx->log_task = NULL;

    ngx_http_modsecurity_log_pending++;

    if (!ngx_http_modsecurity_log_drain.timer_set) {
        ngx_http_modsecurity_log_drain.handler =
                                        ngx_http_modsecurity_log_drain_handler;
        ngx_http_modsecurity_log_drain.log = ngx_cycle->log;
        ngx_http_modsecurity_log_drain.data =
                                        &ngx_http_modsecurity_log_drain_dumb;
        ngx_http_modsecurity_log_drain_dumb.fd = (ngx_socket_t) -1;
        ngx_add_timer(&ngx_http_modsecurity_log_drain, 1000);
    }

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

    /*
     * subrequests share the main request's pool, so the cleanup scan in
     * ngx_http_modsecurity_get_module_ctx() would return its context
     */
    if (r != r->main) {
        return NGX_OK;
    }

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL || ctx->logged || ctx->modsec_transaction == NULL) {
        return NGX_OK;
    }

#if (NGX_THREADS) && (NGX_PCRE2)
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    if (mcf->log_thread_pool != NULL && ctx->log_task != NULL) {
        if (ngx_http_modsecurity_log_offload(r, ctx, mcf) == NGX_OK) {
            return NGX_OK;
        }

        if (ngx_time() - ngx_http_modsecurity_log_inline_warned >= 10) {
            ngx_http_modsecurity_log_inline_warned = ngx_time();

            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "ModSecurity: could not post logging to thread "
                          "pool, %ui tasks pending, processing inline",
                          ngx_http_modsecurity_log_pending);
        }
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
