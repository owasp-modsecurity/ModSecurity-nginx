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

#ifndef MODSECURITY_DDEBUG
#define MODSECURITY_DDEBUG 0
#endif
#include "ddebug.h"

#include "ngx_http_modsecurity_common.h"

typedef struct {
    ngx_http_request_t *r;
    // ngx_http_core_main_conf_t *cmcf;
    ngx_http_modsecurity_ctx_t *ctx;
    int return_code;
} ngx_http_modsecurity_pre_access_thread_ctx_t;

void
ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[ModSecurity] r->main->count: %d => %d", r->main->count+1, r->main->count);
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


void
ngx_http_modsecurity_pre_access_worker(void *data, ngx_log_t *log)
{
#if 1
    // ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_pre_access_thread_ctx_t *t_ctx = data;
    ngx_http_modsecurity_ctx_t *ctx = t_ctx->ctx;
    ngx_http_request_t *r = t_ctx->r;

    ngx_log_error(NGX_LOG_DEBUG, log, 0, "[ModSecurity] Pre-Access Job Dispatched");

    /*
     * FIXME:
     * In order to perform some tests, let's accept everything.
     *
    if (r->method != NGX_HTTP_GET &&
        r->method != NGX_HTTP_POST && r->method != NGX_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NGX_DECLINED;
    }
    */

    int ret = 0;
    int already_inspected = 0;

    ngx_log_error(NGX_LOG_DEBUG, log, 0, "request body is ready to be processed");

    r->write_event_handler = ngx_http_core_run_phases;

    ngx_chain_t *chain = r->request_body->bufs;

    /**
     * TODO: Speed up the analysis by sending chunk while they arrive.
     *
     * Notice that we are waiting for the full request body to
     * start to process it, it may not be necessary. We may send
     * the chunks to ModSecurity while nginx keep calling this
     * function.
     */

    if (r->request_body->temp_file != NULL) {
        ngx_str_t file_path = r->request_body->temp_file->file.name;
        const char *file_name = ngx_str_to_char(file_path, r->pool);
        if (file_name == (char*)-1) {
            t_ctx->return_code = NGX_HTTP_INTERNAL_SERVER_ERROR;
            return;
        }
        /*
            * Request body was saved to a file, probably we don't have a
            * copy of it in memory.
            */
        ngx_log_error(NGX_LOG_DEBUG, log, 0, "request body inspection: file -- %s", file_name);

        msc_request_body_from_file(ctx->modsec_transaction, file_name);

        already_inspected = 1;
    } else {
        ngx_log_error(NGX_LOG_DEBUG, log, 0, "inspection request body in memory.");
    }

    while (chain && !already_inspected)
    {
        u_char *data = chain->buf->pos;

        msc_append_request_body(ctx->modsec_transaction, data,
            chain->buf->last - data);

        if (chain->buf->last_buf) {
            break;
        }
        chain = chain->next;

/* XXX: chains are processed one-by-one, maybe worth to pass all chains and then call intervention() ? */

        /**
         * ModSecurity may perform stream inspection on this buffer,
         * it may ask for a intervention in consequence of that.
         *
         */
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (ret > 0) {
            t_ctx->return_code = ret;
            return;
        }
    }

    /**
     * At this point, all the request body was sent to ModSecurity
     * and we want to make sure that all the request body inspection
     * happened; consequently we have to check if ModSecurity have
     * returned any kind of intervention.
     */

/* XXX: once more -- is body can be modified ?  content-length need to be adjusted ? */

    // old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
    msc_process_request_body(ctx->modsec_transaction);
    // ngx_http_modsecurity_pcre_malloc_done(old_pool);

    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
    if (r->error_page) {
        t_ctx->return_code = NGX_DECLINED;
        return;
    }
    if (ret > 0) {
        t_ctx->return_code = ret;
        return;
    }
    

    ngx_log_error(NGX_LOG_DEBUG, log, 0, "Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
#endif
    t_ctx->return_code = NGX_DECLINED;
    return;
}

void ngx_http_modsecurity_pre_access_finalizer(ngx_event_t *ev){
    ngx_http_modsecurity_pre_access_thread_ctx_t *ctx = ev->data;
    ngx_http_core_main_conf_t *cmcf;

    ngx_log_error(NGX_LOG_DEBUG, ctx->r->connection->log, 0, "[ModSecurity] Pre-Access Job Finalized");

    --ctx->r->main->blocked; /* incremented in ngx_http_modsecurity_prevention_task_offload */
    ctx->r->aio = 0;

    ngx_log_error(NGX_LOG_DEBUG, ctx->r->connection->log, 0, "r->read_event_handler = %s", \
        ctx->r->read_event_handler == ngx_http_block_reading ? \
            "ngx_http_block_reading" : \
        ctx->r->read_event_handler == ngx_http_test_reading ? \
            "ngx_http_test_reading" : \
        ctx->r->read_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN");

    ngx_log_error(NGX_LOG_DEBUG, ctx->r->connection->log, 0, "r->write_event_handler = %s", \
        ctx->r->write_event_handler == ngx_http_handler ? \
            "ngx_http_handler" : \
        ctx->r->write_event_handler == ngx_http_core_run_phases ? \
            "ngx_http_core_run_phases" : \
        ctx->r->write_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN");

    cmcf = ngx_http_get_module_main_conf(ctx->r, ngx_http_core_module);

    switch (ctx->return_code) {
        case NGX_OK:
            ctx->r->phase_handler = cmcf->phase_engine.handlers->next;
            ngx_http_core_run_phases(ctx->r);
            break;
        case NGX_DECLINED:
            ctx->r->phase_handler++;
            ngx_http_core_run_phases(ctx->r);
            break;
        case NGX_AGAIN:
        case NGX_DONE:
            // ngx_http_core_run_phases(ctx->r);
            break;
        default:
            ngx_http_discard_request_body(ctx->r);
            ngx_http_finalize_request(ctx->r, ctx->return_code);
        }

    ngx_http_run_posted_requests(ctx->r->connection);
}

ngx_int_t ngx_http_modsecurity_pre_access_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_conf_t *mcf;
    ngx_http_modsecurity_pre_access_thread_ctx_t *ctx;
    ngx_http_modsecurity_ctx_t *m_ctx;
    ngx_thread_task_t *task;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "catching a new _preaccess_ phase handler");

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "r->read_event_handler = %s", \
        r->read_event_handler == ngx_http_block_reading ? \
            "ngx_http_block_reading" : \
        r->read_event_handler == ngx_http_test_reading ? \
            "ngx_http_test_reading" : \
        r->read_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN");

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "r->write_event_handler = %s", \
        r->write_event_handler == ngx_http_handler ? \
            "ngx_http_handler" : \
        r->write_event_handler == ngx_http_core_run_phases ? \
            "ngx_http_core_run_phases" : \
        r->write_event_handler == ngx_http_request_empty_handler ? \
            "ngx_http_request_empty_handler" : "UNKNOWN");

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }

    m_ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "recovering ctx: %p", m_ctx);

    if (m_ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ctx is null; Nothing we can do, returning an error.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (m_ctx->intervention_triggered)
    {
        return NGX_DECLINED;
    }

    if (m_ctx->waiting_more_body == 1)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "waiting for more data before proceed. / count: %d",
                      r->main->count);

        return NGX_DONE;
    }

    if (m_ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        m_ctx->body_requested = 1;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "asking for the request body, if any. Count: %d",
                      r->main->count);
        /**
         * TODO: Check if there is any benefit to use request_body_in_single_buf set to 1.
         *
         *       saw some module using this request_body_in_single_buf
         *       but not sure what exactly it does, same for the others options below.
         *
         * r->request_body_in_single_buf = 1;
         */
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 1;
        if (!r->request_body_in_file_only)
        {
            // If the above condition fails, then the flag below will have been
            // set correctly elsewhere. We need to set the flag here for other
            // conditions (client_body_in_file_only not used but
            // client_body_buffer_size is)
            r->request_body_in_clean_file = 1;
        }

        rc = ngx_http_read_client_request_body(r,
                                               ngx_http_modsecurity_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE)
        {
#if (nginx_version < 1002006) || \
    (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[ModSecurity] r->main->count: %d => %d", r->main->count + 1, r->main->count);
#endif

            return rc;
        }
        if (rc == NGX_AGAIN)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "nginx is asking us to wait for more data.");

            m_ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    if (m_ctx->waiting_more_body == 0)
    {

        task = ngx_thread_task_alloc(r->pool, sizeof(ngx_http_modsecurity_pre_access_thread_ctx_t));

        ctx = task->ctx;
        ctx->r = r;
        ctx->ctx = m_ctx;
        ctx->return_code = NGX_DECLINED;

        task->handler = ngx_http_modsecurity_pre_access_worker;
        task->event.handler = ngx_http_modsecurity_pre_access_finalizer;
        task->event.data = ctx;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "[ModSecurity] Using Thread Pool: %p", mcf->thread_pool);

        if (ngx_thread_task_post(mcf->thread_pool, task) != NGX_OK)
        {
            return NGX_ERROR;
        }

        r->main->blocked++;
        r->aio = 1;

        return NGX_DONE;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
    return NGX_DECLINED;
}
