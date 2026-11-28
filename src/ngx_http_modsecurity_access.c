/*
 * ModSecurity connector for nginx, http://www.modsecurity.org/
 * Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
 * Copyright (c) 2026 OWASP Foundation (http://www.owasp.org/)
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


/*
 * A request body that NGINX buffered to a temporary file is read and handed
 * to ModSecurity in chunks of at most this size.
 */
#define NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE  32768


/*
 * Hands one piece of the request body to ModSecurity.  SecRequestBodyLimit
 * is enforced by libModSecurity, and neither of its limit actions is a
 * failure: with Reject, msc_append_request_body() returns 1 and leaves a
 * disruptive intervention in the transaction, with ProcessPartial it keeps
 * the body up to the limit and returns 0.  Either way the request body phase
 * runs on what was kept.  No other result is defined.
 */
static ngx_int_t
ngx_http_modsecurity_append_request_chunk(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx, const u_char *data, size_t size)
{
    int  rc;

    rc = msc_append_request_body(ctx->modsec_transaction, data, size);

    if (rc != 0 && rc != 1) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ModSecurity: msc_append_request_body() returned %d",
                      rc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_modsecurity_append_request_body(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    ngx_buf_t    *b;
    ngx_chain_t  *cl;

    if (r->request_body == NULL) {
        return NGX_OK;
    }

    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        b = cl->buf;

        if (b == NULL) {
            goto invalid;
        }

        if (!ngx_buf_special(b)) {
            if (b->pos == NULL || b->last == NULL || b->last < b->pos) {
                goto invalid;
            }

            if (ngx_http_modsecurity_append_request_chunk(r, ctx, b->pos,
                    (size_t) (b->last - b->pos))
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        if (b->last_buf) {
            break;
        }
    }

    return NGX_OK;

invalid:

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                  "ModSecurity: invalid request body buffer");

    return NGX_ERROR;
}


/*
 * Checks that the request body file NGINX holds open is a regular file of
 * the size NGINX wrote to it.
 */
static ngx_int_t
ngx_http_modsecurity_check_request_body_file(ngx_http_request_t *r,
    ngx_file_t *file, off_t size)
{
    ngx_file_info_t  fi;

    if (file->fd == NGX_INVALID_FILE || size < 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ModSecurity: invalid request body file \"%V\"",
                      &file->name);
        return NGX_ERROR;
    }

    if (ngx_fd_info(file->fd, &fi) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "ModSecurity: " ngx_fd_info_n " \"%V\" failed",
                      &file->name);
        return NGX_ERROR;
    }

    if (!ngx_is_file(&fi) || ngx_file_size(&fi) != size) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "ModSecurity: request body file \"%V\" is not "
                      "a regular file of %O bytes", &file->name, size);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Reads a request body that NGINX buffered to a temporary file through the
 * descriptor NGINX holds, one bounded chunk at a time, instead of opening
 * the file again by its name and loading it whole into memory.
 */
static ngx_int_t
ngx_http_modsecurity_inspect_request_body_file(ngx_http_request_t *r,
    ngx_http_modsecurity_ctx_t *ctx)
{
    off_t        size, offset, file_offset;
    size_t       amount;
    u_char      *buf;
    ssize_t      n;
    ngx_int_t    rc;
    ngx_file_t  *file;

    file = &r->request_body->temp_file->file;
    size = r->request_body->temp_file->offset;

    if (ngx_http_modsecurity_check_request_body_file(r, file, size)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (size == 0) {
        return NGX_OK;
    }

    buf = ngx_pnalloc(r->pool, NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    rc = NGX_OK;

    /* ngx_read_file() advances file->offset, which belongs to NGINX */
    file_offset = file->offset;

    for (offset = 0; offset < size; offset += (off_t) amount) {

        if (size - offset > NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE) {
            amount = NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE;

        } else {
            amount = (size_t) (size - offset);
        }

        n = ngx_read_file(file, buf, amount, offset);

        if (n < 0 || (size_t) n != amount) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ModSecurity: reading %uz bytes at %O from the "
                          "request body file \"%V\" returned %z",
                          amount, offset, &file->name, n);
            rc = NGX_ERROR;
            break;
        }

        rc = ngx_http_modsecurity_append_request_chunk(r, ctx, buf, amount);
        if (rc != NGX_OK) {
            break;
        }
    }

    file->offset = file_offset;

    ngx_pfree(r->pool, buf);

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    /* the body must not have changed while it was read */

    return ngx_http_modsecurity_check_request_body_file(r, file, size);
}


void
ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_modsecurity_get_module_ctx(r);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "ModSecurity: no context in the request body "
                      "post handler");
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        r->write_event_handler = ngx_http_core_run_phases;
        ngx_http_core_run_phases(r);
    }
}


/*
 * With "satisfy any" the access phase checker takes a 401 or 403 (and,
 * since nginx 1.31.0, a 407) returned by a handler as one vote only and
 * serves the request if another access module (allow, auth_basic,
 * auth_request) admits the client.  An intervention is final, so under
 * "satisfy any" finalize the request here instead of returning its status
 * to the checker; auth_delay does not apply to a 401 or 407 from a rule
 * there.  Under "satisfy all" return the status: the checker finalizes the
 * request with it, after auth_delay for a 401 or 407.
 */
static ngx_int_t
ngx_http_modsecurity_access_intervention(ngx_http_request_t *r,
    ngx_int_t status)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if (clcf->satisfy == NGX_HTTP_SATISFY_ALL) {
        return status;
    }

    ngx_http_finalize_request(r, status);

    return NGX_DONE;
}


ngx_int_t
ngx_http_modsecurity_access_handler(ngx_http_request_t *r)
{

    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_ctx_t   *ctx;
    ngx_http_modsecurity_conf_t  *mcf;

    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL || mcf->enable != 1) {
        dd("ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }

    /*
    if (r->method != NGX_HTTP_GET &&
        r->method != NGX_HTTP_POST && r->method != NGX_HTTP_HEAD) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST, GET or HEAD");
        return NGX_DECLINED;
    }
    */

    dd("catching a new _access_ phase handler");

    ctx = ngx_http_modsecurity_get_module_ctx(r);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        int ret = 0;

        ngx_connection_t *connection = r->connection;
        /**
         * FIXME: We may want to use struct sockaddr instead of addr_text.
         *
         */
        ngx_str_t addr_text = connection->addr_text;

        ctx = ngx_http_modsecurity_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "ModSecurity: failed to set up the transaction");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /**
         * FIXME: Check if it is possible to hook on nginx on a earlier phase.
         *
         * At this point we are doing an late connection process. Maybe
         * we have to hook into NGX_HTTP_FIND_CONFIG_PHASE, it seems to be the
         * erliest phase that nginx allow us to attach those kind of hooks.
         *
         */
        int client_port = ngx_inet_get_port(connection->sockaddr);
        int server_port = ngx_inet_get_port(connection->local_sockaddr);

        const char *client_addr = ngx_str_to_char(addr_text, r->pool);
        if (client_addr == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

#if defined(MODSECURITY_CHECK_VERSION)
#if MODSECURITY_VERSION_NUM >= 30130100
        ngx_str_t hostname;
        hostname.len = 0;
        // first check if Nginx received a Host header and it's usable
        // (i.e. not empty)
        // if yes, we can use that
        if (r->headers_in.server.len > 0) {
            hostname.len = r->headers_in.server.len;
            hostname.data = r->headers_in.server.data;
        }
        else {
            // otherwise we try to use the server config, namely the
            // server_name $SERVER_NAME
            // directive
            // for eg. in default config, server_name is "_"
            // possible all requests without a Host header will be
            // handled by this server block
            ngx_http_core_srv_conf_t  *cscf;
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            if (cscf->server_name.len > 0) {
                hostname.len = cscf->server_name.len;
                hostname.data = cscf->server_name.data;
            }
        }
        if (hostname.len > 0) {
            const char *host_name = ngx_str_to_char(hostname, r->pool);
            if (host_name == (char*)-1 || host_name == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            else {
                // set the hostname in the transaction
                // this function is only available in ModSecurity 3.0.13 and later
                msc_set_request_hostname(ctx->modsec_transaction, (const unsigned char *)host_name);
            }
        }
#endif
#endif

        ngx_str_t s;
        u_char addr[NGX_SOCKADDR_STRLEN];
        s.len = NGX_SOCKADDR_STRLEN;
        s.data = addr;
        if (ngx_connection_local_sockaddr(r->connection, &s, 0) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        const char *server_addr = ngx_str_to_char(s, r->pool);
        if (server_addr == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        ret = msc_process_connection(ctx->modsec_transaction,
            client_addr, client_port,
            server_addr, server_port);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);
        if (ret != 1){
            dd("Was not able to extract connection information.");
        }
        /*
         * An intervention is enforced through
         * ngx_http_modsecurity_access_intervention(): under "satisfy any"
         * it finalizes the request here, under "satisfy all" the access
         * phase checker finalizes it with the returned status.
         */
        dd("Processing intervention with the connection information filled in");
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ngx_http_modsecurity_access_intervention(r, ret);
        }

        const char *http_version;
        switch (r->http_version) {
            case NGX_HTTP_VERSION_9 :
                http_version = "0.9";
                break;
            case NGX_HTTP_VERSION_10 :
                http_version = "1.0";
                break;
            case NGX_HTTP_VERSION_11 :
                http_version = "1.1";
                break;
#if defined(nginx_version) && nginx_version >= 1009005
            case NGX_HTTP_VERSION_20 :
                http_version = "2.0";
                break;
#endif
            default :
                http_version = ngx_str_to_char(r->http_protocol, r->pool);
                if (http_version == (char*)-1) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }
                if ((http_version != NULL) && (strlen(http_version) > 5) && (!strncmp("HTTP/", http_version, 5))) {
                    http_version += 5;
                } else {
                    http_version = "1.0";
                }
                break;
        }

        const char *n_uri = ngx_str_to_char(r->unparsed_uri, r->pool);
        const char *n_method = ngx_str_to_char(r->method_name, r->pool);
        if (n_uri == (char*)-1 || n_method == (char*)-1) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        if (n_uri == NULL) {
            dd("uri is of length zero");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_uri(ctx->modsec_transaction, n_uri, n_method, http_version);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        dd("Processing intervention with the transaction information filled in (uri, method and version)");
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ngx_http_modsecurity_access_intervention(r, ret);
        }

        /**
         * Since incoming request headers are already in place, lets send it to ModSecurity
         *
         */
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        for (i = 0 ; /* void */ ; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /**
             * By using u_char (utf8_t) I believe nginx is hoping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to ModSecurity, it will handle with those later.
             *
             */

            dd("Adding request header: %.*s with value %.*s", (int)data[i].key.len, data[i].key.data, (int) data[i].value.len, data[i].value.data);
            msc_add_n_request_header(ctx->modsec_transaction,
                (const unsigned char *) data[i].key.data,
                data[i].key.len,
                (const unsigned char *) data[i].value.data,
                data[i].value.len);
        }

        /**
         * Since ModSecurity already knew about all headers, i guess it is safe
         * to process this information.
         */

        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_request_headers(ctx->modsec_transaction);
        ngx_http_modsecurity_pcre_malloc_done(old_pool);
        dd("Processing intervention with the request headers information filled in");
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 1);
        if (r->error_page) {
            return NGX_DECLINED;
            }
        if (ret > 0) {
            ctx->intervention_triggered = 1;
            return ngx_http_modsecurity_access_intervention(r, ret);
        }
    }

#if 1

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

    if (ctx == NULL)
    {
        dd("ctx is null; Nothing we can do, returning an error.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->request_body_processed) {
        // should we use r->internal or r->filter_finalize?
        return NGX_DECLINED;
    }

    if (ctx->intervention_triggered) {
        return NGX_DECLINED;
    }

    if (ctx->request_body_failed) {
        /* part of the body may be in the transaction already: do not retry */
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ctx->waiting_more_body == 1)
    {
        dd("waiting for more data before proceed. / count: %d",
            r->main->count);

        return NGX_DONE;
    }

    if (ctx->body_requested == 0)
    {
        ngx_int_t rc = NGX_OK;

        ctx->body_requested = 1;

        dd("asking for the request body, if any. Count: %d",
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
        if (!r->request_body_in_file_only) {
            // If the above condition fails, then the flag below will have been
            // set correctly elsewhere. We need to set the flag here for other
            // conditions (client_body_in_file_only not used but
            // client_body_buffer_size is)
            r->request_body_in_clean_file = 1;
        }

        rc = ngx_http_read_client_request_body(r,
            ngx_http_modsecurity_request_read);
        if (rc == NGX_ERROR || rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if (nginx_version < 1002006) ||                                             \
    (nginx_version >= 1003000 && nginx_version < 1003009)
            r->main->count--;
#endif

            return rc;
        }
        if (rc == NGX_AGAIN)
        {
            dd("nginx is asking us to wait for more data.");

            ctx->waiting_more_body = 1;
            return NGX_DONE;
        }
    }

    if (ctx->waiting_more_body == 0)
    {
        int ret = 0;
        ngx_int_t rc;

        dd("request body is ready to be processed");

        r->write_event_handler = ngx_http_core_run_phases;

        /**
         * TODO: Speed up the analysis by sending chunk while they arrive.
         *
         * Notice that we are waiting for the full request body to
         * start to process it, it may not be necessary. We may send
         * the chunks to ModSecurity while nginx keep calling this
         * function.
         */

        /*
         * The whole body goes to ModSecurity before an intervention is
         * looked for.  Rules see the body only in the request body phase,
         * so the only intervention appending it can raise is that of
         * SecRequestBodyLimitAction Reject, and the transaction keeps it
         * for the check after msc_process_request_body() below.  A failure
         * to hand the body over is an error of the connector, not a rule
         * decision, and fails the request.
         */
        if (r->request_body != NULL && r->request_body->temp_file != NULL) {
            dd("inspecting the request body in its temporary file");
            rc = ngx_http_modsecurity_inspect_request_body_file(r, ctx);

        } else {
            dd("inspecting the request body in memory");
            rc = ngx_http_modsecurity_append_request_body(r, ctx);
        }

        if (rc != NGX_OK) {
            ctx->request_body_failed = 1;
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        /**
         * At this point, all the request body was sent to ModSecurity
         * and we want to make sure that all the request body inspection
         * happened; consequently we have to check if ModSecurity have
         * returned any kind of intervention.
         */

/* XXX: once more -- is body can be modified ?  content-length need to be adjusted ? */

        old_pool = ngx_http_modsecurity_pcre_malloc_init(r->pool);
        msc_process_request_body(ctx->modsec_transaction);
        ctx->request_body_processed = 1;
        ngx_http_modsecurity_pcre_malloc_done(old_pool);

        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_transaction, r, 0);
        if (r->error_page) {
            return NGX_DECLINED;
            }
        if (ret > 0) {
            return ngx_http_modsecurity_access_intervention(r, ret);
        }
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
#endif
    return NGX_DECLINED;
}

