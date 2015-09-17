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

#include <ngx_http.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/assay.h>
#include <modsecurity/rules.h>
#include <modsecurity/intervention.h>

#include "ddebug.h"
#include "ngx_http_modsecurity.h"

// #define DISABLE_BODY_FILTER 1
// #define DISABLE_HEADER_FILTER 1

#ifndef DISABLE_HEADER_FILTER
static ngx_http_output_header_filter_pt ngx_http_next_header_filter;
#endif

#ifndef DISABLE_BODY_FILTER
static ngx_http_output_body_filter_pt ngx_http_next_body_filter;
#endif

static ngx_int_t ngx_http_modsecurity_preaccess_handler(ngx_http_request_t *r);
static void ngx_http_modsecurity_request_read(ngx_http_request_t *r);

#ifndef DISABLE_HEADER_FILTER
static ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r);
#endif

#ifndef DISABLE_BODY_FILTER
static ngx_int_t ngx_http_modsecurity_body_filter(ngx_http_request_t *r,
        ngx_chain_t *in);
#endif

static ngx_int_t ngx_http_modsecurity_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf);

static void *ngx_http_modsecurity_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_modsecurity_merge_loc_conf(ngx_conf_t *cf,
        void *parent, void *child);

static void ngx_http_modsecurity_terminate_master(ngx_cycle_t *cycle);
static void ngx_http_modsecurity_terminate_process(ngx_cycle_t *cycle);

static ngx_int_t
ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r);

static ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r);


static char*
ngx_http_modsecurity_set_remote_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;
    ngx_str_t *field, *field2, *value;

    dd("Setting the remote server variables.");

    field = (ngx_str_t *) (p + cmd->offset);
    field2 = (ngx_str_t *) (p + cmd->offset + sizeof(ngx_str_t));

    if (field->data) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = value[2];
    *field2 = value[1];

    return NGX_CONF_OK;

}

static ngx_command_t ngx_http_modsecurity_commands[] =  {
  {
    ngx_string("modsecurity"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_rules_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules_file),
    NULL
  },
  {
    ngx_string("modsecurity_rules_remote"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
    ngx_http_modsecurity_set_remote_server,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules_remote_server),
    NULL
  },
  {
    ngx_string("modsecurity_rules"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules),
    NULL
  },
  ngx_null_command
};


static void
ngx_http_modsecurity_main_conf_cleanup(void *data)
{
    ngx_http_modsecurity_main_conf_t *cf = data;
    msc_cleanup(cf->modsec);
    cf->modsec = NULL;
}


static void ngx_http_modsecurity_log(void *log, const char* msg) {
    if (log == NULL) {
        return;
    }

    ngx_log_error(NGX_LOG_INFO, (ngx_log_t *)log, 0, msg);
}


static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_main_conf_t *conf;

    dd("crating ModSecurity main configuration");

    /* ngx_pcalloc already set all the scructure to zero. */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_main_conf_t));

    if (conf == NULL) {
        return NULL;
    }

    conf->modsec = msc_init();
    if (conf->modsec == NULL)
    {
        dd("failed to create ModSecurity local configuration");
        return NULL;
    }
    else
    {
        ngx_pool_cleanup_t *cln = NULL;
        msc_set_connector_info(conf->modsec, "ModSecurity-nginx v0.0.1-alpha");
        msc_set_log_cb(conf->modsec, ngx_http_modsecurity_log);

        cln = ngx_pool_cleanup_add(cf->pool, 0);
        if (cln == NULL)
        {
            dd("failed to create ModSecurity main configuration cleanup");
            return NULL;
        }
        cln->handler = ngx_http_modsecurity_main_conf_cleanup;
        cln->data = conf;
    }

    return conf;
}


static ngx_http_module_t ngx_http_modsecurity_ctx = {
    ngx_http_modsecurity_preconfiguration, /* preconfiguration */
    ngx_http_modsecurity_init, /* postconfiguration */

    ngx_http_modsecurity_create_main_conf, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_modsecurity_create_loc_conf, /* create location configuration */
    ngx_http_modsecurity_merge_loc_conf /* merge location configuration */
};


ngx_module_t ngx_http_modsecurity = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_ctx, /* module context */
    ngx_http_modsecurity_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    ngx_http_modsecurity_terminate_process, /* exit process */
    ngx_http_modsecurity_terminate_master, /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_inline void
ngx_http_modsecurity_config_cleanup(void *data)
{
    ngx_http_modsecurity_loc_conf_t *t = (ngx_http_modsecurity_loc_conf_t *) data;
    dd("deleting a loc conf -- RuleSet is: \"%p\"", t->rules_set);
    msc_rules_cleanup(t->rules_set);
    t->rules_set = NULL;
}


static void *
ngx_http_modsecurity_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_loc_conf_t  *conf;
    ngx_pool_cleanup_t *cln = NULL;

    conf = (ngx_http_modsecurity_loc_conf_t  *)
        ngx_palloc(cf->pool, sizeof(ngx_http_modsecurity_loc_conf_t));

    dd("creating a loc conf");

    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->rules_remote_server.len = 0;
    conf->rules_remote_key.len = 0;
    conf->rules_file.len = 0;
    conf->rules.len = 0;
    conf->id = 0;
    conf->rules_set = msc_create_rules_set();

    dd("creating a loc conf -- RuleSet is: \"%p\"", conf->rules_set);

    msc_rules_dump(conf->rules_set);
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    cln->handler = ngx_http_modsecurity_config_cleanup;
    cln->data = conf;

    return conf;
}


ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    char *str = NULL;

    if (a.len == 0) {
        return NULL;
    }

    str = ngx_pcalloc(p, a.len+1);

    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}


static char *
ngx_http_modsecurity_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_modsecurity_loc_conf_t *p = NULL;
    ngx_http_modsecurity_loc_conf_t *c = NULL;

    p = parent;
    c = child;

    ngx_conf_merge_value(c->enable, p->enable, 0);

    dd("Rules set: '%p'\n", c->rules_set);
    dd("Parent ModSecurityRuleSet is: '%p' current is: '%p'", p->rules_set, c->rules_set);
    if (p->rules_set != NULL)
    {
        dd("Parent is not null, so we have to merge this configurations");
        msc_rules_merge(c->rules_set, p->rules_set);
    }


    /**
     * FIXME: Fix the rules inclusion order.
     *
     * We are not respecting the order of the rules inclusion,
     * we should; It is not hard to do. Maybe for further
     * versions.
     */
    if (c->rules_remote_server.len != 0)
    {
        int res;
        const char *error = NULL;
        const char *rules_remote_server = ngx_str_to_char(c->rules_remote_server, cf->pool);
        const char *rules_remote_key = ngx_str_to_char(c->rules_remote_key, cf->pool);
        res = msc_rules_add_remote(c->rules_set, rules_remote_key, rules_remote_server, &error);
        dd("Loading rules from: '%s'", rules_remote_server);
        if (res < 0) {
            dd("Failed to load the rules from: '%s'  - reason: '%s'", rules_remote_server, error);

            return strdup(error);
        }
        dd("Loaded '%d' rules.", res);
    }
    if (c->rules_file.len != 0)
    {
        int res;
        const char *error = NULL;
        char *rules_set = ngx_str_to_char(c->rules_file, cf->pool);
        res = msc_rules_add_file(c->rules_set, rules_set, &error);
        dd("Loading rules from: '%s'", rules_set);
        if (res < 0) {
            dd("Failed to load the rules from: '%s' - reason: '%s'", rules_set, error);
            return strdup(error);
        }
        dd("Loaded '%d' rules.", res);
    }
    if (c->rules.len != 0)
    {
        int res;
        const char *error = NULL;
        char *rules = ngx_str_to_char(c->rules, cf->pool);
        res = msc_rules_add(c->rules_set, rules, &error);
        dd("Loading rules: '%s'", rules);
        if (res < 0) {
            dd("Failed to load the rules: '%s' - reason: '%s'", rules, error);
            return strdup(error);
        }
    }
    msc_rules_dump(c->rules_set);
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_modsecurity_preconfiguration(ngx_conf_t *cf)
{
    /*
     *
     * FIXME: Ops. Nginx hooks those two guys, we have to figure out a better
     * way to deal with it.
     *
     */
    pcre_malloc = malloc;
    pcre_free = free;

    return NGX_OK;
}


static void
ngx_http_modsecurity_terminate_process(ngx_cycle_t *cycle)
{
    dd("Terminating process...\n");
}


static void
ngx_http_modsecurity_terminate_master(ngx_cycle_t *cycle)
{
    dd("Terminating master...\n");
}


static ngx_int_t
ngx_http_modsecurity_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h_rewrite;
    ngx_http_handler_pt *h_preaccess;
    ngx_http_handler_pt *h_log;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /**
     * 
     * Semms like we cannot do this very same thing with
     * NGX_HTTP_FIND_CONFIG_PHASE. it does not seems to
     * be an array. Our next option is the REWRITE.
     *
     * TODO: check if we can hook prior to NGX_HTTP_REWRITE_PHASE phase.
     *
     */
    h_rewrite = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h_rewrite == NULL) {
        dd("Not able to create a new NGX_HTTP_REWRITE_PHASE handle");
        return NGX_ERROR;
    }
    *h_rewrite = ngx_http_modsecurity_rewrite_handler;

    /**
     *
     * Processing the request body on the preaccess phase.
     *
     * TODO: check if hook into separated phases is the best thing to do.
     *
     */
    h_preaccess = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h_preaccess == NULL) {
        dd("Not able to create a new NGX_HTTP_PREACCESS_PHASE handle");
        return NGX_ERROR;
    }
    *h_preaccess = ngx_http_modsecurity_preaccess_handler;

    /**
     * Process the log phase.
     *
     * TODO: check if the log phase happens like it happens on Apache.
     *       check if last phase will not hold the request.
     *
     */
    h_log = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h_log == NULL) {
        dd("Not able to create a new NGX_HTTP_LOG_PHASE handle");
        return NGX_ERROR;
    }
    *h_log = ngx_http_modsecurity_log_handler;

#ifndef DISABLE_HEADER_FILTER
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_modsecurity_header_filter;
#endif

#ifndef DISABLE_BODY_FILTER
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_modsecurity_body_filter;
#endif

    return NGX_OK;
}


int ngx_http_modsecurity_process_intervention (Assay *assay, ngx_http_request_t *r)
{
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;

    dd("processing intervention.");

    if (msc_intervention(assay, &intervention) == 0)
    {
        dd("nothing to do.");
        return 0;
    }

    if (intervention.log == NULL)
    {
        intervention.log = "(no log message was specified)";
    }
    if (intervention.url != NULL)
    {
        dd("intervention -- redirecting to: %s with status code: %d", intervention.url, intervention.status);

        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");
            return -1;
        }
        /**
         * Not sure if it sane to do this indepent of the phase
         * but, here we go...
         * 
         * This code cames from: http/ngx_http_special_response.c
         * function: ngx_http_send_error_page
         * src/http/ngx_http_core_module.c
         * From src/http/ngx_http_core_module.c (line 1910) i learnt
         * that location->hash should be set to 1.
         * 
         */
        ngx_http_clear_location(r);
        ngx_str_t a = ngx_string("");

        a.data = (unsigned char *)intervention.url;
        a.len = strlen(intervention.url);

        ngx_table_elt_t *location = NULL;
        location = ngx_list_push(&r->headers_out.headers);
        ngx_str_set(&location->key, "Location");
        location->value = a;
        r->headers_out.location = location;
        r->headers_out.location->hash = 1;

        return intervention.status;
    }

    if (intervention.status != 200)
    {
        if (r->header_sent)
        {
            dd("Headers are already sent. Cannot perform the redirection at this point.");       
            return -1;
        }
        dd("intervention -- returning code: %d", intervention.status);
        return intervention.status;
    }
    return 0;
}


static ngx_int_t
ngx_http_modsecurity_log_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_modsecurity_loc_conf_t *cf;

    dd("catching a new _log_ pahase handler");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);
    if (cf == NULL || cf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return NGX_OK;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_POST) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST or GET");
        return NGX_OK;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("something really bad happened here. returning NGX_ERROR");
        return NGX_ERROR;
    }

    msc_process_logging(ctx->modsec_assay, r->access_code);

    return NGX_OK;
}


static ngx_inline void
ngx_http_modsecurity_cleanup(void *data)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = (ngx_http_modsecurity_ctx_t *) data;

    msc_assay_cleanup(ctx->modsec_assay);
}


static ngx_inline ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_loc_conf_t *loc_cf = NULL;
    ngx_http_modsecurity_main_conf_t *cf = NULL;
    ngx_pool_cleanup_t *cln = NULL;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (ctx == NULL)
    {
        dd("failed to allocate memory for the context.");
        return NULL;
    }
    cf = ngx_http_get_module_main_conf(r, ngx_http_modsecurity);
    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);

    dd("creating assay with the following rules: '%p' -- ms: '%p'", loc_cf->rules_set, cf->modsec);

    ctx->modsec_assay = msc_new_assay(cf->modsec, loc_cf->rules_set, r->connection->log);

    dd("assay created");

    ngx_http_set_ctx(r, ctx, ngx_http_modsecurity);

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    cln->handler = ngx_http_modsecurity_cleanup;
    cln->data = ctx;

    return ctx;
}


static ngx_int_t
ngx_http_modsecurity_rewrite_handler(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_modsecurity_loc_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);
    if (cf == NULL || cf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }

    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_POST) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST or GET");
        return NGX_DECLINED;
    }

    dd("catching a new _rewrite_ pahase handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

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
        ngx_str_t server_addr_text = connection->listening->addr_text;

        ctx = ngx_http_modsecurity_create_ctx(r);

        dd("ctx was NULL, creating new context: %p", ctx);

        if (ctx == NULL)
        {
            dd("ctx still null; Nothing we can do, returning an error.");

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
        int client_port = 0; /* htons(((struct sockaddr_in *) sockaddr).sin_port); */
        int server_port = 0;
        const char *client_addr = ngx_str_to_char(addr_text, r->pool);
        const char *server_addr = ngx_str_to_char(server_addr_text, r->pool);
        msc_process_connection(ctx->modsec_assay,
            client_addr, client_port,
            server_addr, server_port);
        /**
         *
         * FIXME: Check how we can finalize a request without crash nginx.
         *
         * I don't think nginx is expecting to finalize a request at that
         * point as it seems that it clean the ngx_http_request_t information
         * and try to use it later. 
         *
         */
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
        if (ret > 0)
        {
            return ret;
        }

        /**
         * TODO: Fix http_version
         *
         */

        msc_process_uri(ctx->modsec_assay, ngx_str_to_char(r->unparsed_uri, r->pool),
            ngx_str_to_char(r->method_name, r->pool), "1.0"
        );
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
        if (ret > 0)
        {
            return ret;
        }

        /**
         * Since headers are already in place, lets send it to ModSecurity
         * 
         */
        ngx_list_part_t *part = &r->headers_in.headers.part;
        ngx_table_elt_t *data = part->elts;
        ngx_uint_t i = 0;
        for (i = 0 ;; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                data = part->elts;
                i = 0;
            }

            /**
             * By using u_char (utf8_t) I believe nginx is hopping to deal
             * with utf8 strings.
             * Casting those into to unsigned char * in order to pass
             * it to ModSecurity, it will handle with those later.
             * 
             */

            msc_add_n_request_header(ctx->modsec_assay,
                (const unsigned char *) data[i].key.data,
                data[i].key.len,
                (const unsigned char *) data[i].value.data,
                data[i].value.len);
        }

        /**
         * Since ModSecurity already knew about all headers, i guess it is safe
         * to process this information.
         */

        msc_process_request_headers(ctx->modsec_assay);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
        if (ret > 0)
        {
            return ret;
        }
    }


    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_modsecurity_preaccess_handler(ngx_http_request_t *r)
{
#if 1
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_modsecurity_loc_conf_t *cf;

    dd("catching a new _preaccess_ pahase handler");

    cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);
    if (cf == NULL || cf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return NGX_DECLINED;
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_POST) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST or GET");
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("ctx is null; Nothing we can do, returning an error.");
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
        r->request_body_in_clean_file = 1;

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
        int already_inspected = 0;

        dd("request body is ready to be processed");

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
            /*
             * Request body was saved to a file, probably we don't have a
             * copy of it in memory.
             */
            dd("request body inspection: file -- %s", file_name);

            msc_request_body_from_file(ctx->modsec_assay, file_name);

            already_inspected = 1;
        } else {
            dd("inspection request body in memory.");
        }

        while (chain && !already_inspected)
        {
            u_char *data = chain->buf->start;

            msc_append_request_body(ctx->modsec_assay, data,
                chain->buf->end - data);

            if (chain->buf->last_buf)
            {
                break;
            }
            chain = chain->next;

            /**
             * ModSecurity may perform stream inspection on this buffer,
             * it may ask for a intervention in consequence of that.
             * 
             */
            ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
            if (ret > 0)
            {
                return ret;
            }
        }

        /**
         * At this point, all the request body was sent to ModSecurity 
         * and we want to make sure that all the request body inspection
         * happened; consequently we have to check if ModSecurity have
         * returned any kind of intervention.
         */

        msc_process_request_body(ctx->modsec_assay);
        ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
        if (ret > 0)
        {
            return ret;
        }
    }

    dd("Nothing to add on the body inspection, reclaiming a NGX_DECLINED");
#endif
    return NGX_DECLINED;
}


void ngx_http_modsecurity_request_read(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

#if defined(nginx_version) && nginx_version >= 8011
    r->main->count--;
#endif

    if (ctx->waiting_more_body)
    {
        ctx->waiting_more_body = 0;
        ngx_http_core_run_phases(r);
    }
}


#ifndef DISABLE_HEADER_FILTER
static ngx_int_t
ngx_http_modsecurity_header_filter(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_list_part_t *part = &r->headers_out.headers.part;
    ngx_table_elt_t *data = part->elts;
    ngx_uint_t i = 0;
    int ret = 0;
    ngx_http_modsecurity_loc_conf_t *cf;

    cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity);
    if (cf == NULL || cf->enable != 1)
    {
        dd("ModSecurity not enabled... returning");
        return ngx_http_next_header_filter(r);
    }
    if (r->method != NGX_HTTP_GET && r->method != NGX_HTTP_POST) {
        dd("ModSecurity is not ready to deal with anything different from " \
            "POST or GET");
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity);

    dd("header filter, recovering ctx: %p", ctx);

    if (ctx == NULL)
    {
        dd("something really bad happened here. going to the next filter.");
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

        msc_add_n_response_header(ctx->modsec_assay,
            (const unsigned char *) data[i].key.data,
            data[i].key.len,
            (const unsigned char *) data[i].value.data,
            data[i].value.len);
    }

    msc_process_response_headers(ctx->modsec_assay);
    ret = ngx_http_modsecurity_process_intervention(ctx->modsec_assay, r);
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
#endif

#ifndef DISABLE_BODY_FILTER
static ngx_int_t
ngx_http_modsecurity_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
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
#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
