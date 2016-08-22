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

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf);
static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_modsecurity_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_modsecurity_main_config_cleanup(void *data);
static void ngx_http_modsecurity_config_cleanup(void *data);

/*
 * pcre malloc/free hack magic
 */
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);

void
ngx_http_modsecurity_pcre_malloc_init(void)
{
    old_pcre_malloc = pcre_malloc;
    old_pcre_free = pcre_free;

    pcre_malloc = malloc;
    pcre_free = free;
}

void
ngx_http_modsecurity_pcre_malloc_done(void)
{
    if (old_pcre_malloc == NULL)
        return;

    pcre_malloc = old_pcre_malloc;
    pcre_free = old_pcre_free;

    old_pcre_malloc = NULL;
    old_pcre_free = NULL;
}

/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to ModSecurity
 */
ngx_inline char *
ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    char *str = NULL;

    if (a.len == 0) {
        return NULL;
    }

    str = ngx_pnalloc(p, a.len+1);
    if (str == NULL) {
            dd("failed to allocate memory to convert space ngx_string to C string");
            /* We already returned NULL for an empty string, so return -1 here to indicate allocation error */
            return (char *)-1;
    }
    ngx_memcpy(str, a.data, a.len);
    str[a.len] = '\0';

    return str;
}


ngx_inline int
ngx_http_modsecurity_process_intervention (Transaction *transaction, ngx_http_request_t *r)
{
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;

    dd("processing intervention");

    if (msc_intervention(transaction, &intervention) == 0) {
        dd("nothing to do");
        return 0;
    }

    if (intervention.log == NULL) {
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

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
        ngx_http_modescurity_store_ctx_header(r, &location->key, &location->value);
#endif

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


void
ngx_http_modsecurity_cleanup(void *data)
{
    ngx_http_modsecurity_ctx_t *ctx;

    ctx = (ngx_http_modsecurity_ctx_t *) data;

    msc_transaction_cleanup(ctx->modsec_transaction);

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    /*
     * Purge stored context headers.  Memory allocated for individual stored header
     * name/value pair will be freed automatically when r->pool is destroyed.
     */
    ngx_array_destroy(ctx->sanity_headers_out);
#endif
}


ngx_inline ngx_http_modsecurity_ctx_t *
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
    cf = ngx_http_get_module_main_conf(r, ngx_http_modsecurity_module);
    loc_cf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    dd("creating transaction with the following rules: '%p' -- ms: '%p'", loc_cf->rules_set, cf->modsec);

    ctx->modsec_transaction = msc_new_transaction(cf->modsec, loc_cf->rules_set, r->connection->log);

    dd("transaction created");

    ngx_http_set_ctx(r, ctx, ngx_http_modsecurity_module);

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (cln == NULL)
    {
        dd("failed to create the ModSecurity context cleanup");
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_modsecurity_cleanup;
    cln->data = ctx;

#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ctx->sanity_headers_out = ngx_array_create(r->pool, 12, sizeof(ngx_http_modsecurity_header_t));
    if (ctx->sanity_headers_out == NULL) {
        return NGX_CONF_ERROR;
    }
#endif

    return ctx;
}

static char *
ngx_http_modsecurity_set_remote_server(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char *p = conf;
    ngx_str_t *field, *field2, *value;

    dd("Setting the remote server variables.");

    field = (ngx_str_t *) (p + cmd->offset);
    field2 = (ngx_str_t *) (p + cmd->offset + sizeof(ngx_str_t));

    if (field->data) {
        return "occurs multiple times";
    }

    value = cf->args->elts;

    *field = value[2];
    *field2 = value[1];

    return NGX_CONF_OK;

}


static ngx_command_t ngx_http_modsecurity_commands[] =  {
  {
    ngx_string("modsecurity"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_sanity_checks"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, sanity_checks_enabled),
    NULL
  },
  {
    ngx_string("modsecurity_rules_file"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules_file),
    NULL
  },
  {
    ngx_string("modsecurity_rules_remote"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
    ngx_http_modsecurity_set_remote_server,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules_remote_server),
    NULL
  },
  {
    ngx_string("modsecurity_rules"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_str_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_loc_conf_t, rules),
    NULL
  },
  ngx_null_command
};


static ngx_http_module_t ngx_http_modsecurity_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_modsecurity_init,              /* postconfiguration */

    ngx_http_modsecurity_create_main_conf,  /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_modsecurity_create_loc_conf,   /* create location configuration */
    ngx_http_modsecurity_merge_loc_conf     /* merge location configuration */
};


ngx_module_t ngx_http_modsecurity_module = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_ctx,              /* module context */
    ngx_http_modsecurity_commands,          /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_modsecurity_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h_rewrite;
    ngx_http_handler_pt *h_preaccess;
    ngx_http_handler_pt *h_log;
    ngx_http_core_main_conf_t *cmcf;
    int rc = 0;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (cmcf == NULL)
    {
        dd("We are not sure how this returns, NGINX doesn't seem to think it will ever be null");
        return NGX_ERROR;
    }
    /**
     *
     * Seems like we cannot do this very same thing with
     * NGX_HTTP_FIND_CONFIG_PHASE. it does not seems to
     * be an array. Our next option is the REWRITE.
     *
     * TODO: check if we can hook prior to NGX_HTTP_REWRITE_PHASE phase.
     *
     */
    h_rewrite = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h_rewrite == NULL)
    {
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
    if (h_preaccess == NULL)
    {
        dd("Not able to create a new NGX_HTTP_PREACCESS_PHASE handle");
        return NGX_ERROR;
    }
    *h_preaccess = ngx_http_modsecurity_pre_access_handler;

    /**
     * Process the log phase.
     *
     * TODO: check if the log phase happens like it happens on Apache.
     *       check if last phase will not hold the request.
     *
     */
    h_log = ngx_array_push(&cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h_log == NULL)
    {
        dd("Not able to create a new NGX_HTTP_LOG_PHASE handle");
        return NGX_ERROR;
    }
    *h_log = ngx_http_modsecurity_log_handler;


    rc = ngx_http_modsecurity_header_filter_init();
    if (rc != NGX_OK) {
        return rc;
    }

    rc = ngx_http_modsecurity_body_filter_init();
    if (rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
}


static void *
ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_main_conf_t *conf;

    dd("creating the ModSecurity main configuration");

    /* ngx_pcalloc already sets all of this scructure to zeros. */
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_modsecurity_main_conf_t));

    if (conf == NULL) {
        dd("failed to allocate space for the ModSecurity configuration");
        return NGX_CONF_ERROR;
    }

    /* Create our ModSecurity instace */
    conf->modsec = msc_init();
    if (conf->modsec == NULL)
    {
        dd("failed to create the ModSecurity instance");
        return NGX_CONF_ERROR;
    }

    ngx_pool_cleanup_t *cln = NULL;

    /* Provide our connector information to LibModSecurity */
    msc_set_connector_info(conf->modsec, "ModSecurity-nginx v0.1.1-beta");
    msc_set_log_cb(conf->modsec, ngx_http_modsecurity_log);

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL)
    {
        dd("failed to create the ModSecurity main configuration cleanup");
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_modsecurity_main_config_cleanup;
    cln->data = conf;


    return conf;
}


static void *
ngx_http_modsecurity_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_modsecurity_loc_conf_t  *conf;
    ngx_pool_cleanup_t *cln = NULL;

    conf = (ngx_http_modsecurity_loc_conf_t  *)
        ngx_palloc(cf->pool, sizeof(ngx_http_modsecurity_loc_conf_t));
    dd("creating a location specific conf");

    if (conf == NULL)
    {
        dd("Failed to allocate space for a location specific conf");
        return NGX_CONF_ERROR;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->sanity_checks_enabled = NGX_CONF_UNSET;
    conf->rules_remote_server.len = 0;
    conf->rules_remote_server.data = NULL;
    conf->rules_remote_key.len = 0;
    conf->rules_remote_key.data = NULL;
    conf->rules_file.len = 0;
    conf->rules_file.data = NULL;
    conf->rules.len = 0;
    conf->rules.data = NULL;
    conf->id = 0;

    /* Create a new rules instance */
    conf->rules_set = msc_create_rules_set();

    dd("created a location specific conf -- RuleSet is at: \"%p\"", conf->rules_set);

    //msc_rules_dump(conf->rules_set); // This was for debug
    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        dd("failed to create the ModSecurity location specific configuration cleanup");
        return NGX_CONF_ERROR;
    }
    cln->handler = ngx_http_modsecurity_config_cleanup;
    cln->data = conf;

    return conf;
}


static char *
ngx_http_modsecurity_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_modsecurity_loc_conf_t *p = NULL;
    ngx_http_modsecurity_loc_conf_t *c = NULL;

    p = parent;
    c = child;

    ngx_conf_merge_value(c->enable, p->enable, 0);
    ngx_conf_merge_value(c->sanity_checks_enabled, p->sanity_checks_enabled, 0);

    dd("Rules set: '%p'\n", c->rules_set);
    dd("Parent ModSecurityRuleSet is: '%p' current is: '%p'", p->rules_set, c->rules_set);
    if (p->rules_set != NULL)
    {
        dd("Parent is not null, so we have to merge these configurations");
        msc_rules_merge(c->rules_set, p->rules_set);
    }


    /**
     * FIXME: Fix the rules inclusion order.
     *
     * We are not respecting the order of the rules inclusion,
     * we should; It is not hard to do. Maybe for further
     * versions.
     */
    if (c->rules_remote_server.len > 0)
    {
        int res;
        const char *error = NULL;
        const char *rules_remote_server = ngx_str_to_char(c->rules_remote_server, cf->pool);
        if (rules_remote_server == (char *)-1) {
            return NGX_CONF_ERROR;
        }
        const char *rules_remote_key = ngx_str_to_char(c->rules_remote_key, cf->pool);
        if (rules_remote_key == (char *)-1) {
            return NGX_CONF_ERROR;
        }
        ngx_http_modsecurity_pcre_malloc_init();
        res = msc_rules_add_remote(c->rules_set, rules_remote_key, rules_remote_server, &error);
        ngx_http_modsecurity_pcre_malloc_done();
        dd("Loading rules from: '%s'", rules_remote_server);
        if (res < 0) {
            dd("Failed to load the rules from: '%s'  - reason: '%s'", rules_remote_server, error);
            return strdup(error);
        }
        dd("Loaded '%d' rules.", res);
    }
    if (c->rules_file.len > 0)
    {
        int res;
        const char *error = NULL;
        char *rules_set = ngx_str_to_char(c->rules_file, cf->pool);
        if (rules_set == (char *)-1) {
            return NGX_CONF_ERROR;
        }
        ngx_http_modsecurity_pcre_malloc_init();
        res = msc_rules_add_file(c->rules_set, rules_set, &error);
        ngx_http_modsecurity_pcre_malloc_done();
        dd("Loading rules from: '%s'", rules_set);
        if (res < 0) {
            dd("Failed to load the rules from: '%s' - reason: '%s'", rules_set, error);
            return strdup(error);
        }
        dd("Loaded '%d' rules.", res);
    }
    if (c->rules.len > 0)
    {
        int res;
        const char *error = NULL;
        char *rules = ngx_str_to_char(c->rules, cf->pool);
        if (rules == (char *)-1) {
            return NGX_CONF_ERROR;
        }
        ngx_http_modsecurity_pcre_malloc_init();
        res = msc_rules_add(c->rules_set, rules, &error);
        ngx_http_modsecurity_pcre_malloc_done();
        dd("Loading rules: '%s'", rules);
        if (res < 0) {
            dd("Failed to load the rules: '%s' - reason: '%s'", rules, error);
            return strdup(error);
        }
    }
#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    msc_rules_dump(c->rules_set);
#endif
    return NGX_CONF_OK;
}


static void
ngx_http_modsecurity_main_config_cleanup(void *data)
{
    ngx_http_modsecurity_main_conf_t *cf = data;
    msc_cleanup(cf->modsec);
    cf->modsec = NULL;
}


static void
ngx_http_modsecurity_config_cleanup(void *data)
{
    ngx_http_modsecurity_loc_conf_t *t = (ngx_http_modsecurity_loc_conf_t *) data;
    dd("deleting a loc conf -- RuleSet is: \"%p\"", t->rules_set);
    ngx_http_modsecurity_pcre_malloc_init();
    msc_rules_cleanup(t->rules_set);
    ngx_http_modsecurity_pcre_malloc_done();
    t->rules_set = NULL;
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
