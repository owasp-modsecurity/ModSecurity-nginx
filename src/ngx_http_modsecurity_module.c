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
#include "stdio.h"
#include <ctype.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef _MSC_VER
#define strdup _strdup
#endif

static ngx_int_t ngx_http_modsecurity_init(ngx_conf_t *cf);
static void *ngx_http_modsecurity_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_modsecurity_create_conf(ngx_conf_t *cf);
static char *ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child);
static void ngx_http_modsecurity_cleanup_instance(void *data);
static void ngx_http_modsecurity_cleanup_rules(void *data);
static char *ngx_conf_set_phase4_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_phase4_content_types_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_phase4_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_modsecurity_phase4_set_default_content_types(ngx_conf_t *cf, ngx_http_modsecurity_conf_t *mcf);
static char *ngx_http_modsecurity_phase4_load_content_types_file(ngx_conf_t *cf, ngx_http_modsecurity_conf_t *mcf, ngx_str_t *path);
static ngx_int_t ngx_http_modsecurity_phase4_validate_content_type(u_char *s, size_t len);

/*
 * PCRE malloc/free workaround, based on
 * https://github.com/openresty/lua-nginx-module/blob/master/src/ngx_http_lua_pcrefix.c
 */

#if !(NGX_PCRE2)
static void *(*old_pcre_malloc)(size_t);
static void (*old_pcre_free)(void *ptr);
static ngx_pool_t *ngx_http_modsec_pcre_pool = NULL;

static void *
ngx_http_modsec_pcre_malloc(size_t size)
{
    if (ngx_http_modsec_pcre_pool) {
        return ngx_palloc(ngx_http_modsec_pcre_pool, size);
    }

    fprintf(stderr, "error: modsec pcre malloc failed due to empty pcre pool");

    return NULL;
}

static void
ngx_http_modsec_pcre_free(void *ptr)
{
    if (ngx_http_modsec_pcre_pool) {
        ngx_pfree(ngx_http_modsec_pcre_pool, ptr);
        return;
    }

#if 0
    /* this may happen when called from cleanup handlers */
    fprintf(stderr, "error: modsec pcre free failed due to empty pcre pool");
#endif

    return;
}

ngx_pool_t *
ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t  *old_pool;

    if (pcre_malloc != ngx_http_modsec_pcre_malloc) {
        ngx_http_modsec_pcre_pool = pool;

        old_pcre_malloc = pcre_malloc;
        old_pcre_free = pcre_free;

        pcre_malloc = ngx_http_modsec_pcre_malloc;
        pcre_free = ngx_http_modsec_pcre_free;

        return NULL;
    }

    old_pool = ngx_http_modsec_pcre_pool;
    ngx_http_modsec_pcre_pool = pool;

    return old_pool;
}

void
ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *old_pool)
{
    ngx_http_modsec_pcre_pool = old_pool;

    if (old_pool == NULL) {
        pcre_malloc = old_pcre_malloc;
        pcre_free = old_pcre_free;
    }
}
#endif

/*
 * ngx_string's are not null-terminated in common case, so we need to convert
 * them into null-terminated ones before passing to ModSecurity
 */
ngx_inline char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
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


int
ngx_http_modsecurity_process_intervention (Transaction *transaction, ngx_http_request_t *r, ngx_int_t early_log)
{
    char *log = NULL;
    ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;
    ngx_http_modsecurity_ctx_t *ctx = NULL;
    ngx_http_modsecurity_conf_t  *mcf;

    dd("processing intervention");

    ctx = ngx_http_modsecurity_get_module_ctx(r);
    if (ctx == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (msc_intervention(transaction, &intervention) == 0) {
        dd("nothing to do");
        return 0;
    }
    ctx->last_intervention_status = intervention.status;
    ctx->last_intervention_log.len = 0;
    ctx->last_intervention_log.data = NULL;
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);
    if (mcf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (mcf->phase4_log_file != NULL && r->header_sent && intervention.log != NULL) {
        size_t l = ngx_strlen(intervention.log);
        u_char *cp = ngx_pnalloc(r->pool, l + 1);
        if (cp != NULL) {
            ngx_memcpy(cp, intervention.log, l);
            cp[l] = '\0';
            ctx->last_intervention_log.data = cp;
            ctx->last_intervention_log.len = l;
        }
    }

    // logging to nginx error log can be disable by setting `modsecurity_use_error_log` to off
    if (mcf->use_error_log) {
        log = intervention.log;
        if (intervention.log == NULL) {
          log = "(no log message was specified)";
        }
        ngx_log_error(NGX_LOG_ERR, (ngx_log_t *)r->connection->log, 0, "%s", log);
    }

    if (intervention.log != NULL) {
        free(intervention.log);
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
        ngx_http_modsecurity_store_ctx_header(r, &location->key, &location->value);
#endif

        return intervention.status;
    }

    if (intervention.status != 200)
    {
        /**
         * FIXME: this will bring proper response code to audit log in case
         * when e.g. error_page redirect was triggered, but there still won't be another
         * required pieces like response headers etc.
         *
         */
        msc_update_status_code(ctx->modsec_transaction, intervention.status);

        if (early_log) {
            dd("intervention -- calling log handler manually with code: %d", intervention.status);
            ngx_http_modsecurity_log_handler(r);
            ctx->logged = 1;
	}

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


ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    ngx_str_t                          s;
    ngx_pool_cleanup_t                *cln;
    ngx_http_modsecurity_ctx_t        *ctx;
    ngx_http_modsecurity_conf_t       *mcf;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_modsecurity_ctx_t));
    if (ctx == NULL)
    {
        dd("failed to allocate memory for the context.");
        return NULL;
    }

    mmcf = ngx_http_get_module_main_conf(r, ngx_http_modsecurity_module);
    mcf = ngx_http_get_module_loc_conf(r, ngx_http_modsecurity_module);

    dd("creating transaction with the following rules: '%p' -- ms: '%p'", mcf->rules_set, mmcf->modsec);

    if (mcf->transaction_id) {
        if (ngx_http_complex_value(r, mcf->transaction_id, &s) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
        ctx->modsec_transaction = msc_new_transaction_with_id(mmcf->modsec, mcf->rules_set, (char *) s.data, r->connection->log);

    } else {
        ctx->modsec_transaction = msc_new_transaction(mmcf->modsec, mcf->rules_set, r->connection->log);
    }

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

ngx_inline ngx_http_modsecurity_ctx_t *
ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    ngx_http_modsecurity_ctx_t *ctx;
    ctx = ngx_http_get_module_ctx(r, ngx_http_modsecurity_module);
    if (ctx == NULL) {
        /*
         * refer <nginx>/src/http/modules/ngx_http_realip_module.c
         * if module context was reset, the original address
         * can still be found in the cleanup handler
         */
        ngx_pool_cleanup_t *cln;
        for (cln = r->pool->cleanup; cln; cln = cln->next) {
            if (cln->handler == ngx_http_modsecurity_cleanup) {
                ctx = cln->data;
                break;
            }
        }
    }
    return ctx;
}

char *
ngx_conf_set_rules(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                                res;
    char                              *rules;
    ngx_str_t                         *value;
    const char                        *error;
    ngx_pool_t                        *old_pool;
    ngx_http_modsecurity_conf_t       *mcf = conf;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules = ngx_str_to_char(value[1], cf->pool);

    if (rules == (char *)-1) {
        return NGX_CONF_ERROR;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add(mcf->rules_set, rules, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules: '%s' - reason: '%s'", rules, error);
        return strdup(error);
    }

    mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_inline += res;

    return NGX_CONF_OK;
}


char *
ngx_conf_set_rules_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                                res;
    char                              *rules_set;
    ngx_str_t                         *value;
    const char                        *error;
    ngx_pool_t                        *old_pool;
    ngx_http_modsecurity_conf_t       *mcf = conf;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules_set = ngx_str_to_char(value[1], cf->pool);

    if (rules_set == (char *)-1) {
        return NGX_CONF_ERROR;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add_file(mcf->rules_set, rules_set, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules from: '%s' - reason: '%s'", rules_set, error);
        return strdup(error);
    }

    mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_file += res;

    return NGX_CONF_OK;
}


char *
ngx_conf_set_rules_remote(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    int                                res;
    ngx_str_t                         *value;
    const char                        *error;
    const char                        *rules_remote_key, *rules_remote_server;
    ngx_pool_t                        *old_pool;
    ngx_http_modsecurity_conf_t       *mcf = conf;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    value = cf->args->elts;
    rules_remote_key = ngx_str_to_char(value[1], cf->pool);
    rules_remote_server = ngx_str_to_char(value[2], cf->pool);

    if (rules_remote_server == (char *)-1) {
        return NGX_CONF_ERROR;
    }

    if (rules_remote_key == (char *)-1) {
        return NGX_CONF_ERROR;
    }

    old_pool = ngx_http_modsecurity_pcre_malloc_init(cf->pool);
    res = msc_rules_add_remote(mcf->rules_set, rules_remote_key, rules_remote_server, &error);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);

    if (res < 0) {
        dd("Failed to load the rules from: '%s'  - reason: '%s'", rules_remote_server, error);
        return strdup(error);
    }

    mmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_modsecurity_module);
    mmcf->rules_remote += res;

    return NGX_CONF_OK;
}


char *ngx_conf_set_transaction_id(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_str_t                         *value;
    ngx_http_complex_value_t           cv;
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_modsecurity_conf_t *mcf = conf;

    value = cf->args->elts;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = &value[1];
    ccv.complex_value = &cv;
    ccv.zero = 1;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    mcf->transaction_id = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (mcf->transaction_id == NULL) {
        return NGX_CONF_ERROR;
    }

    *mcf->transaction_id = cv;

    return NGX_CONF_OK;
}

static char *
ngx_conf_set_phase4_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;
    ngx_str_t *value = cf->args->elts;
    if (ngx_strcmp(value[1].data, "minimal") == 0) mcf->phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_MINIMAL;
    else if (ngx_strcmp(value[1].data, "safe") == 0) mcf->phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_SAFE;
    else if (ngx_strcmp(value[1].data, "strict") == 0) mcf->phase4_mode = NGX_HTTP_MODSEC_PHASE4_MODE_STRICT;
    else return "invalid value for modsecurity_phase4_mode (expected minimal|safe|strict)";
    return NGX_CONF_OK;
}

static char *
ngx_conf_set_phase4_content_types_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;
    ngx_str_t *value = cf->args->elts;
    mcf->phase4_content_types_file = value[1];
    return ngx_http_modsecurity_phase4_load_content_types_file(cf, mcf, &value[1]);
}

static char *
ngx_conf_set_phase4_log(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_modsecurity_conf_t *mcf = conf;
    ngx_str_t *value = cf->args->elts;
    mcf->phase4_log_path = value[1];
    mcf->phase4_log_file = ngx_conf_open_file(cf->cycle, &mcf->phase4_log_path);
    if (mcf->phase4_log_file == NULL) {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_modsecurity_phase4_validate_content_type(u_char *s, size_t len)
{
    size_t i;
    size_t slash = (size_t)-1;
    if (len == 0 || ngx_strchr(s, '*') != NULL) return NGX_ERROR;
    for (i = 0; i < len; i++) {
        u_char c = s[i];
        if (c == '/') {
            if (slash != (size_t)-1 || i == 0 || i + 1 >= len) return NGX_ERROR;
            slash = i;
            continue;
        }
        if (!(isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_' || c == '+')) return NGX_ERROR;
    }
    return (slash != (size_t)-1) ? NGX_OK : NGX_ERROR;
}

static char *
ngx_http_modsecurity_phase4_set_default_content_types(ngx_conf_t *cf, ngx_http_modsecurity_conf_t *mcf)
{
    static const char *defs[] = {"text/html","text/plain","application/json","application/xml","text/xml","application/xhtml+xml"};
    ngx_uint_t i;
    if (mcf->phase4_content_types != NULL) return NGX_CONF_OK;
    mcf->phase4_content_types = ngx_array_create(cf->pool, 6, sizeof(ngx_str_t));
    if (mcf->phase4_content_types == NULL) return NGX_CONF_ERROR;
    for (i = 0; i < 6; i++) {
        ngx_str_t *ct = ngx_array_push(mcf->phase4_content_types);
        if (ct == NULL) return NGX_CONF_ERROR;
        ct->len = ngx_strlen(defs[i]);
        ct->data = ngx_pnalloc(cf->pool, ct->len);
        if (ct->data == NULL) return NGX_CONF_ERROR;
        ngx_memcpy(ct->data, defs[i], ct->len);
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_modsecurity_phase4_push_content_type(ngx_conf_t *cf, ngx_http_modsecurity_conf_t *mcf,
    u_char *line, u_char *end, ngx_str_t *path)
{
    ngx_str_t *ct;

    ngx_strlow(line, line, end - line);
    if (ngx_http_modsecurity_phase4_validate_content_type(line, end - line) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid content-type entry in modsecurity_phase4_content_types_file \"%V\": \"%s\"", path, line);
        return NGX_ERROR;
    }

    ct = ngx_array_push(mcf->phase4_content_types);
    if (ct == NULL) {
        return NGX_ERROR;
    }
    ct->len = end - line;
    ct->data = ngx_pnalloc(cf->pool, ct->len);
    if (ct->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ct->data, line, ct->len);

    return NGX_OK;
}

static void
ngx_http_modsecurity_phase4_trim_line(u_char **line, u_char **end)
{
    while (*line < *end && isspace((unsigned char)**line)) {
        (*line)++;
    }

    while (*end > *line && isspace((unsigned char)*((*end) - 1))) {
        (*end)--;
    }

    **end = '\0';
}

static void
ngx_http_modsecurity_phase4_strip_inline_comment(u_char *line)
{
    u_char *hash = (u_char *) ngx_strchr(line, '#');
    u_char *semi = (u_char *) ngx_strchr(line, ';');

    if (hash && (!semi || hash < semi)) {
        *hash = '\0';
    }
    if (semi) {
        *semi = '\0';
    }
}

static char *
ngx_http_modsecurity_phase4_load_content_types_file(ngx_conf_t *cf, ngx_http_modsecurity_conf_t *mcf, ngx_str_t *path)
{
    ngx_file_t file;
    ngx_file_info_t fi;
    u_char *buf;
    u_char *p;
    u_char *line;
    u_char *end;
    ssize_t n;
    if (ngx_file_info(path->data, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "modsecurity_phase4_content_types_file \"%V\" stat() failed", path);
        return NGX_CONF_ERROR;
    }
    buf = ngx_pnalloc(cf->pool, ngx_file_size(&fi) + 1);
    if (buf == NULL) return NGX_CONF_ERROR;
    ngx_memzero(&file, sizeof(file));
    file.name = *path;
    file.log = cf->log;
    file.fd = ngx_open_file(path->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (file.fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno, "modsecurity_phase4_content_types_file \"%V\" open() failed", path);
        return NGX_CONF_ERROR;
    }
    n = ngx_read_file(&file, buf, ngx_file_size(&fi), 0);
    ngx_close_file(file.fd);
    if (n < 0) return NGX_CONF_ERROR;
    buf[n] = '\0';
    mcf->phase4_content_types = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
    if (mcf->phase4_content_types == NULL) return NGX_CONF_ERROR;
    for (p = buf, line = buf; p <= buf + n; p++) {
        if (p == buf + n || *p == '\n' || *p == '\r') {
            *p = '\0';
            end = p;

            ngx_http_modsecurity_phase4_trim_line(&line, &end);
            if (line[0] == '\0' || line[0] == '#') {
                line = p + 1;
                continue;
            }

            ngx_http_modsecurity_phase4_strip_inline_comment(line);
            end = line + ngx_strlen(line);
            ngx_http_modsecurity_phase4_trim_line(&line, &end);
            if (line[0] == '\0') {
                line = p + 1;
                continue;
            }

            if (ngx_http_modsecurity_phase4_push_content_type(cf, mcf, line, end, path) != NGX_OK) {
                return NGX_CONF_ERROR;
            }
            line = p + 1;
        }
    }
    return NGX_CONF_OK;
}


static ngx_command_t ngx_http_modsecurity_commands[] =  {
  {
    ngx_string("modsecurity"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_rules"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_rules,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_rules_file"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_rules_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_rules_remote"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
    ngx_conf_set_rules_remote,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, enable),
    NULL
  },
  {
    ngx_string("modsecurity_transaction_id"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
    ngx_conf_set_transaction_id,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_phase4_mode"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_phase4_mode,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_phase4_content_types_file"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_phase4_content_types_file,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_phase4_log"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
    ngx_conf_set_phase4_log,
    NGX_HTTP_LOC_CONF_OFFSET,
    0,
    NULL
  },
  {
    ngx_string("modsecurity_use_error_log"),
    NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
    ngx_conf_set_flag_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_modsecurity_conf_t, use_error_log),
    NULL
  },
  ngx_null_command
};


static ngx_http_module_t ngx_http_modsecurity_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_modsecurity_init,             /* postconfiguration */

    ngx_http_modsecurity_create_main_conf, /* create main configuration */
    ngx_http_modsecurity_init_main_conf,   /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_modsecurity_create_conf,      /* create location configuration */
    ngx_http_modsecurity_merge_conf        /* merge location configuration */
};


ngx_module_t ngx_http_modsecurity_module = {
    NGX_MODULE_V1,
    &ngx_http_modsecurity_ctx,             /* module context */
    ngx_http_modsecurity_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_modsecurity_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h_access;
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
     * We want to process everything in the NGX_HTTP_ACCESS_PHASE because we need to allow 
     * ngx_http_limit_*_module to run
     *
     */

    h_access = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h_access == NULL)
    {
        dd("Not able to create a new NGX_HTTP_ACCESS_PHASE handle");
        return NGX_ERROR;
    }
    *h_access = ngx_http_modsecurity_access_handler;


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
    ngx_pool_cleanup_t                *cln;
    ngx_http_modsecurity_main_conf_t  *conf;

    conf = (ngx_http_modsecurity_main_conf_t *) ngx_pcalloc(cf->pool,
                                    sizeof(ngx_http_modsecurity_main_conf_t));

    if (conf == NULL)
    {
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->modsec = NULL;
     *     conf->pool = NULL;
     *     conf->rules_inline = 0;
     *     conf->rules_file = 0;
     *     conf->rules_remote = 0;
     */

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_modsecurity_cleanup_instance;
    cln->data = conf;

    conf->pool = cf->pool;

    /* Create our ModSecurity instance */
    conf->modsec = msc_init();
    if (conf->modsec == NULL)
    {
        dd("failed to create the ModSecurity instance");
        return NGX_CONF_ERROR;
    }

    /* Provide our connector information to LibModSecurity */
    msc_set_connector_info(conf->modsec, MODSECURITY_NGINX_WHOAMI);
    msc_set_log_cb(conf->modsec, ngx_http_modsecurity_log);

    dd ("main conf created at: '%p', instance is: '%p'", conf, conf->modsec);

    return conf;
}


static char *
ngx_http_modsecurity_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_modsecurity_main_conf_t  *mmcf;
    mmcf = (ngx_http_modsecurity_main_conf_t *) conf;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "%s (rules loaded inline/local/remote: %ui/%ui/%ui)",
                  MODSECURITY_NGINX_WHOAMI, mmcf->rules_inline,
                  mmcf->rules_file, mmcf->rules_remote);
    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "libmodsecurity3 version %s.%s.%s",
                  MODSECURITY_MAJOR, MODSECURITY_MINOR, MODSECURITY_PATCHLEVEL);

    return NGX_CONF_OK;
}


static void *
ngx_http_modsecurity_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t           *cln;
    ngx_http_modsecurity_conf_t  *conf;

    conf = (ngx_http_modsecurity_conf_t *) ngx_pcalloc(cf->pool,
                                         sizeof(ngx_http_modsecurity_conf_t));

    if (conf == NULL)
    {
        dd("Failed to allocate space for ModSecurity configuration");
        return NGX_CONF_ERROR;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->enable = 0;
     *     conf->sanity_checks_enabled = 0;
     *     conf->rules_set = NULL;
     *     conf->pool = NULL;
     *     conf->transaction_id = NULL;
     */

    conf->enable = NGX_CONF_UNSET;
    conf->rules_set = msc_create_rules_set();
    conf->pool = cf->pool;
    conf->transaction_id = NGX_CONF_UNSET_PTR;
    conf->use_error_log = NGX_CONF_UNSET;
    conf->phase4_mode = NGX_CONF_UNSET_UINT;
    conf->phase4_content_types = NULL;
    conf->phase4_content_types_file.len = 0;
    conf->phase4_content_types_file.data = NULL;
    conf->phase4_log_file = NULL;
    conf->phase4_log_path.len = 0;
    conf->phase4_log_path.data = NULL;
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    conf->sanity_checks_enabled = NGX_CONF_UNSET;
#endif

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        dd("failed to create the ModSecurity configuration cleanup");
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_http_modsecurity_cleanup_rules;
    cln->data = conf;

    dd ("conf created at: '%p'", conf);

    return conf;
}


static char *
ngx_http_modsecurity_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_modsecurity_conf_t *p = parent;
    ngx_http_modsecurity_conf_t *c = child;
#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
#endif
    int rules;
    const char *error = NULL;

    dd("merging loc config [%s] - parent: '%p' child: '%p'",
        ngx_str_to_char(clcf->name, cf->pool), parent,
        child);

    dd("                  state - parent: '%d' child: '%d'",
        (int) c->enable, (int) p->enable);

    ngx_conf_merge_value(c->enable, p->enable, 0);
    ngx_conf_merge_ptr_value(c->transaction_id, p->transaction_id, NULL);
    ngx_conf_merge_value(c->use_error_log, p->use_error_log, 1);
    ngx_conf_merge_uint_value(c->phase4_mode, p->phase4_mode, NGX_HTTP_MODSEC_PHASE4_MODE_SAFE);
    ngx_conf_merge_ptr_value(c->phase4_log_file, p->phase4_log_file, NULL);
    ngx_conf_merge_ptr_value(c->phase4_content_types, p->phase4_content_types, NULL);
#if defined(MODSECURITY_SANITY_CHECKS) && (MODSECURITY_SANITY_CHECKS)
    ngx_conf_merge_value(c->sanity_checks_enabled, p->sanity_checks_enabled, 0);
#endif

#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    dd("PARENT RULES");
    msc_rules_dump(p->rules_set);
    dd("CHILD RULES");
    msc_rules_dump(c->rules_set);
#endif
    rules = msc_rules_merge(c->rules_set, p->rules_set, &error);

    if (rules < 0) {
        return strdup(error);
    }

#if defined(MODSECURITY_DDEBUG) && (MODSECURITY_DDEBUG)
    dd("NEW CHILD RULES");
    msc_rules_dump(c->rules_set);
#endif
    if (c->phase4_content_types == NULL) {
        return ngx_http_modsecurity_phase4_set_default_content_types(cf, c);
    }
    return NGX_CONF_OK;
}


static void
ngx_http_modsecurity_cleanup_instance(void *data)
{
    ngx_pool_t                        *old_pool;
    ngx_http_modsecurity_main_conf_t  *mmcf;

    mmcf = (ngx_http_modsecurity_main_conf_t *) data;

    dd("deleting a main conf -- instance is: \"%p\"", mmcf->modsec);

    old_pool = ngx_http_modsecurity_pcre_malloc_init(mmcf->pool);
    msc_cleanup(mmcf->modsec);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
}


static void
ngx_http_modsecurity_cleanup_rules(void *data)
{
    ngx_pool_t                   *old_pool;
    ngx_http_modsecurity_conf_t  *mcf;

    mcf = (ngx_http_modsecurity_conf_t *) data;

    dd("deleting a loc conf -- RuleSet is: \"%p\"", mcf->rules_set);

    old_pool = ngx_http_modsecurity_pcre_malloc_init(mcf->pool);
    msc_rules_cleanup(mcf->rules_set);
    ngx_http_modsecurity_pcre_malloc_done(old_pool);
}


/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
