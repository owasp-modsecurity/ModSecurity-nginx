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

#ifndef __NGX_HTTP_MODSECURITY_H__
#define __NGX_HTTP_MODSECURITY_H__


typedef struct {
    ngx_http_request_t *r;
    Assay *modsec_assay;
    ModSecurityIntervention *delayed_intervention;

    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned processed:1;
} ngx_http_modsecurity_ctx_t;


typedef struct {
    ngx_str_t rules;
    ngx_str_t rules_file;
    ngx_str_t rules_remote_server;
    ngx_str_t rules_remote_key;

    ngx_flag_t enable;
    ngx_int_t id;

    Rules *rules_set;
} ngx_http_modsecurity_loc_conf_t;


typedef struct {
    ModSecurity *modsec;

} ngx_http_modsecurity_main_conf_t;


#endif

/* vi:set ft=c ts=4 sw=4 et fdm=marker: */
