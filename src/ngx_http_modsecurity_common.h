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


#ifndef _NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_
#define _NGX_HTTP_MODSECURITY_COMMON_H_INCLUDED_

#include <nginx.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>
#include <modsecurity/rules.h>

typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
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


extern ngx_module_t ngx_http_modsecurity;
extern ngx_http_output_header_filter_pt ngx_http_modsecurity_next_header_filter;
extern ngx_http_output_body_filter_pt ngx_http_modsecurity_next_body_filter;


extern int ngx_http_modsecurity_process_intervention (Transaction *transaction, ngx_http_request_t *r);
extern ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r);
extern char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p);


#endif
