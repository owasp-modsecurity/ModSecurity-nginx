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


#ifndef _NGX_HTTP_MODSECURITY_HEADER_FILTER_H_INCLUDED_
#define _NGX_HTTP_MODSECURITY_HEADER_FILTER_H_INCLUDED_


#include "ngx_http_modsecurity_common.h"


ngx_int_t ngx_http_modsecurity_header_filter_init(void);

ngx_int_t ngx_http_modsecurity_header_filter(ngx_http_request_t *r);

#endif
