#!/usr/bin/perl

#
# ModSecurity, http://www.modsecurity.org/
# Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact Trustwave Holdings, Inc.
# directly using the email address security@modsecurity.org.
#


# Regression test for a WAF-triggered redirect (a phase:3 "redirect:" action)
# replacing an already-populated response.
#
# ngx_http_modsecurity_header_filter() used to report a redirect via
# ngx_http_filter_finalize_request(), which calls nginx's own
# ngx_http_clean_header() and memzeroes the entire headers_out struct --
# including the Location header ModSecurity had just built -- before nginx
# regenerated its own generic, Location-less redirect page. The client never
# actually got redirected, and the discarded response's entity headers
# (Content-Length in particular) leaked into that generic page instead of
# being cleared.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        modsecurity on;
        modsecurity_rules_file %%TESTDIR%%/rules.conf;

        location / {
        }
    }
}
EOF

$t->write_file('rules.conf', <<'EOF');
SecRuleEngine On
SecRule REQUEST_HEADERS:X-Redirect-Me "@streq 1" "id:104,phase:3,redirect:'/other',log"
EOF

# A large body: if the discarded response leaks through anyway, it dwarfs the
# expected empty redirect body and its stale Content-Length would give it
# away.
$t->write_file('index.html', ('x' x 4096) . "\n");

$t->run();
$t->plan(5);

###############################################################################

my $plain = http_get('/');
like($plain, qr/^HTTP\/1\.[01] 200/, 'plain request passes through unmodified');

my $redirect = http(<<EOF);
GET / HTTP/1.0
Host: localhost
X-Redirect-Me: 1

EOF

like($redirect, qr/^HTTP\/1\.[01] 302/m, 'WAF redirect: status is 302');
# nginx absolutizes a relative Location value with the request's scheme and
# Host, so match on the path suffix rather than requiring the literal
# relative form the rule specified.
like($redirect, qr{^Location:.*/other\r?$}m, 'WAF redirect: Location header present');
like($redirect, qr/^Content-Length:\s*0\r?$/m,
    'WAF redirect: no stale Content-Length from the discarded response');
unlike($redirect, qr/x{100}/, 'WAF redirect: original response body was not sent');

###############################################################################
