#!/usr/bin/perl

#
# ModSecurity connector for nginx, http://www.modsecurity.org/
# Copyright (c) 2026 OWASP Foundation (http://www.owasp.org/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact OWASP.
#


# Tests for ModSecurity-nginx connector (the Server response header nginx
# adds itself, as seen by the rules).

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

        location /tokens-off {
            server_tokens off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "@streq nginx" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        location /tokens-on {
            server_tokens on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "@rx ^nginx/[0-9.]+$" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        location /no-match {
            server_tokens off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "@streq apache" \
                    "id:3,phase:3,deny,status:403"
            ';
        }
    }
}
EOF

$t->write_file('tokens-off', 'SEE-THIS');
$t->write_file('tokens-on', 'SEE-THIS');
$t->write_file('no-match', 'SEE-THIS');
$t->run();
$t->plan(3);

###############################################################################

like(http_get('/tokens-off'), qr/^HTTP.* 403/, 'server_tokens off, exact match');
like(http_get('/tokens-on'), qr/^HTTP.* 403/, 'server_tokens on, anchored match');
like(http_get('/no-match'), qr/^HTTP.* 200.*SEE-THIS/s, 'no match');

###############################################################################
