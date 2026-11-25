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


# Tests for ModSecurity-nginx connector (request headers with invalid names).
#
# With `ignore_invalid_headers off` nginx keeps a request header whose name
# has only invalid characters (e.g. "_" while underscores_in_headers is off)
# with a hash of 0, and the proxy module still forwards it.  Unlike a response
# header, a request header with hash 0 is therefore not a deleted one, and the
# rules must still see it.

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

my $t = Test::Nginx->new()->has(qw/http proxy/);

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

        ignore_invalid_headers off;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS "@contains attack-marker" \
                    "id:1,phase:1,deny,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "SEE-THIS";
        }
    }
}
EOF

$t->run();
$t->plan(4);

###############################################################################

like(get('X-Valid'), qr/^HTTP.* 403/, 'valid header name seen');
like(get('_'), qr/^HTTP.* 403/, 'underscore-only header name seen');
like(get('@'), qr/^HTTP.* 403/, 'invalid header name seen');
like(http_get('/'), qr/^HTTP.* 200.*SEE-THIS/s, 'no marker passes');

###############################################################################

sub get {
	my ($name) = @_;
	return http(<<EOF);
GET / HTTP/1.0
Host: localhost
$name: attack-marker

EOF
}

###############################################################################
