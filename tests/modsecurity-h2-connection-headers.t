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


# Tests for ModSecurity-nginx connector (Connection and Keep-Alive response
# headers are HTTP/1 only).
#
# The connector builds Connection and Keep-Alive for the rules, since nginx
# only adds them in its terminal HTTP/1 header filter.  HTTP/2 forbids
# connection-specific header fields and nginx never sends them there, so a
# rule on them must not match an HTTP/2 response (issue #415).
#
# The response protocol handed to the library follows the request's version.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v2/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8081 http2;
        server_name  localhost;

        modsecurity on;
        keepalive_timeout 75 60;

        location /connection {
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Connection "!@eq 0" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        location /protocol {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_PROTOCOL "@streq HTTP 2.0" \
                    "id:3,phase:3,deny,status:403"
            ';
        }

        location /keep-alive {
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Keep-Alive "!@eq 0" \
                    "id:2,phase:3,deny,status:403"
            ';
        }
    }
}
EOF

$t->write_file('connection', 'SEE-THIS');
$t->write_file('keep-alive', 'SEE-THIS');
$t->write_file('protocol', 'SEE-THIS');
$t->run();
$t->plan(6);

###############################################################################

# HTTP/1: both headers are sent, and seen.

like(http_get('/connection'), qr/^HTTP.* 403/, 'Connection seen over HTTP/1');
# A keepalive request, followed by one that closes the connection so that
# http() does not wait for a timeout.
like(http(<<'EOF'), qr/^HTTP.* 403/, 'Keep-Alive seen over HTTP/1');
GET /keep-alive HTTP/1.1
Host: localhost

GET /keep-alive HTTP/1.1
Host: localhost
Connection: close

EOF

# HTTP/2: neither is sent, so neither may be seen.

is(h2_status('/connection'), 200, 'Connection not seen over HTTP/2');

# nginx never sets keepalive on an HTTP/2 stream, so this one only guards
# against a regression.
is(h2_status('/keep-alive'), 200, 'Keep-Alive not seen over HTTP/2');

like(http_get('/protocol'), qr/^HTTP.* 200/, 'response protocol over HTTP/1');
is(h2_status('/protocol'), 403, 'response protocol over HTTP/2');

###############################################################################

sub h2_status {
	my ($path) = @_;

	my $s = Test::Nginx::HTTP2->new(port(8081));
	my $sid = $s->new_stream({ path => $path });
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

	return $frame ? $frame->{headers}->{':status'} : undef;
}

###############################################################################
