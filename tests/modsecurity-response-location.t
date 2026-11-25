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


# Tests for ModSecurity-nginx connector (Location response header).
#
# nginx's terminal header filters, which run after the connector, turn a
# relative Location into an absolute URL when absolute_redirect is on.  The
# rules must see the Location that is sent.
#
# The redirect from a directory name without the trailing slash gives a
# relative Location ("/abs/dir/").

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

        location /abs/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq http://localhost:%%PORT_8080%%/abs/dir/" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        location /h2/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq http://localhost:%%PORT_8081%%/h2/dir/" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        # No Host header: the address of the listening socket.
        location /nohost/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq http://127.0.0.1:%%PORT_8080%%/nohost/dir/" \
                    "id:3,phase:3,deny,status:403"
            ';
        }

        location /name/ {
            server_name_in_redirect on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq http://localhost:%%PORT_8080%%/name/dir/" \
                    "id:4,phase:3,deny,status:403"
            ';
        }

        location /noport/ {
            port_in_redirect off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq http://example.com/noport/dir/" \
                    "id:5,phase:3,deny,status:403"
            ';
        }

        # nginx sends the relative Location as it is.
        location /relative/ {
            absolute_redirect off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location "@streq /relative/dir/" \
                    "id:6,phase:3,deny,status:403"
            ';
        }

        # No rules: what nginx sends.
        location /wire/ {
        }
    }
}
EOF

for my $dir (qw/abs h2 nohost name noport relative wire/) {
	mkdir($t->testdir() . "/$dir");
	mkdir($t->testdir() . "/$dir/dir");
}

$t->run()->plan(9);

###############################################################################

# What nginx sends, so that the tests below do not pass vacuously.

like(http_get('/wire/dir'),
	qr!^Location: http://localhost:@{[port(8080)]}/wire/dir/\x0d?$!m, 'wire: absolute');
like(get10('/wire/dir'),
	qr!^Location: http://127.0.0.1:@{[port(8080)]}/wire/dir/\x0d?$!m,
	'wire: no Host');

like(http_get('/abs/dir'), qr/^HTTP.* 403/, 'absolute Location seen');
is(h2_status('/h2/dir'), 403, 'absolute Location seen over HTTP/2');
like(get10('/nohost/dir'), qr/^HTTP.* 403/, 'no Host: local address');
like(http(<<EOF), qr/^HTTP.* 403/, 'server_name_in_redirect');
GET /name/dir HTTP/1.0
Host: example.com

EOF
like(http(<<EOF), qr/^HTTP.* 403/, 'port_in_redirect off');
GET /noport/dir HTTP/1.0
Host: example.com

EOF
like(http_get('/relative/dir'), qr/^HTTP.* 403/, 'absolute_redirect off');

# Another Host gives another Location, so the rule above does not match.
like(http(<<EOF), qr/^HTTP.* 301/, 'Host is used');
GET /abs/dir HTTP/1.0
Host: example.com

EOF

###############################################################################

sub get10 {
	my ($uri) = @_;
	return http("GET $uri HTTP/1.0\r\n\r\n");
}

sub h2_status {
	my ($path) = @_;

	my $s = Test::Nginx::HTTP2->new(port(8081));
	my $sid = $s->new_stream({ path => $path });
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

	return $frame ? $frame->{headers}->{':status'} : undef;
}

###############################################################################
