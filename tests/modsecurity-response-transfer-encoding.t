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


# Tests for ModSecurity-nginx connector (Transfer-Encoding, and the
# Connection header it affects, in the response headers given to the rules).
#
# nginx's chunked filter runs after the connector's header filter.  It sends
# a body of unknown length chunked over HTTP/1.1, and closes the connection
# instead when it cannot chunk (HTTP/1.0, chunked_transfer_encoding off).
# With trailers it chunks and drops Content-Length.  The rules must see the
# headers that are sent.
#
# "ssi on" clears the length of the static files below before the connector
# runs, which gives a response of unknown length.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 ssi/);

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

        # Transfer-Encoding: chunked is seen when nginx sends it.
        location /chunked/ {
            ssi on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Transfer-Encoding "@streq chunked" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        # No Transfer-Encoding when the length is known.
        location /length/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Transfer-Encoding "!@eq 0" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        # Unknown length but no chunking: nginx closes the connection.
        location /unchunked/ {
            ssi on;
            chunked_transfer_encoding off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Transfer-Encoding "!@eq 0" \
                    "id:3,phase:3,deny,status:403"
                SecRule RESPONSE_HEADERS:Connection "!@streq close" \
                    "id:4,phase:3,deny,status:403"
            ';
        }

        location /keepalive/ {
            ssi on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Connection "!@streq close" \
                    "id:5,phase:3,deny,status:403"
            ';
        }

        # Trailers: chunked, and Content-Length is dropped.
        location /trailer/ {
            add_trailer X-Trailer value;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Transfer-Encoding "@streq chunked" \
                    "id:6,phase:3,deny,status:403"
            ';
        }

        location /trailer-length/ {
            add_trailer X-Trailer value;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Content-Length "!@eq 0" \
                    "id:7,phase:3,deny,status:403"
            ';
        }

        # No rules: what nginx sends.
        location /wire/ {
            ssi on;
        }

        location /wire-trailer/ {
            add_trailer X-Trailer value;
        }
    }
}
EOF

for my $dir (qw/chunked length unchunked keepalive trailer trailer-length
	wire wire-trailer/)
{
	mkdir($t->testdir() . "/$dir");
	$t->write_file("$dir/index.html", 'SEE-THIS');
}

$t->run()->plan(14);

###############################################################################

# What nginx sends, so that the tests below do not pass vacuously.

like(get11('/wire/'), qr/Transfer-Encoding: chunked/, 'wire: chunked');
like(get10('/wire/', 1), qr/Connection: close/, 'wire: HTTP/1.0 closes');
like(get11('/wire-trailer/'), qr/Transfer-Encoding: chunked/,
	'wire: trailer chunked');
unlike(get11('/wire-trailer/'), qr/Content-Length/,
	'wire: trailer has no length');

like(get11('/chunked/'), qr/^HTTP.* 403/, 'chunked seen');
like(get10('/chunked/'), qr/^HTTP.* 200/, 'HTTP/1.0 not chunked');
like(http(<<EOF), qr/^HTTP.* 200/, 'HEAD not chunked');
HEAD /chunked/ HTTP/1.1
Host: localhost
Connection: close

EOF
is(h2_status('/chunked/'), 200, 'HTTP/2 not chunked');
like(get11('/length/'), qr/^HTTP.* 200/, 'known length not chunked');

like(get11('/unchunked/', 1), qr/^HTTP.* 200/,
	'chunked_transfer_encoding off closes');
like(get10('/keepalive/', 1), qr/^HTTP.* 200/,
	'HTTP/1.0 keep-alive closes');
like(get11('/keepalive/', 1), qr/^HTTP.* 403/, 'HTTP/1.1 keeps alive');

like(get11('/trailer/'), qr/^HTTP.* 403/, 'trailer chunked seen');
like(get11('/trailer-length/'), qr/^HTTP.* 200/, 'trailer length dropped');

###############################################################################

# An HTTP/1.1 request; with $keepalive, a second one follows on the same
# connection, so that http() does not wait for the keepalive timeout.
sub get11 {
	my ($uri, $keepalive) = @_;
	my $close = $keepalive ? '' : "Connection: close\n";
	my $next = $keepalive ? <<EOF : '';
GET $uri HTTP/1.1
Host: localhost
Connection: close

EOF

	return http(<<EOF . $next);
GET $uri HTTP/1.1
Host: localhost
$close
EOF
}

sub get10 {
	my ($uri, $keepalive) = @_;
	my $ka = $keepalive ? "Connection: keep-alive\n" : '';

	return http(<<EOF);
GET $uri HTTP/1.0
Host: localhost
$ka
EOF
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
