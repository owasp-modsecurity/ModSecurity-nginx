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


# Tests for ModSecurity-nginx connector (the Content-Length and Content-Type
# response headers seen by the rules match the wire, issue #413).
#
# A zero Content-Length is a real value and must reach the library.  nginx's
# terminal header filters drop Content-Length and Content-Type from a 204
# (always for HTTP/2, and for HTTP/1 unless the status line comes from an
# upstream); those filters run after this module, so the connector has to do
# the same.
#
# `try_files ... =code` runs after the access phase, so the transaction
# exists, and the response goes through ngx_http_special_response_handler(),
# which sets a zero Content-Length.

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

my $t = Test::Nginx->new()->has(qw/http http_v2 proxy/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        listen       127.0.0.1:8082 http2;
        server_name  localhost;

        modsecurity on;

        location /zero/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Content-Length "@eq 0" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        location = /created {
            try_files /missing =201;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Content-Length "@eq 0" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        location = /created-pass {
            try_files /missing =201;
            modsecurity_rules '
                SecRuleEngine On
            ';
        }

        location = /no-content {
            try_files /missing =204;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Content-Length "!@eq 0" \
                    "id:3,phase:3,deny,status:403"
            ';
        }

        location = /proxied-204 {
            proxy_pass http://127.0.0.1:8081;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Content-Length "!@eq 0" \
                    "id:4,phase:3,deny,status:403"
                SecRule &RESPONSE_HEADERS:Content-Type "!@eq 0" \
                    "id:5,phase:3,deny,status:403"
            ';
        }

        location = /proxied-204-pass {
            proxy_pass http://127.0.0.1:8081;
            modsecurity_rules '
                SecRuleEngine On
            ';
        }
    }
}
EOF

mkdir($t->testdir() . '/zero');
$t->write_file('zero/empty', '');
$t->write_file('zero/full', 'SEE-THIS');
$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(11);

###############################################################################

my ($r, $s, $sid, $frames, $frame);

like(http_get('/zero/empty'), qr/^HTTP.* 403/,
    'zero Content-Length seen on an empty file');
like(http_get('/zero/full'), qr/^HTTP.* 200.*SEE-THIS/s,
    'non-zero Content-Length does not match');

like(http_get('/created'), qr/^HTTP.* 403/,
    'zero Content-Length seen on a 201 built by nginx');
like(http_get('/created-pass'),
    qr/^HTTP.* 201.*\x0d\x0aContent-Length: 0\x0d\x0a/s,
    'the 201 carries Content-Length: 0 on the wire');

$r = http_get('/no-content');
like($r, qr/^HTTP.* 204/, 'no Content-Length seen on a 204 built by nginx');
unlike($r, qr/Content-Length/i, 'the 204 carries no Content-Length on the wire');

# The upstream's status line is passed through over HTTP/1, so nginx keeps the
# upstream's Content-Length and Content-Type and the rules must see them.

like(http_get('/proxied-204'), qr/^HTTP.* 403/,
    'proxied 204 headers seen over HTTP/1');
$r = http_get('/proxied-204-pass');
like($r, qr/^HTTP.* 204.*\x0d\x0aContent-Length: 0\x0d\x0a/s,
    'proxied 204 carries Content-Length over HTTP/1');
like($r, qr/\x0d\x0aContent-Type: text\/plain\x0d\x0a/,
    'proxied 204 carries Content-Type over HTTP/1');

# Over HTTP/2 nginx drops both, so the rules must not see them.

$s = Test::Nginx::HTTP2->new(port(8082));
$sid = $s->new_stream({ path => '/proxied-204' });
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 204, 'proxied 204 headers not seen over HTTP/2');

$s = Test::Nginx::HTTP2->new(port(8082));
$sid = $s->new_stream({ path => '/proxied-204-pass' });
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
ok(!exists $frame->{headers}->{'content-length'}
    && !exists $frame->{headers}->{'content-type'},
    'proxied 204 carries neither header over HTTP/2');

###############################################################################

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8081),
		Listen => 5,
		Reuse => 1
	)
		or die "Can't create listening socket: $!\n";

	local $SIG{PIPE} = 'IGNORE';

	while (my $client = $server->accept()) {
		$client->autoflush(1);

		while (<$client>) {
			last if (/^\x0d?\x0a?$/);
		}

		print $client <<"EOF";
HTTP/1.1 204 No Content\r
Content-Type: text/plain\r
Content-Length: 0\r
Connection: close\r
\r
EOF

		close $client;
	}
}

###############################################################################
