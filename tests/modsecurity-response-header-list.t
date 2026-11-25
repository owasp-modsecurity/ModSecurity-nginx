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


# Tests for ModSecurity-nginx connector (response headers taken from the
# header list, issue #230).
#
# * A header another filter deleted (hash 0) is not sent and must not be
#   seen.  The SSI filter runs before this module and deletes ETag.
# * Server, Date and Last-Modified are submitted by dedicated resolvers.  On a
#   proxied response the dedicated fields point into the header list, so the
#   list walk must not submit them a second time.

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

my $t = Test::Nginx->new()->has(qw/http proxy ssi/);

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
        default_type text/html;

        location /ssi/ {
            ssi on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:ETag "!@eq 0" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        location /plain/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:ETag "!@eq 0" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        location /once/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_pass_header Server;
            proxy_pass_header Date;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Server "!@eq 1" \
                    "id:3,phase:3,deny,status:403"
                SecRule &RESPONSE_HEADERS:Date "!@eq 1" \
                    "id:4,phase:3,deny,status:403"
                SecRule &RESPONSE_HEADERS:Last-Modified "!@eq 1" \
                    "id:5,phase:3,deny,status:403"
            ';
        }

        location /value/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_pass_header Server;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Server "@streq upstream-server" \
                    "id:6,phase:3,deny,status:403"
            ';
        }

        location /lm/ {
            proxy_pass http://127.0.0.1:8081/;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Last-Modified \
                    "@streq Mon, 02 Jan 2006 15:04:05 GMT" \
                    "id:7,phase:3,deny,status:403"
            ';
        }

        location /pass/ {
            proxy_pass http://127.0.0.1:8081/;
            proxy_pass_header Server;
            modsecurity_rules '
                SecRuleEngine On
            ';
        }
    }
}
EOF

mkdir($t->testdir() . '/ssi');
mkdir($t->testdir() . '/plain');
$t->write_file('ssi/index.html', 'SEE-THIS');
$t->write_file('plain/index.html', 'SEE-THIS');
$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(10);

###############################################################################

my $r;

$r = http_get('/ssi/index.html');
like($r, qr/^HTTP.* 200.*SEE-THIS/s, 'ETag deleted by ssi not seen');
unlike($r, qr/ETag/i, 'ETag deleted by ssi not sent');
like(http_get('/plain/index.html'), qr/^HTTP.* 403/, 'ETag seen without ssi');

$r = http_get('/once/ok');
like($r, qr/^HTTP.* 200.*SEE-THIS/s,
    'proxied Server, Date and Last-Modified seen once');
like(http_get('/pass/ok'), qr/\x0d\x0aServer: upstream-server\x0d\x0a/,
    'proxied Server sent');
like(http_get('/value/ok'), qr/^HTTP.* 403/, 'proxied Server value seen');

# An upstream's Last-Modified is sent whatever the status.

like(http_get('/lm/ok'), qr/^HTTP.* 403/, 'proxied Last-Modified seen on 200');
like(http_get('/lm/missing'), qr/^HTTP.* 403/,
    'proxied Last-Modified seen on 404');
$r = http_get('/pass/missing');
like($r, qr/^HTTP.* 404/, 'proxied 404');
like($r, qr/\x0d\x0aLast-Modified: Mon, 02 Jan 2006 15:04:05 GMT\x0d\x0a/,
    'proxied Last-Modified sent on 404');

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

		my $headers = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my $status = $headers =~ /^\S+ \/ok / ? '200 OK' : '404 Not Found';

		print $client <<"EOF";
HTTP/1.1 $status\r
Server: upstream-server\r
Date: Mon, 02 Jan 2006 15:04:05 GMT\r
Last-Modified: Mon, 02 Jan 2006 15:04:05 GMT\r
Content-Length: 8\r
Connection: close\r
\r
SEE-THIS
EOF

		close $client;
	}
}

###############################################################################
