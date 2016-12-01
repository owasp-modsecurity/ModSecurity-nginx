#!/usr/bin/perl

# (C) Andrei Belov

# Tests for ModSecurity-nginx connector (request body operations).

###############################################################################

use warnings;
use strict;

use Test::More;
use Socket qw/ CRLF /;

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

        location /bodyaccess {
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQUEST_BODY "@rx BAD BODY" "id:11,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /nobodyaccess {
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess Off
                SecRule REQUEST_BODY "@rx BAD BODY" "id:21,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /bodylimitreject {
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyInMemoryLimit 128
                SecRequestBodyLimit 128
                SecRequestBodyLimitAction Reject
                SecRule REQUEST_BODY "@rx BAD BODY" "id:31,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }

        location /bodylimitprocesspartial {
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyInMemoryLimit 128
                SecRequestBodyLimit 128
                SecRequestBodyLimitAction ProcessPartial
                SecRule REQUEST_BODY "@rx BAD BODY" "id:41,phase:request,deny,log,status:403"
            ';
            proxy_pass http://127.0.0.1:8081;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(7);

###############################################################################

like(http_get_body('/bodyaccess', 'GOOD BODY'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'request body access on, pass');
like(http_get_body('/bodyaccess', 'VERY BAD BODY'), qr/403 Forbidden/, 'request body access on, block');
like(http_get_body('/nobodyaccess', 'VERY BAD BODY'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'request body access off, pass');
like(http_get_body('/bodylimitreject', 'BODY' x 32), qr/TEST-OK-IF-YOU-SEE-THIS/, 'request body limit reject, pass');
like(http_get_body('/bodylimitreject', 'BODY' x 33), qr/403 Forbidden/, 'request body limit reject, block');
like(http_get_body('/bodylimitprocesspartial', 'BODY' x 32 . 'BAD BODY'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'request body limit process partial, pass');
like(http_get_body('/bodylimitprocesspartial', 'BODY' x 30 . 'BAD BODY' x 32), qr/403 Forbidden/, 'request body limit process partial, block');

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
		my $uri = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;

		print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
		print $client "TEST-OK-IF-YOU-SEE-THIS"
			unless $headers =~ /^HEAD/i;

		close $client;
	}
}

sub http_get_body {
	my $uri = shift;
	my $last = pop;
	return http( join '', (map {
		my $body = $_;
		"GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Content-Length: " . (length $body) . CRLF . CRLF
		. $body
	} @_),
		"GET $uri HTTP/1.1" . CRLF
		. "Host: localhost" . CRLF
		. "Connection: close" . CRLF
		. "Content-Length: " . (length $last) . CRLF . CRLF
		. $last
	);
}

###############################################################################
