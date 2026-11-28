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


# Tests for ModSecurity module (request bodies NGINX buffers to a file).

###############################################################################

use warnings;
use strict;

use Test::More;
use Digest::MD5 qw/ md5_hex /;
use Socket qw/ CRLF /;

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

        modsecurity on;
        client_body_buffer_size 1k;
        client_max_body_size 1m;

        location /file {
            client_body_in_file_only clean;
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQUEST_BODY "@contains BAD BODY" "id:11,phase:2,deny,status:403"
                SecRule REQUEST_HEADERS:X-Phase2 "@streq deny" "id:12,phase:2,deny,status:409"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /spill {
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule REQUEST_BODY "@contains BAD BODY" "id:21,phase:2,deny,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /partial {
            client_body_in_file_only clean;
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 40000
                SecRequestBodyLimitAction ProcessPartial
                SecRule REQUEST_BODY "@contains BAD BODY" "id:31,phase:2,deny,status:403"
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /reject {
            client_body_in_file_only clean;
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRequestBodyLimit 40000
                SecRequestBodyLimitAction Reject
            ';
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));

$t->plan(23);

###############################################################################

# The body is read from the file in chunks of 32 KiB: these bodies end before,
# at and after a chunk boundary, and the rule matches across one.

my $chunk = 32768;
my $bad = 'BAD BODY';

passed('/file', 'GOOD BODY', 'small body in a file');
passed('/file', body(100000), 'body of four chunks in a file');
passed('/file', body(2 * $chunk), 'body of exactly two chunks in a file');
passed('/file', '', 'empty body in a file');

blocked('/file', 'VERY BAD BODY', 403, 'small body in a file, block');
blocked('/file', body($chunk - 4) . $bad . body(100), 403,
	'match across a chunk boundary in a file, block');
blocked('/file', body(3 * $chunk + 10) . $bad, 403,
	'match in the last chunk of a file, block');
blocked('/file', '', 409, 'empty body in a file runs the request body phase',
	'X-Phase2: deny');

# Without client_body_in_file_only, only bodies above client_body_buffer_size
# go to a file.

passed('/spill', body(20000), 'body spilled to a file');
blocked('/spill', body(20000) . $bad, 403, 'body spilled to a file, block');
blocked('/spill', 'VERY BAD BODY', 403, 'body in memory, block');

# ProcessPartial inspects the body up to SecRequestBodyLimit and passes the
# whole body on.

blocked('/partial', body(30000) . $bad . body(30000), 403,
	'process partial, match within the limit, block');
passed('/partial', body(50000) . $bad . body(10000),
	'process partial, match beyond the limit, pass');

# Reject denies a body above SecRequestBodyLimit after the request body phase.

passed('/reject', body(40000), 'reject, body at the limit');
blocked('/reject', body(40001), 403, 'reject, body above the limit, block');
blocked('/reject', body(100000), 403, 'reject, body of four chunks, block');

###############################################################################

sub body {
	my ($length) = @_;
	my $pattern = join '', map { chr(ord('a') + $_ % 26) } 0 .. 99;
	return substr($pattern x (int($length / 100) + 1), 0, $length);
}

sub post {
	my ($uri, $body, $header) = @_;
	$header = defined $header ? $header . CRLF : '';
	return http(
		"POST $uri HTTP/1.0" . CRLF
		. "Host: localhost" . CRLF
		. $header
		. "Content-Length: " . length($body) . CRLF . CRLF
		. $body
	);
}

# Checks the response, and that the upstream got the body unchanged.
sub passed {
	my ($uri, $body, $name) = @_;
	my $r = post($uri, $body);
	like($r, qr/^HTTP\/1\.[01] 200.*TEST-OK-IF-YOU-SEE-THIS/s, "$name, pass");
	my $expected = 'LENGTH=' . length($body) . ' MD5=' . md5_hex($body);
	like($r, qr/\Q$expected\E/, "$name, forwarded unchanged");
}

sub blocked {
	my ($uri, $body, $status, $name, $header) = @_;
	like(post($uri, $body, $header), qr/^HTTP\/1\.[01] $status/, $name);
}

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
		binmode $client;

		my $headers = '';

		while (<$client>) {
			$headers .= $_;
			last if (/^\x0d?\x0a?$/);
		}

		my $length = $headers =~ /^Content-Length:\s*(\d+)/mi ? $1 : 0;
		my $body = '';

		while (length($body) < $length) {
			my $n = $client->read($body, $length - length($body),
				length($body));
			last unless $n;
		}

		print $client "HTTP/1.1 200 OK" . CRLF
			. "Connection: close" . CRLF . CRLF
			. "TEST-OK-IF-YOU-SEE-THIS" . CRLF
			. "LENGTH=" . length($body) . " MD5=" . md5_hex($body) . CRLF;

		close $client;
	}
}

###############################################################################
