#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (modsecurity_request_body directive).

###############################################################################

use warnings;
use strict;

use Test::More;
use IO::Select;

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
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRule REQUEST_BODY "@rx BAD BODY" "id:11,phase:2,deny,log,status:403"
            SecRule ARGS:what "@streq badarg" "id:12,phase:2,deny,log,status:403"
        ';

        location /inspect {
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /skip {
            modsecurity_request_body off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /nobuffer {
            modsecurity_request_body off;
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /early {
            modsecurity_request_body off;
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /earlybuf {
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:%%PORT_8081%%;
        }

        location /parent {
            modsecurity_request_body off;

            location /parent/child {
                proxy_pass http://127.0.0.1:%%PORT_8081%%;
            }

            location /parent/on {
                modsecurity_request_body on;
                proxy_pass http://127.0.0.1:%%PORT_8081%%;
            }
        }
    }
}

EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8081));
$t->plan(12);

###############################################################################

like(http_post('/inspect', 'GOOD BODY'), qr/LEN=9/, 'default: good body passes');
like(http_post('/inspect', 'VERY BAD BODY'), qr/^HTTP.*403/, 'default: bad body blocked');
like(http_post('/skip', 'VERY BAD BODY'), qr/LEN=13/, 'off: body not inspected, upstream gets it');
like(http_post('/skip?what=badarg', 'GOOD BODY'), qr/^HTTP.*403/, 'off: phase 2 still runs on ARGS');
like(http_get('/skip'), qr/LEN=0/, 'off: GET without body works');
like(http_post('/nobuffer', 'VERY BAD BODY'), qr/LEN=13/, 'off + proxy_request_buffering off: full body reaches upstream');
like(http_post('/parent/child', 'VERY BAD BODY'), qr/LEN=13/, 'off inherited by nested location');
like(http_post('/parent/on', 'VERY BAD BODY'), qr/^HTTP.*403/, 'on overrides inherited off');
like(http_post('/parent/on', 'GOOD BODY'), qr/LEN=9/, 'on overrides inherited off, good body passes');

# the upstream must see the beginning of the request body before the client
# has sent all of it, otherwise the body is still being buffered by nginx

my $s = http_post_delayed('/early', 'VERY BAD BODY', 6);
like(http_read($s, 5), qr/EARLY LEN=6/,
	'off + proxy_request_buffering off: partial body streamed to upstream');
http_post_finish($s, 'VERY BAD BODY', 6);

$s = http_post_delayed('/earlybuf', 'VERY BAD BODY', 6);
is(http_read($s, 3), '',
	'on + proxy_request_buffering off: nothing sent upstream before the body is complete');
http_post_finish($s, 'VERY BAD BODY', 6);
like(http_read($s, 5), qr/^HTTP.*403/,
	'on + proxy_request_buffering off: complete body still inspected');

###############################################################################

sub http_post {
	my ($url, $body) = @_;
	my $len = length($body);
	return http(<<EOF);
POST $url HTTP/1.0
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: $len

$body
EOF
}

sub http_post_delayed {
	my ($url, $body, $sent) = @_;
	my $len = length($body);
	return http(<<EOF . substr($body, 0, $sent), start => 1);
POST $url HTTP/1.1
Host: localhost
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: $len

EOF
}

sub http_post_finish {
	my ($s, $body, $sent) = @_;

	local $SIG{PIPE} = 'IGNORE';

	eval {
		log_out(substr($body, $sent));
		$s->print(substr($body, $sent));
	};
}

sub http_read {
	my ($s, $timeout) = @_;
	my $reply = '';
	my $select = IO::Select->new($s);

	while ($select->can_read($timeout)) {
		my $buf = '';
		my $n = $s->sysread($buf, 1024);
		last if (!defined $n || $n == 0);
		$reply .= $buf;
	}

	log_in($reply);
	return $reply;
}

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

		my $select = IO::Select->new($client);
		my $buf = '';

		# the whole request is read with sysread(), so that no part of
		# it is left in a buffer where select() cannot see it

		while ($buf !~ /\x0d?\x0a\x0d?\x0a/) {
			last unless $select->can_read(5);
			my $chunk = '';
			my $n = $client->sysread($chunk, 1024);
			last if (!defined $n || $n == 0);
			$buf .= $chunk;
		}

		my ($headers, $body) = split(/\x0d?\x0a\x0d?\x0a/, $buf, 2);
		$headers = '' unless defined $headers;
		$body = '' unless defined $body;

		my $uri = '';
		my $len = 0;

		$uri = $1 if $headers =~ /^\S+\s+([^ ]+)\s+HTTP/i;
		$len = $1 if $headers =~ /Content-Length:\s*(\d+)/i;

		# /early answers with the part of the request body that nginx
		# has already forwarded, the other locations wait for all of it

		my $timeout = ($uri =~ m!^/early!) ? 1 : 5;

		while (length($body) < $len && $select->can_read($timeout)) {
			my $chunk = '';
			my $n = $client->sysread($chunk, $len - length($body));
			last if (!defined $n || $n == 0);
			$body .= $chunk;
		}

		my $got = length($body);

		if ($uri =~ m!^/early!) {
			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

EARLY LEN=$got
EOF
		} else {
			print $client <<"EOF";
HTTP/1.1 200 OK
Connection: close

TEST-OK LEN=$got
EOF
		}

		close $client;
	}
}

###############################################################################
