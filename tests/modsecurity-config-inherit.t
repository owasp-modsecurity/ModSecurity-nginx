#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (rules inheritance across blocks
# that declare no rules of their own: nested locations, if blocks, siblings).
# Content is proxied, not "return"ed: return runs in the rewrite phase, before
# ModSecurity's access phase handler.

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

my $t = Test::Nginx->new()->has(qw/http proxy rewrite/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity on;
    modsecurity_rules '
        SecRuleEngine On
        SecRule ARGS "@streq http" "id:1,phase:1,deny,status:403"
    ';

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /outer {
            location /outer/inner {
                proxy_pass http://127.0.0.1:%%PORT_8090%%;
            }
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /if {
            if ($arg_x) {
                proxy_pass http://127.0.0.1:%%PORT_8090%%;
            }
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /own {
            modsecurity_rules '
                SecRule ARGS "@streq own" "id:2,phase:1,deny,status:403"
            ';

            location /own/nested {
                proxy_pass http://127.0.0.1:%%PORT_8090%%;
            }
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /sibling {
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /off {
            modsecurity off;

            location /off/on {
                modsecurity on;
                proxy_pass http://127.0.0.1:%%PORT_8090%%;
            }
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8081%%;
        server_name  localhost;

        modsecurity_rules '
            SecRule ARGS "@streq server" "id:3,phase:1,deny,status:403"
        ';

        location / {
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }

        location /engine-off {
            modsecurity_rules '
                SecRuleEngine Off
            ';

            location /engine-off/nested {
                proxy_pass http://127.0.0.1:%%PORT_8090%%;
            }
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }
    }

    server {
        listen       127.0.0.1:%%PORT_8082%%;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:%%PORT_8090%%;
        }
    }
}
EOF

$t->run_daemon(\&http_daemon);
$t->run()->waitforsocket('127.0.0.1:' . port(8090));

$t->plan(22);

###############################################################################

my ($p1, $p2) = (port(8081), port(8082));

# http level rules, inherited by blocks without rules of their own
like(http_get('/?a=http'), qr/403/, 'http rules, location');
like(http_get('/?a=clean'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'http rules, clean');
like(http_get('/outer?a=http'), qr/403/, 'http rules, outer location');
like(http_get('/outer/inner?a=http'), qr/403/, 'http rules, nested location');
like(http_get('/if?x=1&a=http'), qr/403/, 'http rules, if block');
like(http_get('/if?a=http'), qr/403/, 'http rules, location with if');

# location rules add to the http ones, and are inherited by nested blocks
like(http_get('/own?a=own'), qr/403/, 'location rules');
like(http_get('/own?a=http'), qr/403/, 'location rules, http rules kept');
like(http_get('/own/nested?a=own'), qr/403/, 'location rules, nested');
like(http_get('/own/nested?a=http'), qr/403/, 'location rules, nested, http');

# rules of a block don't leak into its siblings nor its parent
like(http_get('/sibling?a=own'), qr/TEST-OK-IF-YOU-SEE-THIS/,
	'no leak to sibling location');
like(http_get('/?a=own'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'no leak to parent');
like(http_get('/?a=server'), qr/TEST-OK-IF-YOU-SEE-THIS/,
	'no leak from another server');

# modsecurity off/on is still per block
like(http_get('/off?a=http'), qr/TEST-OK-IF-YOU-SEE-THIS/, 'modsecurity off');
like(http_get('/off/on?a=http'), qr/403/, 'modsecurity on again, nested');

# server level rules
like(http_get_port('/?a=server', $p1), qr/403/, 'server rules');
like(http_get_port('/?a=http', $p1), qr/403/, 'server rules, http rules kept');
like(http_get_port('/engine-off?a=server', $p1), qr/TEST-OK-IF-YOU-SEE-THIS/,
	'SecRuleEngine Off');
like(http_get_port('/engine-off/nested?a=server', $p1),
	qr/TEST-OK-IF-YOU-SEE-THIS/, 'SecRuleEngine Off, nested');

# server without rules of its own
like(http_get_port('/?a=http', $p2), qr/403/, 'server without rules, http');
like(http_get_port('/?a=server', $p2), qr/TEST-OK-IF-YOU-SEE-THIS/,
	'server without rules, clean');
like(http_get_port('/?a=own', $p2), qr/TEST-OK-IF-YOU-SEE-THIS/,
	'server without rules, no leak');

###############################################################################

sub http_get_port {
	my ($uri, $port) = @_;
	return http(<<EOF, PeerAddr => '127.0.0.1:' . $port);
GET $uri HTTP/1.0
Host: localhost

EOF
}

sub http_daemon {
	my $server = IO::Socket::INET->new(
		Proto => 'tcp',
		LocalHost => '127.0.0.1:' . port(8090),
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

		print $client <<'EOF';
HTTP/1.1 200 OK
Connection: close

EOF
		print $client "TEST-OK-IF-YOU-SEE-THIS"
			unless $headers =~ /^HEAD/i;

		close $client;
	}
}

###############################################################################
