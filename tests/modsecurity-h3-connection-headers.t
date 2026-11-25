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
# headers over HTTP/3).
#
# HTTP/3 forbids connection-specific header fields and nginx never sends
# them there, so a rule on them must not match an HTTP/3 response (issue
# #415).  The response protocol handed to the library must be HTTP/3, not
# HTTP/1.1.
#
# Needs nginx built with --with-http_v3_module, the CryptX Perl module and
# the openssl command (for the test certificate); skipped otherwise.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3 cryptx/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
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

        location /keep-alive {
            modsecurity_rules '
                SecRuleEngine On
                SecRule &RESPONSE_HEADERS:Keep-Alive "!@eq 0" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        location /protocol {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_PROTOCOL "@streq HTTP 3.0" \
                    "id:3,phase:3,deny,status:403"
            ';
        }
    }
}
EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file('connection', 'SEE-THIS');
$t->write_file('keep-alive', 'SEE-THIS');
$t->write_file('protocol', 'SEE-THIS');
$t->run()->plan(3);

###############################################################################

# Neither header is sent over HTTP/3, so neither may be seen.

is(h3_status('/connection'), 200, 'Connection not seen over HTTP/3');
is(h3_status('/keep-alive'), 200, 'Keep-Alive not seen over HTTP/3');

# Also shows that the rules run for HTTP/3 responses, so the two above do
# not pass vacuously.

is(h3_status('/protocol'), 403, 'response protocol over HTTP/3');

###############################################################################

sub h3_status {
	my ($path) = @_;

	my $s = Test::Nginx::HTTP3->new();
	my $sid = $s->new_stream({ path => $path });
	my $frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
	my ($frame) = grep { $_->{type} eq "HEADERS" } @$frames;

	return $frame ? $frame->{headers}->{':status'} : undef;
}

###############################################################################
