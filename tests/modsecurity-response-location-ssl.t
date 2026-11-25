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


# Tests for ModSecurity-nginx connector (Location response header over SSL).
#
# nginx makes a relative Location absolute with the https scheme over SSL,
# and leaves out port 443.  The rules must see the Location that is sent.

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

my $t = Test::Nginx->new()->has(qw/http http_ssl socket_ssl/)
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
        listen       127.0.0.1:8443 ssl;
        server_name  localhost;

        modsecurity on;

        location /https/ {
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq https://localhost:%%PORT_8443%%/https/dir/" \
                    "id:1,phase:3,deny,status:403"
            ';
        }

        # The default port is left out.  The test cannot listen on 443, so
        # port_in_redirect off stands in for it here.
        location /noport/ {
            port_in_redirect off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_HEADERS:Location \
                    "@streq https://localhost/noport/dir/" \
                    "id:2,phase:3,deny,status:403"
            ';
        }

        location /wire/ {
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

for my $dir (qw/https noport wire/) {
	mkdir("$d/$dir");
	mkdir("$d/$dir/dir");
}

$t->run()->plan(3);

###############################################################################

like(http_get('/wire/dir', SSL => 1),
	qr!^Location: https://localhost:@{[port(8443)]}/wire/dir/\x0d?$!m, 'wire: https');

like(http_get('/https/dir', SSL => 1), qr/^HTTP.* 403/, 'https Location seen');
like(http_get('/noport/dir', SSL => 1), qr/^HTTP.* 403/,
	'https Location without port seen');

###############################################################################
