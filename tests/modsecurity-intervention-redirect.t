#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (redirect interventions).

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

        location /redirect {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq redirect" "id:101,phase:1,log,status:302,redirect:http://www.modsecurity.org/"
            ';
        }
    }
}
EOF

$t->write_file("/redirect", "should be redirected before this.");

$t->run()->plan(2);

###############################################################################

my $r = http_get('/redirect?what=redirect');

like($r, qr!^HTTP/1.1 302!, 'phase 1 redirect - status');
like($r, qr!^Location: http://www\.modsecurity\.org/\x0d?$!m, 'phase 1 redirect - location');
