#!/usr/bin/perl

# (C) Test for ModSecurity-nginx connector (limit_req ordering).

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

    limit_req_zone $binary_remote_addr zone=limitzone:10m rate=2r/s;
    limit_req_status 429;

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        modsecurity on;
        limit_req zone=limitzone burst=1 nodelay;

        location /limit {
            modsecurity_rules '
                SecRuleEngine On
                SecRule REQUEST_URI "@rx .*" "id:1001,phase:1,log,deny,status:555,msg:\'Request reached ModSecurity\'"
            ';
        }
    }
}
EOF

$t->write_file("/limit", "limit test endpoint");
$t->run();
$t->plan(4);

###############################################################################

my $uri = '/limit';

my $res1 = http_get($uri);
my $res2 = http_get($uri);
my $res3 = http_get($uri);
my $res4 = http_get($uri);

like($res1, qr/^HTTP.*555/, 'limitreq scoring 1 (Blocked by ModSecurity)');
like($res2, qr/^HTTP.*555/, 'limitreq scoring 2 (Blocked by ModSecurity)');
like($res3, qr/^HTTP.*429/, 'limitreq scoring 3 (limited by nginx)');
like($res4, qr/^HTTP.*429/, 'limitreq scoring 4 (limited by nginx)');
