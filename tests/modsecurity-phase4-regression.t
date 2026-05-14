#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/);
my $big = ('A' x 70000) . 'TAIL';

$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /big {
            modsecurity on;
            modsecurity_phase4_mode minimal;
            modsecurity_phase4_log %%TESTDIR%%/phase4-regression.log;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx TAIL" "id:930001,phase:4,deny,log,status:403,msg:\"reg\""
            ';
        }
    }
}
EOC

$t->write_file('/big', $big);
$t->run();
$t->plan(5);

my $resp = http_get('/big');
like($resp, qr/HTTP\/1\.1 200 OK/, 'big response status remains 200 in minimal mode');
like($resp, qr/A{1024}/, 'big response body contains expected prefix chunk');
like($resp, qr/TAIL/, 'big response body tail present (no truncation)');

my $log = $t->read_file('phase4-regression.log');
like($log, qr/"actual_action":"log_only"/, 'minimal mode logs only');
unlike($log, qr/A{100,}|TAIL/, 'no large response data leaked to phase4 log');
