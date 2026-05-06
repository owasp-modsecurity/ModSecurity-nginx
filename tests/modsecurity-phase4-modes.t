#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/);
$t->write_file('phase4-content-types.conf', "# comment\n\nApplication/JSON; charset=utf-8 # inline\ntext/html\n");

$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /m {
            modsecurity on;
            modsecurity_phase4_mode minimal;
            modsecurity_phase4_log %%TESTDIR%%/phase4.log;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-content-types.conf;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx Hello" "id:910001,phase:4,deny,log,status:403,msg:\"x\\nq\""
            ';
        }

        location /s {
            modsecurity on;
            modsecurity_phase4_mode safe;
            modsecurity_phase4_log %%TESTDIR%%/phase4.log;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx Hello" "id:910002,phase:4,deny,log,status:403"
            ';
        }

        location /x {
            modsecurity on;
            modsecurity_phase4_mode strict;
            modsecurity_phase4_log %%TESTDIR%%/phase4.log;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx Hello" "id:910003,phase:4,deny,log,status:403"
            ';
        }
    }
}
EOC

$t->write_file('/m', 'Hello minimal');
$t->write_file('/s', 'Hello safe');
$t->write_file('/x', 'Hello strict');
$t->run();
$t->plan(11);

like(http_get('/m'), qr/Hello minimal/, 'minimal no fake deny');
like(http_get('/s'), qr/Hello safe/, 'safe no fake deny');
is(http_get('/x'), '', 'strict abort after headers sent');

my $log = $t->read_file('phase4.log');
like($log, qr/"actual_action":"log_only"/, 'log_only present');
like($log, qr/"reason":"mode_safe"|"reason":"headers_already_sent"/, 'safe reason present');
like($log, qr/"actual_action":"connection_abort"/, 'strict action logged');
like($log, qr/"event":"phase4_intervention"/, 'event field present');
like($log, qr/"header_sent":true/, 'json boolean header_sent');
unlike($log, qr/Hello minimal|Hello safe|Hello strict/, 'no response body data in phase4 log');

my @lines = grep { length $_ } split /\n/, $log;
ok(@lines >= 1, 'phase4 log has one or more json lines');
my @bad_lines = grep { $_ !~ /^\{.*\}\r?$/ } @lines;
note('phase4.log lines=' . scalar(@lines));
if (@bad_lines) {
    diag('non-json-lines: ' . join(' || ', map { my $x = $_; $x =~ s/\r/\\r/g; $x } @bad_lines));
}
ok(scalar(@bad_lines) == 0, 'each log line is a single JSON object line');
