#!/usr/bin/perl
use warnings; use strict;
use Test::More;
use JSON::PP qw(decode_json);
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# auth_request shares the main request's pool but owns a separate response.
# Its header-only image response must not consume the main transaction's
# response headers or MIME selection. Direct subrequest EOS is covered by
# the compiled owner-isolation regression; auth_request itself is header-only.
my $t = Test::Nginx->new()->has(qw/http auth_request/);
$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    log_format auth_probe '$uri $status';
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        default_type text/plain;
        log_subrequest on;
        modsecurity on;
        modsecurity_phase4_mode strict;
        modsecurity_phase4_log %%TESTDIR%%/phase4-subrequest.log;
        modsecurity_rules 'SecResponseBodyMimeTypesClear';
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecRule RESPONSE_HEADERS:Content-Type "@contains image/png" "id:940002,phase:3,deny,log,status:403,msg:auth-response-headers-leaked"
            SecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" "id:940003,phase:3,pass,log,msg:main-response-headers-seen"
            SecRule RESPONSE_BODY "@contains P4-MAIN-MARKER" "id:940001,phase:4,deny,log,status:403"
        ';
        location = /_auth {
            internal;
            modsecurity off;
            default_type image/png;
            access_log %%TESTDIR%%/auth.log auth_probe;
        }
        location = /control { auth_request /_auth; }
        location = /main { auth_request /_auth; }
    }
}
EOC

$t->write_file('/_auth', 'BENIGN AUTH BODY');
$t->write_file('/control', 'BENIGN MAIN BODY');
$t->write_file('/main', 'P4-MAIN-MARKER');
$t->run();
$t->plan(16);

my $control = http_get('/control');
like($control, qr/^HTTP\/1\.1 200 OK/, 'benign main response passes after authorization');
like($control, qr/BENIGN MAIN BODY/, 'main body remains intact');
unlike($control, qr/BENIGN AUTH BODY/, 'authorization body is absent from main response');
is(http_get('/main'), '', 'main Phase4 marker still triggers strict abort after authorization');
$t->stop();
my @auth_results = $t->read_file('auth.log') =~ /^\/_auth 200\r?$/gm;
is(scalar @auth_results, 2, 'both authorization subrequests completed successfully');
my $error_log = $t->read_file('error.log');
like($error_log, qr/main-response-headers-seen/, 'main response headers are inspected after the subrequest');
unlike($error_log, qr/auth-response-headers-leaked/, 'auth response headers never enter the main transaction');

my $log = $t->read_file('phase4-subrequest.log');
my @events;
my $valid_json = eval {
    @events = map { decode_json($_) } grep { length $_ } split /\n/, $log;
    1;
};
ok($valid_json, 'subrequest regression event is valid JSON');
diag($@) unless $valid_json;
is(scalar @events, 1, 'only the matching main response produces a Phase4 event');
is($events[0]->{uri}, '/main', 'event belongs to the main request');
is($events[0]->{mode}, 'strict', 'main strict mode is retained');
is($events[0]->{actual_action}, 'connection_abort', 'main intervention aborts the connection');
ok($events[0]->{header_sent}, 'main response headers were committed');
is($events[0]->{waf_status}, 403, 'main rule decision is retained');
is($events[0]->{rule_id}, '940001', 'main body rule caused the event');
unlike($log, qr/P4-MAIN-MARKER|BENIGN AUTH BODY|BENIGN MAIN BODY/, 'event log excludes both response bodies');
