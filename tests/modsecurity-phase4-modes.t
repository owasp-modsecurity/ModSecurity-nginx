#!/usr/bin/perl
use warnings; use strict;
use Test::More;
use JSON::PP qw(decode_json);
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# A committed response must fail without attempting another HTTP status.
my $t = Test::Nginx->new()->has(qw/http/);
$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        default_type text/plain;
        modsecurity on;
        modsecurity_phase4_log %%TESTDIR%%/phase4.log;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecRule RESPONSE_BODY "@rx Hello" "id:910001,phase:4,deny,log,status:403"
        ';
        location /off { modsecurity_phase4_mode off; }
        location /default { }
        location /safe { modsecurity_phase4_mode safe; }
        location /strict { modsecurity_phase4_mode strict; }
    }
}
EOC

for my $mode (qw/off default safe strict/) {
    $t->write_file('/' . $mode, 'Hello ' . $mode);
}
$t->run();
$t->plan(19);

is(http_get('/off'), '', 'off preserves native late-deny failure');
is(http_get('/default'), '', 'off is the default');
like(http_get('/safe'), qr/Hello safe/, 'safe continues after a late rule intervention');
is(http_get('/strict'), '', 'strict aborts after headers are committed');

my $log = $t->read_file('phase4.log');
my @events;
my $valid_json = eval {
    @events = map { decode_json($_) } grep { length $_ } split /\n/, $log;
    1;
};
ok($valid_json, 'every Phase4 event is valid JSON');
diag($@) unless $valid_json;
is(scalar @events, 2, 'off and default off emit no dedicated Phase4 event');
my %event = map { $_->{uri} => $_ } @events;
is($event{'/safe'}->{actual_action}, 'log_only', 'safe action logged');
is($event{'/safe'}->{reason}, 'response_committed_safe', 'safe reason logged');
is($event{'/strict'}->{actual_action}, 'connection_abort', 'strict action logged');
is($event{'/strict'}->{reason}, 'response_committed_strict', 'strict reason logged');
is($event{'/safe'}->{mode}, 'safe', 'safe mode logged');
is($event{'/strict'}->{mode}, 'strict', 'strict mode logged');
ok(@events && !grep({ !$_->{header_sent} } @events), 'header_sent is true for late interventions');
ok(@events && !grep({ $_->{event} ne 'phase4_intervention' } @events), 'event kind is stable');
unlike($log, qr/Hello off|Hello default|Hello safe|Hello strict/, 'response body is absent from Phase4 log');

# Stop first so the explicit alert audit includes all worker output.
$t->stop();
my $error_log = $t->read_file('error.log');
my @alerts = $error_log =~ /^.*\[alert\].*$/gm;
is(scalar @alerts, 0, 'no nginx alerts after late intervention');
unlike($error_log, qr/header already sent\b.*request: "GET \/off HTTP\/1\.[01]"/,
    'explicit off never attempts a second response header');
unlike($error_log, qr/header already sent\b.*request: "GET \/default HTTP\/1\.[01]"/,
    'default off never attempts a second response header');
is(scalar(() = $error_log =~ /modsecurity phase4 intervention after headers sent, action=connection_abort, uri="\/strict"/g),
    1, 'strict abort is diagnosed once');
