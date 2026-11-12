#!/usr/bin/perl
use warnings; use strict;
use Test::More;
use JSON::PP qw(decode_json);
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# libModSecurity owns response MIME selection; the connector has no MIME list.
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
        modsecurity on;
        modsecurity_phase4_mode strict;
        modsecurity_phase4_log %%TESTDIR%%/phase4-content-types.log;
        # Separate loads exercise the engine's sequential clear/add merge.
        modsecurity_rules 'SecResponseBodyMimeType text/plain';
        modsecurity_rules 'SecResponseBodyMimeTypesClear';
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType application/json
            SecRule RESPONSE_BODY "@rx HIT" "id:920001,phase:4,deny,log,status:403"
        ';
        location /json { default_type application/json; }
        location /unknown { default_type image/png; }
        location /plain { default_type text/plain; }
    }
}
EOC

$t->write_file('/json', 'HIT JSON');
$t->write_file('/unknown', 'HIT PNG');
$t->write_file('/plain', 'HIT PLAIN');
$t->run();
$t->plan(8);

is(http_get('/json'), '', 'engine-selected JSON triggers strict late abort');
like(http_get('/unknown'), qr/HIT PNG/, 'engine-excluded image body continues');
like(http_get('/plain'), qr/HIT PLAIN/, 'engine MIME clear/add override excludes inherited text/plain');
my $log = $t->read_file('phase4-content-types.log');
my @events;
my $valid_json = eval {
    @events = map { decode_json($_) } grep { length $_ } split /\n/, $log;
    1;
};
ok($valid_json, 'MIME test event is valid JSON');
diag($@) unless $valid_json;
is(scalar @events, 1, 'only engine-inspected matching body causes an event');
is($events[0]->{content_type}, 'application/json', 'engine-selected content type logged');
is($events[0]->{actual_action}, 'connection_abort', 'JSON intervention abort logged');
unlike($log, qr/HIT JSON|HIT PNG|HIT PLAIN/, 'no response body is copied to Phase4 log');
