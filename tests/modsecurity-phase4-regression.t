#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/);
my $big = ('A' x 1100000) . 'TAIL';
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
        modsecurity_phase4_body_limit 64k;
        modsecurity_phase4_log %%TESTDIR%%/phase4-regression.log;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecResponseBodyLimit 2097152
            SecRule RESPONSE_BODY "@endsWith TAIL" "id:930001,phase:4,pass,log,msg:phase4-tail-seen"
        ';
        location /off { modsecurity_phase4_mode off; }
        location /safe { modsecurity_phase4_mode safe; }
        location /strict { modsecurity_phase4_mode strict; }
    }
}
EOC

for my $mode (qw/off safe strict/) {
    $t->write_file('/' . $mode, $big);
}
$t->run();
$t->plan(8);

for my $mode (qw/off safe strict/) {
    my $resp = http_get('/' . $mode);
    like($resp, qr/HTTP\/1\.1 200 OK/, "$mode ignores the legacy connector limit");
    my ($headers, $body) = split /\x0d\x0a\x0d\x0a/, $resp, 2;
    is($body, $big, "$mode forwards the complete large response");
}
$t->stop();
my $error_log = $t->read_file('error.log');
is(scalar(() = $error_log =~ /phase4-tail-seen/g), 3,
    'the engine inspects the tail beyond the legacy limit in every mode');
unlike($t->read_file('phase4-regression.log'), qr/A{100,}|TAIL/,
    'response bytes are absent from event logs');
