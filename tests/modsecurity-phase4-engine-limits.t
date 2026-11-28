#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# Exercise libModSecurity's real append result and queued intervention. The
# static file exceeds the connector's file-reading chunk size; its legacy
# limit is deliberately smaller than the engine's inspection limit.
my $t = Test::Nginx->new()->has(qw/http/);
my $prefix = 'ENGINE_PREFIX_' . ('A' x 50); # exactly 64 bytes
my $body = $prefix . ('B' x 70000) . 'ENGINE_TAIL_MARKER';
my $locations = '';
my $rule_id = 950000;

for my $action (qw/partial reject/) {
    my $engine_action = $action eq 'partial' ? 'ProcessPartial' : 'Reject';
    for my $mode (qw/off safe strict/) {
        my $prefix_id = ++$rule_id;
        my $tail_id = ++$rule_id;
        $locations .= <<EOC;
        location = /$action-$mode {
            modsecurity_phase4_mode $mode;
            # Clear and add in separate loads so the engine merges sequentially.
            modsecurity_rules 'SecResponseBodyMimeTypesClear';
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecResponseBodyLimit 64
                SecResponseBodyLimitAction $engine_action
                SecRule RESPONSE_BODY "\@streq $prefix" "id:$prefix_id,phase:4,pass,log,msg:engine-prefix-exact64-$action-$mode"
                SecRule RESPONSE_BODY "\@contains ENGINE_TAIL_MARKER" "id:$tail_id,phase:4,pass,log,msg:engine-tail-seen-$action-$mode"
            ';
        }
EOC
        $t->write_file('/' . $action . '-' . $mode, $body);
    }
}

$t->write_file_expand('nginx.conf', <<EOC);
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
        modsecurity_phase4_body_limit 1;
        modsecurity_phase4_log %%TESTDIR%%/phase4-engine-limits.log;
$locations
    }
}
EOC

$t->run();
$t->plan(18);

for my $mode (qw/off safe strict/) {
    my $response = http_get('/partial-' . $mode);
    like($response, qr/^HTTP\/1\.1 200 OK/, "$mode accepts engine ProcessPartial");
    my ($headers, $payload) = split /\x0d\x0a\x0d\x0a/, $response, 2;
    is($payload, $body, "$mode ProcessPartial forwards the entire static file");
}

# Static response headers have already passed the header filter when the
# engine queues its body-limit 403. Reject is an engine failure in every mode,
# not a rule intervention that Safe may downgrade. No body reaches downstream.
for my $mode (qw/off safe strict/) {
    is(http_get('/reject-' . $mode), '', "$mode stops native engine Reject");
}

$t->stop();
my $log = $t->read_file('phase4-engine-limits.log');
is($log, '', 'native Reject and ProcessPartial never emit rule-policy events');

my $error_log = $t->read_file('error.log');
for my $mode (qw/off safe strict/) {
    is(scalar(() = $error_log =~ /engine-prefix-exact64-partial-\Q$mode\E/g), 1,
        "$mode engine RESPONSE_BODY is exactly the first 64 bytes");
}
unlike($error_log, qr/engine-tail-seen-/, 'engine inspection excludes the tail in every mode');
unlike($error_log, qr/engine-prefix-exact64-reject-/,
    'engine Reject does not expose a partial inspection prefix');
unlike($error_log, qr/response body inspection append failed/,
    'the engine Reject append result is not mistaken for an API failure');

is(scalar(() = $error_log =~ /response body limit rejected the response/g), 3,
    'every rejected response retains its native-limit diagnostic');
unlike($error_log, qr/\[alert\]/, 'native Reject never attempts a second response header');
