#!/usr/bin/perl

#
# ModSecurity, http://www.modsecurity.org/
# Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact Trustwave Holdings, Inc.
# directly using the email address security@modsecurity.org.
#


# Regression test for a phase-4 RESPONSE_BODY "deny" action.
#
# By the time msc_process_response_body() detects a violation, response
# headers (status, Content-Length) have already been sent to the client --
# this connector does not delay headers until body inspection completes.
# ngx_http_modsecurity_body_filter() used to report that via
# ngx_http_filter_finalize_request(), which tries to send a *fresh* status
# line and headers regardless (via nginx's own ngx_http_clean_header()).
# Since headers were already flushed, this produced nginx's own "header
# already sent" [alert] and a corrupted response instead of a clean abort.

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
        modsecurity_rules_file %%TESTDIR%%/rules.conf;

        location / {
        }
    }
}
EOF

$t->write_file('rules.conf', <<'EOF');
SecRuleEngine On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule RESPONSE_BODY "@rx leakmarker" "id:103,phase:4,deny,status:403"
EOF

# The marker sits at the end of a large body, so the deny only fires once
# the whole response is buffered -- well after headers went out.
$t->write_file('leak.txt', ('x' x 8192) . "leakmarker\n");
$t->write_file('clean.txt', ('x' x 8192) . "\n");

$t->run();
$t->plan(4);

###############################################################################

my $clean = http_get('/clean.txt');
like($clean, qr/^HTTP\/1\.[01] 200/, 'benign response body passes');

my $leak = http_get('/leak.txt');
# The body is small enough to arrive in a single buffer, so the deny fires
# before any of it is forwarded and the connection is dropped after the
# headers. (With a multi-buffer response the buffers preceding the one that
# carries last_buf are forwarded before phase 4 runs, so only the tail is
# withheld.)
unlike($leak // '', qr/leakmarker/,
    'leak marker body was not delivered to the client');

my $d = $t->testdir();
my $errorlog = do {
    local $/ = undef;
    open my $fh, "<", "$d/error.log" or die "could not open: $!";
    <$fh>;
};
# Make sure the body was withheld *because the rule fired*, not because the
# worker died or the connection was refused for some unrelated reason.
like($errorlog, qr/\[id "103"\]/, 'phase-4 deny rule fired');
unlike($errorlog, qr/header already sent/, 'no "header already sent" alert from the deny path');

###############################################################################
