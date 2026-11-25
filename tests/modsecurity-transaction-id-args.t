#!/usr/bin/perl

#
# ModSecurity connector for nginx, http://www.modsecurity.org/
# Copyright (c) 2026 OWASP Foundation (http://www.owasp.org/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact OWASP.
#


# Tests for ModSecurity-nginx connector (modsecurity_transaction_id takes
# exactly one argument, issue #412).

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

# The configuration Test::Nginx starts is a valid one; the invalid ones below
# are only given to `nginx -t`.
$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    modsecurity_transaction_id "tid-A";

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
    }
}
EOF

# "good" is the control: one argument, which nginx -t must accept, so that a
# non-zero exit for the others is down to the arity check alone.
for my $level (qw/good http server location/) {
    my ($h, $s, $l) = ('', '', '');
    my $d = 'modsecurity_transaction_id "tid-A" "tid-B";';
    $d = 'modsecurity_transaction_id "tid-A";' if $level eq 'good';
    $h = $d if $level eq 'good';
    $h = $d if $level eq 'http';
    $s = $d if $level eq 'server';
    $l = $d if $level eq 'location';

    $t->write_file_expand("args-$level.conf", <<"EOF");

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    $h

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;
        $s

        location / {
            $l
        }
    }
}
EOF
}

$t->run();
$t->plan(7);

###############################################################################

my $testdir = $t->testdir();

# With -p, nginx opens <prefix>/logs/error.log before it reads the
# configuration, and fails the test run if it cannot.
mkdir("$testdir/logs");

my $out = `$Test::Nginx::NGINX -t -p $testdir/ -c args-good.conf 2>&1`;
is($?, 0, 'one argument accepted') or diag($out);

for my $level (qw/http server location/) {
    $out = `$Test::Nginx::NGINX -t -p $testdir/ -c args-$level.conf 2>&1`;
    isnt($?, 0, "two arguments rejected at $level level");
    like($out,
        qr/invalid number of arguments in "modsecurity_transaction_id"/,
        "error names the directive at $level level");
}

###############################################################################
