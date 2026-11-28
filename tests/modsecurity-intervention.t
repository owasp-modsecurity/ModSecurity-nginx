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


# Tests for ModSecurity module (interventions in the access phase: the
# Location header of a redirect, disruptive and nondisruptive results).

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

        location /phase1 {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:what "@streq redirect" "id:1,phase:1,status:302,redirect:http://www.modsecurity.org/moved?to=%{ARGS.to}"
                SecRule ARGS:what "@streq redirect307" "id:2,phase:1,status:307,redirect:http://www.modsecurity.org/temporary"
                SecRule ARGS:what "@streq deny" "id:3,phase:1,deny,status:403,msg:loud-deny"
                SecRule ARGS:what "@streq pass" "id:4,phase:1,pass,log,msg:passed-rule"
            ';
        }
        location /phase2 {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecRule ARGS:what "@streq redirect" "id:1,phase:2,status:301,redirect:http://www.modsecurity.org/moved?to=%{ARGS.to}"
                SecRule ARGS:what "@streq deny" "id:3,phase:2,deny,status:403"
            ';
        }
        location /detection {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine DetectionOnly
                SecRule ARGS:what "@streq redirect" "id:1,phase:1,status:302,redirect:http://www.modsecurity.org/"
                SecRule ARGS:what "@streq deny" "id:3,phase:1,deny,status:403"
            ';
        }
        location /quiet {
            modsecurity on;
            modsecurity_use_error_log off;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:what "@streq deny" "id:3,phase:1,deny,status:403,msg:quiet-deny"
            ';
        }
    }
}
EOF

$t->write_file('phase1', 'not moved or blocked');
$t->write_file('phase2', 'not moved or blocked');
$t->write_file('detection', 'not moved or blocked');
$t->write_file('quiet', 'not moved or blocked');
$t->run();
$t->plan(25);

###############################################################################

my $location = qr!^Location: http://www\.modsecurity\.org/moved\?to=!m;
my $r;

# Redirect: the Location header holds the URL of the rule, once, after
# libModSecurity's copy of it is freed; each request has its own

$r = http_get('/phase1?what=redirect&to=first');
like($r, qr/^HTTP.*302/, 'redirect phase 1 - status');
like($r, qr!${location}first\x0d?$!m, 'redirect phase 1 - location');
is(locations($r), 1, 'redirect phase 1 - one location');

$r = http_get('/phase1?what=redirect&to=second-' . ('x' x 512));
like($r, qr!${location}second-x{512}\x0d?$!m, 'redirect phase 1 - next location');

$r = http_get('/phase1?what=redirect307');
like($r, qr/^HTTP.*307/, 'redirect 307 phase 1 - status');
like($r, qr!^Location: http://www\.modsecurity\.org/temporary\x0d?$!m,
	'redirect 307 phase 1 - location');

$r = http_get('/phase2?what=redirect&to=third');
like($r, qr/^HTTP.*301/, 'redirect phase 2 - status');
like($r, qr!${location}third\x0d?$!m, 'redirect phase 2 - location');

$r = http_post('/phase2', 'what=redirect&to=fourth');
like($r, qr/^HTTP.*301/, 'redirect phase 2, request body - status');
like($r, qr!${location}fourth\x0d?$!m, 'redirect phase 2, request body - location');
is(locations($r), 1, 'redirect phase 2, request body - one location');

# Deny

$r = http_get('/phase1?what=deny');
like($r, qr/^HTTP.*403/, 'deny phase 1');
is(locations($r), 0, 'deny phase 1 - no location');
like(http_get('/phase2?what=deny'), qr/^HTTP.*403/, 'deny phase 2');
like(http_post('/phase2', 'what=deny'), qr/^HTTP.*403/,
	'deny phase 2, request body');
like(http_get('/quiet?what=deny'), qr/^HTTP.*403/, 'deny without error log');

# No disruptive intervention: the request is served

like(http_get('/phase1?what=pass'), qr/not moved or blocked/, 'pass phase 1');
like(http_get('/phase1?what=nothing'), qr/not moved or blocked/,
	'nothing phase 1');
like(http_post('/phase2', 'what=nothing'), qr/^HTTP.*405/,
	'nothing phase 2, request body');

$r = http_get('/detection?what=redirect');
like($r, qr/not moved or blocked/, 'redirect detection only');
is(locations($r), 0, 'redirect detection only - no location');
like(http_get('/detection?what=deny'), qr/not moved or blocked/,
	'deny detection only');

# The intervention log: written for a disruptive intervention unless
# modsecurity_use_error_log is off, not written for a nondisruptive rule

$t->stop();

my $log = $t->read_file('error.log');

like($log, qr/\[error\].*loud-deny/, 'error log - deny');
unlike($log, qr/\[error\].*(?:quiet-deny|passed-rule)/,
	'error log - nothing for "pass" and with the log off');
unlike($log, qr/invalid intervention result|no context, configuration/,
	'error log - no technical error');

###############################################################################

sub locations {
	my ($r) = @_;
	my ($header) = split /\x0d?\x0a\x0d?\x0a/, $r, 2;
	return scalar(() = $header =~ /^Location:/mgi);
}

sub http_post {
	my ($uri, $body) = @_;

	return http(<<EOF . $body);
POST $uri HTTP/1.0
Host: localhost
Content-Type: application/x-www-form-urlencoded
Content-Length: @{[ length($body) ]}

EOF
}

###############################################################################
