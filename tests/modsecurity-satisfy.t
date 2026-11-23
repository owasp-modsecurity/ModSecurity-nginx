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


# Tests for ModSecurity module (interventions in a location with "satisfy any").

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

my $t = Test::Nginx->new()->has(qw/http access auth_basic/);

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

        # the client, 127.0.0.1, is admitted by "allow": with "satisfy any"
        # an intervention must still be enforced

        satisfy any;

        allow 127.0.0.1;
        deny all;

        auth_basic "closed site";
        auth_basic_user_file %%TESTDIR%%/htpasswd;

        location /phase1 {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecDefaultAction "phase:1,log,deny,status:403"
                SecRule ARGS "@streq redirect302" "id:2,phase:1,status:302,redirect:http://www.modsecurity.org"
                SecRule ARGS "@streq block401" "id:3,phase:1,status:401,block"
                SecRule ARGS "@streq block403" "id:4,phase:1,status:403,block"
                SecRule ARGS "@streq block407" "id:5,phase:1,status:407,block"
            ';
        }
        location /phase2 {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRequestBodyAccess On
                SecDefaultAction "phase:2,log,deny,status:403"
                SecRule ARGS "@streq redirect302" "id:2,phase:2,status:302,redirect:http://www.modsecurity.org"
                SecRule ARGS "@streq block401" "id:3,phase:2,status:401,block"
                SecRule ARGS "@streq block403" "id:4,phase:2,status:403,block"
                SecRule ARGS "@streq block407" "id:5,phase:2,status:407,block"
            ';
        }
    }
}
EOF

$t->write_file('htpasswd', "user:{PLAIN}secret\n");
$t->write_file('phase1', 'should be moved/blocked before this.');
$t->write_file('phase2', 'should be moved/blocked before this.');
$t->run();
$t->plan(11);

###############################################################################

# Redirect (302)
like(http_get('/phase1?what=redirect302'), qr/^HTTP.*302/, 'redirect 302 - phase 1');
like(http_get('/phase2?what=redirect302'), qr/^HTTP.*302/, 'redirect 302 - phase 2');

# Block (401)
like(http_get('/phase1?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 1');
like(http_get('/phase2?what=block401'), qr/^HTTP.*401/, 'block 401 - phase 2');

# Block (403)
like(http_get('/phase1?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 1');
like(http_get('/phase2?what=block403'), qr/^HTTP.*403/, 'block 403 - phase 2');

# Block (407)
like(http_get('/phase1?what=block407'), qr/^HTTP.*407/, 'block 407 - phase 1');
like(http_get('/phase2?what=block407'), qr/^HTTP.*407/, 'block 407 - phase 2');

# Block (403) on the request body
like(http_post('/phase2', 'what=block403'), qr/^HTTP.*403/,
	'block 403 - phase 2, request body');

# Nothing to detect
like(http_get('/phase1?what=nothing'), qr/should be moved\/blocked before this./, 'nothing phase 1');
like(http_get('/phase2?what=nothing'), qr/should be moved\/blocked before this./, 'nothing phase 2');

###############################################################################

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
