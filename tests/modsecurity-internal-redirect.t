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


# Tests for ModSecurity module (module context recovery after the request
# context has been discarded: internal redirects, named locations and
# filter finalization).

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

my $t = Test::Nginx->new()->has(qw/http rewrite/);

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
        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS:what "@streq bad" "id:91,phase:1,deny,status:403,log,auditlog"
            SecRule RESPONSE_HEADERS:X-Fallback "@streq yes" "id:92,phase:3,log,auditlog,pass"
            SecRule ARGS:what "@streq precond" "id:93,phase:1,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLog %%TESTDIR%%/audit.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        location / {
            try_files $uri /fallback;
        }

        location = /fallback {
            internal;
            add_header X-Fallback yes;
        }

        location /named {
            try_files $uri @named;
        }

        location @named {
            add_header X-Fallback yes;
            return 200 "NAMED";
        }

        location /static {
        }
    }
}

EOF

$t->write_file('fallback', 'FALLBACK');
mkdir($t->testdir() . '/static');
$t->write_file('static/precond.html', 'PRECOND');
$t->run();
$t->plan(8);

###############################################################################

like(http_get('/missing?what=ok'), qr/FALLBACK/, 'try_files fallback served');
like(http_get('/missing?what=bad'), qr/^HTTP.*403/, 'phase 1 deny before try_files');
like(http_get('/named/missing?what=ok'), qr/NAMED/, 'named location served');

# a failed precondition makes the not modified filter call
# ngx_http_filter_finalize_request(), which discards the module contexts
# without setting r->internal

like(http(<<EOF), qr/^HTTP.*412/, 'precondition failed');
GET /static/precond.html?what=precond HTTP/1.0
Host: localhost
If-Match: "bogus"

EOF

my $d = $t->testdir();

my $audit = do {
    local $/ = undef;
    open my $fh, "<", "$d/audit.txt"
        or die "could not open: $!";
    <$fh>;
};

like($audit, qr/\[id "92"\]/, 'phase 3 ran after internal redirect (ctx recovered)');
like($audit, qr/\[id "91"\]/, 'deny audited');
my @p3 = ($audit =~ /\[id "92"\]/g);
is(scalar @p3, 2, 'phase 3 logged once per redirected request');
like($audit, qr/\[id "93"\]/, 'logging phase ran after filter finalization');

###############################################################################
