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


# Tests for ModSecurity module.

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
        server_name  s1;

        error_page 403 /403.html;

        location /403.html {
            alias %%TESTDIR%%/403.html;
            internal;
        }

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule ARGS:phase1 "@streq BAD" "id:10,phase:1,auditlog,status:403,deny"
                SecRule ARGS:phase2 "@streq BAD" "id:11,phase:2,auditlog,status:403,deny"
                SecRule ARGS:phase3 "@streq BAD" "id:12,phase:3,auditlog,status:403,deny"
                SecRule ARGS:phase4 "@streq BAD" "id:13,phase:4,auditlog,status:403,drop"
                SecDebugLog %%TESTDIR%%/auditlog-debug-local.txt
                SecDebugLogLevel 9
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABIJDEFHZ
                SecAuditLog %%TESTDIR%%/auditlog-local.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  s2;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecRule ARGS:phase1 "@streq BAD" "id:10,phase:1,auditlog,status:403,deny"
            SecRule ARGS:phase2 "@streq BAD" "id:11,phase:2,auditlog,status:403,deny"
            SecRule ARGS:phase3 "@streq BAD" "id:12,phase:3,auditlog,status:403,deny"
            SecRule ARGS:phase4 "@streq BAD" "id:13,phase:4,auditlog,status:403,drop"
            SecDebugLog %%TESTDIR%%/auditlog-debug-global.txt
            SecDebugLogLevel 9
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABIJDEFHZ
            SecAuditLog %%TESTDIR%%/auditlog-global.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        error_page 403 /403.html;

        location /403.html {
            modsecurity off;
            alias %%TESTDIR%%/403.html;
            internal;
        }

        location / {
        }
    }
}
EOF

my $index_txt = "This is the index page.";
my $error_txt = "This is a custom error page.";

$t->write_file("/index.html", $index_txt);
$t->write_file("/403.html", $error_txt);

$t->todo_alerts();
$t->run();
$t->plan(32);

###############################################################################

my $d = $t->testdir();

# Performing requests to a server with ModSecurity enabled at location context
like(http_get_host('s1', '/?phase1=BAD'), qr/$error_txt/, 'location context, phase 1, error page');
like(http_get_host('s1', '/?phase1=GOOD'), qr/$index_txt/, 'location context, phase 1, index page');
like(http_get_host('s1', '/?phase2=BAD'), qr/$error_txt/, 'location context, phase 2, error page');
like(http_get_host('s1', '/?phase2=GOOD'), qr/$index_txt/, 'location context, phase 2, index page');
like(http_get_host('s1', '/?phase3=BAD'), qr/$error_txt/, 'location context, phase 3, error page');
like(http_get_host('s1', '/?phase3=GOOD'), qr/$index_txt/, 'location context, phase 3, index page');
is(http_get_host('s1', '/?phase4=BAD'), '', 'location context, phase 4, drop');
like(http_get_host('s1', '/?phase4=GOOD'), qr/$index_txt/, 'location context, phase 4, index page');

my $local = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-local.txt"
        or die "could not open: $!";
    <$fh>;
};

like($local, qr/phase1=BAD/, 'location context, phase 1, BAD in auditlog');
unlike($local, qr/phase1=GOOD/, 'location context, phase 1, GOOD not in auditlog');
like($local, qr/phase2=BAD/, 'location context, phase 2, BAD in auditlog');
unlike($local, qr/phase2=GOOD/, 'location context, phase 2, GOOD not in auditlog');
like($local, qr/phase3=BAD/, 'location context, phase 3, BAD in auditlog');
unlike($local, qr/phase3=GOOD/, 'location context, phase 3, GOOD not in auditlog');
like($local, qr/phase4=BAD/, 'location context, phase 4, BAD in auditlog');
unlike($local, qr/phase4=GOOD/, 'location context, phase 4, GOOD not in auditlog');

# Performing requests to a server with ModSecurity enabled at server context
like(http_get_host('s2', '/?phase1=BAD'), qr/$error_txt/, 'server context, phase 1, error page');
like(http_get_host('s2', '/?phase1=GOOD'), qr/$index_txt/, 'server context, phase 1, index page');
like(http_get_host('s2', '/?phase2=BAD'), qr/$error_txt/, 'server context, phase 2, error page');
like(http_get_host('s2', '/?phase2=GOOD'), qr/$index_txt/, 'server context, phase 2, index page');
like(http_get_host('s2', '/?phase3=BAD'), qr/$error_txt/, 'server context, phase 3, error page');
like(http_get_host('s2', '/?phase3=GOOD'), qr/$index_txt/, 'server context, phase 3, index page');
is(http_get_host('s2', '/?phase4=BAD'), '', 'server context, phase 4, drop');
like(http_get_host('s2', '/?phase4=GOOD'), qr/$index_txt/, 'server context, phase 4, index page');

my $global = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-global.txt"
        or die "could not open: $!";
    <$fh>;
};

like($global, qr/phase1=BAD/, 'server context, phase 1, BAD in auditlog');
unlike($global, qr/phase1=GOOD/, 'server context, phase 1, GOOD not in auditlog');
like($global, qr/phase2=BAD/, 'server context, phase 2, BAD in auditlog');
unlike($global, qr/phase2=GOOD/, 'server context, phase 2, GOOD not in auditlog');
like($global, qr/phase3=BAD/, 'server context, phase 3, BAD in auditlog');
unlike($global, qr/phase3=GOOD/, 'server context, phase 3, GOOD not in auditlog');
like($global, qr/phase4=BAD/, 'server context, phase 4, BAD in auditlog');
unlike($global, qr/phase4=GOOD/, 'server context, phase 4, GOOD not in auditlog');

###############################################################################

sub http_get_host {
	my ($host, $url) = @_;
	return http(<<EOF);
GET $url HTTP/1.0
Host: $host

EOF
}

###############################################################################
