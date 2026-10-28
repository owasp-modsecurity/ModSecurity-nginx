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
            root %%TESTDIR%%/http;
            internal;
        }

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq root" "id:10,phase:1,auditlog,status:403,deny"
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
            SecRule ARGS "@streq root" "id:10,phase:1,auditlog,status:403,deny"
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
            root %%TESTDIR%%/http;
            internal;
        }

        location / {
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  s3;
        root %%TESTDIR%%/http;

        error_page 404 = /protected-error.txt;

        location = /trigger {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:910501,phase:1,pass,nolog"
            ';
            try_files /missing-error-source =404;
        }

        location = /protected-error.txt {
            internal;
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:X-Phase1-Deny "@streq yes" "id:910502,phase:1,deny,status:451,nolog"
                SecRule REQUEST_HEADERS:X-Phase2-Deny "@streq yes" "id:910503,phase:2,deny,status:403,nolog"
            ';
        }
    }
}
EOF

my $index_txt = "This is the index page.";
my $custom_txt = "This is a custom error page.";

$t->write_file("/index.html", $index_txt);
mkdir($t->testdir() . '/http');
$t->write_file("/http/403.html", $custom_txt);
my $protected_txt = "This is a protected error target.";
$t->write_file("/http/protected-error.txt", $protected_txt);

$t->run();
$t->plan(14);

###############################################################################

my $d = $t->testdir();

my $t1;
my $t2;
my $t3;
my $t4;

# Performing requests to a server with ModSecurity enabled at location context
$t1 = http_get_host('s1', '/index.html?what=root');
$t2 = http_get_host('s1', '/index.html?what=other');

# Performing requests to a server with ModSecurity enabled at server context
$t3 = http_get_host('s2', '/index.html?what=root');
$t4 = http_get_host('s2', '/index.html?what=other');

my $local = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-local.txt"
        or die "could not open: $!";
    <$fh>;
};

my $global = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-global.txt"
        or die "could not open: $!";
    <$fh>;
};

like($t1, qr/$custom_txt/, 'ModSecurity at location / root');
like($t2, qr/$index_txt/, 'ModSecurity at location / other');
like($local, qr/what=root/, 'ModSecurity at location / root present in auditlog');
unlike($local, qr/what=other/, 'ModSecurity at location / other not present in auditlog');

like($t3, qr/$custom_txt/, 'ModSecurity at server / root');
like($t4, qr/$index_txt/, 'ModSecurity at server / other');
like($global, qr/what=root/, 'ModSecurity at server / root present in auditlog');
unlike($global, qr/what=other/, 'ModSecurity at server / other not present in auditlog');

like($local, qr/Access denied with code 403/, 'ModSecurity at location / 403 in auditlog');
like($global, qr/Access denied with code 403/, 'ModSecurity at server / 403 in auditlog');

# The origin runs access processing before try_files redirects to a different
# protected location. The target must get its own transaction and run P1/P2.
my $target_allow = http_get_host('s3', '/trigger');
my $target_p1 = http_get_host('s3', '/trigger', 'X-Phase1-Deny: yes');
my $target_p2 = http_get_host('s3', '/trigger', 'X-Phase2-Deny: yes');
like($target_allow, qr/^HTTP\/1\.[01] 200/, 'error-page target allows legitimate request');
like($target_allow, qr/\Q$protected_txt\E/, 'error-page target delivers legitimate content');
like($target_p1, qr/^HTTP\/1\.[01] 451/, 'error-page target preserves P1 deny');
like($target_p2, qr/^HTTP\/1\.[01] 403/, 'error-page target continues from P1 allow to P2 deny');

###############################################################################

sub http_get_host {
	my ($host, $url, $headers) = @_;
	$headers = '' unless defined $headers;
	return http(<<EOF);
GET $url HTTP/1.0
Host: $host
$headers

EOF
}

###############################################################################
