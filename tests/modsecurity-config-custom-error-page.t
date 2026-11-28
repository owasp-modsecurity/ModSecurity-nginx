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

    server {
        listen       127.0.0.1:8080;
        server_name  s4;
        root %%TESTDIR%%/http;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule REQUEST_HEADERS:X-Scanner "@streq yes" "id:910510,phase:1,deny,status:403,log"
            SecRule REQUEST_HEADERS:X-Body-Deny "@streq yes" "id:910511,phase:2,deny,status:403,log"
            SecAuditEngine On
            SecAuditLogParts ABHZ
            SecAuditLog %%TESTDIR%%/auditlog-redirect-all.txt
            SecAuditLogType Serial
        ';
        error_page 403 /block.html;

        location = /attack.html { }
        location = /block.html { internal; }
        location = /same-origin { try_files /missing-same-origin /same-target.html; }
        location = /same-target.html { }
        location = /changed-origin { try_files /missing-changed-origin /changed-target.html; }
        location = /changed-target.html {
            modsecurity_rules 'SecAction "id:910514,phase:1,pass,nolog"';
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  s5;
        root %%TESTDIR%%/http;
        client_body_buffer_size 64k;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRequestBodyAccess On
            SecRequestBodyLimit 11
            SecRequestBodyLimitAction ProcessPartial
            SecRule REQUEST_BODY "@beginsWith partial-hit" "id:910520,phase:2,deny,status:409,nolog"
            SecRule REQUEST_BODY "@contains beyond-limit" "id:910521,phase:2,deny,status:418,nolog"
            SecAuditEngine Off
        ';
        error_page 405 =200 /partial-accepted.txt;
        location = /file-partial { client_body_in_file_only clean; }
        location = /memory-partial { }
        location = /partial-accepted.txt { internal; modsecurity off; }
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
my $block_txt = "Configured WAF block page.";
$t->write_file('/http/block.html', $block_txt);
for my $name (qw/attack.html same-target.html changed-target.html file-partial memory-partial/) {
    $t->write_file('/http/' . $name, 'allowed static response');
}
$t->write_file('/http/partial-accepted.txt', 'accepted partial request');

$t->run();
$t->plan(29);

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

# A configured block page must not run the original scanner/header rules again.
my $blocked_p1 = http_get_host('s4', '/attack.html?marker=p1-scan', 'X-Scanner: yes');
my $blocked_p2 = http_get_host('s4', '/attack.html?marker=p2-scan', 'X-Body-Deny: yes');
like($blocked_p1, qr/^HTTP\/1\.[01] 403/, 'P1 denial keeps its status through the configured block page');
like($blocked_p1, qr/\Q$block_txt\E/, 'P1 denial serves the configured block page');
like($blocked_p2, qr/^HTTP\/1\.[01] 403/, 'P2 denial keeps its status through the configured block page');
like($blocked_p2, qr/\Q$block_txt\E/, 'P2 denial serves the configured block page');

my $same_policy = http_get_host('s4', '/same-origin?marker=same-policy');
my $changed_policy = http_get_host('s4', '/changed-origin?marker=changed-policy');
like($same_policy, qr/^HTTP\/1\.[01] 200/, 'equivalent inherited policy permits the internal redirect');
like($changed_policy, qr/^HTTP\/1\.[01] 200/, 'changed target policy permits its legitimate control');
my $redirect_audit = do {
    local $/ = undef;
    open my $fh, '<', "$d/auditlog-redirect-all.txt" or die "could not open: $!";
    <$fh>;
};
# Part B has one exact HTTP request line per serial native audit transaction.
for my $observation (
    ['/attack.html?marker=p1-scan', 1, 'P1 block is audited once'],
    ['/attack.html?marker=p2-scan', 1, 'original P2 block is audited once'],
    ['/same-origin?marker=same-policy', 1, 'equivalent inherited policy does not duplicate audits'],
    ['/changed-origin?marker=changed-policy', 2, 'both changed-policy transaction owners are audited'],
) {
    my ($uri, $expected, $name) = @$observation;
    my $count = () = $redirect_audit =~ /^GET \Q$uri\E HTTP\/1\.[01]\r?$/mg;
    is($count, $expected, $name);
}

# The retained prefix is inspected identically in memory and a forced temp file.
# The allowed control's forbidden tail must stay beyond the engine-owned limit.
my $partial_hit = 'partial-hit-beyond-limit';
my $partial_allow = 'allowed-xxxbeyond-limit';
my $file_hit = http_post_host('s5', '/file-partial', $partial_hit);
my $memory_hit = http_post_host('s5', '/memory-partial', $partial_hit);
my $file_allow = http_post_host('s5', '/file-partial', $partial_allow);
my $memory_allow = http_post_host('s5', '/memory-partial', $partial_allow);
like($file_hit, qr/^HTTP\/1\.[01] 409/, 'file-backed ProcessPartial runs P2 on the retained prefix');
like($memory_hit, qr/^HTTP\/1\.[01] 409/, 'memory ProcessPartial runs P2 on the retained prefix');
like($file_allow, qr/^HTTP\/1\.[01] 200/, 'file-backed ProcessPartial permits its retained-prefix control');
like($memory_allow, qr/^HTTP\/1\.[01] 200/, 'memory ProcessPartial permits its retained-prefix control');
like($file_allow, qr/accepted partial request/, 'file-backed partial control delivers the expected response');

###############################################################################

sub http_post_host {
    my ($host, $url, $body) = @_;
    my $length = length($body);
    return http(<<EOF);
POST $url HTTP/1.0
Host: $host
Content-Type: text/plain
Content-Length: $length

$body
EOF
}

sub http_get_host {
	my ($host, $url, $headers) = @_;
	# No bytes after the empty line: unread input makes NGINX close lingering,
	# which sends EOF before the log phase writes the audit records read above.
	$headers = defined $headers ? "$headers\n" : '';
	return http(<<EOF);
GET $url HTTP/1.0
Host: $host
$headers
EOF
}

###############################################################################
