#!/usr/bin/perl

# Preserve native audit owners across same-policy, changed-policy and disabled
# internal targets. These checks require a real NGINX/libModSecurity build.

use warnings;
use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http/)->plan(11);

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
        ';
        location /same/ {
            modsecurity_rules '
                SecAuditEngine On
                SecAuditLogType Serial
                SecAuditLogParts ABZ
                SecAuditLog %%TESTDIR%%/audit-source.log
            ';
            try_files $uri /same/index.html;
        }
        location = /changed-start {
            modsecurity_rules '
                SecAuditEngine On
                SecAuditLogType Serial
                SecAuditLogParts ABZ
                SecAuditLog %%TESTDIR%%/audit-source.log
            ';
            try_files /nonexistent-audit-source /changed-final;
        }
        location = /changed-final {
            modsecurity_rules '
                SecAuditEngine On
                SecAuditLogType Serial
                SecAuditLogParts ABZ
                SecAuditLog %%TESTDIR%%/audit-target.log
            ';
        }
        location = /disabled-start {
            modsecurity_rules '
                SecAuditEngine On
                SecAuditLogType Serial
                SecAuditLogParts ABZ
                SecAuditLog %%TESTDIR%%/audit-source.log
            ';
            try_files /nonexistent-audit-source /disabled-final;
        }
        location = /disabled-final {
            modsecurity off;
        }
    }
}
EOF

mkdir($t->testdir() . '/same');
$t->write_file('same/index.html', 'same-policy-response');
$t->write_file('changed-final', 'changed-policy-response');
$t->write_file('disabled-final', 'disabled-policy-response');
$t->run();

my $same = http_get('/same/missing');
like($same, qr/200 OK/, 'same-policy target succeeds');
like($same, qr/same-policy-response/, 'same-policy response preserved');
my $changed = http_get('/changed-start');
like($changed, qr/200 OK/, 'changed-policy target succeeds');
like($changed, qr/changed-policy-response/, 'changed-policy response preserved');
my $disabled = http_get('/disabled-start');
like($disabled, qr/200 OK/, 'disabled target succeeds');
like($disabled, qr/disabled-policy-response/, 'disabled response preserved');

# Each location owns its audit settings: the engine's rules merge otherwise
# lets an explicitly configured parent audit path override a child path.
# Stop first so the native serial audit epilogues are fully written.
$t->stop();
my $source = $t->read_file('audit-source.log');
my $target = $t->read_file('audit-target.log');
# Part B has the original request line, once per native audit record.
for my $uri ('/same/missing', '/changed-start', '/disabled-start') {
    my $count = () = $source =~ /^GET \Q$uri\E HTTP\/1\.[01]\r?$/mg;
    is($count, 1, "one source audit for $uri");
}
my $target_records = () = $target =~ /^GET /mg;
is($target_records, 1, 'only the changed policy creates a second audit owner');
like($target, qr/^GET \/changed-start HTTP\/1\.[01]\r?$/m,
    'the second audit owner records the changed-policy request');
