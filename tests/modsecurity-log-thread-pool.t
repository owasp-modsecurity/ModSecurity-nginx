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


# Tests for ModSecurity module, phase 5 and audit logging in a thread pool.

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

my $t = Test::Nginx->new()->has(qw/http threads/);

plan(skip_all => 'nginx built with --without-pcre2')
	unless $t->has_module('(?s)^(?!.*--without-pcre2)');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

thread_pool modsec threads=2;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        modsecurity on;
        modsecurity_log_thread_pool modsec;
        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS:what "@streq block" "id:71,phase:1,deny,status:403,log,auditlog"
            SecRule ARGS:what "@streq p5" "id:72,phase:5,log,auditlog,pass"
        ';

        # libmodsecurity merges a non-empty parent SecAuditLog over the
        # child's one, so the audit log is configured per location here.

        location / {
            modsecurity_rules '
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABH
                SecAuditLog %%TESTDIR%%/audit.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }

        location /sync/ {
            modsecurity_log_thread_pool off;
            modsecurity_rules '
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABH
                SecAuditLog %%TESTDIR%%/audit-sync.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }
    }
}

EOF

$t->write_file('index.html', 'INDEX');
mkdir($t->testdir() . '/sync');
$t->write_file('/sync/index.html', 'SYNC INDEX');
$t->run();
$t->plan(11);

###############################################################################

like(http_get('/index.html?what=block'), qr/^HTTP.*403/, 'phase 1 deny still blocks');
like(http_get('/index.html?what=p5'), qr/INDEX/, 'request with phase 5 rule passes');
like(http_get('/index.html?what=none'), qr/INDEX/, 'plain request passes');
like(http_get('/sync/index.html?what=p5'), qr/SYNC INDEX/, 'thread pool off in location');

my $audit = wait_for_file($t->testdir() . '/audit.txt', qr/\[id "72"\]/);
like($audit, qr/\[id "72"\]/, 'phase 5 rule logged from thread');
like($audit, qr/what=block/, 'blocked request audited');
like($audit, qr/\[id "71"\]/, 'phase 1 deny audited');

my $sync = wait_for_file($t->testdir() . '/audit-sync.txt', qr/\[id "72"\]/);
like($sync, qr/\[id "72"\]/, 'synchronous location still audits');

# The thread pool's log is the main error_log, which has no handler, so a rule
# message written from the thread carries no ", client: ..." suffix, while one
# written on the request's connection log does.  This tells the offloaded path
# apart from the (deliberately silent) synchronous fallback.

my $errlog = read_file($t->testdir() . '/error.log');
unlike($errlog, qr/could not post logging/, 'logging was not refused by the pool');
like($errlog, qr/^(?:(?!client:).)*\[id "72"\](?:(?!client:).)*$/m,
	'phase 5 rule message written from the thread pool log');
like($errlog, qr/^.*\[id "72"\].*client:.*$/m,
	'phase 5 rule message of the synchronous location keeps the request context');

###############################################################################

sub wait_for_file {
	my ($path, $re) = @_;
	my $data = '';
	for (1 .. 50) {
		$data = read_file($path);
		last if $data =~ $re;
		select undef, undef, undef, 0.1;
	}
	return $data;
}

sub read_file {
	my ($path) = @_;
	open my $fh, '<', $path or return '';
	local $/;
	my $data = <$fh>;
	close $fh;
	return defined $data ? $data : '';
}

###############################################################################
