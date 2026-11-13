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

my $t = Test::Nginx->new()->has(qw/http threads ssi/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

thread_pool modsec threads=2;
thread_pool slow threads=1;

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
            SecRule ARGS:what "@streq p5redir" "id:73,phase:5,log,pass"
        ';

        log_subrequest on;

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

        location /ssi/ {
            ssi on;
            modsecurity_rules '
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABH
                SecAuditLog %%TESTDIR%%/audit-ssi.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }

        location /busy/ {
            modsecurity_log_thread_pool slow max_pending=1;
            modsecurity_rules '
                SecRule REQUEST_URI "@inspectFile %%TESTDIR%%/sleep.sh" "id:74,phase:5,pass,nolog"
            ';
        }

        location /redir/ {
            modsecurity_log_thread_pool off;
            try_files /nonexistent /index.html;
        }
    }
}

EOF

$t->write_file('index.html', 'INDEX');
mkdir($t->testdir() . '/sync');
$t->write_file('/sync/index.html', 'SYNC INDEX');
mkdir($t->testdir() . '/ssi');
$t->write_file('/ssi/index.html', 'SSI <!--#include virtual="/index.html" -->');
mkdir($t->testdir() . '/busy');
$t->write_file('/busy/index.html', 'BUSY INDEX');
$t->write_file('sleep.sh', "#!/bin/sh\nsleep 1\n");
chmod(0755, $t->testdir() . '/sleep.sh');
$t->try_run('no modsecurity_log_thread_pool')->plan(18);

###############################################################################

like(http_get('/index.html?what=block'), qr/^HTTP.*403/, 'phase 1 deny still blocks');
like(http_get('/index.html?what=p5'), qr/INDEX/, 'request with phase 5 rule passes');
like(http_get('/index.html?what=none'), qr/INDEX/, 'plain request passes');
like(http_get('/sync/index.html?what=p5'), qr/SYNC INDEX/, 'thread pool off in location');
like(http_get('/ssi/index.html?what=p5'), qr/SSI INDEX/, 'request with subrequest passes');
like(http_get('/redir/x?what=p5redir'), qr/INDEX/, 'internally redirected request passes');

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

# With log_subrequest on, the log phase of the SSI subrequest must not run
# phase 5 of the main request's transaction.  Each serial audit log record
# starts with a part-A section header line, so counting those counts the
# records; the second run would come from the thread, hence the extra wait.

my $ssi = wait_for_file($t->testdir() . '/audit-ssi.txt', qr/\[id "72"\]/);
select undef, undef, undef, 0.5;
$ssi = read_file($t->testdir() . '/audit-ssi.txt');
my $records = () = $ssi =~ /^---\w+---A--$/mg;
is($records, 1, 'phase 5 ran once for a request with a subrequest');

wait_for_file($t->testdir() . '/error.log', qr/\[id "73"\]/);

my $errlog = read_file($t->testdir() . '/error.log');
unlike($errlog, qr/could not post logging/, 'logging was not refused by the pool');
like($errlog, qr/^(?:(?!client:).)*\[id "72"\](?:(?!client:).)*$/m,
	'phase 5 rule message written from the thread pool log');
like($errlog, qr/^.*\[id "72"\].*client:.*$/m,
	'phase 5 rule message of the synchronous location keeps the request context');
like($errlog, qr/^(?:(?!client:).)*\[id "73"\](?:(?!client:).)*$/m,
	'offload decided by the location the request ended in');

# The phase 5 rule of /busy/ keeps the only thread of its pool busy for a
# second, so the second request finds max_pending reached and is logged
# inline.

like(http_get('/busy/index.html'), qr/BUSY INDEX/, 'first request to busy pool');
like(http_get('/busy/index.html'), qr/BUSY INDEX/, 'second request to busy pool');
like(read_file($t->testdir() . '/error.log'),
	qr/could not post logging to thread pool, 1 tasks pending/,
	'max_pending reached falls back to inline logging');

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
