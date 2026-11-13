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


# Tests for ModSecurity module, logging tasks in a thread pool at worker exit.

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

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

thread_pool tiny threads=1 max_queue=1;
thread_pool slow threads=1;

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
            SecRequestBodyAccess On
            SecRule REQUEST_URI "@inspectFile %%TESTDIR%%/sleep.sh" "id:81,phase:5,pass,nolog"
        ';

        # max_pending=2 with max_queue=1 leaves no room for the pool's exit
        # task while one task runs and one waits.

        location /drain/ {
            modsecurity_log_thread_pool tiny max_pending=2;
            modsecurity_rules '
                SecAuditEngine On
                SecAuditLogParts ABZ
                SecAuditLog %%TESTDIR%%/audit.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }

        location = /pid {
            modsecurity off;
            add_header X-Pid $pid;
            return 204;
        }

        location /upload/ {
            modsecurity_log_thread_pool slow;
            modsecurity_rules '
                SecUploadDir %%TESTDIR%%/upload
                SecTmpSaveUploadedFiles On
                SecUploadKeepFiles Off
            ';
        }
    }
}

EOF

mkdir($t->testdir() . '/drain');
$t->write_file('/drain/index.html', 'DRAIN INDEX');
mkdir($t->testdir() . '/upload');
$t->write_file('sleep.sh', "#!/bin/sh\nsleep 1\n");
chmod(0755, $t->testdir() . '/sleep.sh');
$t->try_run('no modsecurity_log_thread_pool')->plan(5);

###############################################################################

# Graceful shutdown waits for the logging tasks, even when the pool's queue
# has no room for its exit task.

like(http_get('/drain/index.html'), qr/DRAIN INDEX/, 'first request');
select undef, undef, undef, 0.2;
like(http_get('/drain/index.html'), qr/DRAIN INDEX/, 'second request');

$t->stop();

my $records = () = read_file($t->testdir() . '/audit.txt') =~ /^---\w+---Z--$/mg;
is($records, 2, 'audit records written before the worker exited');

# Fast shutdown of the worker: the pool still runs the task, which also destroys the
# transaction and so removes its temporary upload file.

$t->run();

my $body = <<"EOF";
--XyZ\r
Content-Disposition: form-data; name="f"; filename="a.txt"\r
Content-Type: text/plain\r
\r
UPLOADED\r
--XyZ--\r
EOF

http(<<"EOF" . $body);
POST /upload/index.html HTTP/1.0\r
Host: localhost\r
Content-Type: multipart/form-data; boundary=XyZ\r
Content-Length: @{[ length $body ]}\r
\r
EOF

select undef, undef, undef, 0.2;
ok(upload_files($t->testdir()) > 0, 'upload saved to a temporary file');

http_get('/pid') =~ qr/X-Pid: (\d+)/;
my $worker = $1;
kill 'TERM', $worker;

for (1 .. 50) {
	last unless kill 0, $worker;
	select undef, undef, undef, 0.1;
}

is(upload_files($t->testdir()), 0, 'temporary upload file removed at fast shutdown');

###############################################################################

sub upload_files {
	my ($dir) = @_;
	opendir(my $dh, $dir . '/upload') or return -1;
	my @files = grep { !/^\./ } readdir($dh);
	closedir($dh);
	return scalar @files;
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
