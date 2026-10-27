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


# Tests for ModSecurity module (modsecurity_response_body directive).

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

        sendfile on;
        default_type text/plain;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecRule RESPONSE_BODY "@contains MARKER" "id:41,phase:4,log,auditlog,pass"
            SecRule RESPONSE_STATUS "@streq 200" "id:42,phase:4,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        location /inspect/ {
            modsecurity_rules '
                SecAuditLog %%TESTDIR%%/audit-inspect.txt
            ';
            error_log %%TESTDIR%%/error-inspect.log debug;
        }

        location /skip/ {
            modsecurity_response_body off;
            modsecurity_rules '
                SecAuditLog %%TESTDIR%%/audit-skip.txt
            ';
            error_log %%TESTDIR%%/error-skip.log debug;
        }

        location /inherit/ {
            modsecurity_response_body off;

            location /inherit/nested/ {
                modsecurity_rules '
                    SecAuditLog %%TESTDIR%%/audit-nested.txt
                ';
            }
        }
    }
}

EOF

mkdir($t->testdir() . '/inspect');
mkdir($t->testdir() . '/skip');
mkdir($t->testdir() . '/inherit');
mkdir($t->testdir() . '/inherit/nested');
$t->write_file('/inspect/page', 'the body has a MARKER in it');
$t->write_file('/skip/page', 'the body has a MARKER in it');
$t->write_file('/inherit/nested/page', 'the body has a MARKER in it');

$t->run();
$t->plan(13);

###############################################################################

like(http_get('/inspect/page'), qr/MARKER in it/, 'default: body delivered');
like(http_get('/skip/page'), qr/MARKER in it/, 'off: body delivered intact');
like(http_get('/inherit/nested/page'), qr/MARKER in it/,
	'inherited off: body delivered intact');

my $inspect = read_file($t->testdir() . '/audit-inspect.txt');
my $skip = read_file($t->testdir() . '/audit-skip.txt');
my $nested = read_file($t->testdir() . '/audit-nested.txt');

like($inspect, qr/\[id "41"\]/, 'default: RESPONSE_BODY rule matched');
like($inspect, qr/\[id "42"\]/, 'default: phase 4 ran');
unlike($skip, qr/\[id "41"\]/, 'off: RESPONSE_BODY not fed to ModSecurity');
like($skip, qr/\[id "42"\]/, 'off: phase 4 still ran');
unlike($nested, qr/\[id "41"\]/,
	'inherited off: RESPONSE_BODY not fed to ModSecurity');
like($nested, qr/\[id "42"\]/, 'inherited off: phase 4 still ran');

my $einspect = read_file($t->testdir() . '/error-inspect.log');
my $eskip = read_file($t->testdir() . '/error-skip.log');

# the per location error_log takes these requests out of the error.log that
# Test::Nginx scans for alerts, so check them here as well.
unlike($einspect, qr/\[alert\]|\[crit\]|\[emerg\]/, 'default: no alerts');
unlike($eskip, qr/\[alert\]|\[crit\]|\[emerg\]/, 'off: no alerts');

SKIP: {
skip 'needs --with-debug', 2 unless $t->has_module('--with-debug');
skip 'no sendfile on win32', 2 if $^O eq 'MSWin32';

# nginx keeps the buffer flagged as in-file even when it has to read it into
# memory, so sendfile() is used either way here; what "t:1 f:1" tells apart is
# whether the copy filter had to read the file into memory beforehand.  The
# copy filter only leaves a buffer in the file when sendfile is available, so
# without it both locations read the body into memory and there is nothing to
# tell apart.
like($einspect, qr/write new buf t:1 f:1 /, 'default: body read into memory');
unlike($eskip, qr/write new buf t:1 f:1 /, 'off: body sent straight from file');
}

###############################################################################

sub read_file {
	my ($path) = @_;
	local $/;
	open my $fh, '<', $path or return '';
	my $data = <$fh>;
	close $fh;
	return $data;
}
