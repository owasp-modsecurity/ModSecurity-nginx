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

my $t = Test::Nginx->new()->has(qw/http ssi/);

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    sendfile on;
    default_type text/plain;

    modsecurity on;
    modsecurity_rules '
        SecRuleEngine On
        SecResponseBodyAccess On
        SecResponseBodyMimeType text/plain
        SecRule RESPONSE_BODY "@contains MARKER" "id:41,phase:4,log,auditlog,pass"
        SecRule RESPONSE_STATUS "@rx ^[0-9]+$" "id:42,phase:4,log,auditlog,pass"
        SecAuditEngine RelevantOnly
        SecAuditLogParts ABH
        SecAuditLogType Serial
        SecAuditLogStorageDir %%TESTDIR%%/
    ';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

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
                error_log %%TESTDIR%%/error-nested.log debug;
            }
        }

        location /ssi/ {
            ssi on;
            ssi_types text/plain;
            modsecurity_response_body off;
            modsecurity_rules '
                SecAuditLog %%TESTDIR%%/audit-ssi.txt
            ';
        }

        location = /include {
            return 200 "included MARKER";
        }

        location /deny/ {
            modsecurity_response_body off;
            modsecurity_rules '
                SecRule REQUEST_URI "@beginsWith /deny/" "id:43,phase:3,deny,status:403,log,auditlog"
                SecAuditLog %%TESTDIR%%/audit-deny.txt
            ';
            error_page 403 /error;
        }

        location = /error {
            internal;
            return 403 "error page MARKER";
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  srvoff;

        modsecurity_response_body off;

        location /on/ {
            modsecurity_response_body on;
            modsecurity_rules '
                SecAuditLog %%TESTDIR%%/audit-srv-on.txt
            ';
            error_log %%TESTDIR%%/error-srv-on.log debug;
        }

        location /off/ {
            modsecurity_rules '
                SecAuditLog %%TESTDIR%%/audit-srv-off.txt
            ';
            error_log %%TESTDIR%%/error-srv-off.log debug;
        }
    }
}

EOF

for my $d (qw{inspect skip inherit inherit/nested ssi deny on off}) {
	mkdir($t->testdir() . '/' . $d);
}
for my $d (qw{inspect skip inherit/nested on off}) {
	$t->write_file("/$d/page", 'the body has a MARKER in it');
}
$t->write_file('/ssi/page', 'main <!--# include virtual="/include" --> end');
$t->write_file('/deny/page', 'not sent');

$t->run();
$t->plan(36);

###############################################################################

like(http_get('/inspect/page'), qr/MARKER in it/, 'default: body delivered');
like(http_get('/skip/page'), qr/MARKER in it/, 'off: body delivered intact');
like(http_get('/inherit/nested/page'), qr/MARKER in it/,
	'inherited off: body delivered intact');
like(get_srvoff('/on/page'), qr/MARKER in it/,
	'server off, location on: body delivered');
like(get_srvoff('/off/page'), qr/MARKER in it/,
	'server off: body delivered intact');
like(http_get('/ssi/page'), qr/main included MARKER end/,
	'off with SSI include: body delivered');
like(http_get('/deny/page'), qr/403 Forbidden.*error page MARKER/s,
	'off with error_page: error page delivered');

my $inspect = read_file($t->testdir() . '/audit-inspect.txt');
my $skip = read_file($t->testdir() . '/audit-skip.txt');
my $nested = read_file($t->testdir() . '/audit-nested.txt');
my $srvon = read_file($t->testdir() . '/audit-srv-on.txt');
my $srvoff = read_file($t->testdir() . '/audit-srv-off.txt');
my $ssi = read_file($t->testdir() . '/audit-ssi.txt');
my $deny = read_file($t->testdir() . '/audit-deny.txt');

like($inspect, qr/\[id "41"\]/, 'default: RESPONSE_BODY rule matched');
like($inspect, qr/\[id "42"\]/, 'default: phase 4 ran');
unlike($skip, qr/\[id "41"\]/, 'off: RESPONSE_BODY not fed to ModSecurity');
like($skip, qr/\[id "42"\]/, 'off: phase 4 still ran');
unlike($nested, qr/\[id "41"\]/,
	'inherited off: RESPONSE_BODY not fed to ModSecurity');
like($nested, qr/\[id "42"\]/, 'inherited off: phase 4 still ran');
like($srvon, qr/\[id "41"\]/,
	'server off, location on: RESPONSE_BODY rule matched');
like($srvon, qr/\[id "42"\]/, 'server off, location on: phase 4 ran');
unlike($srvoff, qr/\[id "41"\]/,
	'server off: RESPONSE_BODY not fed to ModSecurity');
like($srvoff, qr/\[id "42"\]/, 'server off: phase 4 still ran');

# the include is a subrequest in a location left at the default "on"; the
# main request's setting applies to the whole response.
unlike($ssi, qr/\[id "41"\]/,
	'off with SSI include: included body not fed to ModSecurity');
like($ssi, qr/\[id "42"\]/, 'off with SSI include: phase 4 ran');

# the error page is served from a location left at the default "on" after the
# header filter already ran for the "off" location.
like($deny, qr/\[id "43"\]/, 'off with error_page: phase 3 rule denied');
unlike($deny, qr/\[id "41"\]/,
	'off with error_page: error page body not fed to ModSecurity');
like($deny, qr/\[id "42"\]/, 'off with error_page: phase 4 ran');

my %elog;
for my $n (qw/inspect skip nested srv-on srv-off/) {
	$elog{$n} = read_file($t->testdir() . "/error-$n.log");
}

# the per location error_log takes these requests out of the error.log that
# Test::Nginx scans for alerts, so check them here as well.
for my $n (qw/inspect skip nested srv-on srv-off/) {
	unlike($elog{$n}, qr/\[alert\]|\[crit\]|\[emerg\]/, "$n: no alerts");
}

SKIP: {
skip 'needs --with-debug', 9 unless $t->has_module('--with-debug');
skip 'no sendfile on win32', 9 if $^O eq 'MSWin32';

# nginx keeps the buffer flagged as in-file even when it has to read it into
# memory, so sendfile() is used either way here; what "t:1 f:1" tells apart is
# whether the copy filter had to read the file into memory beforehand, while
# "t:0 f:1" is a buffer sent straight from the file.  The copy filter only
# leaves a buffer in the file when sendfile is available, so without it both
# locations read the body into memory and there is nothing to tell apart.
like($elog{'inspect'}, qr/write new buf t:1 f:1 /,
	'default: body read into memory');
like($elog{'skip'}, qr/write new buf t:0 f:1 /,
	'off: body sent straight from file');
unlike($elog{'skip'}, qr/write new buf t:1 f:1 /,
	'off: body not read into memory');
like($elog{'nested'}, qr/write new buf t:0 f:1 /,
	'inherited off: body sent straight from file');
unlike($elog{'nested'}, qr/write new buf t:1 f:1 /,
	'inherited off: body not read into memory');
like($elog{'srv-on'}, qr/write new buf t:1 f:1 /,
	'server off, location on: body read into memory');
unlike($elog{'srv-on'}, qr/write new buf t:0 f:1 /,
	'server off, location on: body not sent straight from file');
like($elog{'srv-off'}, qr/write new buf t:0 f:1 /,
	'server off: body sent straight from file');
unlike($elog{'srv-off'}, qr/write new buf t:1 f:1 /,
	'server off: body not read into memory');
}

###############################################################################

sub get_srvoff {
	my ($uri) = @_;
	return http(<<EOF);
GET $uri HTTP/1.0
Host: srvoff

EOF
}

sub read_file {
	my ($path) = @_;
	local $/;
	open my $fh, '<', $path or return '';
	my $data = <$fh>;
	close $fh;
	return $data;
}
