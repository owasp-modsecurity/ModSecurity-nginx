#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (native logging phase).
#
# msc_process_logging() -- phase 5 rules and the audit log -- runs at most
# once per transaction: after early logging of an access-phase intervention,
# after an internal redirect, and for a request whose subrequests run the LOG
# phase too ("log_subrequest on").

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

    server {
        listen       127.0.0.1:8080;
        server_name  early;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS:what "@streq deny" "id:100,phase:1,deny,status:403,log,auditlog"
            SecRule ARGS:what "@streq pass" "id:101,phase:1,pass,log,auditlog"
            SecRule REQUEST_URI "@rx ." "id:900,phase:5,pass,log,auditlog"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABHZ
            SecAuditLog %%TESTDIR%%/audit-early.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        error_page 403 /403.html;
        error_page 404 /off/404.html;

        location / {
        }

        location /off/ {
            modsecurity off;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  ssi;

        log_subrequest on;
        default_type text/html;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/html
            SecRule REQUEST_HEADERS:X-Test "@streq ssi" "id:200,phase:1,pass,log,auditlog"
            SecRule RESPONSE_BODY "@contains END-OF-MAIN" "id:300,phase:4,pass,log,auditlog"
            SecRule REQUEST_URI "@rx ." "id:901,phase:5,pass,log,auditlog"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABHZ
            SecAuditLog %%TESTDIR%%/audit-ssi.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        location = /ssi.html {
            ssi on;
        }
    }
}

EOF

$t->write_file('index.html', 'MAIN PAGE');
$t->write_file('403.html', 'BLOCKED PAGE');
mkdir($t->testdir() . '/off');
$t->write_file('off/404.html', 'NOT FOUND PAGE');
$t->write_file('ssi.html',
	'BEFORE <!--# include virtual="/included.html" --> END-OF-MAIN');
$t->write_file('included.html', 'INCLUDED');

$t->run();
$t->plan(13);

###############################################################################

# With HTTP/1.0 nginx closes the connection only after the LOG phase, so the
# logs are complete once http() returns.

# Each serial audit log record starts with a part A header of the form
# "---<boundary>---A--" on a line of its own.

sub records {
	my ($audit) = @_;
	return scalar(() = $audit =~ /^---\w+---A--$/mg);
}

# Every run of the logging phase matches the phase 5 rule once, and
# libModSecurity reports each match in the error log.

sub matches {
	my ($log, $id) = @_;
	return scalar(() = $log =~ /\[id "$id"\]/g);
}

my $r;

# An access-phase intervention is logged early; the error_page internal
# redirect and the LOG phase that follow must not run the logging phase again.

$r = http(<<EOF);
GET /index.html?what=deny HTTP/1.0
Host: early

EOF

like($r, qr/^HTTP\/1\.1 403 /, 'early: request denied');
like($r, qr/BLOCKED PAGE/, 'early: error page delivered');

is(records($t->read_file('audit-early.txt')), 1,
	'early: one audit log record');
is(matches($t->read_file('error.log'), 900), 1, 'early: phase 5 ran once');

# Without an intervention the LOG phase logs the transaction, also after an
# internal redirect into a location with ModSecurity off.

$r = http(<<EOF);
GET /missing.html?what=pass HTTP/1.0
Host: early

EOF

like($r, qr/^HTTP\/1\.1 404 /, 'redirect: not found');
like($r, qr/NOT FOUND PAGE/, 'redirect: error page delivered');

is(records($t->read_file('audit-early.txt')), 2,
	'redirect: one more audit log record');
is(matches($t->read_file('error.log'), 900), 2,
	'redirect: phase 5 ran once more');

# The LOG phase of a subrequest shares the transaction of the main request,
# which logs it once its response is complete.

$r = http(<<EOF);
GET /ssi.html HTTP/1.0
Host: ssi
X-Test: ssi

EOF

like($r, qr/BEFORE INCLUDED END-OF-MAIN/, 'ssi: include delivered');

is(records($t->read_file('audit-ssi.txt')), 1, 'ssi: one audit log record');
is(matches($t->read_file('error.log'), 901), 1, 'ssi: phase 5 ran once');
like($t->read_file('audit-ssi.txt'), qr/\[id "300"\]/,
	'ssi: logged after the response body was inspected');
unlike($t->read_file('error.log'),
	qr/ModSecurity: (?:the logging phase|no transaction)/,
	'no native logging failure reported');

###############################################################################
