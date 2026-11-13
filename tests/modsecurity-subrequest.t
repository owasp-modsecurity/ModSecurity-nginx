#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (subrequests).

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

my $t = Test::Nginx->new()->has(qw/http auth_request ssi/);

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

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule RESPONSE_STATUS "@streq 204" "id:501,phase:3,log,auditlog,pass"
            SecRule RESPONSE_HEADERS:X-Main-Marker "@streq main" "id:502,phase:3,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLog %%TESTDIR%%/audit-auth.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        location = /auth {
            return 204;
        }

        location / {
            auth_request /auth;
            add_header X-Main-Marker main;
        }
    }

    server {
        listen       127.0.0.1:8080;
        server_name  ssi;

        sendfile on;
        log_subrequest on;
        default_type text/plain;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/html
            SecRule REQUEST_HEADERS:X-Test "@streq ssi" "id:500,phase:1,log,auditlog,pass"
            SecRule RESPONSE_BODY "@contains INCLUDED-MARKER" "id:503,phase:4,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLog %%TESTDIR%%/audit-ssi.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        location = /ssi.html {
            default_type text/html;
            ssi on;
        }
    }
}

EOF

$t->write_file('index.html', 'MAIN PAGE');
$t->write_file('ssi.html',
	'BEFORE <!--# include virtual="/static.txt" --> AFTER');
$t->write_file('static.txt', 'INCLUDED-MARKER');
$t->run();
$t->plan(7);

###############################################################################

my $r = http_get('/index.html');

like($r, qr/^HTTP.*200/, 'request with auth_request passes');
like($r, qr/MAIN PAGE/, 'main body delivered');

my $audit = $t->read_file('audit-auth.txt');

like($audit, qr/\[id "502"\]/, 'main response headers inspected');
unlike($audit, qr/\[id "501"\]/, 'auth subrequest response not inspected as main response');

$r = http(<<EOF);
GET /ssi.html HTTP/1.0
Host: ssi
X-Test: ssi

EOF

like($r, qr/BEFORE INCLUDED-MARKER AFTER/, 'ssi include delivered');

$audit = $t->read_file('audit-ssi.txt');

like($audit, qr/\[id "503"\]/, 'included file inspected in phase 4');

# Each serial audit log record starts with a part-A section header of the
# form "---<boundary>---A--" on a line of its own.  The SSI subrequest is
# created while the main response body is sent, after every ACCESS-phase
# handler has run, so rule 500 has made the transaction relevant by then and
# a phase 5 run for the logged subrequest would show up as an extra record.

my $records = () = $audit =~ /^---\w+---A--$/mg;

is($records, 1, 'phase 5 ran once for the transaction');

###############################################################################
