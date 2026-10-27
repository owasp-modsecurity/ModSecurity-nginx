#!/usr/bin/perl

# (C) Andrei Belov

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

my $t = Test::Nginx->new()->has(qw/http auth_request/);

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
        log_subrequest on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule REQUEST_URI "@streq /index.html" "id:500,phase:2,log,auditlog,pass"
            SecRule RESPONSE_STATUS "@streq 204" "id:501,phase:3,log,auditlog,pass"
            SecRule RESPONSE_HEADERS:X-Main-Marker "@streq main" "id:502,phase:3,log,auditlog,pass"
            SecAuditEngine RelevantOnly
            SecAuditLogParts ABH
            SecAuditLog %%TESTDIR%%/audit.txt
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
}

EOF

$t->write_file('index.html', 'MAIN PAGE');
$t->run();
$t->plan(5);

###############################################################################

my $r = http_get('/index.html');

like($r, qr/^HTTP.*200/, 'request with auth_request passes');
like($r, qr/MAIN PAGE/, 'main body delivered');

my $audit = read_file($t->testdir() . '/audit.txt');

like($audit, qr/\[id "502"\]/, 'main response headers inspected');
unlike($audit, qr/\[id "501"\]/, 'auth subrequest response not inspected as main response');

# Each serial audit log record starts with a part-A section header of the
# form "---<boundary>---A--" on a line of its own, so counting those lines
# counts the records.  The rule with id 500 makes the transaction relevant
# before the auth subrequest is even created, so a second, premature run of
# phase 5 (one per logged subrequest) shows up as an extra record here.

my $records = () = $audit =~ /^---\w+---A--$/mg;

is($records, 1, 'phase 5 ran once for the transaction');

###############################################################################

sub read_file {
	my ($file) = @_;

	local $/ = undef;
	open my $fh, '<', $file
		or return '';
	my $content = <$fh>;
	close $fh;

	return $content;
}

###############################################################################
