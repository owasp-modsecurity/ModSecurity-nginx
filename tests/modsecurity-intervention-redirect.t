#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (redirect interventions).

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

        modsecurity on;

        location /redirect {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq redirect" "id:101,phase:1,log,status:302,redirect:http://www.modsecurity.org/"
            ';
        }

        location /respredirect {
            default_type text/plain;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecResponseBodyMimeType text/plain
                SecAuditEngine RelevantOnly
                SecAuditLogParts ABH
                SecAuditLogType Serial
                SecAuditLog %%TESTDIR%%/audit-respredirect.txt
                SecRule RESPONSE_BODY "@contains MARKER" "id:102,phase:4,log,auditlog,status:302,redirect:http://www.modsecurity.org/"
            ';
        }
    }
}
EOF

$t->write_file("/redirect", "should be redirected before this.");
$t->write_file("/respredirect", "response body with a MARKER in it.");

$t->run();

# the phase 4 intervention below happens after the response headers have
# already been sent, so nginx finalizes the request with an alert
$t->todo_alerts();

$t->plan(4);

###############################################################################

my $r = http_get('/redirect?what=redirect');

like($r, qr!^HTTP/1.1 302!, 'phase 1 redirect - status');
like($r, qr!^Location: http://www\.modsecurity\.org/\x0d?$!m, 'phase 1 redirect - location');

# headers are already sent at this point, the redirection cannot be
# performed; the only requirement here is that nginx stays alive
http_get('/respredirect');

like(http_get('/redirect?what=redirect'), qr!^HTTP/1.1 302!, 'phase 1 redirect - still serving after phase 4 intervention');

my $audit = '';
$audit = $t->read_file('audit-respredirect.txt')
    if -e $t->testdir() . '/audit-respredirect.txt';

like($audit, qr/\[id "102"\]/, 'phase 4 redirect - audit log');
