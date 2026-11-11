#!/usr/bin/perl

# Tests for ModSecurity-nginx connector ($msc_tx_* variables).

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

    log_format tx 'late=$msc_tx_late';

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        root %%TESTDIR%%;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:tag "@unconditionalMatch" "id:1,phase:1,pass,nolog,setvar:tx.waf_tag=%{ARGS.tag}"
                SecRule ARGS:mixed "@unconditionalMatch" "id:2,phase:2,pass,nolog,setvar:tx.Mixed_Case=yes"
                SecRule ARGS:deny "@unconditionalMatch" "id:3,phase:1,deny,status:403,setvar:tx.reason=denied"
            ';
            add_header X-Tag $msc_tx_waf_tag;
            add_header X-Mixed $msc_tx_mixed_case;
            error_page 403 /blocked;
        }

        location /late {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule RESPONSE_STATUS "@eq 200" "id:10,phase:3,pass,nolog,setvar:tx.late=yes"
            ';
            add_header X-Late "[$msc_tx_late]";
            access_log %%TESTDIR%%/late.log tx;
        }

        location /blocked {
            modsecurity off;
            add_header X-Reason $msc_tx_reason always;
        }

        location /off {
            modsecurity off;
            add_header X-Tag "[$msc_tx_waf_tag]";
        }
    }
}
EOF

$t->write_file('index.html', 'ok');
$t->write_file('off', 'ok');
$t->write_file('late', 'ok');
$t->write_file('blocked', 'blocked');
$t->try_run('no msc_get_tx() in libmodsecurity')->plan(9);

###############################################################################

like(http_get('/index.html?tag=admin'), qr/X-Tag: admin/, 'tx variable set in phase 1');
like(http_get('/index.html?mixed=1'), qr/X-Mixed: yes/, 'tx variable name is case-insensitive');
unlike(http_get('/index.html'), qr/X-Tag:/, 'unset tx variable is empty');
like(http_get('/off?tag=admin'), qr/X-Tag: \[\]/, 'empty when modsecurity is off');

my $r = http_get('/index.html?tag=a%0d%0aX-Injected:%201');
unlike($r, qr/X-Injected/, 'CRLF in tx value does not inject headers');
unlike($r, qr/X-Tag:/, 'tx value with CRLF is empty');

like(http_get('/late'), qr/X-Late: \[\]/, 'phase 3 value not seen by add_header');
like($t->read_file('late.log'), qr/^late=yes$/m,
	'access_log sees phase 3 value set after add_header cached it');

like(http_get('/index.html?deny=1'), qr/X-Reason: denied/,
	'tx value kept after error_page redirect');

###############################################################################
