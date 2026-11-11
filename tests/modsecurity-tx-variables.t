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

    server {
        listen       127.0.0.1:8080;
        server_name  localhost;

        root %%TESTDIR%%;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:tag "@rx ^(.+)$" "id:1,phase:1,pass,nolog,capture,setvar:tx.waf_tag=%{TX.1}"
                SecRule ARGS:mixed "@unconditionalMatch" "id:2,phase:2,pass,nolog,setvar:tx.Mixed_Case=yes"
            ';
            add_header X-Tag $msc_tx_waf_tag;
            add_header X-Mixed $msc_tx_mixed_case;
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
$t->try_run('no msc_get_tx() in libmodsecurity')->plan(4);

###############################################################################

like(http_get('/index.html?tag=admin'), qr/X-Tag: admin/, 'tx variable set in phase 1');
like(http_get('/index.html?mixed=1'), qr/X-Mixed: yes/, 'tx variable name is case-insensitive');
unlike(http_get('/index.html'), qr/X-Tag:/, 'unset tx variable is empty');
like(http_get('/off?tag=admin'), qr/X-Tag: \[\]/, 'empty when modsecurity is off');

###############################################################################
