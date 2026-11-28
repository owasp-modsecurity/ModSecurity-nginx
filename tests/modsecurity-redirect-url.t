#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (CR and LF in redirect URLs).
#
# libmodsecurity expands the redirect action at run time, so a rule can put
# request data such as %{ARGS.to} into the URL. ARGS are URL-decoded, so a
# client can supply real CR and LF bytes. The connector must not copy them
# into the Location header, and must leave valid URLs untouched.

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

        location /phase1 {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:to "@rx ." "id:1,phase:1,status:302,redirect:http://www.example.com/%{ARGS.to}"
            ';
        }

        location /phase3 {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:to "@rx ." "id:2,phase:3,status:302,redirect:http://www.example.com/%{ARGS.to}"
            ';
        }

        location /status307 {
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS:to "@rx ." "id:3,phase:1,status:307,redirect:http://www.example.com/%{ARGS.to}"
            ';
        }

        location /status301 {
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:4,phase:1,status:301,redirect:https://www.example.com/moved"
            ';
        }

        location /status303 {
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:5,phase:1,status:303,redirect:https://www.example.com/other"
            ';
        }

        location /encoded {
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:6,phase:1,status:302,redirect:https://www.example.com/a%20b/c?q=%0d%0a&r=%25#frag"
            ';
        }

        location /relative {
            modsecurity_rules '
                SecRuleEngine On
                SecAction "id:7,phase:1,status:302,redirect:/target?x=1#top"
            ';
        }
    }
}
EOF

$t->write_file("/phase1", "phase 1 content");
$t->write_file("/phase3", "phase 3 content");
$t->write_file("/status307", "status 307 content");
$t->run()->plan(29);

###############################################################################

my $crlf = 'ok%0d%0aX-Injected:%20yes';
my $cr = 'ok%0dX-Injected:%20yes';
my $lf = 'ok%0aX-Injected:%20yes';
my $r;

# Valid URLs, from request data and from the rule itself.

$r = http_get('/phase1?to=ok%3Fq%3D1%23frag');
like($r, qr!^HTTP/1\.1 302 !, 'phase 1 dynamic - status');
like($r, qr!^Location: http://www\.example\.com/ok\?q=1#frag\x0d?$!m,
	'phase 1 dynamic - location');

# The Location of a phase 3 redirect does not reach the client yet: the
# header filter finalizes the request, which clears the response headers.
# That is a separate issue, so only the status is checked here.

like(http_get('/phase3?to=ok'), qr!^HTTP/1\.1 302 !, 'phase 3 dynamic - status');

$r = http_get('/status301');
like($r, qr!^HTTP/1\.1 301 !, 'status 301 - status');
like($r, qr!^Location: https://www\.example\.com/moved\x0d?$!m,
	'status 301 - location');

$r = http_get('/status303');
like($r, qr!^HTTP/1\.1 303 !, 'status 303 - status');
like($r, qr!^Location: https://www\.example\.com/other\x0d?$!m,
	'status 303 - location');

$r = http_get('/status307?to=ok');
like($r, qr!^HTTP/1\.1 307 !, 'status 307 - status');
like($r, qr!^Location: http://www\.example\.com/ok\x0d?$!m,
	'status 307 - location');

# Percent-encoded CR and LF are plain text in a URL: kept and not decoded.

$r = http_get('/encoded');
like($r, qr!^HTTP/1\.1 302 !, 'percent-encoded - status');
like($r, qr!^Location: https://www\.example\.com/a%20b/c\?q=%0d%0a&r=%25#frag\x0d?$!m,
	'percent-encoded - location unchanged');

# NGINX makes a relative Location absolute, as for any other module.

$r = http_get('/relative');
like($r, qr!^HTTP/1\.1 302 !, 'relative - status');
like($r, qr!^Location: http://localhost(:\d+)?/target\?x=1#top\x0d?$!m,
	'relative - location');

# CR, LF or both from request data: no redirect, no injected header.

$r = http_get("/phase1?to=$crlf");
like($r, qr!^HTTP/1\.1 500 !, 'phase 1 CRLF - status');
unlike($r, qr!^Location:!mi, 'phase 1 CRLF - no location');
unlike($r, qr!^X-Injected:!mi, 'phase 1 CRLF - no injected header');
unlike($r, qr!phase 1 content!, 'phase 1 CRLF - content not served');

$r = http_get("/phase1?to=$cr");
like($r, qr!^HTTP/1\.1 500 !, 'phase 1 CR - status');
unlike($r, qr!^Location:!mi, 'phase 1 CR - no location');

$r = http_get("/phase1?to=$lf");
like($r, qr!^HTTP/1\.1 500 !, 'phase 1 LF - status');
unlike($r, qr!^Location:!mi, 'phase 1 LF - no location');
unlike($r, qr!^X-Injected:!mi, 'phase 1 LF - no injected header');

$r = http_get("/phase3?to=$crlf");
like($r, qr!^HTTP/1\.1 500 !, 'phase 3 CRLF - status');
unlike($r, qr!^X-Injected:!mi, 'phase 3 CRLF - no injected header');
unlike($r, qr!phase 3 content!, 'phase 3 CRLF - content not served');

$r = http_get("/status307?to=$crlf");
like($r, qr!^HTTP/1\.1 500 !, 'status 307 CRLF - status');
unlike($r, qr!^X-Injected:!mi, 'status 307 CRLF - no injected header');

# A valid redirect after a rejected one still works.

like(http_get('/phase1?to=again'),
	qr!^Location: http://www\.example\.com/again\x0d?$!m,
	'valid redirect after a rejected one');

$t->stop();

like($t->read_file('error.log'),
	qr/ModSecurity: the redirect URL contains CR or LF/,
	'rejection logged');

###############################################################################
