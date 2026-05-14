#!/usr/bin/perl
use warnings; use strict;
use Test::More tests => 1;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx::Socket -Base;

my $t = Test::Nginx::Socket->new()->has(qw/http/);
$t->write_file('phase4-invalid.conf', "text/*\n");

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%

events {}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 127.0.0.1:%%PORT%%;
        server_name localhost;
        location / {
            modsecurity on;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-invalid.conf;
            return 200 "ok\n";
        }
    }
}
EOF

my $cmd = "$t->{_testdir}/../nginx -p $t->{_testdir}/ -c nginx.conf -t 2>&1";
my $out = `$cmd`;

like($out, qr/invalid content-type entry in modsecurity_phase4_content_types_file/,
    'error points to invalid content-type entry');
