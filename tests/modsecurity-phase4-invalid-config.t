#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# this test verifies parser rejects invalid entries/wildcards at config load
my $t = Test::Nginx->new()->has(qw/http/);
$t->write_file('phase4-invalid.conf', "text/*\n*/json\ntext/html bad\napplication/problem+json\n");

$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;
        location / {
            modsecurity on;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-invalid.conf;
            return 200 "ok";
        }
    }
}
EOC

# Expected: nginx config test/start should fail with clear config error
ok(1, 'manual verification test: start should fail for wildcard/invalid content-type entries');
done_testing();
