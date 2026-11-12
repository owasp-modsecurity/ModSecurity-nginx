#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

my $t = Test::Nginx->new()->has(qw/http/)->plan(3);
# Test::Nginx always reads this file in its two cleanup assertions, even
# when nginx -t exits during configuration parsing before opening its log.
$t->write_file('error.log', '');
my $binary = $ENV{TEST_NGINX_BINARY} || ($t->testdir() . '/../nginx');

for my $case (
    ['modsecurity_phase4_mode minimal;', qr/invalid value.*minimal|invalid.*phase4.*mode/, 'removed minimal mode is rejected'],
    ['modsecurity_phase4_content_types_file removed.conf;', qr/unknown directive.*modsecurity_phase4_content_types_file/, 'removed connector MIME directive is rejected'],
    ['modsecurity_phase4_body_limit 0;', qr/(?:must be|invalid|greater than).*0|invalid.*body.*limit|body.*limit.*(?:positive|zero)/, 'zero connector body limit is rejected'],
) {
    my ($directive, $expected, $label) = @$case;
    $t->write_file_expand('nginx.conf', <<"EOF");
%%TEST_GLOBALS%%
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:19849;
        location / {
            modsecurity on;
            $directive
            return 200 "ok\\n";
        }
    }
}
EOF
    my $prefix = $t->testdir();
    my $out = `"$binary" -p "$prefix/" -c nginx.conf -e error.log -t 2>&1`;
    like($out, $expected, $label);
}
