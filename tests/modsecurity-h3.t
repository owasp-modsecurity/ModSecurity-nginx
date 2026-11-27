#!/usr/bin/perl

# Tests for ModSecurity module (HTTP/3).
# Tests that Host header from :authority pseudo-header is passed to ModSecurity.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP3;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http http_v3/)
	->has_daemon('openssl');

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    ssl_certificate_key localhost.key;
    ssl_certificate localhost.crt;

    server {
        listen       127.0.0.1:%%PORT_8980_UDP%% quic;
        server_name  localhost;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq whee" "id:10,phase:2"
            ';
            return 200 "OK";
        }

        location /check-host {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule &REQUEST_HEADERS:Host "@gt 0" "id:999,phase:1,log,pass,msg:Host header FOUND with value %{REQUEST_HEADERS.Host}"
                SecRule &REQUEST_HEADERS:Host "@eq 0" "id:920280,phase:1,deny,status:449,msg:Missing Host Header"
            ';
            return 200 "Host header present";
        }

        location /inspect-host {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule REQUEST_HEADERS:Host "@streq localhost" "id:100,phase:1,pass,setvar:tx.host_matched=1"
                SecRule TX:host_matched "!@eq 1" "id:101,phase:1,deny,status:400,msg:Host header mismatch"
            ';
            return 200 "Host matched";
        }

    }
}
EOF

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 2048
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

my $d = $t->testdir();

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->run();
$t->plan(3);

###############################################################################

my ($s, $sid, $frames, $frame);

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream({
    headers => [
        { name => ':method', value => 'GET', mode => 0 },
        { name => ':scheme', value => 'http', mode => 0 },
        { name => ':path', value => '/', mode => 0 },
        { name => ':authority', value => 'localhost', mode => 4 },
    ]
});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'basic HTTP/3 request');

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream({
    headers => [
        { name => ':method', value => 'GET', mode => 0 },
        { name => ':scheme', value => 'http', mode => 0 },
        { name => ':path', value => '/check-host', mode => 4 },
        { name => ':authority', value => 'localhost', mode => 4 },
    ]
});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'Host header from :authority visible to ModSecurity');

$s = Test::Nginx::HTTP3->new();
$sid = $s->new_stream({
    headers => [
        { name => ':method', value => 'GET', mode => 0 },
        { name => ':scheme', value => 'http', mode => 0 },
        { name => ':path', value => '/inspect-host', mode => 4 },
        { name => ':authority', value => 'localhost', mode => 4 },
    ]
});
$frames = $s->read(all => [{ sid => $sid, fin => 1 }]);
($frame) = grep { $_->{type} eq "HEADERS" } @$frames;
is($frame->{headers}->{':status'}, 200, 'Host header value matches :authority');

###############################################################################
