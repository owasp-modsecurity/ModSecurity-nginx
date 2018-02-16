#!/usr/bin/perl

#
# ModSecurity, http://www.modsecurity.org/
# Copyright (c) 2015 Trustwave Holdings, Inc. (http://www.trustwave.com/)
#
# You may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# If any of the files related to licensing are missing or if you have any
# other questions related to licensing please contact Trustwave Holdings, Inc.
# directly using the email address security@modsecurity.org.
#


# Tests for ModSecurity module.

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

        error_page 403 /403.html;

        location /403.html {
            root %%TESTDIR%%/http;
            internal;
        }

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@streq root" "id:10,phase:1,auditlog,status:403,deny"
                SecDebugLog %%TESTDIR%%/auditlog-debug-local.txt
                SecDebugLogLevel 9
                SecAuditEngine RelevantOnly
                SecAuditLogParts AB
                SecAuditLog %%TESTDIR%%/auditlog-local.txt
                SecAuditLogType Serial
                SecAuditLogStorageDir %%TESTDIR%%/
            ';
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS "@streq root" "id:10,phase:1,auditlog,status:403,deny"
            SecDebugLog %%TESTDIR%%/auditlog-debug-global.txt
            SecDebugLogLevel 9
            SecAuditEngine RelevantOnly
            SecAuditLogParts AB
            SecAuditLog %%TESTDIR%%/auditlog-global.txt
            SecAuditLogType Serial
            SecAuditLogStorageDir %%TESTDIR%%/
        ';

        error_page 403 /403.html;

        location /403.html {
            modsecurity off;
            root %%TESTDIR%%/http;
            internal;
        }

        location / {
        }
    }
}
EOF

my $index_txt = "This is the index page.";
my $custom_txt = "This is a custom error page.";

$t->write_file("/index.html", $index_txt);
mkdir($t->testdir() . '/http');
$t->write_file("/http/403.html", $custom_txt);

$t->run();
$t->plan(8);

###############################################################################

my $d = $t->testdir();

my $t1;
my $t2;
my $t3;
my $t4;

# Performing requests to a server with ModSecurity enabled at location context
$t1 = http_get('/index.html?what=root');
$t2 = http_get('/index.html?what=other');

# Performing requests to a server with ModSecurity enabled at server context
$t3 = http_get2('/index.html?what=root');
$t4 = http_get2('/index.html?what=other');

my $local = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-local.txt"
        or die "could not open: $!";
    <$fh>;
};

my $global = do {
    local $/ = undef;
    open my $fh, "<", "$d/auditlog-global.txt"
        or die "could not open: $!";
    <$fh>;
};

like($t1, qr/$custom_txt/, 'ModSecurity at location / root');
like($t2, qr/$index_txt/, 'ModSecurity at location / other');
like($local, qr/what=root/, 'ModSecurity at location / root present in auditlog');
unlike($local, qr/what=other/, 'ModSecurity at location / other not present in auditlog');

like($t3, qr/$custom_txt/, 'ModSecurity at server / root');
like($t4, qr/$index_txt/, 'ModSecurity at server / other');
like($global, qr/what=root/, 'ModSecurity at server / root present in auditlog');
unlike($global, qr/what=other/, 'ModSecurity at server / other not present in auditlog');

###############################################################################

sub http_get2($;%) {
	my ($url, %extra) = @_;
	return http2(<<EOF, %extra);
GET $url HTTP/1.0
Host: localhost

EOF
}

sub http2($;%) {
	my ($request, %extra) = @_;

	my $s = http_start2($request, %extra);

	return $s if $extra{start} or !defined $s;
	return http_end2($s);
}

sub http_start2($;%) {
	my ($request, %extra) = @_;
	my $s;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		$s = $extra{socket} || IO::Socket::INET->new(
			Proto => 'tcp',
			PeerAddr => '127.0.0.1:' . port(8081)
		)
			or die "Can't connect to nginx: $!\n";

		log_out($request);
		$s->print($request);

		select undef, undef, undef, $extra{sleep} if $extra{sleep};
		return '' if $extra{aborted};

		if ($extra{body}) {
			log_out($extra{body});
			$s->print($extra{body});
		}

		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in("died: $@");
		return undef;
	}

	return $s;
}

sub http_end2($;%) {
	my ($s) = @_;
	my $reply;

	eval {
		local $SIG{ALRM} = sub { die "timeout\n" };
		local $SIG{PIPE} = sub { die "sigpipe\n" };
		alarm(8);

		local $/;
		$reply = $s->getline();

		alarm(0);
	};
	alarm(0);
	if ($@) {
		log_in("died: $@");
		return undef;
	}

	log_in($reply);
	return $reply;
}

###############################################################################
