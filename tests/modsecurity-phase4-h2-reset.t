#!/usr/bin/perl

# Exercise Strict phase-4 stream finalization while another HTTP/2 stream is
# active.  The auth backend resumes static content outside the HTTP/2 read
# handler; its small, unbuffered final body reaches the filter as last_buf.

use warnings;
use strict;

use Test::More;
use IO::Socket::INET;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;
use Test::Nginx::HTTP2;

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $owner = $$;
my $t = Test::Nginx->new()->has(qw/http http_v2 proxy auth_request/)->plan(21);
my $s;
my $prefix = 'allowed-prefix-';
my $tail = 'allowed-tail';
my $forbidden = 'H2-STRICT-FORBIDDEN-TAIL';
my $expect_queued = $ENV{TEST_NGINX_H2_RESET_EXPECT_QUEUED} || 0;

# Release blocked backends on failed assertions or an early bailout as well.
# Daemon children inherit END blocks and must not release the parent's gates.
END {
	if ($$ == $owner && defined $t) {
		eval {
			$t->write_file('hold-release', "\n");
			$t->write_file('strict-release', "\n");
		};
		undef $s;
		undef $t;
	}
}

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    default_type text/plain;
    sendfile off;
    postpone_output 0;

    server {
        listen 127.0.0.1:8080 http2;
        server_name localhost;
        root %%TESTDIR%%;

        modsecurity on;
        modsecurity_phase4_mode strict;
        modsecurity_phase4_log %%TESTDIR%%/strict-h2.log;
        modsecurity_rules '
            SecRuleEngine On
            SecResponseBodyAccess On
            SecResponseBodyMimeType text/plain
            SecRule RESPONSE_BODY "@contains H2-STRICT-FORBIDDEN-TAIL" "id:942377,phase:4,deny,status:403,log"
        ';

        location = /hold {
            proxy_pass http://127.0.0.1:8081;
            proxy_buffering off;
            proxy_read_timeout 30s;
        }

        location = /strict {
            auth_request /authorize-strict;
        }

        location = /authorize-strict {
            internal;
            modsecurity off;
            proxy_pass http://127.0.0.1:8082;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_read_timeout 30s;
        }

        location = /allow {
        }
    }
}
EOF

$t->write_file('strict', $forbidden);
$t->write_file('allow', 'allowed-after-reset');
$t->run_daemon(\&backend, 'hold', port(8081), $t->testdir());
$t->run_daemon(\&backend, 'strict', port(8082), $t->testdir());
$t->run();
$t->waitforsocket('127.0.0.1:' . port(8081)) or BAIL_OUT('hold backend unavailable');
$t->waitforsocket('127.0.0.1:' . port(8082)) or BAIL_OUT('auth backend unavailable');

$s = Test::Nginx::HTTP2->new();
my $held = $s->new_stream({ path => '/hold' });
my $frames = $s->read(all => [{ sid => $held, length => length($prefix) }]);
is(stream_status($frames, $held), 200, 'held stream has response headers');
is(stream_body($frames, $held), $prefix, 'held stream starts delivering allowed data');
ok(!stream_finished($frames, $held), 'held stream remains active');

my $strict = $s->new_stream({ path => '/strict' });
my $ready = $t->waitforfile($t->testdir() . '/strict-ready');
ok($ready, 'strict request reached asynchronous auth gate');
BAIL_OUT('strict auth request did not reach its gate') unless $ready;

# Settle all earlier input, including the constructor's SETTINGS ACK, while
# auth is still blocked.  Reading frames never generates acknowledgements.
$s->h2_ping('gatewait');
my $barrier = $s->read(all => [{ type => 'PING' }], wait => 3);
push @$frames, @$barrier;
my $settled = grep { $_->{type} eq 'PING' && ($_->{flags} & 1)
	&& $_->{value} eq 'gatewait' } @$barrier;
ok($settled, 'PING acknowledgement settles client input before auth release');
BAIL_OUT('HTTP/2 input did not settle before auth release') unless $settled;
$t->write_file('strict-release', "\n");

# No client frame is sent between releasing auth and observing RST_STREAM.
# A real phase-4 event is required: a broken backend is never baseline proof.
my $decision = wait_for_decision();
ok($decision, 'native Strict policy reached connection_abort');
BAIL_OUT('native Strict phase-4 decision was not recorded') unless $decision;
my $prompt = $s->read(all => [{ type => 'RST_STREAM' }], wait => 1);
push @$frames, @$prompt;
is(!!stream_reset($prompt, $strict), !$expect_queued,
	$expect_queued ? 'unpatched core queues reset while another stream is active'
	: 'Strict reset arrives promptly while another stream is active');
ok(!stream_finished($frames, $held) && !stream_reset($frames, $held),
	'held stream is still active during reset observation');

$t->write_file('hold-release', "\n");
my @remaining = ({ sid => $held, fin => 1 });
push @remaining, { type => 'RST_STREAM' } unless stream_reset($frames, $strict);
my $released = $s->read(all => \@remaining, wait => 5);
push @$frames, @$released;
ok(stream_reset($frames, $strict), 'strict stream eventually receives a definite reset');
is(stream_status($frames, $strict), 200, 'strict response started before its late denial');
unlike(stream_body($frames, $strict), qr/\Q$forbidden\E/,
	'Strict final body is withheld');
ok(!stream_finished($frames, $strict), 'strict stream has no successful end of response');
is(stream_body($frames, $held), $prefix . $tail, 'unrelated stream delivers its complete body');
ok(stream_finished($frames, $held), 'unrelated stream ends normally');
ok(!stream_reset($frames, $held), 'unrelated stream is not reset');
ok(!grep({ $_->{type} eq 'GOAWAY' } @$frames), 'multiplexed connection is not closed');

my $allowed = $s->new_stream({ path => '/allow' });
my $after = $s->read(all => [{ sid => $allowed, fin => 1 }], wait => 5);
is(stream_status($after, $allowed), 200, 'same connection accepts another request');
is(stream_body($after, $allowed), 'allowed-after-reset', 'later allowed response is complete');
ok(stream_finished($after, $allowed), 'later allowed response ends normally');
ok(!grep({ $_->{type} eq 'GOAWAY' } @$after), 'reused connection has no GOAWAY');
ok(!stream_reset($after, $allowed), 'later allowed stream is not reset');

undef $s;
# Run Test::Nginx's alert/sanitizer assertions before Test::More finalizes TAP.
undef $t;

sub stream_body {
	my ($list, $sid) = @_;
	return join '', map { $_->{data} }
		grep { $_->{type} eq 'DATA' && $_->{sid} == $sid } @$list;
}

sub stream_status {
	my ($list, $sid) = @_;
	my ($header) = grep { $_->{type} eq 'HEADERS' && $_->{sid} == $sid } @$list;
	return $header ? $header->{headers}->{':status'} : undef;
}

sub stream_finished {
	my ($list, $sid) = @_;
	return scalar grep { $_->{sid} == $sid && ($_->{flags} & 1)
		&& ($_->{type} eq 'HEADERS' || $_->{type} eq 'DATA') } @$list;
}

sub stream_reset {
	my ($list, $sid) = @_;
	return scalar grep { $_->{type} eq 'RST_STREAM' && $_->{sid} == $sid } @$list;
}

sub wait_for_decision {
	for (1 .. 100) {
		my $log = $t->read_file('strict-h2.log');
		return 1 if defined $log && $log =~ /"uri":"\/strict"[^\n]*"actual_action":"connection_abort"/;
		select undef, undef, undef, 0.05;
	}
	return 0;
}

sub backend {
	my ($kind, $listen, $dir) = @_;
	my $server = IO::Socket::INET->new(Proto => 'tcp',
		LocalHost => '127.0.0.1', LocalPort => $listen,
		Listen => 5, Reuse => 1) or die "listen: $!";
	local $SIG{PIPE} = 'IGNORE';
	while (my $client = $server->accept()) {
		$client->autoflush(1);
		binmode $client;
		my $headers = '';
		while (my $line = <$client>) {
			$headers .= $line;
			last if $line =~ /^\r?\n$/;
		}
		unless (length $headers) {
			close $client;
			next;
		}
		open my $ready, '>', "$dir/$kind-ready" or die "ready: $!";
		close $ready;
		if ($kind eq 'hold') {
			print $client "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
				. 'Content-Length: ' . length($prefix . $tail)
				. "\r\nConnection: close\r\n\r\n$prefix";
		}
		for (1 .. 1500) {
			last if -e "$dir/$kind-release";
			select undef, undef, undef, 0.02;
		}
		die "gate timed out: $kind" unless -e "$dir/$kind-release";
		if ($kind eq 'hold') {
			print $client $tail;
		} else {
			print $client "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n"
				. "Connection: close\r\n\r\n";
		}
		close $client;
	}
}
