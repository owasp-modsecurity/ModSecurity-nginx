#!/usr/bin/perl

# Tests for ModSecurity-nginx connector (configuration error reporting).
#
# The connector hands nginx the error message produced by libmodsecurity.  The
# message buffer is owned by the connector once libmodsecurity returned it, so
# it has to be copied before it is released.  These tests assert that the
# message nginx prints is complete and correctly terminated -- a copy that is
# released too early, or one that is not NUL-terminated, shows up here as a
# truncated or garbled emerg line.

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

my $t = Test::Nginx->new()->has(qw/http/)->plan(6);

$t->write_file('error.log', '');

$t->write_file('bad-rules.conf', <<'EOF');
SecRuleEngine On
SecRule REQUEST_HEADERS:User-Agent "@rx bad-ua" "id:4242,phase:1,deny,nosuchaction"
EOF

$t->write_file_expand('bad-inline.conf', <<'EOF');

%%TEST_GLOBALS%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            modsecurity on;
            modsecurity_rules '
                SecRuleEngine On
                SecRule ARGS "@rx attack" "id:4141,phase:1,deny,nosuchaction"
            ';
        }
    }
}

EOF

$t->write_file_expand('bad-file.conf', <<'EOF');

%%TEST_GLOBALS%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        location / {
            modsecurity on;
            modsecurity_rules_file %%TESTDIR%%/bad-rules.conf;
        }
    }
}

EOF

$t->write_file_expand('bad-merge.conf', <<'EOF');

%%TEST_GLOBALS%%

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen       127.0.0.1:%%PORT_8080%%;
        server_name  localhost;

        modsecurity on;
        modsecurity_rules '
            SecRuleEngine On
            SecRule ARGS "@rx parent" "id:7777,phase:1,deny,status:403"
        ';

        location /child {
            modsecurity_rules '
                SecRule ARGS "@rx child" "id:7777,phase:1,deny,status:403"
            ';
        }
    }
}

EOF

###############################################################################

# Run "nginx -t" on one of the configurations above, the way Test::Nginx's own
# dump_config() builds its command line, and return the exit code together with
# everything the test printed on stdout/stderr.

sub nginx_t {
	my ($t, $conf) = @_;
	my $testdir = $t->testdir();

	# No -g here: every configuration above was written with
	# write_file_expand(), so %%TEST_GLOBALS%% already put "pid" and
	# "error_log" into the file itself.
	my $command = "$Test::Nginx::NGINX -t -p $testdir/ -c $conf "
		. "-e error.log";

	my $out = qx/$command 2>&1/;

	return ($?, $out);
}

###############################################################################

my ($rc, $out);

($rc, $out) = nginx_t($t, 'bad-inline.conf');
isnt($rc, 0, 'inline rules syntax error rejected');
like($out, qr/Rules error\..*got:\s+nosuchaction" in \S*bad-inline\.conf:\d+$/m,
	'inline rules error message intact');

($rc, $out) = nginx_t($t, 'bad-file.conf');
isnt($rc, 0, 'rules file syntax error rejected');
like($out, qr/Rules error\..*bad-rules\.conf.*got:\s+nosuchaction" in \S*bad-file\.conf:\d+$/m,
	'rules file error message intact');

($rc, $out) = nginx_t($t, 'bad-merge.conf');
isnt($rc, 0, 'duplicated rule id rejected on merge');
like($out, qr/Rule id: 7777 is duplicated\s+in \S*bad-merge\.conf:\d+$/m,
	'merge error message intact');

###############################################################################
