#!/usr/bin/perl
use warnings; use strict;
use Test::More;
BEGIN { use FindBin; chdir($FindBin::Bin); }
use lib 'lib';
use Test::Nginx;

# content-type parsing and scope behavior
my $t = Test::Nginx->new()->has(qw/http/);

$t->write_file('phase4-content-types.conf', <<'CT');
# comments and whitespace

Application/JSON; charset=utf-8   # inline comment
TEXT/HTML
text/plain
application/xml
application/vnd.api+json
application/problem+json
application/x.custom_type
CT

$t->write_file_expand('nginx.conf', <<'EOC');
%%TEST_GLOBALS%%
daemon off;
events {}
http {
    %%TEST_GLOBALS_HTTP%%
    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        location /json {
            modsecurity on;
            modsecurity_phase4_mode strict;
            modsecurity_phase4_log %%TESTDIR%%/phase4-content-types.log;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-content-types.conf;
            default_type application/json;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx HIT" "id:920001,phase:4,deny,log,status:403,msg:\"ct\""
            ';
        }

        location /unknown {
            modsecurity on;
            modsecurity_phase4_mode strict;
            modsecurity_phase4_log %%TESTDIR%%/phase4-content-types.log;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-content-types.conf;
            default_type image/png;
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx HIT" "id:920002,phase:4,deny,log,status:403,msg:\"ct\""
            ';
        }

        location /emptytype {
            modsecurity on;
            modsecurity_phase4_mode strict;
            modsecurity_phase4_log %%TESTDIR%%/phase4-content-types.log;
            modsecurity_phase4_content_types_file %%TESTDIR%%/phase4-content-types.conf;
            types { }
            default_type "";
            modsecurity_rules '
                SecRuleEngine On
                SecResponseBodyAccess On
                SecRule RESPONSE_BODY "@rx HIT" "id:920003,phase:4,deny,log,status:403,msg:\"ct\""
            ';
        }
    }
}
EOC

$t->write_file('/json', 'HIT JSON');
$t->write_file('/unknown', 'HIT UNKNOWN');
$t->write_file('/emptytype', 'HIT EMPTY');

$t->run();
$t->plan(9);

is(http_get('/json'), '', 'json in-scope + strict => abort after headers sent');
like(http_get('/unknown'), qr/HIT UNKNOWN/, 'unknown content-type not in scope => no hard action');
like(http_get('/emptytype'), qr/HIT EMPTY/, 'empty content-type => no hard action');

my $log = $t->read_file('phase4-content-types.log');
like($log, qr/"content_type":"application\/json"|"content_type":"application\/json"/, 'json content type logged');
like($log, qr/"actual_action":"connection_abort"/, 'strict in-scope abort logged');
like($log, qr/"reason":"content_type_not_in_scope"/, 'out-of-scope reason logged');
like($log, qr/"event":"phase4_intervention"/, 'json lines event present');
unlike($log, qr/HIT JSON|HIT UNKNOWN|HIT EMPTY/, 'no response body data in log');
like($log, qr/"content_type":"application\/json"/, 'application/json remains valid');
