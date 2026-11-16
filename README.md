
<img src="https://github.com/owasp-modsecurity/ModSecurity/raw/v3/master/others/modsec.png" width="50%">

[![Quality Assurance new](https://github.com/owasp-modsecurity/ModSecurity-nginx/actions/workflows/test_new.yml/badge.svg)](https://github.com/owasp-modsecurity/ModSecurity-nginx/actions/workflows/test_new.yml)


The ModSecurity-nginx connector is the connection point between nginx and libmodsecurity (ModSecurity v3). Said another way, this project provides a communication channel between nginx and libmodsecurity. This connector is required to use LibModSecurity with nginx. 

The ModSecurity-nginx connector takes the form of an nginx module. The module simply serves as a layer of communication between nginx and ModSecurity.

Notice that this project depends on libmodsecurity rather than ModSecurity (version 2.9 or less).

### What is the difference between this project and the old ModSecurity add-on for nginx?

The old version uses ModSecurity standalone, which is a wrapper for
Apache internals to link ModSecurity to nginx. This current version is closer
to nginx, consuming the new libmodsecurity which is no longer dependent on
Apache. As a result, this current version has less dependencies, fewer bugs, and is faster. In addition, some new functionality is also provided - such as the possibility of use of global rules configuration with per directory/location customizations (e.g. SecRuleRemoveById).


# Compilation

Before compile this software make sure that you have libmodsecurity installed.
You can download it from the [ModSecurity git repository](https://github.com/owasp-modsecurity/ModSecurity). For information pertaining to the compilation and installation of libmodsecurity please consult the documentation provided along with it.

With libmodsecurity installed, you can proceed with the installation of the ModSecurity-nginx connector, which follows the nginx third-party module installation procedure. From the nginx source directory:

```
./configure --add-module=/path/to/ModSecurity-nginx
```

Or, to build a dynamic module:

```
./configure --add-dynamic-module=/path/to/ModSecurity-nginx --with-compat
```

Note that when building a dynamic module, your nginx source version
needs to match the version of nginx you're compiling this for.

If libmodsecurity is not installed in the system library path or in
`/usr/local/modsecurity`, point the build at it with the `MODSECURITY_INC` and
`MODSECURITY_LIB` environment variables. If libyajl is also in a non-standard
location, set `YAJL_LIB` to the directory that contains it (not to the library
file); `YAJL_LIB` is only honoured together with `MODSECURITY_INC` /
`MODSECURITY_LIB` and is ignored when the library is auto-discovered (including
from `/usr/local/modsecurity`). On Linux, set `NGX_IGNORE_RPATH=YES` to avoid
embedding the library path in the resulting binary; the dynamic loader then has
to find libmodsecurity at runtime, for example through `ld.so.conf` or
`LD_LIBRARY_PATH`. On platforms where nginx uses `-R` (such as Solaris), the
path is always embedded.

For building on Windows with MSVC, see [win32/README.md](win32/README.md).

Further information about building nginx third-party modules is available [here](https://nginx.org/en/docs/dev/development_guide.html#adding_new_modules).


# Usage

ModSecurity for nginx extends your nginx configuration directives.
It adds the following directives:

modsecurity
-----------
**syntax:** *modsecurity on | off*

**context:** *http, server, location*

**default:** *off*

Turns on or off ModSecurity functionality.
Note that this configuration directive is no longer related to the SecRule state.
Instead, it now serves solely as an nginx flag to enable or disable the module.

modsecurity_rules_file
----------------------
**syntax:** *modsecurity_rules_file &lt;path to rules file&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies the location of the modsecurity configuration file, e.g.:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_file /etc/my_modsecurity_rules.conf;
    }
}
```

modsecurity_rules_remote
------------------------
**syntax:** *modsecurity_rules_remote &lt;key&gt; &lt;URL to rules&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies from where (on the internet) a modsecurity configuration file will be downloaded.
It also specifies the key that will be used to authenticate to that server:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_remote my-server-key https://my-own-server/rules/download;
    }
}
```

modsecurity_rules
-----------------
**syntax:** *modsecurity_rules &lt;modsecurity rule&gt;*

**context:** *http, server, location*

**default:** *no*

Allows for the direct inclusion of a ModSecurity rule into the nginx configuration.
The following example is loading rules from a file and injecting specific configurations per directory/alias:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_file /etc/my_modsecurity_rules.conf;
    }
    location /ops {
        root /var/www/html/opts;
        modsecurity_rules '
          SecRuleEngine On
          SecDebugLog /path/to/modsec_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
        ';
    }
}
```

Replace `/path/to/modsec_debug.log` with a real path. The directory must
already exist, otherwise the rules fail to load and nginx does not start. The
debug log is opened by the nginx master process (usually running as root) when
the configuration is loaded, so the directory must be writable by the user
nginx is started as, and neither it nor any of its parent directories may be
writable by anyone else (in particular not by the worker user, for example
`www-data` or `nginx`, nor through a group or ACL): anyone who can write
there could replace the log file, or a directory on its path, with a symlink
and have root append request data to any file. The debug log contains request
data, so also keep the directory and file unreadable by unprivileged users (see
the
[Hardening Notes](SECURITY.md#hardening-notes)).

modsecurity_transaction_id
--------------------------
**syntax:** *modsecurity_transaction_id string*

**context:** *http, server, location*

**default:** *no*

Allows to pass transaction ID from nginx instead of generating it in the library.
This can be useful for tracing purposes, e.g. consider this configuration:

```nginx
log_format extended '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" $request_id';

server {
    server_name host1;
    modsecurity on;
    modsecurity_transaction_id "host1-$request_id";
    access_log logs/host1-access.log extended;
    error_log logs/host1-error.log;
    location / {
        ...
    }
}

server {
    server_name host2;
    modsecurity on;
    modsecurity_transaction_id "host2-$request_id";
    access_log logs/host2-access.log extended;
    error_log logs/host2-error.log;
    location / {
        ...
    }
}
```

Using a combination of log_format and modsecurity_transaction_id you will
be able to find correlations between access log and error log entries
using the same unique identificator.

String can contain variables.

modsecurity_use_error_log
-------------------------
**syntax:** *modsecurity_use_error_log on | off*

**context:** *http, server, location*

**default:** *on*

Turns on or off ModSecurity error log functionality.

modsecurity_response_body
-------------------------
**syntax:** *modsecurity_response_body on | off*

**context:** *http, server, location*

**default:** *on*

Controls whether the connector buffers response bodies and hands them to
ModSecurity.  It does not enable inspection on its own: whether the body is
inspected at all is still decided by `SecResponseBodyAccess` and
`SecResponseBodyMimeType`.

When turned off the connector no longer asks nginx to keep the response body
in memory, so with `sendfile` enabled file buffers are sent straight from the
file instead of being read into memory first, and it no longer copies the
response buffers into ModSecurity.  The setting of the main request's location at
the time ModSecurity processes the response headers applies to the whole
response, including subrequests (SSI includes, `add_after_body`,
`auth_request`) and an `error_page` served after a ModSecurity intervention.

ModSecurity still runs phase 4 on the last buffer, but against an empty body
(ModSecurity itself skips phase 4 altogether when `SecResponseBodyAccess` is
`Off` or the response Content-Type is not listed in
`SecResponseBodyMimeType`):

* `RESPONSE_BODY` is empty and `RESPONSE_CONTENT_LENGTH` is `0`.
* Rules that look for content in the response body silently stop matching.
  This includes the OWASP CRS outbound data leakage rules
  (`RESPONSE-95x-*.conf`) that inspect `RESPONSE_BODY`.
* Rules that match on the absence of content now match on every response,
  for instance `RESPONSE_BODY "!@contains </html>"`, `RESPONSE_BODY "@rx ^$"`
  or `RESPONSE_CONTENT_LENGTH "@lt 100"`.  If such a rule is disruptive, it
  fires after the response header has already been passed on, so the client
  gets an empty or truncated response instead of the error page.
* The audit log has no part E (response body).
* Phase 4 rules that do not look at the body, for instance rules on
  `RESPONSE_STATUS` or on variables set in earlier phases, keep working.

Turning it off is recommended for locations serving static files or large
downloads, and wherever `SecResponseBodyAccess Off` is in use: ModSecurity
still copies the response bodies of the configured MIME types and the
connector has no way to query that setting, so this directive is the only
way to avoid the cost.

```nginx
server {
    sendfile on;
    modsecurity on;
    modsecurity_rules_file /etc/my_modsecurity_rules.conf;
    location /static/ {
        modsecurity_response_body off;
    }
}
```

# Contributing

As an open source project we invite (and encourage) anyone from the community to contribute to our project. This may take the form of: new
functionality, bug fixes, bug reports, beginners user support, and anything else that you
are willing to help with. Thank you.


## Providing Patches

We prefer to have your patch within the GitHub infrastructure to facilitate our
review work, and our QA integration. GitHub provides an excellent
documentation on how to perform “Pull Requests”. More information available
here: https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request

Please respect the coding style in use. Pull requests can include various commits, so
provide one fix or one functionality per commit. Do not change anything outside
the scope of your target work (e.g. coding style in a function that you have
passed by). 

### Don’t know where to start?

Within our code there are various items marked as TODO or FIXME that may need
your attention. Check the list of items by performing a grep:

```
$ cd /path/to/modsecurity-nginx
$ egrep -Rin "TODO|FIXME" -R *
```

You may also take a look at recent bug reports and open issues to get an idea of what kind of help we are looking for.

### Testing your patch

Along with the manual testing, we strongly recommend that you to use the nginx test
utility to make sure that you patch does not adversely affect the behavior or performance of nginx. 

The nginx tests are available on: https://github.com/nginx/nginx-tests

To use those tests, make sure you have the Perl utility prove (part of Perl 5)
and proceed with the following commands:

```
$ cp /path/to/ModSecurity-nginx/tests/* /path/to/nginx/test/repository
$ cd /path/to/nginx/test/repository
$ TEST_NGINX_BINARY=/path/to/your/nginx prove .
```

If you are facing problems getting your added functionality to pass all the nginx tests, feel free to open a GitHub issue.

### Debugging 

We respect the nginx debugging schema. By using the configuration option
"--with-debug" during the nginx configuration you will also be enabling the
connector's debug messages, see https://nginx.org/en/docs/debugging_log.html.
Core dumps and crashes are expected to be debugged in the same fashion that is
used to debug nginx; to get a core dump from a worker, set
[`worker_rlimit_core`](https://nginx.org/en/docs/ngx_core_module.html#worker_rlimit_core)
and
[`working_directory`](https://nginx.org/en/docs/ngx_core_module.html#working_directory).


## Reporting Issues

If you are facing a configuration issue or if something is not working as you
expect it to be, please open an issue on
[GitHub](https://github.com/owasp-modsecurity/ModSecurity-nginx/issues).
Don’t forget to look for an existing issue before opening a new one.

Lastly, If you are planning to open an issue on GitHub, please don’t forget to tell us the
version of your libmodsecurity and the version of the nginx connector you are running.

### Security issue

Please do not report security issues publicly. See [SECURITY.md](SECURITY.md)
for how to report them privately.


## Feature Request

We would love to discuss any ideas that you may have for a new feature. Please keep in mind this is a community driven project, so feel free to open
GitHub issues requesting new features and to gather feedback there. Before opening a new issue, please check if there is an existing feature request for the desired functionality.


## Packaging

Having our packages in distros on time is something we highly desire. Let us know if
there is anything we can do to facilitate your work as a packager.
