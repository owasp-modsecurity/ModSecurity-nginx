
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
It adds six new directives and they are:

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

# Performance considerations

## Request body

When `modsecurity` is on, the connector reads the **whole** request body in
nginx's ACCESS phase, before the content handler (for example `proxy_pass`)
runs, and libmodsecurity keeps its own copy of it. Only `modsecurity off`
avoids this: `SecRuleEngine Off` or `DetectionOnly` and
`SecRequestBodyAccess Off` change what libmodsecurity does with the copy, not
whether the body is buffered and copied. Consequences:

* `proxy_request_buffering off` has no effect in such locations: the body has
  already been buffered by the time the proxy module sees it.
* A body that does not fit in nginx's body buffer is written to a temporary
  file under `client_body_temp_path`. Over HTTP/1.x with a Content-Length,
  bodies up to about 1.25 times `client_body_buffer_size` (twice the system
  page size, 8k on most platforms) stay in memory; chunked and HTTP/2 bodies
  spill once they exceed `client_body_buffer_size`.
* libmodsecurity reopens a spilled file by name and reads it back in full,
  because ModSecurity v3 has no `SecRequestBodyInMemoryLimit` (the rule
  parser rejects it). It reads the whole file into a temporary string and
  then copies that into its own buffer, so the body is held twice while it is
  loaded, and the file is read in full even when it exceeds
  `SecRequestBodyLimit`, which only caps the second copy. The spill costs a
  write and a read and saves no memory.
* Raising `client_body_buffer_size` avoids the spill, but every body
  without a Content-Length, every body that spills and every HTTP/3 body gets
  a buffer of the full size (otherwise a body that stays in memory gets one
  of its own size, and an HTTP/1.x body that fits in the rest of the request
  header buffer needs none), so a large value multiplies worker memory under
  concurrency. Size it against the
  bodies you actually expect, not against `client_max_body_size`, which only
  decides which requests are accepted, nor against `SecRequestBodyLimit`,
  which is applied after the connector has already read the body.
* The spilled file keeps its name under `client_body_temp_path` for the
  duration of the request, because libmodsecurity reopens it by path; it is
  created with mode 0600 and deleted when the request ends (unless
  `client_body_in_file_only on` asks nginx to keep it). nginx creates a
  missing `client_body_temp_path` with mode 0700, but never removes group or
  other access from an existing directory: keep that directory private to
  the nginx user. A tmpfs-backed `client_body_temp_path` keeps the spill off disk, at
  the price of holding it in RAM.
* With `SecRequestBodyAccess Off`, libmodsecurity still runs the request
  body processor (multipart, urlencoded, or JSON/XML when selected with
  `ctl:requestBodyProcessor`) over its copy in phase 2, and only then returns
  before evaluating the phase 2 rules. Only a body over
  `SecRequestBodyNoFilesLimit` skips the urlencoded, JSON and XML parsers;
  multipart is always parsed. `SecRuleEngine Off` skips the parsing
  as well, but not the buffering or the copy.

## Response body

The connector asks nginx to keep every response body in memory
(`filter_need_in_memory`) and feeds every response buffer to libmodsecurity,
regardless of `SecResponseBodyAccess` and `SecRuleEngine`; again only
`modsecurity off` avoids this.

* A file-backed response (a static file, or a proxied response buffered to
  disk) is read into memory in `output_buffers`-sized pieces (default
  `2 32k`) before it is passed on, so nginx's own extra memory per request
  stays bounded by `output_buffers`. `sendfile` is still used to transmit it,
  so the cost is the extra read and copy rather than the loss of `sendfile`.
* libmodsecurity accumulates its own copy of the whole response. It skips
  the copy only for responses whose Content-Type is not in a non-empty
  `SecResponseBodyMimeType` list, and caps it at `SecResponseBodyLimit`
  according to `SecResponseBodyLimitAction`. To limit the copy, list only the
  types you inspect.
* Do not use `SecResponseBodyMimeTypesClear` to turn response inspection off.
  If it leaves the list empty, libmodsecurity copies every response, but
  phase 4 inspects none of them.
* Phase 4 runs on the buffer that ends the response, after the response
  headers have been committed and earlier buffers have been passed on. A
  disruptive phase 4 action can therefore neither send its status nor
  redirect: the connector aborts the response, and the client receives
  nothing or a truncated response.

## Rules loading

Each `modsecurity_rules_file` directive parses and compiles the referenced
file again. Load a large rule set such as the OWASP Core Rule Set once at the
`http` level and only toggle `modsecurity on|off` per server or location.
The rule objects are then shared, but every `server` and `location` block,
including those with `modsecurity off` or without any modsecurity directive,
still gets its own rules set into which the enclosing level's rules are
merged at configuration load, so configuration load time and memory grow
with the number of locations times the number of rules.

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
