
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

modsecurity_log_thread_pool
---------------------------
**syntax:** *modsecurity_log_thread_pool &lt;name&gt; [max_pending=&lt;number&gt;] | off*

**context:** *http, server, location*

**default:** *off*

Runs the LOGGING phase (phase 5) rules and the audit log write in the named
nginx `thread_pool` instead of on the worker's event loop, so that audit log
I/O no longer stalls the other connections handled by the worker. The
transaction is detached from the request when the task is posted and is
cleaned up once the task completes. Whether a request is offloaded is decided
by the configuration of the location the request is finally logged in.

Each posted task keeps the complete transaction in memory until it has run,
including the buffered request and response bodies, up to
`SecRequestBodyLimit` and `SecResponseBodyLimit`. The optional `max_pending`
parameter limits the number of logging tasks a worker has posted, to any pool,
and not yet completed (default 128); a request that finds the limit reached is
logged on the event loop, as without this directive, and a warning is written
at most once every 10 seconds. Size it so that `max_pending` times the per-request
memory fits the worker's budget, and use a pool dedicated to this directive
with `max_queue` greater than `max_pending`. A pool that refuses a task makes
nginx log a `queue overflow` error, and at worker exit a full queue leaves no
room for the pool's own exit task (see below).

Within a worker, phase 5 and the audit log write are serialised: the thread,
the inline fallback and the early logging of a disruptive intervention all
hold one per-worker mutex around them. The serial audit log writer of
libmodsecurity only takes an `fcntl()` lock, which belongs to the process, so
two threads of one worker do not exclude each other, and one thread releasing
the lock lets another process write while the other thread is still writing.
As a consequence a thread pool with more than one thread gives no additional
logging parallelism, and inline or early logging on the event loop can wait
for the mutex while another transaction's phase 5 and audit write run, so that
wait is not bounded by the request's own logging time. `threads=1` is enough.

This directive requires nginx built with `--with-threads` and with PCRE2;
other builds refuse it at configuration time, except for
`modsecurity_log_thread_pool off`, which is accepted everywhere. Builds using
the original PCRE library are excluded because there the connector has to swap
the process-global `pcre_malloc` and `pcre_free` pointers around every
libmodsecurity call, which is not thread-safe.

Rule messages emitted during phase 5 are written using the thread pool's log,
which is the main context `error_log` at its configured level, rather than the
`error_log` of the server or location the request was handled by, and they lack
the usual client and request context. As they are emitted at the `info` level,
the main `error_log` has to be set to `info` or lower for them to appear, and it
has to be a file: an `error_log` that writes to `syslog:` or `memory:` must not
be used with this directive, because those writers are not thread-safe. Any
`SecDebugLog` output produced during phase 5 is likewise written from the
thread.

The logging performed early by a disruptive intervention stays synchronous, as
does everything up to phase 4. The logging phase runs once per transaction, for
the main request; with `log_subrequest on`, the log phase of a subrequest does
not process it.

The feature is experimental, and it needs a libmodsecurity that supports
processing transactions concurrently -- the way the threaded Apache MPMs use
it: phases 1 to 4 of one transaction still run on the event loop while phase 5
of another runs in the thread. Two caveats are worth knowing about:

* `SecDebugLog` writes made during phases 1 to 4 are not covered by the mutex
  and can interleave with debug log writes from the thread;
* the LMDB collection backend (`--with-lmdb`) has not been reviewed for use
  from several threads of one process.

The thread destroys the transaction once it has been logged, so temporary
files of the transaction, such as saved uploads, are removed even if the
worker exits before the task's completion handler runs.

On graceful shutdown (`nginx -s quit`) the worker does not exit while logging
tasks are pending: it keeps a timer armed until their completion handlers have
run. Use graceful shutdown when queued audit records must be written. A worker
that receives `SIGTERM` exits at once, and the thread pool runs the tasks still
queued before its threads exit, provided the pool's exit task fits into the
queue -- hence `max_queue` greater than `max_pending` on a dedicated pool. On
fast shutdown (`nginx -s stop`), though, the master sends `SIGKILL` to workers
that have not exited after about 1.5 seconds, so queued and running logging tasks
can be lost and their temporary files left behind, whatever the queue size. A
thread blocked on a contended audit log delays a graceful exit, and
`worker_shutdown_timeout` does not shorten that wait.

```nginx
thread_pool modsec threads=1 max_queue=256;

http {
    modsecurity on;
    modsecurity_rules_file /etc/modsecurity/main.conf;
    modsecurity_log_thread_pool modsec max_pending=128;
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
