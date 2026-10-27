
<img src="https://github.com/SpiderLabs/ModSecurity/raw/v3/master/others/modsec.png" width="50%">

[![Build Status](https://travis-ci.org/SpiderLabs/ModSecurity-nginx.svg?branch=master)](https://travis-ci.org/SpiderLabs/ModSecurity-nginx)
[![](https://raw.githubusercontent.com/ZenHubIO/support/master/zenhub-badge.png)](https://zenhub.com)


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
You can download it from the [ModSecurity git repository](https://github.com/SpiderLabs/ModSecurity). For information pertaining to the compilation and installation of libmodsecurity please consult the documentation provided along with it.

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

Further information about nginx third-party add-ons support are available [here](https://www.f5.com/company/blog/nginx/compiling-dynamic-modules-nginx-plus).


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
          SecDebugLog /tmp/modsec_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
        ';
    }
}
```

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
-----------
**syntax:** *modsecurity_use_error_log on | off*

**context:** *http, server, location*

**default:** *on*

Turns on or off ModSecurity error log functionality.

modsecurity_log_thread_pool
---------------------------
**syntax:** *modsecurity_log_thread_pool &lt;name&gt; | off*

**context:** *http, server, location*

**default:** *off*

Runs the LOGGING phase (phase 5) rules and the audit log write in the named
nginx `thread_pool` instead of on the worker's event loop, so that audit log
I/O no longer stalls the other connections handled by the worker. The
transaction is detached from the request when the task is posted and is
cleaned up once the task completes.

This directive requires nginx built with `--with-threads` and with PCRE2;
builds using the original PCRE library refuse it at configuration time,
because there the connector has to swap the process-global `pcre_malloc` and
`pcre_free` pointers around every libmodsecurity call, which is not
thread-safe.

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
does everything up to phase 4 and the logging phase of subrequests.

The feature is experimental, and it needs a libmodsecurity that supports
processing transactions concurrently -- the way the threaded Apache MPMs use
it. Two caveats are worth knowing about:

* concurrent writes of serial audit log entries rely on the atomicity of a
  single `fwrite()`; the `fcntl()` lock taken by the library does not exclude
  other threads of the same process. `SecAuditLogType Concurrent`, or a thread
  pool with a single thread, avoids the question;
* the LMDB collection backend (`--with-lmdb`) has not been reviewed for use
  from several threads of one process.

Logging tasks that are still queued when a worker shuts down are still run --
the pool's exit task queues behind them -- so their audit log entries are
written, but their completion handler does not run, and the transaction, the
log holder and the task pool are released only by the exiting process. Because
the worker waits for the whole queue to drain, a thread blocked on a contended
audit log can delay shutdown beyond `worker_shutdown_timeout`, which does not
apply to thread pools.

```nginx
thread_pool modsec threads=4;

http {
    modsecurity on;
    modsecurity_rules_file /etc/modsecurity/main.conf;
    modsecurity_log_thread_pool modsec;
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
here: https://help.github.com/articles/using-pull-requests/

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

The nginx tests are available on: http://hg.nginx.org/nginx-tests/ 

To use those tests, make sure you have the Perl utility prove (part of Perl 5)
and proceed with the following commands:

```
$ cp /path/to/ModSecurity-nginx/tests/* /path/to/nginx/test/repository
$ cd /path/to/nginx/test/repository
$ TEST_NGINX_BINARY=/path/to/your/nginx prove .
```

If you are facing problems getting your added functionality to pass all the nginx tests, feel free to contact us or the nginx mailing list at: http://nginx.org/en/support.html

### Debugging 

We respect the nginx debugging schema. By using the configuration option
"--with-debug" during the nginx configuration you will also be enabling the
connector's debug messages. Core dumps and crashes are expected to be debugged
in the same fashion that is used to debug nginx. For further information,
please check the nginx debugging information: http://wiki.nginx.org/Debugging


## Reporting Issues

If you are facing a configuration issue or if something is not working as you
expect it to be, please use ModSecurity user’s mailing list. Issues on GitHub
are also welcome, but we prefer to have users question on the mailing list first,
where you can reach an entire community. Also don’t forget to look for an
existing issue before opening a new one.

Lastly, If you are planning to open an issue on GitHub, please don’t forget to tell us the
version of your libmodsecurity and the version of the nginx connector you are running.

### Security issue

Please do not publicly report any security issue. Instead, contact us at:
security@modsecurity.org to report the issue. Once the problem is fixed we will provide you with credit for the discovery.


## Feature Request

We would love to discuss any ideas that you may have for a new feature. Please keep in mind this is a community driven project so be sure to contact the community via the mailing list to get feedback first. Alternatively,
feel free to open GitHub issues requesting for new features. Before opening a new issue, please check if there is an existing feature request for the desired functionality.


## Packaging

Having our packages in distros on time is something we highly desire. Let us know if
there is anything we can do to facilitate your work as a packager.


