
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
It adds four new directives and they are:

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

# Performance considerations

## Request body

When `modsecurity` is on, the connector reads the **whole** request body in
nginx's ACCESS phase, before the content handler (for example `proxy_pass`)
runs. Consequences:

* `proxy_request_buffering off` has no effect in such locations: the body has
  already been buffered by the time the proxy module sees it.
* Bodies larger than `client_body_buffer_size` (twice the system page size, 8k
  on most platforms) are written to a temporary file under
  `client_body_temp_path`. libmodsecurity then re-opens that file and reads it
  back into memory in full, because ModSecurity v3 has no
  `SecRequestBodyInMemoryLimit`: the directive was removed and the rule parser
  rejects it as a configuration error. The spill therefore costs a write and a
  read and saves no memory. Raising `client_body_buffer_size` avoids the spill,
  but nginx allocates that buffer for every request that carries a body (it is
  trimmed to the body size only when the Content-Length is known and smaller),
  so a large value multiplies worker memory under concurrency. Size it against
  the bodies you actually expect, not against `client_max_body_size`, which
  only decides which requests are accepted, nor against `SecRequestBodyLimit`,
  which is applied after the connector has already read the body. A
  tmpfs-backed `client_body_temp_path` keeps the spill off disk, at the price
  of holding it in RAM.
* libmodsecurity copies the body into its own buffer even when
  `SecRequestBodyAccess Off` is set; the copy is made before libmodsecurity
  returns early from phase 2, so the buffering above is not avoided either.

## Response body

The connector feeds every response buffer to libmodsecurity regardless of
`SecResponseBodyAccess`. libmodsecurity skips the copy only for responses whose
Content-Type is not listed in `SecResponseBodyMimeType` (with no such list
every response is copied), and applies `SecResponseBodyLimit` together with
`SecResponseBodyLimitAction` once the copy grows past the limit. The connector
also asks nginx to keep every response body in memory
(`filter_need_in_memory`), again regardless of `SecResponseBodyAccess`. In
locations where `modsecurity` is on, a file-backed response (a static file, or
a proxied response buffered to disk) is therefore read into memory and copied
through the output chain before it is sent, even when no rule ever looks at
it. `sendfile` is still used to transmit it, so the cost is the extra read and
copy rather than the loss of `sendfile`. Each buffer chain is fed to
ModSecurity before it is forwarded, and phase 4 runs on the chain that carries
the end of the response, before that chain is passed on. A phase 4 rule can
therefore still act on the buffers of that last chain, but not on anything the
preceding calls have already sent to the client.

## Rules loading

Each `modsecurity_rules_file` directive parses and compiles the referenced
file again. Load a large rule set such as the OWASP Core Rule Set once at the
`http` level and only toggle `modsecurity on|off` per server or location.

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


