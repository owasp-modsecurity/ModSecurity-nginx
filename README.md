# Introduction

ModSecurity-nginx is a connector which provides ModSecurity functionality
inside nginx. Built to use the libmodsecurity this nginx add-on provides
a layer of communication between ModSecurity and nginx.

Notice that this project depends on libmodsecurity rather than ModSecurity.
libmodsecurity is not released as stable yet, thus, use this project with
caution.

### What is the difference between this project and the old ModSecurity add-on for nginx?

The old version uses ModSecurity standalone, which is a wrapper using
Apache internals to link ModSecurity to nginx. This current version is closer
to nginx, consuming the new libmodsecurity which is no longer dependent of
Apache. This current version has less dependencies and must be faster. Some new
functionalities are also provided such as the possibility to use global rules
configuration with per directory/location customizations
(e.g. SecRuleRemoveById).

NOTICE: libmodsecurity is not feature complete and it is not considerable
stable, so use that implementation carefully.

# Compilation

Before compile this software make sure that you have libmodsecurity installed.
You can download it straight from ModSecurity git repository. Follow the
guidance in the ModSecurity instructions to have it compiled and installed.

With libmodsecurity installed, you can proceed with the installation of this
add-on, which follows nginx 3rd party module installation process:

```
./configure --add-module=/path/your/modsecurity-for-nginx
```

Further information about nginx 3rd party add-ons support are available here:
http://wiki.nginx.org/3rdPartyModules

# Usage

ModSecurity for nginx extends your nginx configuration directives. It adds four
new directives and they are:

modsecurity: [On|Off] turn on and off ModSecurity functionality. Notice that
this configuration directive is no longer related to the SecRule state. It is 
currently a nginx flag to enable or disable the module.

modsecurity_rules_file: accept a file as parameter, where the rules will be
loaded from.
modsecurity_rules_remote: expect a remote server, where the rules can be loaded
from.
modsecurity_rules: inject ModSecurity rules among other nginx configuration.


### Usage example: injecting rules within nginx configuration
```
...
modsecurity on;
location / {
  modsecurity_rules '
    SecRuleEngine On
    SecDebugLog /tmp/modsec_debug.log
    SecDebugLogLevel 9
    SecRule ARGS "@contains phase2" "id:1,phase:2,t:trim,block"
  ';
}
...
```

### Usage example: loading rules from a file and injecting specific configurations per directory/alias
```
...
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
...
```

### Usage example: loading rules from a remote server
```
...
modsecurity on;
location / {
  root /var/www/html;
  modsecurity_rules_remote my-server-key https://my-own-server/rules/download;
}
...
```

# Contributing

You are more than welcome to contribute with the growth of our community. New
functionalities, fixes, bug report, beginners users support, and anything that you
are willing to help.

## Providing Patches

We prefer to have your patch within the GtiHub infrastructure to facilitate our
review work, and our Q.A. integration. GitHub provides an excellent
documentation on how to perform “Pull Requests”. More information available
here: https://help.github.com/articles/using-pull-requests/

Please respect the coding style. Pull requests can include various commits, so
provide one fix or one functionality per commit. Do not change anything outside
the scope of our target work (e.g. coding style in a function that you have
passed by). 

### Don’t know where to start?

Within our code there are various items marked as TODO or FIXME that may need
your attention. Check the list of items by performing a grep:

```
$ cd /path/to/modsecurity-nginx
$ egrep -Rin "TODO|FIXME" -R *
```

### Testing your patch

Along with the manual testing, we strongly recommend you to use the nginx test
utility to make sure that you patch is not affecting the well behavior of nginx. 

The nginx tests are available on: http://hg.nginx.org/nginx-tests/ 

To use those tests, make sure you have the Perl utility prove (part of Perl 5)
and proceed with the following commands:

```
$ cp /path/to/ModSecurity-nginx/tests/* /path/to/nginx/test/repository
$ cd /path/to/nginx/test/repository
$ TEST_NGINX_BINARY=/path/to/your/nginx prove .
```

If you are facing problems to have nginx passing in all the tests after your
patch, contact us or the nginx mailing list at: http://nginx.org/en/support.html

### Debugging 

We respect the nginx debugging schema. By using the configuration option
“--with-debug”  during the nginx configuration you will be also enabling that
connector debug messages. Core dumps and crashes are expected to be debugged
in the same fashion that is used to debug nginx. For further information,
please check the nginx debugging information: http://wiki.nginx.org/Debugging


## Reporting Issues

If you are facing a configuration issue or if something is not working as you
expected to be, please use ModSecurity user’s mailing list. Issues on GitHub
are also welcomed, but prefer to have user questions on the mailing list first,
where you can reach an entire community. Also don’t forget to look for an
existent issue before opening a new one.

If you are willing to open an issue on GitHub, don’t forget to tell us the
version of your libmodsecurity and the version of your nginx connector.

### Security issue

Please do not make public any security issue. Contacts us at:
security@modsecurity.org reporting the issue. Once the problem is fixed your
credits will be given.

## Feature Request

It will be a pleasure to discuss any feature request with the community, also
feel free to open GitHub issues requesting for new features. Before opening a new
one, please check if there is something already opened with the same subject.

## Packing

Having our packages in distros on time is a desire that we have. Let us know if
there is anything we can do to facilitate your work as a packager.


