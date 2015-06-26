# Introduction

The ModSecurity-nginx connector is the connection point between Nginx and libmodsecurity (ModSecurity v3). Said another way, this project provides a communication channel between Nginx and libmodsecurity. This connector is required to use LibModSecurity with Nginx. 

The ModSecurity-nginx connector takes the form of an Nginx module. The module simply serves as a layer of communication between Nginx and ModSecurity.

Notice that this project depends on libmodsecurity rather than ModSecurity (version 2.9 or less).
libmodsecurity has not reached a stable release candidate, thus, use this project with caution.

### What is the difference between this project and the old ModSecurity add-on for nginx?

The old version uses ModSecurity standalone, which is a wrapper for
Apache internals to link ModSecurity to nginx. This current version is closer
to nginx, consuming the new libmodsecurity which is no longer dependent on
Apache. As a result, This current version has less dependencies, fewer bugs, and is faster. In addition, Some new functionality is also provided - such as the possibility of use of global rules configuration with per directory/location customizations (e.g. SecRuleRemoveById).

NOTICE: libmodsecurity is not feature complete and it is not considerable
stable, so use is undertaken at your own risk.

# Compilation

Before compile this software make sure that you have libmodsecurity installed.
You can download it from the ModSecurity git repository. For information pertaining to the compilation and installation of libmodsecurity please consult the documentation provided along with it.

With libmodsecurity installed, you can proceed with the installation of the ModSecurity-nginx connector, which follow thes Nginx 3rd party module installation procedure:

```
./configure --add-module=/path/your/modsecurity-for-nginx
```

Further information about nginx 3rd party add-ons support are available here:
http://wiki.nginx.org/3rdPartyModules

# Usage

ModSecurity for Nginx extends your Nginx configuration directives. It adds four
new directives and they are:

modsecurity [On|Off] - This directive turns on or off ModSecurity functionality. Note that
this configuration directive is no longer related to the SecRule state. Instead, it now serves soley as an Nginx flag to enable or disable the module.

modsecurity_rules_file [<path to rules file>] - This directive indicates the location of the modsecurity configuartion file.

modsecurity_rules_remote [server-key] [<url to rules>] - This directive is used to indicate from where (on the internet) a modsecurity configuration file will be downloaded. It also specifies the key that will be used to authenticate to that server.

modsecurity_rules [<modsecurity rule>] - This directive allows for the direct inclusion of a ModSecurity rule into the Nginx configuration.


### Usage example: injecting rules within nginx configuration
```
...
modsecurity on;
location / {
  modsecurity_rules '
    SecRuleEngine On
    SecDebugLog /tmp/modsec_debug.log
    SecDebugLogLevel 9
    SecRule ARGS "@contains test" "id:1,phase:2,t:trim,block"
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

As an open source project we invite (and encourage) anyone from the community to contribute to our project. This may take the form of: new
functionality, bug fixes, bug reports, beginners user support, and anything else that you
are willing to help with. Thank you.

## Providing Patches

We prefer to have your patch within the GtiHub infrastructure to facilitate our
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
utility to make sure that you patch does not adversly affect the behavior or performance of Nginx. 

The nginx tests are available on: http://hg.nginx.org/nginx-tests/ 

To use those tests, make sure you have the Perl utility prove (part of Perl 5)
and proceed with the following commands:

```
$ cp /path/to/ModSecurity-nginx/tests/* /path/to/nginx/test/repository
$ cd /path/to/nginx/test/repository
$ TEST_NGINX_BINARY=/path/to/your/nginx prove .
```

If you are facing problems getting your added functionality to pass all the  Nginx tests, feel free to contact us or the nginx mailing list at: http://nginx.org/en/support.html

### Debugging 

We respect the nginx debugging schema. By using the configuration option
“--with-debug”  during the nginx configuration you will also  be enabling the
connector's debug messages. Core dumps and crashes are expected to be debugged
in the same fashion that is used to debug Nginx. For further information,
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

We would love to discuss any ideas that you may have for a new feature. Please keep in mind this is a community driven project so be sure to contact the community via the mailing list to get feedback first. Alternativly,
feel free to open GitHub issues requesting for new features. Before opening a new issue, please check if there is an existing feature request for the desired functionalityt.

## Packing

Having our packages in distros on time is something we highly desire. Let us know if
there is anything we can do to facilitate your work as a packager.


