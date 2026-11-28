# Tests

Those are nginx test files. You can copy those files into yours nginx test
tree, to perform the tests using the "prove" utility.

For more information about those tests, read the subsection "Testing your
patch" on the project's README file.

test_native_intervention_runtime.py is not an nginx test. It compiles
ngx_http_modsecurity_process_intervention() with stand-ins for nginx and
libModSecurity, and needs only Python 3 and a C compiler. Run it from the
top of the repository:

    CC=gcc python3 -m unittest discover -s tests -p 'test_native_intervention_runtime.py' -v

For more about nginx tests, check their repository:
http://hg.nginx.org/nginx-tests/