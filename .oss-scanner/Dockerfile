# Build environment for Anthropic's OSS Scanner (https://github.com/anthropics/oss-scanner).
# The scanner builds this image with the repository checkout as the build context, then
# analyses it with no network access, so everything the build and the tests need is fetched
# here. Keep it aligned with the build-linux job in .github/workflows/test_new.yml.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git build-essential clang autoconf automake libtool pkg-config \
      perl curl gdb valgrind \
      libpcre2-dev pcre2-utils zlib1g-dev libyajl-dev libxml2-dev libmaxminddb-dev \
      libcurl4-gnutls-dev \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

ENV DEBUG_FLAGS="-g -O1 -fno-omit-frame-pointer"

# libModSecurity (v3/master), the library this connector feeds, with its sources kept in
# /opt/ModSecurity so the scanner can follow calls into it
RUN git clone --recurse-submodules https://github.com/owasp-modsecurity/ModSecurity /opt/ModSecurity \
    && cd /opt/ModSecurity \
    && ./build.sh \
    && ./configure --without-lmdb --prefix=/usr CFLAGS="$DEBUG_FLAGS" CXXFLAGS="$DEBUG_FLAGS" \
    && make -j"$(nproc)" \
    && make install

# nginx (latest 1.30.x stable release) and its test framework
RUN tag=$(git ls-remote --tags --refs https://github.com/nginx/nginx 'release-1.30.*' \
          | sed 's#.*refs/tags/##' | grep -E '^release-1\.30\.[0-9]+$' | sort -V | tail -n 1) \
    && git clone --depth 1 --branch "$tag" https://github.com/nginx/nginx /opt/nginx \
    && git clone --depth 1 https://github.com/nginx/nginx-tests /opt/nginx-tests

# The OWASP CRS v4 (latest release), for checking a finding against a default CRS deployment;
# see threat_model.md
RUN tag=$(git ls-remote --tags --refs https://github.com/coreruleset/coreruleset 'v4.*' \
          | sed 's#.*refs/tags/##' | grep -E '^v4\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1) \
    && git clone --depth 1 --branch "$tag" https://github.com/coreruleset/coreruleset /opt/coreruleset

# nginx with this connector built in, as CI builds it. A failing step fails the build.
RUN cd /opt/nginx \
    && ./auto/configure --with-debug --with-http_v2_module --with-http_auth_request_module \
         --with-cc-opt="$DEBUG_FLAGS" --add-module=/src \
    && make -j"$(nproc)"

# The connector's tests (tests/*.t) use nginx-tests' Test::Nginx from a lib/ next to them.
# They run as the unprivileged user `builder`, as in CI (as root, nginx workers switch to
# nobody and cannot reach the test directories), but do not let a failing test abort the build.
RUN ln -s /opt/nginx-tests/lib /src/tests/lib \
    && useradd --create-home builder \
    && (cd /src/tests && runuser -u builder -- env TEST_NGINX_BINARY=/opt/nginx/objs/nginx prove modsecurity*.t \
        || echo "WARNING: prove reported failures")
