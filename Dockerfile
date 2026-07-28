# Build image for the ModSecurity-nginx connector: libmodsecurity3, nginx,
# and this connector, statically linked (matching the .github/workflows/
# test_new.yml CI build). Used as the base for Dockerfile.fuzz's
# valgrind/helgrind soak; not intended as a production nginx image.
FROM debian:bookworm-slim AS builder

ARG NGINX_VERSION=1.29.1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        wget \
        automake \
        autoconf \
        libtool \
        pkg-config \
        pcre2-utils \
        libpcre2-dev \
        libyajl-dev \
        libxml2-dev \
        libmaxminddb-dev \
        libcurl4-openssl-dev \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# Stage 1: libmodsecurity v3, matching test_new.yml's build.
WORKDIR /build
RUN git clone --depth 1 --branch v3/master --recurse-submodules \
        https://github.com/owasp-modsecurity/ModSecurity.git libmodsecurity
WORKDIR /build/libmodsecurity
RUN ./build.sh && \
    ./configure --without-lmdb --prefix=/usr && \
    make -j"$(nproc)" && \
    make install

# Stage 2: nginx, statically linked against this connector.
WORKDIR /build
RUN wget -q -O nginx.tar.gz "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" && \
    tar -xzf nginx.tar.gz
COPY . /build/ModSecurity-nginx
WORKDIR /build/nginx-${NGINX_VERSION}
RUN ./configure \
        --with-ld-opt="-Wl,-rpath,/usr/lib" \
        --with-http_v2_module \
        --with-http_auth_request_module \
        --add-module=../ModSecurity-nginx && \
    make -j"$(nproc)" && \
    make install

# Runtime image: nginx binary + libmodsecurity's runtime deps only.
FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libpcre2-8-0 \
        libyajl2 \
        libxml2 \
        libmaxminddb0 \
        libcurl4 \
        libstdc++6 \
        zlib1g && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/nginx /usr/local/nginx
COPY --from=builder /usr/lib/libmodsecurity* /usr/lib/
RUN ldconfig

EXPOSE 80
ENTRYPOINT ["/usr/local/nginx/sbin/nginx"]
CMD ["-g", "daemon off;"]
