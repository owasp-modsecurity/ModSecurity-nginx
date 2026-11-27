#!/usr/bin/env bash
# Resolves NGINX_VERSION (from the workflow's nginx_version matrix) to the
# nginx git ref to build, and picks the PCRE2, zlib and OpenSSL versions that
# nginx is built with (--with-pcre, --with-zlib, --with-openssl) for that ref.
# Writes the ref to $GITHUB_OUTPUT (as "ref"), and the library versions and
# their SHA-256 sums to $GITHUB_ENV, for fetch-nginx-libs.sh and the build.
set -euo pipefail

# The library versions nginx is built with, on Linux and on Windows, and the
# SHA-256 of each release tarball (fetch-nginx-libs.sh checks them). When
# bumping a version, update its sum: it is the "digest" GitHub shows for the
# release asset, and OpenSSL also publishes it as <tarball>.sha256.
PCRE2_VERSION="10.49"
PCRE2_SHA256="929f0b20e62879252a15886b06c89f1edef61a363cbd5826fb041080a5e557ae"
ZLIB_VERSION="1.4"
ZLIB_SHA256="02dd159783677a749c04adbdd02b55b8a2bcc7e054f51b76b549199a916ad584"
# nginx supports OpenSSL 4 since 1.29.8 ("OpenSSL 4.0 compatibility" in
# CHANGES); older releases are built with the newest OpenSSL 3.
OPENSSL_VERSION="4.1.0"
OPENSSL_SHA256="50c17baf54cb008f6ce42d50deb4b28050a1aad711636cabd4b241c7e90cc2fd"
OPENSSL4_MIN_NGINX="1.29.8"
OPENSSL3_VERSION="3.6.5"
OPENSSL3_SHA256="a2157c2830efdec3788939b00c9b0638306d3f0bbb76dc4832ee503bb397df98"

VERSION="${NGINX_VERSION:-}"

if [[ -z "${VERSION}" ]]; then
  echo "NGINX_VERSION is not set" >&2
  exit 1
fi

echo "Requested NGINX_VERSION=${VERSION}"

if [[ "${VERSION}" =~ ^[0-9]+\.[0-9]+\.x$ ]]; then
  PREFIX="release-${VERSION%.x}."
  REF=$(git ls-remote --tags https://github.com/nginx/nginx.git "refs/tags/${PREFIX}*" \
    | sed -E 's#.*refs/tags/##; s#\^\{\}##' \
    | grep -E "^${PREFIX}[0-9]+$" \
    | sort -V \
    | tail -n 1)
elif [[ "${VERSION}" =~ ^release-[0-9]+\.[0-9]+\.[0-9]+$ || "${VERSION}" == "master" || "${VERSION}" == "main" ]]; then
  REF="${VERSION}"
else
  echo "Unsupported NGINX_VERSION=${VERSION}" >&2
  echo "Use e.g. master, 1.31.x, 1.30.x or exact tag release-1.30.0" >&2
  exit 1
fi

if [[ -z "${REF}" ]]; then
  echo "No matching Nginx tag found for ${VERSION}" >&2
  exit 1
fi

echo "Resolved Nginx ref: ${REF}"

# master and main are newer than any release
if [[ "${REF}" =~ ^release-([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  NGINX_RELEASE="${BASH_REMATCH[1]}"
  OLDEST=$(printf '%s\n' "${NGINX_RELEASE}" "${OPENSSL4_MIN_NGINX}" | sort -V | head -n 1)
  if [[ "${OLDEST}" != "${OPENSSL4_MIN_NGINX}" ]]; then
    echo "nginx ${NGINX_RELEASE} is older than ${OPENSSL4_MIN_NGINX}, which added OpenSSL 4 support"
    OPENSSL_VERSION="${OPENSSL3_VERSION}"
    OPENSSL_SHA256="${OPENSSL3_SHA256}"
  fi
fi

echo "PCRE2 ${PCRE2_VERSION}, zlib ${ZLIB_VERSION}, OpenSSL ${OPENSSL_VERSION}"

echo "ref=${REF}" >> "${GITHUB_OUTPUT}"
{
  echo "PCRE2_VERSION=${PCRE2_VERSION}"
  echo "PCRE2_SHA256=${PCRE2_SHA256}"
  echo "ZLIB_VERSION=${ZLIB_VERSION}"
  echo "ZLIB_SHA256=${ZLIB_SHA256}"
  echo "OPENSSL_VERSION=${OPENSSL_VERSION}"
  echo "OPENSSL_SHA256=${OPENSSL_SHA256}"
} >> "${GITHUB_ENV}"
