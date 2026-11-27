#!/usr/bin/env bash
# Downloads, checks and extracts the PCRE2, zlib and OpenSSL sources that
# nginx is built with into the directory given as the only argument, as
# pcre2-X.Y, zlib-X.Y and openssl-X.Y.Z. The versions and SHA-256 sums come
# from the environment (PCRE2_VERSION, PCRE2_SHA256, ZLIB_VERSION, ...), as
# resolve-nginx-ref.sh sets them.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <directory>" >&2
  exit 1
fi

for var in PCRE2_VERSION PCRE2_SHA256 ZLIB_VERSION ZLIB_SHA256 \
           OPENSSL_VERSION OPENSSL_SHA256; do
  if [ -z "${!var:-}" ]; then
    echo "$var is not set" >&2
    exit 1
  fi
done

mkdir -p "$1"
cd "$1"

# Download to a file before extracting, rather than piping straight
# into tar: a retried download restarts from byte 0, which a pipe
# that tar already consumed can't rewind. The retry loop is at the
# shell level (one wget attempt per iteration, partial file removed
# in between) because wget's own --tries neither retries HTTP 5xx /
# DNS failures nor rewrites a partial -O file: it sends a Range
# request and appends, which corrupts the archive when the server
# ignores Range. -nv keeps wget's errors and one-line summary
# without the dot progress meter. An archive whose SHA-256 does not
# match is not extracted.
for entry in \
  "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VERSION}/pcre2-${PCRE2_VERSION}.tar.gz ${PCRE2_SHA256}" \
  "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz ${ZLIB_SHA256}" \
  "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz ${OPENSSL_SHA256}" \
; do
  url="${entry% *}"
  sha256="${entry##* }"
  archive="$(basename "$url")"
  for attempt in 1 2 3; do
    rm -f "$archive"
    if wget -nv --tries=1 --timeout=60 -O "$archive" "$url" \
       && echo "${sha256}  ${archive}" | sha256sum -c - \
       && tar -xzf "$archive"; then
      break
    fi
    if [ "$attempt" -eq 3 ]; then
      echo "::error::failed to fetch $url after $attempt attempts"
      exit 1
    fi
    echo "fetching $url failed (attempt $attempt), retrying in 5s"
    sleep 5
  done
  rm -f "$archive"
done
