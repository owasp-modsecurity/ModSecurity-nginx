#!/usr/bin/env bash
set -euo pipefail

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
  echo "Use e.g. 1.30.x, 1.29.x, 1.28.x or exact tag release-1.30.0" >&2
  exit 1
fi

if [[ -z "${REF}" ]]; then
  echo "No matching Nginx tag found for ${VERSION}" >&2
  exit 1
fi

echo "Resolved Nginx ref: ${REF}"
echo "ref=${REF}" >> "${GITHUB_OUTPUT}"
