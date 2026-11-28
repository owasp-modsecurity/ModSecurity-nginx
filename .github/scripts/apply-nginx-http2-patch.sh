#!/bin/sh

# Apply the versioned host correction before configuring/building NGINX.
# The connector itself does not own NGINX's physical HTTP/2 connection events.
set -eu

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 /path/to/nginx/source" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
patch_file="$script_dir/../../patches/nginx-http2-close-stream-flush.patch"
nginx_dir=$(CDPATH= cd -- "$1" && pwd)

if [ ! -f "$nginx_dir/src/http/v2/ngx_http_v2.c" ]; then
    echo "NGINX HTTP/2 source is missing in $nginx_dir" >&2
    exit 1
fi

if ! command -v patch >/dev/null 2>&1; then
    echo "The patch utility is required to apply the NGINX HTTP/2 fix" >&2
    exit 1
fi

# Match the source checkout's line endings without rewriting NGINX before the
# dry run.  Windows checkouts may use CRLF even when this patch is stored as LF.
patch_input=$(mktemp "${TMPDIR:-/tmp}/modsecurity-nginx-h2-patch.XXXXXX")
trap 'rm -f "$patch_input"' 0 HUP INT TERM
cr=$(printf '\r')
if LC_ALL=C grep -qU "${cr}$" "$nginx_dir/src/http/v2/ngx_http_v2.c"; then
    sed "s/${cr}\{0,1\}$/${cr}/" "$patch_file" > "$patch_input"
else
    sed "s/${cr}$//" "$patch_file" > "$patch_input"
fi

if patch --binary --dry-run --batch --forward --fuzz=0 -p1 -d "$nginx_dir" \
    -i "$patch_input" >/dev/null 2>&1; then
    patch --binary --batch --forward --fuzz=0 --no-backup-if-mismatch -p1 \
        -d "$nginx_dir" -i "$patch_input"
    echo "Applied NGINX HTTP/2 close-stream reset flush fix"
elif patch --binary --dry-run --batch --reverse --fuzz=0 -p1 -d "$nginx_dir" \
    -i "$patch_input" >/dev/null 2>&1; then
    echo "NGINX HTTP/2 close-stream reset flush fix is already applied"
else
    echo "NGINX HTTP/2 source does not match the versioned fix; review it before building" >&2
    exit 1
fi
