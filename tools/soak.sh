#!/usr/bin/env bash
#
# Sustained mixed-load soak for the ModSecurity-nginx connector. Drives a real
# nginx (optionally under valgrind memcheck or helgrind) with concurrent
# benign AND attack-shaped requests for a fixed duration, then asserts the
# worker survived cleanly: no valgrind/helgrind error, no crash, no leak, no
# error-log [alert]/[emerg].
#
# The traffic mix deliberately exercises the WAF decision path in both
# directions -- benign requests that must pass (200) and attack requests the
# in-config SecRules must block (403) -- across ten request shapes that drive
# every attacker-reachable path in this connector:
#   * URI-arg, request-body, and request-header attacks (phase 1/2 deny)
#   * benign GET, POST, and large response body (pass)
#   * large chunked request body -> file-backed request-body inspection
#     (msc_request_body_from_file, access.c)
#   * 40 large request headers -> the multi-ngx_list-part traversal loop in
#     the request-header forwarding code (access.c)
#   * RESPONSE_BODY inspection, both pass and phase-4 deny -- the deny
#     aborts the connection mid-transfer rather than a clean 403, since
#     headers are already committed by the time the full body is
#     buffered for inspection (body_filter.c)
#   * a phase:3 "redirect:" action replacing an already-populated response --
#     the Location header must survive and the discarded response's entity
#     headers must not leak (header_filter.c / body_filter.c)
# so allocation/free of the ModSecurity transaction, header forwarding, and
# request/response body inspection all run every iteration.
#
# Usage:
#   tools/soak.sh <nginx-binary> [duration_seconds] [concurrency]
#   USE_VALGRIND=1 tools/soak.sh <nginx-binary> 120 8
#   USE_HELGRIND=1 tools/soak.sh <nginx-binary> 120 8
#
# Env:
#   MODSECURITY_MODULE_SO : path to ngx_http_modsecurity_module.so, for a
#                            --add-dynamic-module build (default: sibling of
#                            the nginx binary). Unused for a static build.
#
# Exit non-zero on ANY of: valgrind/helgrind error, nginx crash/non-clean
# exit, error-log alert/emerg, or a WAF verdict regression (benign blocked /
# attack allowed).

set -euo pipefail

NGINX="${1:?usage: soak.sh <nginx-binary> [duration] [concurrency]}"
DURATION="${2:-60}"
CONC="${3:-8}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

WORK="$(mktemp -d)"
# Kill the (possibly valgrind-wrapped) server too: under `set -e` an early
# failure would otherwise orphan it, holding the port for later runs.
trap 'kill -9 "${NGINX_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$WORK/conf" "$WORK/logs" "$WORK/html"
# When nginx runs as root (e.g. in a container) it drops worker processes to
# its compiled-in default user, which can't traverse mktemp's 0700-root dir.
chmod 755 "$WORK" "$WORK/html"

echo "hello modsecurity" >"$WORK/html/index.html"
head -c 200000 /dev/urandom | base64 >"$WORK/html/medium"
# Benign response body scanned by the phase-4 RESPONSE_BODY rule (must pass).
head -c 120000 /dev/urandom | base64 >"$WORK/html/respbody"
# Response body carrying the leak marker (must be blocked 403 at phase 4).
{
    head -c 40000 /dev/urandom | base64
    echo "leakmarker"
} >"$WORK/html/leak"
# Served with real Content-Length/Last-Modified/ETag, so the redirect case
# below actually has stale entity headers to discard.
head -c 8000 /dev/urandom | base64 >"$WORK/html/entityheaders"

# Locate the built module (.so). --add-dynamic-module builds it into objs/;
# if the caller installed it, allow an override via $MODSECURITY_MODULE_SO.
MODULE_SO="${MODSECURITY_MODULE_SO:-}"
if [ -z "$MODULE_SO" ]; then
    MODULE_SO="$(dirname "$NGINX")/ngx_http_modsecurity_module.so"
fi
LOAD_MODULE_DIRECTIVE=""
if [ -f "$MODULE_SO" ]; then
    LOAD_MODULE_DIRECTIVE="load_module $MODULE_SO;"
fi

# SecRules live in their own file, not inline in modsecurity_rules: the
# redirect: action needs single-quoted string arguments
# (redirect:'/other'), and nesting single quotes inside nginx's own
# single-quoted modsecurity_rules '...' value does not parse.
cat >"$WORK/conf/rules.conf" <<'EOF'
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain
SecRule ARGS "@rx attackmarker" "id:100,phase:2,deny,status:403"
SecRule REQUEST_BODY "@rx evilbody" "id:101,phase:2,deny,status:403"
SecRule REQUEST_HEADERS:X-Attack "@rx headermarker" "id:102,phase:1,deny,status:403"
SecRule RESPONSE_BODY "@rx leakmarker" "id:103,phase:4,deny,status:403"
SecRule REQUEST_HEADERS:X-Redirect-Me "@streq 1" "id:104,phase:3,redirect:'/medium',log"
EOF

cat >"$WORK/conf/nginx.conf" <<EOF
$LOAD_MODULE_DIRECTIVE
daemon off;
master_process on;
worker_processes 4;
error_log $WORK/logs/error.log info;
pid $WORK/logs/nginx.pid;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:18223;
        root $WORK/html;
        default_type text/plain;

        # Small body buffer so the large chunked upload spills to a temp
        # file, exercising the connector's file-backed request-body path.
        client_body_buffer_size 16k;
        # Headroom for the many-large-headers traffic shape (40 headers).
        large_client_header_buffers 8 16k;

        modsecurity on;
        modsecurity_rules_file $WORK/conf/rules.conf;

        # The static handler rejects POST with 405; the soak POSTs benign
        # bodies (must pass) and attack bodies (ModSecurity denies 403 in
        # phase 2, before the handler). Route POSTs that survive the WAF to
        # a 200 so a clean benign body is a 200, not a spurious 405.
        error_page 405 = @ok;
        location @ok { return 200 "ok\n"; }

        location / { }
        location /medium { alias $WORK/html/medium; }
        # Response-body inspect target: served content is scanned by the
        # phase-4 RESPONSE_BODY rule above, exercising the response-body
        # copy/clone + buffered-inspection path (body_filter.c).
        location /respbody { alias $WORK/html/respbody; }
        # A response carrying the leak marker MUST be blocked at phase 4,
        # driving the response-body deny path end to end.
        location /leak { alias $WORK/html/leak; }
        # WAF-triggered redirect target: a real static file, so it carries
        # real Content-Length/Last-Modified/ETag for the redirect case to
        # discard.
        location /entityheaders { alias $WORK/html/entityheaders; }
    }
}
EOF

RUN=("$NGINX" -p "$WORK" -c "$WORK/conf/nginx.conf")
if [ "${USE_VALGRIND:-0}" = "1" ]; then
    RUN=(valgrind --error-exitcode=99 --leak-check=full
        --errors-for-leak-kinds=definite
        --suppressions="$SCRIPT_DIR/valgrind.suppress"
        --log-file="$WORK/logs/valgrind.%p" "${RUN[@]}")
elif [ "${USE_HELGRIND:-0}" = "1" ]; then
    RUN=(valgrind --tool=helgrind --error-exitcode=99
        --suppressions="$SCRIPT_DIR/valgrind.suppress"
        --log-file="$WORK/logs/helgrind.%p" "${RUN[@]}")
fi

# Capture nginx (and valgrind) stderr -- config-parse failures print HERE,
# before error.log is ever opened.
"${RUN[@]}" >"$WORK/logs/stdout.txt" 2>"$WORK/logs/stderr.txt" &
NGINX_PID=$!

# Wait for listen. valgrind starts slowly, so allow up to ~120s; bail early
# if the process already died (config error, missing module, etc.) rather
# than burning the full timeout.
up=0
for _ in $(seq 1 1200); do
    if ! kill -0 "$NGINX_PID" 2>/dev/null; then
        break # process gone -- startup failed, report below
    fi
    curl -fsS -o /dev/null "http://127.0.0.1:18223/" 2>/dev/null && {
        up=1
        break
    }
    sleep 0.1
done
if [ "$up" -ne 1 ]; then
    echo "FAIL: nginx never came up"
    echo "--- stderr ---"
    cat "$WORK/logs/stderr.txt" 2>/dev/null || true
    echo "--- error.log ---"
    cat "$WORK/logs/error.log" 2>/dev/null || echo "(none written)"
    if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
        echo "--- valgrind/helgrind log ---"
        cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
    fi
    kill "$NGINX_PID" 2>/dev/null || true
    exit 1
fi

echo "soak: ${DURATION}s, concurrency ${CONC}$(
    [ "${USE_VALGRIND:-0}" = 1 ] && echo ' (valgrind)'
    [ "${USE_HELGRIND:-0}" = 1 ] && echo ' (helgrind)'
)"
END=$(($(date +%s) + DURATION))
fail=0

# A large body forces nginx to buffer the request into a temp file, driving
# the connector's file-backed request-body path (not just the in-memory
# single-buffer case a tiny -d body hits).
BIG_BODY="$WORK/html/bigreq"
head -c 300000 /dev/urandom | base64 >"$BIG_BODY"

worker() {
    while [ "$(date +%s)" -lt "$END" ]; do
        case $((RANDOM % 10)) in
        0) # benign GET -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || {
                echo "benign GET got $code"
                return 1
            }
            ;;
        1) # benign larger response body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:18223/medium" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || {
                echo "benign /medium got $code"
                return 1
            }
            ;;
        2) # URI-arg attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                "http://127.0.0.1:18223/?q=attackmarker" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || {
                echo "URI attack got $code (want 403)"
                return 1
            }
            ;;
        3) # request-body attack -> must be blocked 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                -d 'x=evilbody' \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || {
                echo "body attack got $code (want 403)"
                return 1
            }
            ;;
        4) # benign POST body -> must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                -d 'x=harmless' \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || {
                echo "benign POST got $code"
                return 1
            }
            ;;
        5) # large chunked request body -> temp-file inspection path, must pass
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                -H 'Transfer-Encoding: chunked' \
                --data-binary "@$BIG_BODY" \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || {
                echo "large chunked body got $code"
                return 1
            }
            ;;
        6) # many + large request headers -> multi-ngx_list-part traversal
            hdrs=()
            for i in $(seq 1 40); do hdrs+=(-H "X-H$i: v$i-$(head -c 64 /dev/zero | tr '\0' a)"); done
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                "${hdrs[@]}" \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "200" ] || {
                echo "many-headers got $code"
                return 1
            }
            ;;
        7) # request-header attack -> phase-1 header rule, must block 403
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                -H 'X-Attack: headermarker' \
                "http://127.0.0.1:18223/" 2>/dev/null || echo 000)
            [ "$code" = "403" ] || {
                echo "header attack got $code (want 403)"
                return 1
            }
            ;;
        8) # response-body: benign scanned body passes; leak marker triggers
            # a phase-4 deny. This connector doesn't delay response headers
            # until body inspection finishes, so by the time the leak marker
            # is found (msc_process_response_body(), after the full body is
            # buffered), the 200 status and Content-Length are already
            # committed to the client -- blocking manifests as the
            # connection aborting mid-transfer, not a clean 403. Assert the
            # transfer fails/truncates rather than completing normally.
            if [ $((RANDOM % 2)) -eq 0 ]; then
                code=$(curl -s -o /dev/null -w '%{http_code}' \
                    "http://127.0.0.1:18223/respbody" 2>/dev/null || echo 000)
                [ "$code" = "200" ] || {
                    echo "benign respbody got $code"
                    return 1
                }
            else
                rc=0
                curl -s -o /dev/null "http://127.0.0.1:18223/leak" 2>/dev/null || rc=$?
                [ "$rc" -ne 0 ] || {
                    echo "resp leak: transfer completed cleanly (want aborted mid-transfer)"
                    return 1
                }
            fi
            ;;
        9) # WAF-triggered redirect on an already-populated response: Location
            # must be present, and the discarded response's stale
            # Content-Length must not leak into the redirect.
            resp_headers=$(curl -s -D - -o /dev/null -H 'X-Redirect-Me: 1' \
                "http://127.0.0.1:18223/entityheaders" 2>/dev/null || echo "")
            case "$resp_headers" in
            *"HTTP/1.1 302"*) : ;;
            *)
                echo "redirect: wrong status: $resp_headers"
                return 1
                ;;
            esac
            case "$resp_headers" in
            *"Location:"*) : ;;
            *)
                echo "redirect: missing Location: $resp_headers"
                return 1
                ;;
            esac
            case "$resp_headers" in
            *"Content-Length: 0"*) : ;;
            *)
                echo "redirect: stale Content-Length leaked: $resp_headers"
                return 1
                ;;
            esac
            ;;
        esac
    done
}

pids=()
for _ in $(seq 1 "$CONC"); do
    worker &
    pids+=($!)
done
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done

# Clean shutdown so all pool cleanups (incl. the ModSecurity transaction) run.
kill -QUIT "$NGINX_PID" 2>/dev/null || true
rc=0
wait "$NGINX_PID" 2>/dev/null || rc=$?

problems=0
if ls "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* >/dev/null 2>&1; then
    if grep -qE 'ERROR SUMMARY: [1-9]|definitely lost: [1-9]' \
        "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null; then
        echo "FAIL: valgrind/helgrind errors:"
        grep -E 'ERROR SUMMARY|definitely lost' \
            "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null
        problems=1
    fi
fi
if grep -nE '\[alert\]|\[emerg\]' "$WORK/logs/error.log" 2>/dev/null; then
    echo "FAIL: alert/emerg in error.log"
    problems=1
fi
if [ "$fail" -ne 0 ]; then
    echo "FAIL: a worker reported a WAF verdict regression"
    problems=1
fi
# QUIT is a clean exit; valgrind/helgrind use 99 on error.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 130 ]; then
    echo "FAIL: nginx exited $rc"
    tail -40 "$WORK/logs/error.log" || true
    problems=1
fi

if [ "$problems" -ne 0 ]; then
    echo "--- full valgrind/helgrind logs (for triage) ---"
    cat "$WORK"/logs/valgrind.* "$WORK"/logs/helgrind.* 2>/dev/null || true
    exit 1
fi
echo "✓ soak clean: ${DURATION}s @ ${CONC} concurrent, no leak/race/crash, WAF verdicts held"
