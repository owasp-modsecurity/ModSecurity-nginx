"""Run the access handler's request phases (P1) with small NGINX/SDK doubles.

The access handler from src/ is compiled with doubles for NGINX and
libModSecurity, so that msc_process_connection(), msc_process_uri() and
msc_process_request_headers() can return any value.  The released
libModSecurity versions always return 1 from them, so their failure paths
cannot be reached by the native suites (modsecurity*.t).

Run from the repository root with Python 3 and GCC or Clang:

    CC=gcc python3 -m unittest discover -s tests -p 'test_request_phase_runtime.py' -v
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACCESS = ROOT / "src" / "ngx_http_modsecurity_access.c"


def function_definition(source: str, name: str) -> str:
    """Return the definition of name(), from its line to its closing brace."""
    for match in re.finditer(rf"^{re.escape(name)}\s*\(", source, re.MULTILINE):
        body = source.find("{", match.end())
        depth = 0
        for index in range(body, len(source)):
            if source[index] == "{":
                depth += 1
            elif source[index] == "}":
                depth -= 1
                if depth == 0:
                    return source[match.start():index + 1]
    raise AssertionError(f"{name}() is not defined in {ACCESS.name}")


PREAMBLE = r"""
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct { int unused; } ngx_sockaddr_t;
typedef struct ngx_http_request_s ngx_http_request_t;
typedef struct ngx_list_part_s {
    void *elts; ngx_uint_t nelts; struct ngx_list_part_s *next;
} ngx_list_part_t;
typedef struct { ngx_list_part_t part; } ngx_list_t;
typedef struct { ngx_str_t key, value; } ngx_table_elt_t;
typedef struct { u_char *pos, *last; int last_buf; } ngx_buf_t;
typedef struct ngx_chain_s { ngx_buf_t *buf; struct ngx_chain_s *next; } ngx_chain_t;
typedef struct { ngx_str_t name; } ngx_file_t;
typedef struct { ngx_file_t file; } ngx_temp_file_t;
typedef struct { ngx_temp_file_t *temp_file; ngx_chain_t *bufs; } ngx_http_request_body_t;
typedef struct {
    ngx_sockaddr_t *sockaddr, *local_sockaddr; void *log; ngx_str_t addr_text;
} ngx_connection_t;
typedef struct {
    ngx_http_request_t *r;
    Transaction *modsec_transaction;
    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned processed:1;
    unsigned logged:1;
    unsigned intervention_triggered:1;
    unsigned request_body_processed:1;
} ngx_http_modsecurity_ctx_t;
typedef struct { int enable; } ngx_http_modsecurity_conf_t;
typedef struct { ngx_uint_t satisfy; } ngx_http_core_loc_conf_t;
struct ngx_http_request_s {
    ngx_pool_t *pool; ngx_connection_t *connection; ngx_http_request_t *main;
    int count, http_version, header_sent, error_page;
    ngx_str_t http_protocol, unparsed_uri, method_name;
    struct { ngx_str_t server; ngx_list_t headers; } headers_in;
    ngx_http_request_body_t *request_body;
    int request_body_in_single_buf, request_body_in_persistent_file;
    int request_body_in_file_only, request_body_in_clean_file;
    void (*write_event_handler)(ngx_http_request_t *);
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *modsecurity_conf;
    ngx_http_core_loc_conf_t *core_conf;
};
#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_AGAIN (-2)
#define NGX_DONE (-4)
#define NGX_DECLINED (-5)
#define NGX_HTTP_UNAUTHORIZED 401
#define NGX_HTTP_FORBIDDEN 403
#define NGX_HTTP_PROXY_AUTH_REQUIRED 407
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_SPECIAL_RESPONSE 300
#define NGX_HTTP_SATISFY_ALL 0
#define NGX_HTTP_SATISFY_ANY 1
#define NGX_HTTP_VERSION_9 9
#define NGX_HTTP_VERSION_10 1000
#define NGX_HTTP_VERSION_11 1001
#define NGX_SOCKADDR_STRLEN 64
#define NGX_LOG_ALERT 2
#define NGX_LOG_ERR 4
#define dd(...) ((void)0)
#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); return 1; \
} } while (0)

/* The request every case starts from; the doubles check that the handler
 * hands exactly these values to libModSecurity. */
#define CLIENT_ADDRESS "192.0.2.10"
#define CLIENT_PORT 50000
#define SERVER_ADDRESS "198.51.100.20"
#define SERVER_PORT 8080
#define REQUEST_URI "/index.html?a=b"
#define REQUEST_METHOD "POST"
#define REQUEST_VERSION "1.1"
#define REQUEST_BODY "a=b"

enum { CONNECTION, URI, REQUEST_HEADERS, REQUEST_BODY_PHASE, PHASES };

static int ngx_http_modsecurity_module, ngx_http_core_module;
static ngx_sockaddr_t client_sockaddr, server_sockaddr;
static Transaction transaction;
static ngx_http_modsecurity_ctx_t created;
static ngx_pool_t previous_pcre_pool;
static ngx_pool_t *pcre_pool = &previous_pcre_pool;
static int pcre_inits, pcre_dones, pcre_misuse, bad_arguments;
static int native_results[PHASES] = {1, 1, 1, 1};
static int native_calls[PHASES], intervention_results[PHASES], intervention_calls[PHASES];
static int active_phase = -1, headers_added, body_reads, body_appends, body_files;
static int finalize_calls, run_phases_calls, error_log_calls, error_log_level;
static ngx_int_t finalized_with;
static size_t expected_body_size = sizeof(REQUEST_BODY) - 1;
static char error_log_message[256];

static void *loc_conf(ngx_http_request_t *r, int *module)
{
    if (module == &ngx_http_core_module) return r->core_conf;
    return r->modsecurity_conf;
}
#define ngx_http_get_module_loc_conf(r, module) loc_conf((r), &(module))

static void ngx_http_core_run_phases(ngx_http_request_t *r) { (void)r; ++run_phases_calls; }
static void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    (void)r; ++finalize_calls; finalized_with = rc;
}
static void ngx_log_error(ngx_uint_t level, void *log, int error, const char *format, ...)
{
    va_list arguments;
    (void)log; (void)error;
    ++error_log_calls; error_log_level = (int)level;
    va_start(arguments, format);
    vsnprintf(error_log_message, sizeof(error_log_message), format, arguments);
    va_end(arguments);
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    return r->ctx;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    memset(&created, 0, sizeof(created));
    created.r = r; created.modsec_transaction = &transaction;
    r->ctx = &created;
    return &created;
}
/* Like the module's: NULL for an empty string.  The values handed in are
 * NUL-terminated already. */
static char *ngx_str_to_char(ngx_str_t value, ngx_pool_t *pool)
{
    (void)pool;
    return value.len == 0 ? NULL : (char *)value.data;
}
static int ngx_inet_get_port(ngx_sockaddr_t *address)
{
    return address == &client_sockaddr ? CLIENT_PORT : SERVER_PORT;
}
static ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *out, int port)
{
    (void)c; (void)port;
    out->data = (u_char *)SERVER_ADDRESS; out->len = sizeof(SERVER_ADDRESS) - 1;
    return NGX_OK;
}
/* The PCRE1 build points pcre_malloc at the request pool around each native
 * call; the previous pool must be back on every path. */
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *pool)
{
    ngx_pool_t *old = pcre_pool;
    ++pcre_inits; pcre_pool = pool;
    return old;
}
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *old)
{
    ++pcre_dones;
    if (old != &previous_pcre_pool) pcre_misuse = 1;
    pcre_pool = old;
}
static int native(int phase)
{
    if (pcre_pool == &previous_pcre_pool) pcre_misuse = 1;
    active_phase = phase; ++native_calls[phase];
    return native_results[phase];
}
static int msc_process_connection(Transaction *t, const char *client, int client_port,
    const char *server, int server_port)
{
    if (t != &transaction || strcmp(client, CLIENT_ADDRESS) != 0 || client_port != CLIENT_PORT
        || strcmp(server, SERVER_ADDRESS) != 0 || server_port != SERVER_PORT)
    {
        bad_arguments = 1;
    }
    return native(CONNECTION);
}
static int msc_process_uri(Transaction *t, const char *uri, const char *method,
    const char *version)
{
    if (t != &transaction || strcmp(uri, REQUEST_URI) != 0
        || strcmp(method, REQUEST_METHOD) != 0 || strcmp(version, REQUEST_VERSION) != 0)
    {
        bad_arguments = 1;
    }
    return native(URI);
}
static ngx_table_elt_t headers[] = {
    {{4, (u_char *)"Host"}, {9, (u_char *)"localhost"}},
    {{6, (u_char *)"Accept"}, {3, (u_char *)"*/*"}},
};
static int msc_add_n_request_header(Transaction *t, const u_char *key, size_t key_len,
    const u_char *value, size_t value_len)
{
    ngx_table_elt_t *header = &headers[headers_added++];
    if (t != &transaction || key != header->key.data || key_len != header->key.len
        || value != header->value.data || value_len != header->value.len)
    {
        bad_arguments = 1;
    }
    return 1;
}
static int msc_process_request_headers(Transaction *t)
{
    if (t != &transaction) bad_arguments = 1;
    return native(REQUEST_HEADERS);
}
static int msc_request_body_from_file(Transaction *t, const char *path)
{
    (void)t; (void)path; ++body_files;
    return 1;
}
static int msc_append_request_body(Transaction *t, const u_char *data, size_t size)
{
    (void)data;
    if (t != &transaction || size != expected_body_size) bad_arguments = 1;
    ++body_appends;
    return 1;
}
static int msc_process_request_body(Transaction *t)
{
    if (t != &transaction) bad_arguments = 1;
    return native(REQUEST_BODY_PHASE);
}
static int status_updates, updated_status;
static int msc_update_status_code(Transaction *t, int status)
{
    if (t != &transaction) bad_arguments = 1;
    ++status_updates; updated_status = status;
    return 1;
}
static int ngx_http_modsecurity_process_intervention(Transaction *t, ngx_http_request_t *r,
    ngx_int_t early_log)
{
    (void)r; (void)early_log;
    if (t != &transaction || active_phase < 0) abort();
    ++intervention_calls[active_phase];
    return intervention_results[active_phase];
}
static ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
    void (*post_handler)(ngx_http_request_t *))
{
    (void)r; (void)post_handler; ++body_reads;
    return NGX_OK;
}
"""

CASES = r"""
#define SERVED 200

/*
 * What the client gets once ngx_http_core_access_phase() (nginx 1.31) has
 * the handler's rc, if the next access module (allow, auth_basic,
 * auth_request) admits the client.  SERVED: the request reaches the content
 * phase, for a proxied location the upstream.
 */
static ngx_int_t access_phase(ngx_http_request_t *r, ngx_int_t rc)
{
    if (rc == NGX_DECLINED || rc == NGX_OK) return SERVED;
    if (rc == NGX_DONE) return finalize_calls == 1 ? finalized_with : NGX_AGAIN;
    if (r->core_conf->satisfy == NGX_HTTP_SATISFY_ANY
        && (rc == NGX_HTTP_FORBIDDEN || rc == NGX_HTTP_UNAUTHORIZED
            || rc == NGX_HTTP_PROXY_AUTH_REQUIRED))
    {
        return SERVED;
    }
    return rc;
}

static int processing_count(void)
{
    int phase, count = pcre_inits + headers_added + body_reads + body_appends + body_files;
    for (phase = CONNECTION; phase < PHASES; ++phase) {
        count += native_calls[phase] + intervention_calls[phase];
    }
    return count;
}

static const char *phase_names[] = {"connection", "URI", "request headers"};

int main(int argc, char **argv)
{
    ngx_pool_t pool = {0};
    ngx_connection_t connection = {0};
    ngx_http_modsecurity_conf_t modsecurity_conf = {1};
    ngx_http_core_loc_conf_t core_conf = {NGX_HTTP_SATISFY_ALL};
    u_char bytes[] = REQUEST_BODY;
    ngx_buf_t buffer = {bytes, bytes + sizeof(REQUEST_BODY) - 1, 1};
    ngx_chain_t chain = {&buffer, NULL};
    ngx_http_request_body_t body = {NULL, &chain};
    ngx_http_request_t request = {0};
    const char *scenario, *state;
    int phase, value, failed, intervened, earlier, later, before, header_count = 2;
    ngx_int_t result, outcome;
    char expected[128];

    CHECK(argc == 6);
    scenario = argv[1]; phase = atoi(argv[2]); value = atoi(argv[3]); state = argv[5];
    CHECK(phase >= CONNECTION && phase <= REQUEST_HEADERS);

    request.pool = &pool; request.connection = &connection; request.main = &request;
    request.modsecurity_conf = &modsecurity_conf; request.core_conf = &core_conf;
    request.request_body = &body; request.http_version = NGX_HTTP_VERSION_11;
    request.unparsed_uri.data = (u_char *)REQUEST_URI;
    request.unparsed_uri.len = sizeof(REQUEST_URI) - 1;
    request.method_name.data = (u_char *)REQUEST_METHOD;
    request.method_name.len = sizeof(REQUEST_METHOD) - 1;
    request.headers_in.headers.part.elts = headers;
    request.headers_in.headers.part.nelts = header_count;
    connection.sockaddr = &client_sockaddr; connection.local_sockaddr = &server_sockaddr;
    connection.addr_text.data = (u_char *)CLIENT_ADDRESS;
    connection.addr_text.len = sizeof(CLIENT_ADDRESS) - 1;

    if (strcmp(argv[4], "any") == 0) core_conf.satisfy = NGX_HTTP_SATISFY_ANY;
    else if (strcmp(argv[4], "all") != 0) return 2;

    if (strcmp(state, "header-sent") == 0) request.header_sent = 1;
    else if (strcmp(state, "error-page") == 0) request.error_page = 1;
    else if (strcmp(state, "no-headers") == 0) {
        request.headers_in.headers.part.elts = NULL;
        request.headers_in.headers.part.nelts = header_count = 0;
    }
    else if (strcmp(state, "empty-header-value") == 0) headers[1].value.len = 0;
    else if (strcmp(state, "empty-body") == 0) { buffer.last = buffer.pos; expected_body_size = 0; }
    else if (strcmp(state, "none") != 0) return 2;

    failed = strcmp(scenario, "native") == 0;
    intervened = strcmp(scenario, "intervention") == 0;
    if (failed) native_results[phase] = value;
    else if (intervened) intervention_results[phase] = value;
    else if (strcmp(scenario, "empty-uri") == 0) request.unparsed_uri.len = 0;
    else if (strcmp(scenario, "allow") != 0) return 2;

    result = ngx_http_modsecurity_access_handler(&request);
    outcome = access_phase(&request, result);

    CHECK(pcre_inits == pcre_dones && !pcre_misuse && pcre_pool == &previous_pcre_pool);
    CHECK(!bad_arguments && request.ctx == &created);

    if (strcmp(scenario, "allow") == 0) {
        CHECK(result == NGX_DECLINED && outcome == SERVED);
        CHECK(finalize_calls == 0 && error_log_calls == 0 && status_updates == 0);
        CHECK(!created.intervention_triggered && created.request_body_processed);
        for (later = CONNECTION; later < PHASES; ++later) {
            CHECK(native_calls[later] == 1 && intervention_calls[later] == 1);
        }
        CHECK(headers_added == header_count && body_reads == 1 && body_appends == 1);
        return 0;
    }

    if (strcmp(scenario, "empty-uri") == 0) {
        /* Unchanged: an empty URI is refused before the URI phase. */
        CHECK(result == NGX_HTTP_INTERNAL_SERVER_ERROR && outcome == result);
        CHECK(native_calls[CONNECTION] == 1 && native_calls[URI] == 0);
        CHECK(native_calls[REQUEST_HEADERS] == 0 && headers_added == 0 && body_reads == 0);
        CHECK(finalize_calls == 0 && error_log_calls == 0);
        return 0;
    }

    CHECK(native_calls[phase] == 1);
    for (earlier = CONNECTION; earlier < phase; ++earlier) {
        CHECK(native_calls[earlier] == 1 && intervention_calls[earlier] == 1);
    }
    for (later = phase + 1; later < PHASES; ++later) {
        CHECK(native_calls[later] == 0 && intervention_calls[later] == 0);
    }
    CHECK(headers_added == (phase == REQUEST_HEADERS ? header_count : 0));
    /* The request body is neither read nor inspected. */
    CHECK(body_reads == 0 && body_appends == 0 && body_files == 0);
    CHECK(!created.request_body_processed);

    if (intervened && request.error_page && phase == REQUEST_HEADERS) {
        /* Unchanged: a request headers rule does not block an error page. */
        CHECK(result == NGX_DECLINED && outcome == SERVED && finalize_calls == 0);
        CHECK(intervention_calls[phase] == 1 && !created.intervention_triggered);
        return 0;
    }

    CHECK(created.intervention_triggered);

    if (failed) {
        /* A failed phase is final under both "satisfy" modes and on an error
         * page; its intervention is not looked at. */
        CHECK(intervention_calls[phase] == 0);
        CHECK(result == (request.header_sent ? NGX_ERROR : NGX_HTTP_INTERNAL_SERVER_ERROR));
        CHECK(outcome == result && finalize_calls == 0);
        /* The audit log gets the 500; after the header, the sent status
         * stands. */
        if (request.header_sent) CHECK(status_updates == 0);
        else CHECK(status_updates == 1 && updated_status == NGX_HTTP_INTERNAL_SERVER_ERROR);
        CHECK(error_log_calls == 1 && error_log_level == NGX_LOG_ERR);
        if (value == 0) {
            snprintf(expected, sizeof(expected),
                     "ModSecurity: %s phase processing failed", phase_names[phase]);
        } else {
            snprintf(expected, sizeof(expected),
                     "ModSecurity: %s phase processing returned an unexpected result: %d",
                     phase_names[phase], value);
        }
        CHECK(strcmp(error_log_message, expected) == 0);
    } else {
        /* ngx_http_modsecurity_process_intervention() records the status. */
        CHECK(intervention_calls[phase] == 1 && error_log_calls == 0 && status_updates == 0);
        if (core_conf.satisfy == NGX_HTTP_SATISFY_ANY) {
            /* #410: under "satisfy any" the handler finalizes it itself. */
            CHECK(result == NGX_DONE && finalize_calls == 1 && finalized_with == value);
        } else {
            CHECK(result == value && finalize_calls == 0);
        }
        CHECK(outcome == value);
    }

    /* A later run of the handler for this request, for an error page after
     * an internal redirect, repeats no phase and reads no body. */
    before = processing_count();
    CHECK(ngx_http_modsecurity_access_handler(&request) == NGX_DECLINED);
    CHECK(processing_count() == before && pcre_pool == &previous_pcre_pool);
    return 0;
}
"""


def program(access: str) -> str:
    helpers = ""
    for name, result in (
        ("ngx_http_modsecurity_request_read", "void"),
        ("ngx_http_modsecurity_access_intervention", "static ngx_int_t"),
        ("ngx_http_modsecurity_request_phase_failed", "static ngx_int_t"),
        ("ngx_http_modsecurity_access_handler", "ngx_int_t"),
    ):
        helpers += "\n" + result + "\n" + function_definition(access, name) + "\n"
    return PREAMBLE + helpers + CASES


PHASES = {"connection": 0, "uri": 1, "request headers": 2}
SATISFY = ("all", "any")


class RequestPhaseRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C17 compiler")
        workspace = tempfile.TemporaryDirectory(prefix="nginx-request-phase-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        source = directory / "request_phase.c"
        source.write_text(program(ACCESS.read_text(encoding="utf-8")), encoding="utf-8")
        cls.binary = directory / ("request_phase.exe" if os.name == "nt" else "request_phase")
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if build.returncode:
            raise AssertionError(f"Request phase helper build failed:\n{build.stderr}")

    def case(self, scenario: str, phase: int, value: int, satisfy: str,
             state: str = "none") -> None:
        result = subprocess.run(
            [str(self.binary), scenario, str(phase), str(value), satisfy, state],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_allowed_request_runs_every_phase_once(self):
        for state in ("none", "no-headers", "empty-header-value", "empty-body"):
            for satisfy in SATISFY:
                with self.subTest(state=state, satisfy=satisfy):
                    self.case("allow", 0, 0, satisfy, state)

    def test_native_failure_ends_the_request_with_500(self):
        for name, phase in PHASES.items():
            for satisfy in SATISFY:
                with self.subTest(phase=name, satisfy=satisfy):
                    self.case("native", phase, 0, satisfy)

    def test_unexpected_native_result_ends_the_request_with_500(self):
        for name, phase in PHASES.items():
            for value in (-1, 2, 42):
                for satisfy in SATISFY:
                    with self.subTest(phase=name, value=value, satisfy=satisfy):
                        self.case("native", phase, value, satisfy)

    def test_request_headers_failure_without_header_values(self):
        for state in ("no-headers", "empty-header-value"):
            with self.subTest(state=state):
                self.case("native", PHASES["request headers"], 0, "all", state)

    def test_native_failure_after_the_header_closes_the_request(self):
        for name, phase in PHASES.items():
            for satisfy in SATISFY:
                with self.subTest(phase=name, satisfy=satisfy):
                    self.case("native", phase, 0, satisfy, "header-sent")

    def test_error_page_does_not_hide_a_native_failure(self):
        for name, phase in PHASES.items():
            with self.subTest(phase=name):
                self.case("native", phase, 0, "all", "error-page")

    def test_empty_uri_is_refused_before_the_uri_phase(self):
        self.case("empty-uri", 0, 0, "all")

    def test_interventions_are_enforced_as_before(self):
        for name, phase in PHASES.items():
            for status in (302, 401, 403):
                for satisfy in SATISFY:
                    with self.subTest(phase=name, status=status, satisfy=satisfy):
                        self.case("intervention", phase, status, satisfy)

    def test_error_page_request_headers_intervention_as_before(self):
        for satisfy in SATISFY:
            with self.subTest(satisfy=satisfy):
                self.case("intervention", PHASES["request headers"], 403, satisfy,
                          "error-page")


if __name__ == "__main__":
    unittest.main()
