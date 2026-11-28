"""Exercise the request body inspection of the access handler.

The access handler and its request body helpers are compiled from
src/ngx_http_modsecurity_access.c with small NGINX and libModSecurity
doubles. The doubles model what the connector relies on: libModSecurity
enforces SecRequestBodyLimit while the body is appended, ProcessPartial
returns 0, and Reject returns 1 and leaves an intervention in the
transaction until it is read.

These cases cover what a native test cannot provoke: invalid descriptors,
failed and short reads, a file that changes while it is read and failed
allocations. tests/modsecurity-request-body-file.t covers the same code
through NGINX and libModSecurity.

Run from the repository root with GCC or Clang:

    CC=gcc python3 -m unittest tests/test_request_body_runtime.py -v
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


def function_definition(source: str, name: str) -> str:
    """Return the definition of a function, from its name to its last brace.

    The return type, which NGINX style puts on the line before, is not
    included. Comments, strings and character constants are skipped when
    the braces are counted.
    """
    start = source.find("\n" + name + "(")
    if start < 0:
        raise AssertionError(f"{name}() not found")
    start += 1
    depth = 0
    i = source.index("{", start)
    while i < len(source):
        if source.startswith("//", i):
            i = source.index("\n", i)
        elif source.startswith("/*", i):
            i = source.index("*/", i) + 1
        elif source[i] in "\"'":
            quote = source[i]
            i += 1
            while source[i] != quote:
                i += 2 if source[i] == "\\" else 1
        elif source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i + 1] + "\n"
        i += 1
    raise AssertionError(f"{name}() has no end")


PREAMBLE = r"""
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define nginx_version 1031010
#define dd(...) ((void) 0)

typedef unsigned char u_char;
typedef long ngx_int_t;
typedef unsigned long ngx_uint_t;
typedef int ngx_fd_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int unused; } ngx_pool_t;
typedef struct { int unused; } Transaction;
typedef struct ngx_http_request_s ngx_http_request_t;

typedef struct ngx_list_part_s {
    void *elts; ngx_uint_t nelts; struct ngx_list_part_s *next;
} ngx_list_part_t;
typedef struct { ngx_list_part_t part; } ngx_list_t;
typedef struct { ngx_str_t key, value; } ngx_table_elt_t;

typedef struct {
    u_char *pos, *last;
    unsigned temporary:1, memory:1, mmap:1, in_file:1;
    unsigned flush:1, sync:1, last_buf:1;
} ngx_buf_t;
typedef struct ngx_chain_s { ngx_buf_t *buf; struct ngx_chain_s *next; } ngx_chain_t;
typedef struct { ngx_fd_t fd; ngx_str_t name; off_t offset; } ngx_file_t;
typedef struct { off_t size; int regular; } ngx_file_info_t;
typedef struct { ngx_file_t file; off_t offset; } ngx_temp_file_t;
typedef struct { ngx_temp_file_t *temp_file; ngx_chain_t *bufs; } ngx_http_request_body_t;

typedef struct {
    void *sockaddr, *local_sockaddr, *log; ngx_str_t addr_text;
} ngx_connection_t;

typedef struct {
    Transaction *modsec_transaction;
    unsigned waiting_more_body:1;
    unsigned body_requested:1;
    unsigned request_body_failed:1;
    unsigned intervention_triggered:1;
    unsigned request_body_processed:1;
} ngx_http_modsecurity_ctx_t;

typedef struct { int enable; } ngx_http_modsecurity_conf_t;
typedef struct { int satisfy; } ngx_http_core_loc_conf_t;

struct ngx_http_request_s {
    ngx_pool_t *pool; ngx_connection_t *connection; ngx_http_request_t *main;
    int count, http_version, error_page;
    ngx_str_t http_protocol, unparsed_uri, method_name;
    struct { ngx_list_t headers; } headers_in;
    ngx_http_request_body_t *request_body;
    unsigned request_body_in_single_buf:1, request_body_in_persistent_file:1;
    unsigned request_body_in_file_only:1, request_body_in_clean_file:1;
    void (*write_event_handler)(ngx_http_request_t *);
    ngx_http_modsecurity_ctx_t *ctx;
    ngx_http_modsecurity_conf_t *conf;
    ngx_http_core_loc_conf_t *core;
};

enum { ngx_http_modsecurity_module = 1, ngx_http_core_module = 2 };

#define NGX_OK 0
#define NGX_ERROR (-1)
#define NGX_AGAIN (-2)
#define NGX_DONE (-4)
#define NGX_DECLINED (-5)
#define NGX_HTTP_SPECIAL_RESPONSE 300
#define NGX_HTTP_INTERNAL_SERVER_ERROR 500
#define NGX_HTTP_SATISFY_ALL 0
#define NGX_HTTP_SATISFY_ANY 1
#define NGX_HTTP_VERSION_9 9
#define NGX_HTTP_VERSION_10 1000
#define NGX_HTTP_VERSION_11 1001
#define NGX_HTTP_VERSION_20 2000
#define NGX_SOCKADDR_STRLEN 64
#define NGX_LOG_ERR 4
#define NGX_INVALID_FILE (-1)
#define NGX_FILE_ERROR (-1)
#define ngx_errno 0
#define ngx_fd_info_n "fstat()"
#define ngx_is_file(fi) ((fi)->regular)
#define ngx_file_size(fi) ((fi)->size)
#define ngx_buf_in_memory(b) ((b)->temporary || (b)->memory || (b)->mmap)
#define ngx_buf_special(b) \
    (((b)->flush || (b)->last_buf || (b)->sync) \
     && !ngx_buf_in_memory(b) && !(b)->in_file)
#define ngx_http_get_module_loc_conf(r, module) \
    ((module) == ngx_http_core_module ? (void *) (r)->core : (void *) (r)->conf)

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "line %d: %s\n", __LINE__, #condition); exit(1); \
} } while (0)

#define FILE_FD 7
#define CHUNK 32768

/* libModSecurity: the body it keeps, its limit and the intervention it holds */
static u_char kept[3 * CHUNK + 16];
static size_t kept_len, limit;
static int reject_limit, pending_status, forced_append_result, forced_append_at;
static int append_calls, p2_calls, p2_status, interventions_after_p2;
static int interventions_before_p2, finalized_status;

/* NGINX: the temporary file, its descriptor and the request pool */
static u_char disk[3 * CHUNK + 16], scratch[CHUNK];
static off_t disk_size;
static int fd_info_calls, fd_info_fails, not_regular, shrink_after_read;
static int read_calls, fail_read_at, short_read_at;
static size_t largest_read;
static int alloc_calls, fail_alloc, freed, error_logs;

static ngx_http_modsecurity_ctx_t context;
static Transaction transaction;

static void ngx_log_error(int level, void *log, int err, const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
    ++error_logs;
}

static void ngx_http_core_run_phases(ngx_http_request_t *r) { (void) r; }
static void ngx_http_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    (void) r; finalized_status = (int) rc;
}
void ngx_http_modsecurity_request_read(ngx_http_request_t *r) { (void) r; }

static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_get_module_ctx(ngx_http_request_t *r)
{
    return r->ctx;
}
static ngx_http_modsecurity_ctx_t *ngx_http_modsecurity_create_ctx(ngx_http_request_t *r)
{
    memset(&context, 0, sizeof(context));
    context.modsec_transaction = &transaction;
    r->ctx = &context;
    return &context;
}
static char *ngx_str_to_char(ngx_str_t a, ngx_pool_t *p)
{
    static char copy[64];
    (void) p;
    if (a.len == 0) return NULL;
    memcpy(copy, a.data, a.len); copy[a.len] = '\0';
    return copy;
}
static int ngx_inet_get_port(void *sa) { (void) sa; return 80; }
static ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s, ngx_uint_t port)
{
    (void) c; (void) port; s->data = (u_char *) "127.0.0.1"; s->len = 9;
    return NGX_OK;
}
static ngx_pool_t *ngx_http_modsecurity_pcre_malloc_init(ngx_pool_t *p) { return p; }
static void ngx_http_modsecurity_pcre_malloc_done(ngx_pool_t *p) { (void) p; }
static ngx_int_t ngx_http_read_client_request_body(ngx_http_request_t *r,
    void (*post_handler)(ngx_http_request_t *))
{
    (void) r; (void) post_handler; return NGX_OK;
}

static int msc_process_connection(Transaction *t, const char *ca, int cp, const char *sa, int sp)
{
    (void) t; (void) ca; (void) cp; (void) sa; (void) sp; return 1;
}
static int msc_process_uri(Transaction *t, const char *uri, const char *m, const char *v)
{
    (void) t; (void) uri; (void) m; (void) v; return 1;
}
static int msc_add_n_request_header(Transaction *t, const u_char *k, size_t kl,
    const u_char *v, size_t vl)
{
    (void) t; (void) k; (void) kl; (void) v; (void) vl; return 1;
}
static int msc_process_request_headers(Transaction *t) { (void) t; return 1; }

/* Transaction::appendRequestBody(), with a test hook for undefined results */
static int msc_append_request_body(Transaction *t, const u_char *data, size_t len)
{
    (void) t;
    ++append_calls;
    if (forced_append_at == append_calls) return forced_append_result;
    if (limit > 0 && kept_len + len > limit) {
        if (!reject_limit) {
            memcpy(kept + kept_len, data, limit - kept_len);
            kept_len = limit;
            return 0;
        }
        pending_status = 403;
        return 1;
    }
    CHECK(kept_len + len <= sizeof(kept));
    memcpy(kept + kept_len, data, len);
    kept_len += len;
    return 1;
}

/* a phase 2 rule: deny with p2_status if the kept body contains "BAD" */
static int msc_process_request_body(Transaction *t)
{
    size_t i;
    (void) t;
    ++p2_calls;
    if (pending_status == 0 && p2_status != 0) {
        for (i = 0; i + 3 <= kept_len; i++) {
            if (memcmp(kept + i, "BAD", 3) == 0) { pending_status = p2_status; break; }
        }
    }
    return 1;
}

/* reads, and so clears, the intervention the transaction holds */
static int ngx_http_modsecurity_process_intervention(Transaction *t,
    ngx_http_request_t *r, ngx_int_t early_log)
{
    int status = pending_status;
    (void) t; (void) r; (void) early_log;
    if (p2_calls > 0) ++interventions_after_p2;
    else if (append_calls > 0) ++interventions_before_p2;
    pending_status = 0;
    return status;
}

static int ngx_fd_info(ngx_fd_t fd, ngx_file_info_t *fi)
{
    ++fd_info_calls;
    if (fd != FILE_FD || fd_info_fails) return NGX_FILE_ERROR;
    fi->size = disk_size - (shrink_after_read && read_calls > 0 ? 1 : 0);
    fi->regular = !not_regular;
    return 0;
}

/* ngx_read_file(), which advances file->offset like the real one */
static ssize_t ngx_read_file(ngx_file_t *file, u_char *buf, size_t size, off_t offset)
{
    size_t n = size;
    CHECK(file->fd == FILE_FD && buf == scratch && size <= CHUNK && offset >= 0);
    ++read_calls;
    if (size > largest_read) largest_read = size;
    if (fail_read_at == read_calls) return NGX_ERROR;
    if (short_read_at == read_calls) n = size - 1;
    if ((off_t) n > disk_size - offset) n = (size_t) (disk_size - offset);
    memcpy(buf, disk + offset, n);
    file->offset += (off_t) n;
    return (ssize_t) n;
}

/* a failed allocation is logged by ngx_alloc() */
static void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    ++alloc_calls;
    CHECK(size == CHUNK);
    if (fail_alloc) { ++error_logs; return NULL; }
    return scratch;
}
static ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p)
{
    (void) pool;
    CHECK(p == scratch);
    ++freed;
    return NGX_OK;
}
"""


CASES = r"""
enum { MEMORY, FILE_BODY, NO_BODY };

static ngx_pool_t pool;
static ngx_connection_t connection;
static ngx_http_modsecurity_conf_t conf = {1};
static ngx_http_core_loc_conf_t core = {NGX_HTTP_SATISFY_ALL};
static ngx_http_request_body_t body;
static ngx_temp_file_t temp_file;
static ngx_http_request_t request;
static ngx_buf_t buffers[3];
static ngx_chain_t chain[3];

static void fill_disk(off_t size)
{
    off_t i;
    CHECK((size_t) size <= sizeof(disk));
    for (i = 0; i < size; i++) disk[i] = (u_char) ('a' + i % 26);
    disk_size = size;
}

static void setup(int kind, off_t size)
{
    request.pool = &pool; request.connection = &connection; request.main = &request;
    request.conf = &conf; request.core = &core;
    request.http_version = NGX_HTTP_VERSION_11;
    request.unparsed_uri.data = (u_char *) "/"; request.unparsed_uri.len = 1;
    request.method_name.data = (u_char *) "POST"; request.method_name.len = 4;
    connection.addr_text.data = (u_char *) "127.0.0.1"; connection.addr_text.len = 9;
    fill_disk(size);
    if (kind == NO_BODY) return;
    request.request_body = &body;
    if (kind == FILE_BODY) {
        temp_file.file.fd = FILE_FD;
        temp_file.file.name.data = (u_char *) "body"; temp_file.file.name.len = 4;
        temp_file.file.offset = size;
        temp_file.offset = size;
        body.temp_file = &temp_file;
    }
}

/* the body in memory as one data buffer per piece and a last_buf marker */
static void memory_body(const char *first, const char *second)
{
    int n = 0;
    const char *piece[2] = {first, second};
    int i;
    for (i = 0; i < 2; i++) {
        if (piece[i] == NULL) continue;
        buffers[n].pos = (u_char *) piece[i];
        buffers[n].last = (u_char *) piece[i] + strlen(piece[i]);
        buffers[n].temporary = 1;
        n++;
    }
    buffers[n].last_buf = 1;
    for (i = 0; i <= n; i++) {
        chain[i].buf = &buffers[i];
        chain[i].next = i < n ? &chain[i + 1] : NULL;
    }
    body.bufs = &chain[0];
}

static ngx_int_t run(void) { return ngx_http_modsecurity_access_handler(&request); }

/* the body was inspected: P2 ran once, after the whole body was appended */
static void inspected(ngx_int_t rc, ngx_int_t expected)
{
    CHECK(rc == expected);
    CHECK(p2_calls == 1 && context.request_body_processed);
    CHECK(!context.request_body_failed);
    CHECK(interventions_before_p2 == 0 && interventions_after_p2 == 1);
    CHECK(run() == NGX_DECLINED && p2_calls == 1);
}

/* a technical failure: 500, P2 never runs, and the failure sticks */
static void failed(ngx_int_t rc)
{
    int appends = append_calls, reads = read_calls;
    CHECK(rc == NGX_HTTP_INTERNAL_SERVER_ERROR);
    CHECK(context.request_body_failed && !context.request_body_processed);
    CHECK(p2_calls == 0 && interventions_before_p2 == 0 && error_logs > 0);
    CHECK(run() == NGX_HTTP_INTERNAL_SERVER_ERROR);
    CHECK(append_calls == appends && read_calls == reads && p2_calls == 0);
}

/* NGINX's view of the file is unchanged, and the scratch buffer is freed */
static void file_untouched(off_t size)
{
    CHECK(body.temp_file == &temp_file && body.bufs == NULL);
    CHECK(temp_file.offset == size && temp_file.file.offset == size);
    CHECK(freed == alloc_calls);
}

int main(int argc, char **argv)
{
    const char *name;
    int parameter;

    CHECK(argc == 3);
    name = argv[1];
    parameter = atoi(argv[2]);

    if (strcmp(name, "memory") == 0) {
        setup(MEMORY, 0); memory_body("GOOD ", "BODY");
        inspected(run(), NGX_DECLINED);
        CHECK(append_calls == 2 && kept_len == 9 && memcmp(kept, "GOOD BODY", 9) == 0);

    } else if (strcmp(name, "memory-deny") == 0) {
        setup(MEMORY, 0); memory_body("VERY ", "BAD BODY"); p2_status = 418;
        inspected(run(), 418);

    } else if (strcmp(name, "memory-invalid") == 0) {
        setup(MEMORY, 0); memory_body("GOOD", NULL);
        if (parameter == 0) chain[0].buf = NULL;
        if (parameter == 1) { buffers[0].pos += 2; buffers[0].last = buffers[0].pos - 1; }
        if (parameter == 2) buffers[0].pos = NULL;
        failed(run());
        CHECK(append_calls == 0);

    } else if (strcmp(name, "append-result") == 0) {
        setup(parameter < 10 ? MEMORY : FILE_BODY, 3 * CHUNK);
        if (parameter < 10) memory_body("GOOD ", "BODY");
        forced_append_at = 2; forced_append_result = parameter % 10 - 1;
        if (forced_append_result == 0 || forced_append_result == 1) {
            inspected(run(), NGX_DECLINED);
        } else {
            failed(run());
            CHECK(append_calls == 2);
        }
        if (parameter >= 10) file_untouched(3 * CHUNK);

    } else if (strcmp(name, "partial") == 0) {
        /* the kept prefix is inspected, the rest is not, no error */
        setup(parameter ? FILE_BODY : MEMORY, 2 * CHUNK + 10);
        if (!parameter) memory_body("0123456789", "BAD BODY");
        limit = parameter ? CHUNK + 5 : 10; p2_status = 418;
        if (parameter) memcpy(disk + CHUNK + 5, "BAD", 3);
        inspected(run(), NGX_DECLINED);
        CHECK(kept_len == limit);
        if (parameter) {
            CHECK(memcmp(kept, disk, limit) == 0);
            file_untouched(2 * CHUNK + 10);
        }

    } else if (strcmp(name, "partial-deny") == 0) {
        setup(parameter ? FILE_BODY : MEMORY, 2 * CHUNK + 10);
        if (!parameter) memory_body("01BAD6789", "tail");
        limit = parameter ? CHUNK + 5 : 10; p2_status = 418;
        if (parameter) memcpy(disk + CHUNK, "BAD", 3);
        inspected(run(), 418);

    } else if (strcmp(name, "reject") == 0) {
        /* Reject: the intervention waits in the transaction until after P2 */
        setup(parameter ? FILE_BODY : MEMORY, 3 * CHUNK + 1);
        if (!parameter) memory_body("0123456789", "abcdef");
        limit = parameter ? CHUNK + 5 : 12; reject_limit = 1;
        inspected(run(), 403);
        if (parameter) {
            CHECK(append_calls == 4 && read_calls == 4);
            file_untouched(3 * CHUNK + 1);
        }

    } else if (strcmp(name, "reject-satisfy-any") == 0) {
        setup(FILE_BODY, 2 * CHUNK); limit = 10; reject_limit = 1;
        core.satisfy = NGX_HTTP_SATISFY_ANY;
        inspected(run(), NGX_DONE);
        CHECK(finalized_status == 403);

    } else if (strcmp(name, "file") == 0) {
        /* bounded reads at increasing offsets: the engine gets the file */
        off_t size = (off_t) parameter;
        setup(FILE_BODY, size);
        inspected(run(), NGX_DECLINED);
        CHECK(kept_len == (size_t) size && memcmp(kept, disk, kept_len) == 0);
        CHECK(read_calls == (int) ((size + CHUNK - 1) / CHUNK));
        CHECK(append_calls == read_calls && largest_read <= CHUNK);
        CHECK(fd_info_calls == (size > 0 ? 2 : 1));
        CHECK(alloc_calls == (size > 0 ? 1 : 0));
        file_untouched(size);

    } else if (strcmp(name, "no-body") == 0) {
        setup(parameter ? MEMORY : NO_BODY, 0);
        inspected(run(), NGX_DECLINED);
        CHECK(append_calls == 0);

    } else if (strcmp(name, "file-error") == 0) {
        setup(FILE_BODY, 3 * CHUNK);
        switch (parameter) {
        case 0: temp_file.file.fd = NGX_INVALID_FILE; break;
        case 1: temp_file.offset = -1; break;
        case 2: fd_info_fails = 1; break;
        case 3: not_regular = 1; break;
        case 4: disk_size = 3 * CHUNK - 1; break;
        case 5: short_read_at = 2; break;
        case 6: fail_read_at = 3; break;
        case 7: shrink_after_read = 1; break;
        case 8: fail_alloc = 1; break;
        default: return 2;
        }
        failed(run());
        CHECK(alloc_calls == (parameter >= 5 ? 1 : 0));
        CHECK(freed == (parameter >= 5 && parameter != 8 ? 1 : 0));
        if (parameter >= 5) CHECK(temp_file.file.offset == 3 * CHUNK);
        if (parameter == 5 || parameter == 6) CHECK(append_calls == read_calls - 1);

    } else {
        return 2;
    }

    return 0;
}
"""


def program(access: str) -> str:
    # the production chunk size: the doubles fail on reads above CHUNK
    chunk = re.search(r"^#define NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE .*$",
                      access, re.MULTILINE)
    if chunk is None:
        raise AssertionError("NGX_HTTP_MODSECURITY_BODY_CHUNK_SIZE not found")
    helpers = "\n" + chunk.group(0) + "\n"
    for result, name in (
        ("static ngx_int_t", "ngx_http_modsecurity_append_request_chunk"),
        ("static ngx_int_t", "ngx_http_modsecurity_append_request_body"),
        ("static ngx_int_t", "ngx_http_modsecurity_check_request_body_file"),
        ("static ngx_int_t", "ngx_http_modsecurity_inspect_request_body_file"),
        ("static ngx_int_t", "ngx_http_modsecurity_access_intervention"),
        ("ngx_int_t", "ngx_http_modsecurity_access_handler"),
    ):
        helpers += "\n" + result + "\n" + function_definition(access, name)
    return PREAMBLE + helpers + CASES


class RequestBodyRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shlex.split(os.environ.get("CC", "cc"))
        if not compiler or shutil.which(compiler[0]) is None:
            raise RuntimeError("set CC to a GCC- or Clang-compatible C compiler")
        workspace = tempfile.TemporaryDirectory(prefix="modsec-request-body-")
        cls.addClassCleanup(workspace.cleanup)
        directory = Path(workspace.name)
        source = directory / "request_body.c"
        source.write_text(program(
            (ROOT / "src/ngx_http_modsecurity_access.c").read_text(encoding="utf-8")
        ), encoding="utf-8")
        cls.binary = directory / "request_body"
        build = subprocess.run(
            [*compiler, "-std=c17", "-Wall", "-Wextra", "-Werror",
             str(source), "-o", str(cls.binary)],
            capture_output=True, text=True, check=False, timeout=60,
        )
        if build.returncode:
            raise AssertionError(f"build failed:\n{build.stderr}")

    def case(self, name: str, parameter: int = 0) -> None:
        result = subprocess.run(
            [str(self.binary), name, str(parameter)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_memory_body_is_appended_whole_before_the_request_body_phase(self):
        self.case("memory")

    def test_memory_body_rule_decision_is_enforced(self):
        self.case("memory-deny")

    def test_invalid_memory_buffers_fail_closed(self):
        for invalid in range(3):
            with self.subTest(invalid=invalid):
                self.case("memory-invalid", invalid)

    def test_append_results_other_than_zero_and_one_fail_closed(self):
        # memory (0..3) and file (10..13) bodies, results -1, 0, 1 and 2
        for parameter in (0, 1, 2, 3, 10, 11, 12, 13):
            with self.subTest(parameter=parameter):
                self.case("append-result", parameter)

    def test_process_partial_is_not_a_failure(self):
        for in_file in (0, 1):
            with self.subTest(in_file=in_file):
                self.case("partial", in_file)
                self.case("partial-deny", in_file)

    def test_reject_is_dispatched_after_the_request_body_phase(self):
        for in_file in (0, 1):
            with self.subTest(in_file=in_file):
                self.case("reject", in_file)

    def test_reject_is_enforced_under_satisfy_any(self):
        self.case("reject-satisfy-any")

    def test_file_is_read_in_bounded_chunks(self):
        for size in (0, 1, 32767, 32768, 32769, 65536, 3 * 32768 + 1):
            with self.subTest(size=size):
                self.case("file", size)

    def test_missing_and_empty_bodies_still_run_the_request_body_phase(self):
        for in_memory in (0, 1):
            with self.subTest(in_memory=in_memory):
                self.case("no-body", in_memory)

    def test_file_errors_fail_closed(self):
        for failure in range(9):
            with self.subTest(failure=failure):
                self.case("file-error", failure)


if __name__ == "__main__":
    unittest.main()
