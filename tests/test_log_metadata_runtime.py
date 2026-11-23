"""Compile the real standalone metadata/JSON header with small NGINX doubles.

Expected records follow the complete native RuleMessage framing contract.
Python's strict UTF-8 decoder and JSON parser independently check the escaped
output. Invalid input bytes are represented as U+00xx; valid UTF-8 is retained.
These are helper regressions, not native HTTP or audit-log integration tests.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

PREAMBLE = r"""
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u_char;
typedef intptr_t ngx_int_t;
typedef struct { size_t len; u_char *data; } ngx_str_t;
typedef struct { int fail; unsigned calls; } ngx_pool_t;
#define ngx_inline inline

static void *allocations[8];
static unsigned allocation_count;

static void *ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *result;

    pool->calls++;
    if (pool->fail || allocation_count == 8) {
        return NULL;
    }
    result = malloc(size == 0 ? 1 : size);
    if (result != NULL) {
        allocations[allocation_count++] = result;
    }
    return result;
}

#include "ngx_http_modsecurity_log_metadata.h"
"""

PROGRAM = PREAMBLE + r"""
static int from_hex(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

int main(int argc, char **argv)
{
    ngx_pool_t pool = {0, 0};
    ngx_str_t input, output = {5, (u_char *) "stale"};
    u_char *bytes;
    size_t size, index;
    ngx_int_t result;
    int high, low;

    if (argc < 3 || strlen(argv[2]) % 2 != 0) return 2;
    size = strlen(argv[2]) / 2;
    /* Deliberately do not append a NUL: the production API is len-bounded. */
    bytes = malloc(size == 0 ? 1 : size);
    if (bytes == NULL) return 2;
    for (index = 0; index < size; index++) {
        high = from_hex(argv[2][index * 2]);
        low = from_hex(argv[2][index * 2 + 1]);
        if (high < 0 || low < 0) return 2;
        bytes[index] = (u_char) (high * 16 + low);
    }
    input.data = bytes;
    input.len = size;
    if (argc > 3) pool.fail = atoi(argv[3]);
    if (argc > 4) {
        input.len = (size_t) strtoull(argv[4], NULL, 10);
        if (input.len > size) return 2;
    }
    if (strcmp(argv[1], "json-oversize") == 0) input.len = SIZE_MAX;
    if (strcmp(argv[1], "json-null") == 0 ||
        strcmp(argv[1], "metadata-null") == 0) input.data = NULL;

    if (strncmp(argv[1], "json", 4) == 0) {
        ngx_http_modsecurity_json_escape(&pool, &input, &output);
        if (output.data == NULL) {
            if (output.len != 0) return 3;
            fputs("NULL", stdout);
        } else {
            if (output.data[output.len] != '\0') return 3;
            fwrite(output.data, 1, output.len, stdout);
        }
    } else if (strncmp(argv[1], "metadata", 8) == 0) {
        result = ngx_http_modsecurity_parse_rule_metadata(input, &output);
        if (pool.calls != 0) return 3;
        printf("%ld\n", (long) result);
        if (result != 1 && output.len != 0) return 3;
        fwrite(output.data, 1, output.len, stdout);
    } else if (strcmp(argv[1], "extract") == 0) {
        ngx_http_modsecurity_extract_rule_id(&pool, &input, &output);
        /* The copied ID must survive overwriting the temporary input. */
        memset(bytes, 'x', size);
        if (output.data == NULL) {
            if (output.len != 0) return 3;
            fputs("NULL", stdout);
        } else {
            if (output.data[output.len] != '\0') return 3;
            fwrite(output.data, 1, output.len, stdout);
        }
    } else if (strcmp(argv[1], "summary") == 0) {
        output = ngx_http_modsecurity_sanitize_intervention(&pool, input);
        if (pool.calls != 0) return 3;
        fwrite(output.data, 1, output.len, stdout);
    } else {
        return 2;
    }
    free(bytes);
    for (index = 0; index < allocation_count; index++) free(allocations[index]);
    return 0;
}
"""

PARSER_ONLY = PREAMBLE + r"""
int main(void)
{
    ngx_str_t input = {0, (u_char *) ""};
    ngx_str_t output;

    return ngx_http_modsecurity_parse_rule_metadata(input, &output) != 0;
}
"""


def engine_record(*, rule_id: str = "942100", changes=None, tags=(), tail=False) -> bytes:
    fields = [
        ("file", "/rules/response.conf"),
        ("line", "12"),
        ("id", rule_id),
        ("rev", ""),
        ("msg", "response rule"),
        ("data", r"Matched \x22data\x22"),
        ("severity", "2"),
        ("ver", "test"),
        ("maturity", "0"),
        ("accuracy", "0"),
    ]
    fields += [("tag", value) for value in tags]
    fields += [
        ("hostname", "example.invalid"),
        ("uri", "/response"),
        ("unique_id", "transaction"),
        ("ref", "o0,4v0,4"),
    ]
    if changes:
        fields = [(name, changes.get(name, value)) for name, value in fields]
    if tail:
        fields += [("hostname", "example.invalid"), ("uri", "/response"),
                   ("unique_id", "transaction")]
    return " ".join(f'[{name} "{value}"]' for name, value in fields).encode("ascii")


class LogMetadataRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiler = shlex.split(os.environ.get("CC", "cc"))
        if not cls.compiler or shutil.which(cls.compiler[0]) is None:
            raise unittest.SkipTest("A C compiler is needed for metadata helper regressions")
        cls.directory = tempfile.TemporaryDirectory(prefix="modsec-log-metadata-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.binary = Path(cls.directory.name) / "metadata"
        cls.parser_binary = Path(cls.directory.name) / "parser-only"
        for name, source, binary in (
            ("metadata.c", PROGRAM, cls.binary),
            ("parser-only.c", PARSER_ONLY, cls.parser_binary),
        ):
            path = Path(cls.directory.name) / name
            path.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                cls.compiler + ["-std=c99", "-Wall", "-Wextra", "-Werror",
                                "-I", str(ROOT / "src"), str(path), "-o", str(binary)],
                capture_output=True, text=True, check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stdout + completed.stderr)

    def execute(self, operation: str, data: bytes, *, fail=False, length=None) -> bytes:
        command = [str(self.binary), operation, data.hex(), str(int(fail))]
        if length is not None:
            command.append(str(length))
        completed = subprocess.run(command, capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        return completed.stdout

    def parse(self, data: bytes, **kwargs):
        result, rule_id = self.execute("metadata", data, **kwargs).split(b"\n", 1)
        return int(result), rule_id

    def escaped(self, data: bytes, **kwargs):
        output = self.execute("json", data, **kwargs)
        text = output.decode("utf-8", "strict")
        return output, json.loads('"' + text + '"')

    def test_header_can_be_included_for_only_the_parser_without_unused_warnings(self):
        completed = subprocess.run([str(self.parser_binary)], capture_output=True, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_complete_record_and_optional_error_log_tail(self):
        for tail in (False, True):
            with self.subTest(tail=tail):
                self.assertEqual(self.parse(engine_record(tail=tail)), (1, b"942100"))

    def test_decimal_ids_are_preserved_without_integer_conversion(self):
        value = "000" + "9" * 100
        self.assertEqual(self.parse(engine_record(rule_id=value)), (1, value.encode("ascii")))

    def test_reflected_bare_id_before_actual_metadata_does_not_win(self):
        data = b'Matched data: id "1" Operator msg "reflected" ' + engine_record()
        self.assertEqual(self.parse(data), (1, b"942100"))
        self.assertEqual(self.execute("summary", data), b"id:present msg:present op:-")

    def test_bare_presence_snippets_remain_redacted(self):
        for data in (b'id "1"', b'Operator', b'msg "body"', b'id "1" Operator'):
            with self.subTest(data=data):
                self.assertEqual(self.parse(data), (0, b""))
                self.assertEqual(self.execute("summary", data), b"redacted")

    def test_forged_or_duplicate_records_are_unknown(self):
        real = engine_record()
        for data in (
            engine_record(rule_id="1") + b" " + real,
            b'[file "malformed" ' + real,
            engine_record(changes={"uri": '/[file "forged'}),
            b"prefix" + real,
        ):
            with self.subTest(data=data):
                self.assertEqual(self.parse(data), (-1, b""))
                self.assertEqual(self.execute("summary", data), b"redacted")

    def test_complete_order_and_terminal_framing_are_required(self):
        record = engine_record()
        invalid = (
            record[:-1],
            record + b" trailing",
            record.replace(b'[rev ""] ', b""),
            record.replace(b'[line "12"] [id "942100"]', b'[id "942100"] [line "12"]'),
            record + b' [hostname "example.invalid"]',
        )
        for data in invalid:
            with self.subTest(data=data):
                self.assertEqual(self.parse(data), (-1, b""))

    def test_native_numeric_fields_must_be_nonempty_decimal(self):
        for field in ("line", "id", "severity", "maturity", "accuracy"):
            for value in ("", "-1", "1x"):
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.parse(engine_record(changes={field: value})), (-1, b""))

    def test_raw_quotes_and_hex_escaped_fields_follow_engine_framing(self):
        record = engine_record(changes={"file": '/rules/quoted"name.conf'},
                               tags=(r"attack-\x22tag\x22", "second"))
        self.assertEqual(self.parse(record), (1, b"942100"))
        for value in (r"bad\z", r"bad\x2", r"bad\xGG", 'raw"quote'):
            with self.subTest(value=value):
                self.assertEqual(self.parse(engine_record(changes={"data": value})), (-1, b""))

    def test_metadata_is_length_bounded_and_rejects_embedded_controls(self):
        record = engine_record()
        self.assertEqual(self.parse(record + b' [file "outside"]', length=len(record)),
                         (1, b"942100"))
        for character in (b"\0", b"\n", b"\x80"):
            data = record.replace(b"response rule", b"response" + character + b"rule")
            self.assertEqual(self.parse(data), (-1, b""))
        self.assertEqual(self.execute("metadata-null", b""), b"0\n")
        self.assertEqual(self.execute("metadata-null", b"x"), b"-1\n")

    def test_extracted_id_is_an_owned_nul_terminated_copy(self):
        self.assertEqual(self.execute("extract", engine_record()), b"942100")
        self.assertEqual(self.execute("extract", b'id "1"'), b"")
        self.assertEqual(self.execute("extract", engine_record(), fail=True), b"NULL")

    def test_summary_is_complete_redacted_and_needs_no_allocation(self):
        record = engine_record(changes={"msg": "Operator private matched-data"})
        expected = b"id:present msg:present op:-"
        self.assertEqual(self.execute("summary", record), expected)
        self.assertEqual(self.execute("summary", record, fail=True), expected)
        self.assertNotIn(b"private", self.execute("summary", record))

    def test_all_bytes_produce_strict_json_without_losing_controls(self):
        data = bytes(range(256))
        escaped, value = self.escaped(data)
        self.assertEqual(value, "".join(chr(character) for character in range(256)))
        self.assertIn(b"\\u0000", escaped)
        self.assertIn(b"\\u001f", escaped)
        self.assertIn(b"\\u00ff", escaped)

    def test_valid_utf8_is_preserved_byte_for_byte(self):
        text = "Grüße 日本語 😀\u2028\u2029"
        data = text.encode("utf-8")
        escaped, value = self.escaped(data)
        self.assertEqual(escaped, data)
        self.assertEqual(value, text)

    def test_valid_utf8_boundary_sequences_are_retained(self):
        data = b"\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf"
        escaped, value = self.escaped(data)
        self.assertEqual(escaped, data)
        self.assertEqual(value, data.decode("utf-8", "strict"))

    def test_invalid_and_truncated_utf8_bytes_are_explicitly_escaped(self):
        invalid = (
            b"\x80\xbf", b"\xc0\xaf", b"\xc1\xbf", b"\xe0\x80\xaf",
            b"\xed\xa0\x80", b"\xf0\x80\x80\x80", b"\xf4\x90\x80\x80",
            b"\xf5\x80\x80\x80", b"\xff", b"\xc2", b"\xe1\x80", b"\xf1\x80\x80",
        )
        for data in invalid:
            with self.subTest(data=data):
                escaped, value = self.escaped(data)
                self.assertTrue(escaped.isascii())
                self.assertEqual(value, "".join(chr(character) for character in data))

    def test_json_respects_declared_length(self):
        self.assertEqual(self.escaped(b"ok\xff", length=2), (b"ok", "ok"))

    def test_json_allocation_failure_is_distinct_from_valid_empty(self):
        self.assertEqual(self.execute("json", b"ordinary", fail=True), b"NULL")
        self.assertEqual(self.execute("json", b"", fail=True), b"")
        self.assertEqual(self.execute("json-null", b""), b"")
        self.assertEqual(self.execute("json-null", b"x"), b"NULL")
        self.assertEqual(self.execute("json-oversize", b"x"), b"NULL")


if __name__ == "__main__":
    unittest.main()
