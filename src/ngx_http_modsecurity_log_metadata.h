/*
 * ModSecurity-nginx metadata helpers.
 * Adapted from common/src/rule_id.c and common/src/json_escape.c in
 * Easton97-Jens/ModSecurity-conector at
 * d420a12c4155a4bc2b9ea63ee5cef633085705e7.
 * Uses bounded NGINX strings and pools without a Common runtime dependency.
 */

#ifndef NGX_HTTP_MODSECURITY_LOG_METADATA_H
#define NGX_HTTP_MODSECURITY_LOG_METADATA_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    ngx_str_t input;
    size_t position;
} ngx_http_modsecurity_metadata_cursor_t;

static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_field_starts(ngx_str_t input, size_t position,
    const char *name)
{
    size_t length = strlen(name);

    return position <= input.len && input.len - position >= length + 4 &&
        input.data[position] == '[' &&
        memcmp(input.data + position + 1, name, length) == 0 &&
        input.data[position + length + 1] == ' ' &&
        input.data[position + length + 2] == '"';
}

static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_hex_digit(u_char value)
{
    return (value >= '0' && value <= '9') ||
        (value >= 'a' && value <= 'f') ||
        (value >= 'A' && value <= 'F');
}

/* Engine toHexIfNeeded() uses literal \xHH sequences in the escaped fields.
 * Do not decode them while locating delimiters. Raw fields may contain quotes
 * without a following ']', but the complete ordered record must still match. */
static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_parse_field(
    ngx_http_modsecurity_metadata_cursor_t *cursor, const char *name,
    ngx_int_t escaped, ngx_int_t decimal, ngx_str_t *value)
{
    size_t start, position, remaining;
    u_char character;

    if (!ngx_http_modsecurity_metadata_field_starts(cursor->input,
            cursor->position, name)) {
        return 0;
    }
    start = cursor->position + strlen(name) + 3;
    position = start;
    while (position < cursor->input.len) {
        remaining = cursor->input.len - position;
        character = cursor->input.data[position];
        if (character == '"' && remaining >= 2 &&
            cursor->input.data[position + 1] == ']') {
            if (decimal && position == start) {
                return 0;
            }
            if (value != NULL) {
                value->data = cursor->input.data + start;
                value->len = position - start;
            }
            cursor->position = position + 2;
            return 1;
        }
        if (character < 0x20 || character > 0x7e ||
            (decimal && (character < '0' || character > '9'))) {
            return 0;
        }
        if (escaped && character == '\\') {
            if (remaining < 4 || cursor->input.data[position + 1] != 'x' ||
                !ngx_http_modsecurity_metadata_hex_digit(
                    cursor->input.data[position + 2]) ||
                !ngx_http_modsecurity_metadata_hex_digit(
                    cursor->input.data[position + 3])) {
                return 0;
            }
            position += 4;
        } else {
            if (escaped && character == '"') {
                return 0;
            }
            position++;
        }
    }
    return 0;
}

static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_next_field(
    ngx_http_modsecurity_metadata_cursor_t *cursor, const char *name,
    ngx_int_t escaped, ngx_int_t decimal)
{
    if (cursor->position >= cursor->input.len ||
        cursor->input.data[cursor->position] != ' ') {
        return 0;
    }
    cursor->position++;
    return ngx_http_modsecurity_metadata_parse_field(cursor, name, escaped,
        decimal, NULL);
}

static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_parse_record(
    ngx_http_modsecurity_metadata_cursor_t *cursor, ngx_str_t *rule_id)
{
    if (!ngx_http_modsecurity_metadata_parse_field(cursor, "file", 0, 0, NULL) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "line", 0, 1) ||
        cursor->position >= cursor->input.len ||
        cursor->input.data[cursor->position] != ' ') {
        return 0;
    }
    cursor->position++;
    if (!ngx_http_modsecurity_metadata_parse_field(cursor, "id", 0, 1, rule_id) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "rev", 1, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "msg", 0, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "data", 1, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "severity", 0, 1) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "ver", 1, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "maturity", 0, 1) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "accuracy", 0, 1)) {
        return 0;
    }
    while (cursor->position < cursor->input.len &&
        cursor->input.data[cursor->position] == ' ' &&
        ngx_http_modsecurity_metadata_field_starts(cursor->input,
            cursor->position + 1, "tag")) {
        if (!ngx_http_modsecurity_metadata_next_field(cursor, "tag", 1, 0)) {
            return 0;
        }
    }
    if (!ngx_http_modsecurity_metadata_next_field(cursor, "hostname", 0, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "uri", 0, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "unique_id", 0, 0) ||
        !ngx_http_modsecurity_metadata_next_field(cursor, "ref", 0, 0)) {
        return 0;
    }
    if (cursor->position < cursor->input.len &&
        cursor->input.data[cursor->position] == ' ' &&
        (!ngx_http_modsecurity_metadata_next_field(cursor, "hostname", 0, 0) ||
         !ngx_http_modsecurity_metadata_next_field(cursor, "uri", 0, 0) ||
         !ngx_http_modsecurity_metadata_next_field(cursor, "unique_id", 0, 0))) {
        return 0;
    }
    return cursor->position == cursor->input.len;
}

/* Return 1 for one complete, unambiguous native record, 0 for no record, and
 * -1 for malformed/ambiguous framing. The successful ID is a bounded view
 * into input; input need not be NUL-terminated and no allocation is made.
 * Bare ID snippets and the untrusted matched-data prefix are never metadata. */
static ngx_inline ngx_int_t
ngx_http_modsecurity_parse_rule_metadata(ngx_str_t input, ngx_str_t *rule_id)
{
    static const char marker[] = "[file \"";
    ngx_http_modsecurity_metadata_cursor_t cursor;
    ngx_str_t candidate;
    size_t position, first;

    if (rule_id == NULL) {
        return -1;
    }
    rule_id->data = (u_char *) "";
    rule_id->len = 0;
    if (input.data == NULL) {
        return input.len == 0 ? 0 : -1;
    }
    if (input.len < sizeof(marker) - 1) {
        return 0;
    }
    first = input.len;
    for (position = 0; position <= input.len - (sizeof(marker) - 1);
         position++) {
        if (memcmp(input.data + position, marker, sizeof(marker) - 1) != 0) {
            continue;
        }
        /* Reject extra candidates even if only one suffix would parse: a raw
         * URI or reflected prefix can contain a forged complete record. */
        if (first != input.len ||
            (position != 0 && input.data[position - 1] != ' ')) {
            return -1;
        }
        first = position;
    }
    if (first == input.len) {
        return 0;
    }
    cursor.input = input;
    cursor.position = first;
    if (!ngx_http_modsecurity_metadata_parse_record(&cursor, &candidate)) {
        return -1;
    }
    *rule_id = candidate;
    return 1;
}

static ngx_inline void
ngx_http_modsecurity_extract_rule_id(ngx_pool_t *pool, ngx_str_t *intervention,
    ngx_str_t *rule_id)
{
    ngx_str_t candidate;

    rule_id->data = (u_char *) "";
    rule_id->len = 0;
    if (intervention == NULL ||
        ngx_http_modsecurity_parse_rule_metadata(*intervention, &candidate) != 1) {
        return;
    }
    rule_id->data = ngx_pnalloc(pool, candidate.len + 1);
    if (rule_id->data == NULL) {
        return;
    }
    memcpy(rule_id->data, candidate.data, candidate.len);
    rule_id->data[candidate.len] = '\0';
    rule_id->len = candidate.len;
}

static ngx_inline ngx_str_t
ngx_http_modsecurity_sanitize_intervention(ngx_pool_t *pool, ngx_str_t input)
{
    static ngx_str_t redacted = {
        sizeof("redacted") - 1, (u_char *) "redacted"
    };
    static ngx_str_t summary = {
        sizeof("id:present msg:present op:-") - 1,
        (u_char *) "id:present msg:present op:-"
    };
    ngx_str_t rule_id;

    (void) pool;
    /* A complete record supplies id/msg fields, but no trusted operator
     * field. Never derive presence flags from matched data or message prose.
     * Static complete strings avoid allocation failure and truncation. */
    return ngx_http_modsecurity_parse_rule_metadata(input, &rule_id) == 1
        ? summary : redacted;
}

static ngx_inline ngx_int_t
ngx_http_modsecurity_metadata_utf8_continuation(u_char value)
{
    return value >= 0x80 && value <= 0xbf;
}

static ngx_inline size_t
ngx_http_modsecurity_metadata_utf8_size(const u_char *input, size_t remaining)
{
    u_char first = input[0];

    if (first >= 0xc2 && first <= 0xdf) {
        return remaining >= 2 &&
            ngx_http_modsecurity_metadata_utf8_continuation(input[1]) ? 2 : 0;
    }
    if (first >= 0xe0 && first <= 0xef) {
        if (remaining < 3 ||
            !ngx_http_modsecurity_metadata_utf8_continuation(input[1]) ||
            !ngx_http_modsecurity_metadata_utf8_continuation(input[2]) ||
            (first == 0xe0 && input[1] < 0xa0) ||
            (first == 0xed && input[1] > 0x9f)) {
            return 0;
        }
        return 3;
    }
    if (first >= 0xf0 && first <= 0xf4) {
        if (remaining < 4 ||
            !ngx_http_modsecurity_metadata_utf8_continuation(input[1]) ||
            !ngx_http_modsecurity_metadata_utf8_continuation(input[2]) ||
            !ngx_http_modsecurity_metadata_utf8_continuation(input[3]) ||
            (first == 0xf0 && input[1] < 0x90) ||
            (first == 0xf4 && input[1] > 0x8f)) {
            return 0;
        }
        return 4;
    }
    return 0;
}

/* Preserve valid UTF-8 as-is. JSON controls and invalid UTF-8 bytes are
 * represented as \u00xx; each invalid byte retains its unsigned byte value.
 * Success is NUL-terminated with an explicit length. Allocation/size failure
 * returns data == NULL, len == 0 so the caller can diagnose the optional sink
 * failure without confusing it with a valid empty field. */
static ngx_inline void
ngx_http_modsecurity_json_escape(ngx_pool_t *pool, ngx_str_t *src, ngx_str_t *dst)
{
    static const u_char hex[] = "0123456789abcdef";
    size_t position, size, consumed, width;
    u_char character, *output;

    dst->data = NULL;
    dst->len = 0;
    if (src == NULL || src->len == 0) {
        dst->data = (u_char *) "";
        return;
    }
    if (src->data == NULL || src->len == SIZE_MAX) {
        return;
    }
    size = 0;
    for (position = 0; position < src->len; position += consumed) {
        character = src->data[position];
        consumed = 1;
        if (character < 0x20) {
            width = 6;
        } else if (character == '"' || character == '\\') {
            width = 2;
        } else if (character < 0x80) {
            width = 1;
        } else {
            consumed = ngx_http_modsecurity_metadata_utf8_size(
                src->data + position, src->len - position);
            if (consumed == 0) {
                consumed = 1;
                width = 6;
            } else {
                width = consumed;
            }
        }
        if (width > SIZE_MAX - 1 - size) {
            return;
        }
        size += width;
    }
    dst->data = ngx_pnalloc(pool, size + 1);
    if (dst->data == NULL) {
        return;
    }
    output = dst->data;
    for (position = 0; position < src->len; position += consumed) {
        character = src->data[position];
        consumed = 1;
        if (character == '"' || character == '\\') {
            *output++ = '\\';
            *output++ = character;
        } else if (character < 0x20 ||
            (character >= 0x80 &&
             (consumed = ngx_http_modsecurity_metadata_utf8_size(
                src->data + position, src->len - position)) == 0)) {
            *output++ = '\\';
            *output++ = 'u';
            *output++ = '0';
            *output++ = '0';
            *output++ = hex[character >> 4];
            *output++ = hex[character & 0x0f];
            consumed = 1;
        } else {
            memcpy(output, src->data + position, consumed);
            output += consumed;
        }
    }
    *output = '\0';
    dst->len = size;
}

#endif /* NGX_HTTP_MODSECURITY_LOG_METADATA_H */
