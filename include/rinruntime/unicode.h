/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_UNICODE_H
#define RINRUNTIME_UNICODE_H

#include <stddef.h>
#include <stdint.h>

static inline int rinruntime_utf8_decode(const char* value, size_t size,
                                         size_t offset, uint32_t* codepoint,
                                         size_t* width)
{
    unsigned char first;
    uint32_t cp;
    size_t count;
    size_t index;
    if (value == NULL || codepoint == NULL || width == NULL || offset >= size)
        return 0;
    first = (unsigned char)value[offset];
    if (first <= 0x7fu) { cp = first; count = 1u; }
    else if (first >= 0xc2u && first <= 0xdfu) { cp = first & 0x1fu; count = 2u; }
    else if (first >= 0xe0u && first <= 0xefu) { cp = first & 0x0fu; count = 3u; }
    else if (first >= 0xf0u && first <= 0xf4u) { cp = first & 0x07u; count = 4u; }
    else return 0;
    if (offset > size - count) return 0;
    for (index = 1u; index < count; ++index) {
        unsigned char byte = (unsigned char)value[offset + index];
        if ((byte & 0xc0u) != 0x80u) return 0;
        cp = (cp << 6) | (byte & 0x3fu);
    }
    if ((count == 3u && cp < 0x800u) || (count == 4u && cp < 0x10000u) ||
        cp > 0x10ffffu || (cp >= 0xd800u && cp <= 0xdfffu)) return 0;
    if ((first == 0xe0u && (unsigned char)value[offset + 1u] < 0xa0u) ||
        (first == 0xedu && (unsigned char)value[offset + 1u] >= 0xa0u) ||
        (first == 0xf0u && (unsigned char)value[offset + 1u] < 0x90u) ||
        (first == 0xf4u && (unsigned char)value[offset + 1u] >= 0x90u)) return 0;
    *codepoint = cp;
    *width = count;
    return 1;
}

static inline int rinruntime_utf8_validate(const char* value, size_t size,
                                           size_t* valid_prefix)
{
    size_t offset = 0u;
    if (value == NULL && size != 0u) { if (valid_prefix) *valid_prefix = 0u; return 0; }
    while (offset < size) {
        size_t width = 0u;
        uint32_t codepoint = 0u;
        if (!rinruntime_utf8_decode(value, size, offset, &codepoint, &width)) {
            if (valid_prefix) *valid_prefix = offset;
            return 0;
        }
        offset += width;
    }
    if (valid_prefix) *valid_prefix = offset;
    return 1;
}

#ifdef __cplusplus
extern "C" {
#endif

/* Product Unicode ownership lives in libunicode.  RinRuntime exposes these
 * bounded forwarding entry points so its C++ text model uses the same
 * grapheme boundary contract on every host, including Windows builds where
 * Aquamarine is not linked. */
size_t rinruntime_unicode_grapheme_next(const char* value, size_t size,
                                        size_t offset);
size_t rinruntime_unicode_grapheme_prev(const char* value, size_t size,
                                        size_t offset);

/* Public runtime forwarding for LibUnicode's bounded locale formatter.  The
 * model is caller-owned and uses the proleptic Gregorian calendar, year
 * 0..9999, weekday 0..6 with Sunday=0.  conversion accepts c/x/X and the
 * selected locale's documented strftime subset; failures clear output and
 * return zero.  Locale data and timezone ownership remain outside Runtime. */
typedef struct RinRuntimeUnicodeDateTime {
    int32_t year;
    int32_t month;
    int32_t day;
    int32_t weekday;
    int32_t hour;
    int32_t minute;
    int32_t second;
} RinRuntimeUnicodeDateTime;

size_t rinruntime_unicode_format_datetime(
    char* output, size_t output_capacity,
    const RinRuntimeUnicodeDateTime* value, char conversion);

/* Public runtime forwarding for LibUnicode's bounded locale number
 * formatters.  The locale and number strings are borrowed caller inputs;
 * LibUnicode applies its fixed scan bounds and failure-atomic output rules.
 * A null locale selects the current snapshot.  These adapters do not own
 * locale data, currency policy, authentication, or filesystem state. */
size_t rinruntime_unicode_format_integer(
    char* output, size_t output_capacity, int64_t value, const char* locale);

size_t rinruntime_unicode_format_decimal(
    char* output, size_t output_capacity, const char* number,
    const char* locale);

size_t rinruntime_unicode_format_currency(
    char* output, size_t output_capacity, const char* number,
    const char* locale);

#ifdef __cplusplus
}
#endif

static inline int rinruntime_unicode_combining(uint32_t codepoint)
{
    return (codepoint >= 0x0300u && codepoint <= 0x036fu) ||
           (codepoint >= 0x1ab0u && codepoint <= 0x1affu) ||
           (codepoint >= 0x1dc0u && codepoint <= 0x1dffu) ||
           (codepoint >= 0x20d0u && codepoint <= 0x20ffu) ||
           (codepoint >= 0xfe20u && codepoint <= 0xfe2fu);
}

#endif
