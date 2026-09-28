/* SPDX-License-Identifier: MIT */

#include "../include/rinruntime/unicode.h"
#include "../../libunicode/rin_unicode.h"

RinRuntimeUnicodeGraphemeProperty rinruntime_unicode_grapheme_property(
    uint32_t codepoint)
{
    return (RinRuntimeUnicodeGraphemeProperty)
        rin_unicode_grapheme_property(codepoint);
}

int rinruntime_unicode_is_extended_pictographic(uint32_t codepoint)
{
    return rin_unicode_is_extended_pictographic(codepoint);
}

size_t rinruntime_unicode_grapheme_next(const char* value, size_t size,
                                        size_t offset)
{
    return rin_unicode_grapheme_next(value, size, offset);
}

size_t rinruntime_unicode_grapheme_prev(const char* value, size_t size,
                                        size_t offset)
{
    return rin_unicode_grapheme_prev(value, size, offset);
}

int rinruntime_unicode_line_break_opportunity(const char* value, size_t size,
                                              size_t offset)
{
    return rin_unicode_line_break_opportunity(value, size, offset);
}

size_t rinruntime_unicode_line_break_next(const char* value, size_t size,
                                          size_t offset)
{
    return rin_unicode_line_break_next(value, size, offset);
}

size_t rinruntime_unicode_casefold_full(uint32_t codepoint,
                                        uint32_t output[3])
{
    return rin_unicode_casefold_full(codepoint, output);
}

size_t rinruntime_unicode_casefold_locale(uint32_t codepoint,
                                          const char* locale,
                                          uint32_t output[3])
{
    return rin_unicode_casefold_locale(codepoint, locale, output);
}

size_t rinruntime_unicode_normalize_utf8(
    char* output, size_t output_capacity, const char* input, int form)
{
    return rin_unicode_normalize_utf8(output, output_capacity, input, form);
}

size_t rinruntime_unicode_normalize_utf32(
    uint32_t* output, size_t output_capacity, const uint32_t* input,
    size_t input_length, int form)
{
    return rin_unicode_normalize_utf32(output, output_capacity, input,
                                       input_length, form);
}

int rinruntime_unicode_compare_utf8(const char* left, const char* right)
{
    return rin_unicode_compare_utf8(left, right);
}

int rinruntime_unicode_compare_utf32(const uint32_t* left,
                                     const uint32_t* right)
{
    return rin_unicode_compare_utf32(left, right);
}

int rinruntime_unicode_locale_canonicalize(const char* locale, char* output,
                                           size_t output_capacity)
{
    return rin_unicode_locale_canonicalize(locale, output, output_capacity);
}

size_t rinruntime_unicode_format_datetime(
    char* output, size_t output_capacity,
    const RinRuntimeUnicodeDateTime* value, char conversion)
{
    return rin_unicode_locale_format_datetime(
        output, output_capacity,
        (const rin_unicode_datetime_t*)value, conversion);
}

size_t rinruntime_unicode_format_datetime_pattern(
    char* output, size_t output_capacity,
    const RinRuntimeUnicodeDateTime* value, const char* pattern)
{
    return rin_unicode_locale_format_datetime_pattern(
        output, output_capacity,
        (const rin_unicode_datetime_t*)value, pattern);
}

size_t rinruntime_unicode_format_integer(
    char* output, size_t output_capacity, int64_t value, const char* locale)
{
    return rin_unicode_locale_format_integer(output, output_capacity, value,
                                             locale);
}

size_t rinruntime_unicode_format_decimal(
    char* output, size_t output_capacity, const char* number,
    const char* locale)
{
    return rin_unicode_locale_format_decimal(output, output_capacity, number,
                                             locale);
}

size_t rinruntime_unicode_format_currency(
    char* output, size_t output_capacity, const char* number,
    const char* locale)
{
    return rin_unicode_locale_format_currency(output, output_capacity, number,
                                              locale);
}
