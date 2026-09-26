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

size_t rinruntime_unicode_format_datetime(
    char* output, size_t output_capacity,
    const RinRuntimeUnicodeDateTime* value, char conversion)
{
    return rin_unicode_locale_format_datetime(
        output, output_capacity,
        (const rin_unicode_datetime_t*)value, conversion);
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
