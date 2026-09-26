/* SPDX-License-Identifier: MIT */

#include "../include/rinruntime/unicode.h"
#include "../../libunicode/rin_unicode.h"

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
