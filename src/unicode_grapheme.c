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
