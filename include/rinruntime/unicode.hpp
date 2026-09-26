/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_UNICODE_HPP
#define RINRUNTIME_UNICODE_HPP

#include "unicode.h"
#include <cstdint>
#include <string>

namespace RinRuntime {

inline bool utf8GraphemeExtend(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_EXTEND;
}

inline bool utf8GraphemeSpacingMark(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_SPACING_MARK;
}

inline bool utf8GraphemePrepend(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_PREPEND;
}

inline bool utf8GraphemeControl(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_CONTROL;
}

inline bool utf8GraphemeRegionalIndicator(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_RI;
}

inline bool utf8GraphemeExtendedPictographic(std::uint32_t codepoint)
{
    return rinruntime_unicode_is_extended_pictographic(codepoint) != 0;
}

inline bool utf8GraphemeHangulL(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_L;
}

inline bool utf8GraphemeHangulV(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_V;
}

inline bool utf8GraphemeHangulT(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_T;
}

inline bool utf8GraphemeHangulLV(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_LV;
}

inline bool utf8GraphemeHangulLVT(std::uint32_t codepoint)
{
    return rinruntime_unicode_grapheme_property(codepoint) ==
           RINRUNTIME_UNICODE_GRAPHEME_LVT;
}

inline bool utf8GraphemeHangulBreakless(std::uint32_t previous,
                                        std::uint32_t following)
{
    return (utf8GraphemeHangulL(previous) &&
            (utf8GraphemeHangulL(following) ||
             utf8GraphemeHangulV(following) ||
             utf8GraphemeHangulLV(following) ||
             utf8GraphemeHangulLVT(following))) ||
           ((utf8GraphemeHangulLV(previous) ||
             utf8GraphemeHangulV(previous)) &&
            (utf8GraphemeHangulV(following) ||
             utf8GraphemeHangulT(following))) ||
           ((utf8GraphemeHangulLVT(previous) ||
             utf8GraphemeHangulT(previous)) &&
            utf8GraphemeHangulT(following));
}

inline std::size_t utf8GraphemeNext(const std::string& value,
                                    std::size_t offset)
{
    return rinruntime_unicode_grapheme_next(value.data(), value.size(),
                                            offset);
}

inline std::size_t utf8GraphemePrev(const std::string& value,
                                    std::size_t offset)
{
    return rinruntime_unicode_grapheme_prev(value.data(), value.size(),
                                            offset);
}

inline bool utf8Valid(const char* value, std::size_t size)
{
    std::size_t valid = 0u;
    return rinruntime_utf8_validate(value, size, &valid) && valid == size;
}

inline bool utf8Encode(char* destination, std::size_t capacity,
                       std::uint32_t codepoint, std::size_t* written)
{
    std::size_t width;
    if (written != nullptr) *written = 0u;
    if (!destination || !written || codepoint > 0x10ffffu ||
        (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return false;
    if (codepoint <= 0x7fu) width = 1u;
    else if (codepoint <= 0x7ffu) width = 2u;
    else if (codepoint <= 0xffffu) width = 3u;
    else width = 4u;
    if (capacity < width) return false;
    if (width == 1u) destination[0] = (char)codepoint;
    else if (width == 2u) { destination[0] = (char)(0xc0u | (codepoint >> 6)); destination[1] = (char)(0x80u | (codepoint & 0x3fu)); }
    else if (width == 3u) { destination[0] = (char)(0xe0u | (codepoint >> 12)); destination[1] = (char)(0x80u | ((codepoint >> 6) & 0x3fu)); destination[2] = (char)(0x80u | (codepoint & 0x3fu)); }
    else { destination[0] = (char)(0xf0u | (codepoint >> 18)); destination[1] = (char)(0x80u | ((codepoint >> 12) & 0x3fu)); destination[2] = (char)(0x80u | ((codepoint >> 6) & 0x3fu)); destination[3] = (char)(0x80u | (codepoint & 0x3fu)); }
    *written = width;
    return true;
}

} // namespace RinRuntime

#endif
