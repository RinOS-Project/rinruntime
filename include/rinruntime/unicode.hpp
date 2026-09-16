/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_UNICODE_HPP
#define RINRUNTIME_UNICODE_HPP

#include "unicode.h"
#include <cstdint>
#include <string>

namespace RinRuntime {

inline bool utf8GraphemeExtend(std::uint32_t codepoint)
{
    return rinruntime_unicode_combining(codepoint) ||
           codepoint == 0x200cu || codepoint == 0x20e3u ||
           (codepoint >= 0xfe00u && codepoint <= 0xfe0fu) ||
           (codepoint >= 0xe0100u && codepoint <= 0xe01efu) ||
           (codepoint >= 0x1f3fbu && codepoint <= 0x1f3ffu) ||
           (codepoint >= 0xe0020u && codepoint <= 0xe007fu);
}

inline bool utf8GraphemeSpacingMark(std::uint32_t codepoint)
{
    /* Keep the table small and deterministic while covering the combining
     * vowel signs used by the public text model.  Full Unicode property data
     * remains a separate libunicode/i18n data delivery task. */
    return codepoint == 0x0903u ||
           (codepoint >= 0x093eu && codepoint <= 0x0940u) ||
           (codepoint >= 0x0949u && codepoint <= 0x094cu) ||
           (codepoint >= 0x0982u && codepoint <= 0x0983u) ||
           (codepoint >= 0x09beu && codepoint <= 0x09c0u) ||
           (codepoint >= 0x09c7u && codepoint <= 0x09ccu) ||
           (codepoint >= 0x0abeu && codepoint <= 0x0ac0u) ||
           codepoint == 0x0ac9u ||
           (codepoint >= 0x0acbu && codepoint <= 0x0accu) ||
           codepoint == 0x0b3eu || codepoint == 0x0b40u ||
           (codepoint >= 0x0b47u && codepoint <= 0x0b48u) ||
           (codepoint >= 0x0b4bu && codepoint <= 0x0b4cu) ||
           (codepoint >= 0x0bbeu && codepoint <= 0x0bc2u) ||
           (codepoint >= 0x0bc6u && codepoint <= 0x0bc8u) ||
           (codepoint >= 0x0bcau && codepoint <= 0x0bccu) ||
           (codepoint >= 0x0c01u && codepoint <= 0x0c03u) ||
           (codepoint >= 0x0c41u && codepoint <= 0x0c44u) ||
           (codepoint >= 0x0c82u && codepoint <= 0x0c83u) ||
           codepoint == 0x0cbeu ||
           (codepoint >= 0x0cc0u && codepoint <= 0x0cc4u) ||
           (codepoint >= 0x0cc7u && codepoint <= 0x0cc8u) ||
           (codepoint >= 0x0ccau && codepoint <= 0x0cccu) ||
           (codepoint >= 0x0d3eu && codepoint <= 0x0d40u) ||
           (codepoint >= 0x0d46u && codepoint <= 0x0d48u) ||
           (codepoint >= 0x0d4au && codepoint <= 0x0d4cu) ||
           (codepoint >= 0x17beu && codepoint <= 0x17c5u);
}

inline bool utf8GraphemePrepend(std::uint32_t codepoint)
{
    return (codepoint >= 0x0600u && codepoint <= 0x0605u) ||
           codepoint == 0x06ddu || codepoint == 0x070fu ||
           (codepoint >= 0x0890u && codepoint <= 0x0891u) ||
           codepoint == 0x08e2u || codepoint == 0x0d4eu ||
           codepoint == 0x110bdu || codepoint == 0x110cdu ||
           (codepoint >= 0x111c2u && codepoint <= 0x111c3u) ||
           codepoint == 0x11941u || codepoint == 0x11a3au ||
           codepoint == 0x11d46u;
}

inline bool utf8GraphemeControl(std::uint32_t codepoint)
{
    return codepoint == 0x000du || codepoint == 0x000au ||
           (codepoint <= 0x001fu) ||
           (codepoint >= 0x007fu && codepoint <= 0x009fu);
}

inline bool utf8GraphemeRegionalIndicator(std::uint32_t codepoint)
{
    return codepoint >= 0x1f1e6u && codepoint <= 0x1f1ffu;
}

inline bool utf8GraphemeExtendedPictographic(std::uint32_t codepoint)
{
    return (codepoint >= 0x2300u && codepoint <= 0x27bfu) ||
           (codepoint >= 0x1f000u && codepoint <= 0x1faffu);
}

inline bool utf8GraphemeHangulL(std::uint32_t codepoint)
{
    return (codepoint >= 0x1100u && codepoint <= 0x115fu) ||
           (codepoint >= 0xa960u && codepoint <= 0xa97cu);
}

inline bool utf8GraphemeHangulV(std::uint32_t codepoint)
{
    return (codepoint >= 0x1160u && codepoint <= 0x11a7u) ||
           (codepoint >= 0xd7b0u && codepoint <= 0xd7c6u);
}

inline bool utf8GraphemeHangulT(std::uint32_t codepoint)
{
    return (codepoint >= 0x11a8u && codepoint <= 0x11ffu) ||
           (codepoint >= 0xd7cbu && codepoint <= 0xd7fbu);
}

inline bool utf8GraphemeHangulLV(std::uint32_t codepoint)
{
    return codepoint >= 0xac00u && codepoint <= 0xd7a3u &&
           ((codepoint - 0xac00u) % 28u) == 0u;
}

inline bool utf8GraphemeHangulLVT(std::uint32_t codepoint)
{
    return codepoint >= 0xac00u && codepoint <= 0xd7a3u &&
           ((codepoint - 0xac00u) % 28u) != 0u;
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
    if (offset >= value.size()) return value.size();
    std::uint32_t codepoint = 0u;
    std::size_t width = 0u;
    if (!rinruntime_utf8_decode(value.data(), value.size(), offset,
                                &codepoint, &width)) return offset;
    std::size_t next = offset + width;
    if (codepoint == 0x000du && next < value.size()) {
        std::uint32_t following = 0u;
        std::size_t followingWidth = 0u;
        if (rinruntime_utf8_decode(value.data(), value.size(), next,
                                   &following, &followingWidth) &&
            following == 0x000au)
            return next + followingWidth;
    }
    if (utf8GraphemeControl(codepoint)) return next;
    std::uint32_t previousSignificant = codepoint;
    std::size_t regionalCount =
        utf8GraphemeRegionalIndicator(codepoint) ? 1u : 0u;
    bool afterZwj = false;
    while (next < value.size()) {
        std::uint32_t following = 0u;
        std::size_t followingWidth = 0u;
        if (!rinruntime_utf8_decode(value.data(), value.size(), next,
                                    &following, &followingWidth)) return next;
        if (utf8GraphemeControl(following)) break;
        if (afterZwj) {
            if (!utf8GraphemeExtendedPictographic(following)) break;
            next += followingWidth;
            previousSignificant = following;
            afterZwj = false;
            continue;
        }
        if (utf8GraphemeExtend(following) ||
            utf8GraphemeSpacingMark(following)) {
            next += followingWidth;
            continue;
        }
        if (following == 0x200du) {
            next += followingWidth;
            afterZwj = utf8GraphemeExtendedPictographic(previousSignificant);
            continue;
        }
        if (utf8GraphemePrepend(previousSignificant) ||
            utf8GraphemeHangulBreakless(previousSignificant, following)) {
            next += followingWidth;
            previousSignificant = following;
            continue;
        }
        if (utf8GraphemeRegionalIndicator(following) &&
            utf8GraphemeRegionalIndicator(previousSignificant) &&
            (regionalCount & 1u) != 0u) {
            next += followingWidth;
            ++regionalCount;
            previousSignificant = following;
            continue;
        }
        break;
    }
    return next;
}

inline std::size_t utf8GraphemePrev(const std::string& value,
                                    std::size_t offset)
{
    if (offset > value.size()) offset = value.size();
    if (offset == 0u) return 0u;
    std::size_t cursor = 0u;
    std::size_t previous = 0u;
    while (cursor < offset) {
        previous = cursor;
        std::size_t next = utf8GraphemeNext(value, cursor);
        if (next <= cursor || next >= offset) break;
        cursor = next;
    }
    return previous;
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
