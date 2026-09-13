/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_UNICODE_HPP
#define RINRUNTIME_UNICODE_HPP

#include "unicode.h"
#include <cstdint>
#include <string>

namespace RinRuntime {

inline std::size_t utf8GraphemeNext(const std::string& value,
                                    std::size_t offset)
{
    if (offset >= value.size()) return value.size();
    std::uint32_t codepoint = 0u;
    std::size_t width = 0u;
    if (!rinruntime_utf8_decode(value.data(), value.size(), offset,
                                &codepoint, &width)) return offset;
    std::size_t next = offset + width;
    while (next < value.size()) {
        std::uint32_t following = 0u;
        std::size_t followingWidth = 0u;
        if (!rinruntime_utf8_decode(value.data(), value.size(), next,
                                    &following, &followingWidth)) return next;
        if (rinruntime_unicode_combining(following) || following == 0xfe0fu) {
            next += followingWidth;
            continue;
        }
        if (codepoint == 0x200du) {
            codepoint = following;
            next += followingWidth;
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
