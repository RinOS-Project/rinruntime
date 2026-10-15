/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_IPV6_LITERAL_HPP
#define RIN_SHARED_IPV6_LITERAL_HPP

#include <cstddef>

inline bool rin_shared_ipv4_address_valid(const char* value, std::size_t size)
{
    if (value == nullptr || size == 0u)
        return false;
    std::size_t index = 0u;
    unsigned int parts = 0u;
    while (index < size) {
        const std::size_t begin = index;
        unsigned int octet = 0u;
        unsigned int digits = 0u;
        while (index < size && value[index] >= '0' && value[index] <= '9') {
            if (++digits > 3u)
                return false;
            octet = octet * 10u +
                static_cast<unsigned int>(value[index] - '0');
            ++index;
        }
        if (digits == 0u || octet > 255u ||
            (digits > 1u && value[begin] == '0') || ++parts > 4u)
            return false;
        if (index == size)
            break;
        if (value[index++] != '.' || index == size)
            return false;
    }
    return parts == 4u;
}

/* Validate an IPv6 address literal without a surrounding pair of brackets.
 * Scoped zone identifiers are intentionally excluded from host identity. */
inline bool rin_shared_ipv6_address_valid(const char* value, std::size_t size)
{
    if (value == nullptr || size == 0u)
        return false;

    std::size_t index = 0u;
    unsigned int groups = 0u;
    bool compressed = false;
    if (value[0] == ':') {
        if (size < 2u || value[1] != ':')
            return false;
        compressed = true;
        index = 2u;
        if (index == size)
            return true;
    }

    while (index < size) {
        const std::size_t segmentStart = index;
        unsigned int digits = 0u;
        while (index < size && value[index] != ':' && value[index] != '.') {
            const unsigned char byte = static_cast<unsigned char>(value[index]);
            const bool hex = (byte >= static_cast<unsigned char>('0') &&
                              byte <= static_cast<unsigned char>('9')) ||
                             (byte >= static_cast<unsigned char>('a') &&
                              byte <= static_cast<unsigned char>('f')) ||
                             (byte >= static_cast<unsigned char>('A') &&
                              byte <= static_cast<unsigned char>('F'));
            if (!hex || ++digits > 4u)
                return false;
            ++index;
        }

        if (index < size && value[index] == '.') {
            /* An IPv4 tail occupies the final two 16-bit IPv6 groups. */
            if (!rin_shared_ipv4_address_valid(value + segmentStart,
                                               size - segmentStart))
                return false;
            groups += 2u;
            index = size;
            break;
        }

        if (digits == 0u || ++groups > 8u)
            return false;
        if (index == size)
            break;
        if (value[index] != ':')
            return false;
        if (index + 1u < size && value[index + 1u] == ':') {
            if (compressed)
                return false;
            compressed = true;
            index += 2u;
            if (index == size)
                break;
        } else {
            ++index;
            if (index == size)
                return false;
        }
    }

    return compressed ? groups < 8u : groups == 8u;
}

#endif /* RIN_SHARED_IPV6_LITERAL_HPP */
