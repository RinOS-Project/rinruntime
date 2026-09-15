/* SPDX-License-Identifier: MIT */
/* Contract test for the standalone public LZ4 block decoder. */

#include "../include/rincompression/lz4.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

static bool cancelNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

int main()
{
    RinCompression::Lz4BlockEncoder encoder;
    RinCompression::Lz4BlockDecoder decoder;
    std::vector<std::uint8_t> output;

    const std::uint8_t literal[] = {0x50u, 'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> encoded;
    assert(encoder.encode(reinterpret_cast<const std::uint8_t*>("hello"), 5u,
                          encoded) == RinCompression::Lz4Result::Ok);
    assert(encoded.size() == sizeof(literal));
    assert(std::equal(encoded.begin(), encoded.end(), literal));
    assert(decoder.decode(encoded.data(), encoded.size(), output) ==
           RinCompression::Lz4Result::Ok);
    assert(std::string(output.begin(), output.end()) == "hello");

    assert(decoder.decode(literal, sizeof(literal), output) ==
           RinCompression::Lz4Result::Ok);
    assert(std::string(output.begin(), output.end()) == "hello");

    const std::uint8_t match[] = {
        0x32u, 'a', 'b', 'c', 0x03u, 0x00u, 0x10u, 'X'};
    assert(decoder.decode(match, sizeof(match), output) ==
           RinCompression::Lz4Result::Ok);
    assert(std::string(output.begin(), output.end()) == "abcabcabcX");

    const std::uint8_t extendedLiteral[] = {
        0xf0u, 0x01u, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
    assert(decoder.decode(extendedLiteral, sizeof(extendedLiteral), output) ==
           RinCompression::Lz4Result::Ok);
    assert(output.size() == 16u);

    assert(decoder.decode(match, sizeof(match), output, 8u, nullptr,
                          nullptr) == RinCompression::Lz4Result::Limit);
    assert(output.empty());

    const std::uint8_t malformed[] = {0x10u, 'x', 0x00u, 0x00u};
    assert(decoder.decode(malformed, sizeof(malformed), output) ==
           RinCompression::Lz4Result::Malformed);
    assert(output.empty());

    std::uint32_t cancelled = 1u;
    assert(decoder.decode(literal, sizeof(literal), output,
                          RinCompression::kLz4MaximumBytes, cancelNow,
                          &cancelled) == RinCompression::Lz4Result::Cancelled);
    assert(output.empty());
    assert(decoder.decode(nullptr, 1u, output) ==
           RinCompression::Lz4Result::InvalidArgument);
    std::uint32_t cancelledEncode = 1u;
    assert(encoder.encode(reinterpret_cast<const std::uint8_t*>("hello"), 5u,
                          encoded, cancelNow, &cancelledEncode) ==
           RinCompression::Lz4Result::Cancelled);
    assert(encoded.empty());
    return 0;
}
