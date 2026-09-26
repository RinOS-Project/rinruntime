/* SPDX-License-Identifier: MIT */
/* Contract test for the standalone public Zstandard frame subset. */

#include "../include/rincompression/zstd.hpp"

#include <cassert>
#include <cstdint>
#include <vector>

static bool cancelNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

int main()
{
    RinCompression::ZstdFrameEncoder encoder;
    RinCompression::ZstdFrameDecoder decoder;
    std::vector<std::uint8_t> encoded;
    std::vector<std::uint8_t> decoded;
    const std::uint8_t hello[] = {'h', 'e', 'l', 'l', 'o'};

    assert(encoder.encode(hello, sizeof(hello), encoded) ==
           RinCompression::ZstdResult::Ok);
    assert(encoded.size() == 14u);
    assert(encoded[0] == 0x28u && encoded[1] == 0xb5u &&
           encoded[2] == 0x2fu && encoded[3] == 0xfdu);
    assert(decoder.decode(encoded.data(), encoded.size(), decoded) ==
           RinCompression::ZstdResult::Ok);
    assert(decoded.size() == sizeof(hello));
    assert(decoded == std::vector<std::uint8_t>(hello, hello + sizeof(hello)));

    std::vector<std::uint8_t> repeated(128u * 1024u, 0x5au);
    assert(encoder.encode(repeated.data(), repeated.size(), encoded) ==
           RinCompression::ZstdResult::Ok);
    assert(decoder.decode(encoded.data(), encoded.size(), decoded) ==
           RinCompression::ZstdResult::Ok && decoded == repeated);

    assert(decoder.decode(encoded.data(), encoded.size(), decoded,
                          repeated.size() - 1u, nullptr, nullptr) ==
           RinCompression::ZstdResult::Limit && decoded.empty());
    std::uint32_t cancelled = 1u;
    assert(encoder.encode(hello, sizeof(hello), encoded, cancelNow,
                          &cancelled) == RinCompression::ZstdResult::Cancelled &&
           encoded.empty());
    assert(decoder.decode(nullptr, 1u, decoded) ==
           RinCompression::ZstdResult::InvalidArgument);

    /* A frame carrying a compressed-block type is rejected explicitly. */
    const std::uint8_t compressedBlock[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x01u,
        0x0du, 0x00u, 0x00u, 0x00u};
    assert(decoder.decode(compressedBlock, sizeof(compressedBlock), decoded) ==
           RinCompression::ZstdResult::Unsupported && decoded.empty());

    /* A checksum-bearing raw frame for the empty payload. The low 32 bits of
     * XXH64("") are 0x51d8e999 and are stored little-endian. */
    const std::uint8_t checksumFrame[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x24u, 0x00u, 0x01u, 0x00u, 0x00u,
        0x99u, 0xe9u, 0xd8u, 0x51u};
    assert(decoder.decode(checksumFrame, sizeof(checksumFrame), decoded) ==
           RinCompression::ZstdResult::Ok && decoded.empty());
    /* The low 32 bits of XXH64("hello") are 0x889f6da3. */
    const std::uint8_t helloChecksumFrame[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x24u, 0x05u, 0x29u, 0x00u,
        0x00u, 'h', 'e', 'l', 'l', 'o', 0xa3u, 0x6du, 0x9fu, 0x88u};
    assert(decoder.decode(helloChecksumFrame,
                          sizeof(helloChecksumFrame), decoded) ==
           RinCompression::ZstdResult::Ok && decoded ==
               std::vector<std::uint8_t>(hello, hello + sizeof(hello)));
    const std::uint8_t badChecksum[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x24u, 0x00u, 0x01u, 0x00u, 0x00u,
        0x98u, 0xe9u, 0xd8u, 0x51u};
    assert(decoder.decode(badChecksum, sizeof(badChecksum), decoded) ==
           RinCompression::ZstdResult::ChecksumMismatch && decoded.empty());

    /* Empty raw blocks must not provide an unbounded CPU amplification path. */
    const std::size_t tooManyBlockBytes =
        6u + (RinCompression::kZstdMaximumBlocks + 1u) * 3u;
    std::vector<std::uint8_t> tooManyBlocks(tooManyBlockBytes, 0u);
    tooManyBlocks[0] = 0x28u;
    tooManyBlocks[1] = 0xb5u;
    tooManyBlocks[2] = 0x2fu;
    tooManyBlocks[3] = 0xfdu;
    tooManyBlocks[4] = 0x20u;
    tooManyBlocks[5] = 0x00u;
    const std::size_t finalBlockHeader =
        6u + RinCompression::kZstdMaximumBlocks * 3u;
    tooManyBlocks[finalBlockHeader] = 0x01u;
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(tooManyBlocks.data(), tooManyBlocks.size(), decoded) ==
           RinCompression::ZstdResult::Limit && decoded.empty());
    return 0;
}
