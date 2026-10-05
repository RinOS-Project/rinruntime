/* SPDX-License-Identifier: MIT */
/* Contract test for the standalone public Zstandard frame subset. */

#include "../include/rincompression/zstd.hpp"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <vector>

static bool cancelNow(void* context)
{
    return context != nullptr &&
           *static_cast<const std::uint32_t*>(context) != 0u;
}

static bool throwingCancel(void*)
{
    throw std::runtime_error("cancellation callback failure");
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
    encoded.assign(1u, 0xa5u);
    assert(encoder.encode(hello, sizeof(hello), encoded, throwingCancel,
                          nullptr) == RinCompression::ZstdResult::Cancelled &&
           encoded.empty());
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(hello, sizeof(hello), decoded,
                          RinCompression::kZstdMaximumBytes, throwingCancel,
                          nullptr) == RinCompression::ZstdResult::Cancelled &&
           decoded.empty());
    assert(decoder.decode(nullptr, 1u, decoded) ==
           RinCompression::ZstdResult::InvalidArgument);
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(nullptr, 0u, decoded) ==
           RinCompression::ZstdResult::InvalidArgument && decoded.empty());

    /* A truncated standard compressed-literals section is malformed. */
    const std::uint8_t compressedBlock[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x00u,
        0x15u, 0x00u, 0x00u, 0x80u, 0x00u};
    assert(decoder.decode(compressedBlock, sizeof(compressedBlock), decoded) ==
           RinCompression::ZstdResult::Malformed && decoded.empty());

    /* A compressed block may carry raw literals and no sequences.  This is a
     * useful interoperable subset that does not pretend to decode sequence
     * commands. */
    const std::uint8_t compressedRawLiterals[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x05u,
        0x3du, 0x00u, 0x00u, 0x28u, 'h', 'e', 'l', 'l', 'o', 0x00u};
    assert(decoder.decode(compressedRawLiterals,
                          sizeof(compressedRawLiterals), decoded) ==
           RinCompression::ZstdResult::Ok);
    assert(decoded == std::vector<std::uint8_t>(hello, hello + sizeof(hello)));

    const std::uint8_t compressedRleLiterals[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x05u,
        0x1du, 0x00u, 0x00u, 0x29u, 'x', 0x00u};
    assert(decoder.decode(compressedRleLiterals,
                          sizeof(compressedRleLiterals), decoded) ==
           RinCompression::ZstdResult::Ok);
    assert(decoded == std::vector<std::uint8_t>(5u, 'x'));

    const std::uint8_t compressedWithSequences[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x08u,
        0x45u, 0x00u, 0x00u, 0x08u, 'x', 0x01u,
        0x54u, 0x01u, 0x00u, 0x04u, 0x01u};
    assert(decoder.decode(compressedWithSequences,
                          sizeof(compressedWithSequences), decoded) ==
           RinCompression::ZstdResult::Ok &&
           decoded == std::vector<std::uint8_t>(8u, 'x'));

    /* The public sequence subset rejects non-RLE sequence tables and never
     * turns an unsupported entropy mode into partial output. */
    std::vector<std::uint8_t> unsupportedSequence(
        compressedWithSequences,
        compressedWithSequences + sizeof(compressedWithSequences));
    unsupportedSequence[12] = 0x94u;
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(unsupportedSequence.data(),
                          unsupportedSequence.size(), decoded) ==
           RinCompression::ZstdResult::Unsupported && decoded.empty());

    std::vector<std::uint8_t> unsupportedMatchLength(
        compressedWithSequences,
        compressedWithSequences + sizeof(compressedWithSequences));
    unsupportedMatchLength[15] = 0x05u;
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(unsupportedMatchLength.data(),
                          unsupportedMatchLength.size(), decoded) ==
           RinCompression::ZstdResult::Unsupported && decoded.empty());

    /* A direct-table, single-stream Huffman literal section is a public
     * entropy-coded subset.  The tree describes symbols 0 and 1 with equal
     * one-bit weights; the final bit in 0x15 is the stream end marker. */
    const std::uint8_t compressedHuffmanLiterals[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x04u,
        0x3du, 0x00u, 0x00u, 0x42u, 0xc0u, 0x00u,
        0x80u, 0x10u, 0x15u, 0x00u};
    const std::vector<std::uint8_t> huffmanExpected = {0u, 1u, 0u, 1u};
    assert(decoder.decode(compressedHuffmanLiterals,
                          sizeof(compressedHuffmanLiterals), decoded) ==
           RinCompression::ZstdResult::Ok && decoded == huffmanExpected);

    /* The same direct tree is valid in the four-stream form.  Each stream
     * contains two one-bit symbols and a final-bit marker. */
    const std::uint8_t compressedHuffmanFourStreams[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x08u,
        0x85u, 0x00u, 0x00u, 0x86u, 0x00u, 0x03u,
        0x80u, 0x10u, 0x01u, 0x00u, 0x01u, 0x00u,
        0x01u, 0x00u, 0x05u, 0x05u, 0x06u, 0x06u, 0x00u};
    const std::vector<std::uint8_t> fourStreamExpected =
        {0u, 1u, 0u, 1u, 1u, 0u, 1u, 0u};
    assert(decoder.decode(compressedHuffmanFourStreams,
                          sizeof(compressedHuffmanFourStreams), decoded) ==
           RinCompression::ZstdResult::Ok && decoded == fourStreamExpected);

    /* A frame emitted by the reference encoder with an FSE-compressed
     * Huffman-weight section exercises the bounded public tree decoder. */
    const std::uint8_t compressedFseHuffmanLiterals[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x60u, 0x00u, 0x00u, 0xadu, 0x06u,
        0x00u, 0x06u, 0x50u, 0x34u, 0x13u, 0x30u, 0x5eu, 0xfau, 0x23u,
        0x2du, 0x20u, 0x1bu, 0x50u, 0xdau, 0x21u, 0x8bu, 0x6bu, 0xfeu,
        0xc2u, 0xdau, 0xa7u, 0x64u, 0x23u, 0x24u, 0x2du, 0x00u, 0x2eu,
        0x00u, 0x2du, 0x00u, 0x00u, 0x8au, 0x57u, 0xf0u, 0xecu, 0xf3u,
        0xc2u, 0x20u, 0xf6u, 0x31u, 0xe6u, 0x56u, 0xd6u, 0x78u, 0x1fu,
        0x06u, 0xaau, 0xedu, 0x3au, 0x50u, 0xb8u, 0xdbu, 0x5du, 0xb3u,
        0x12u, 0x52u, 0x3au, 0x93u, 0xf9u, 0x04u, 0xb4u, 0xa7u, 0x59u,
        0xbfu, 0x31u, 0xfau, 0xa6u, 0x7fu, 0x39u, 0x2eu, 0x32u, 0xc1u,
        0xdbu, 0xc7u, 0x03u, 0x8fu, 0xe7u, 0xbcu, 0x5du, 0xd8u, 0x84u,
        0x79u, 0xf1u, 0xcbu, 0x35u, 0xa8u, 0x64u, 0x39u, 0x89u, 0xd6u,
        0x92u, 0xdbu, 0x0du, 0xe8u, 0x6fu, 0xebu, 0xf6u, 0x05u, 0xc7u,
        0x6cu, 0xe0u, 0x12u, 0xcau, 0x09u, 0xf3u, 0xd0u, 0xa2u, 0xb2u,
        0x54u, 0xb5u, 0x51u, 0x03u, 0xc2u, 0x1cu, 0x2eu, 0xf2u, 0xd6u,
        0x81u, 0x4fu, 0x40u, 0x04u, 0x36u, 0x6bu, 0x5au, 0xb7u, 0x07u,
        0x92u, 0x94u, 0xacu, 0x47u, 0x39u, 0x4bu, 0xaau, 0x15u, 0xa2u,
        0x0au, 0xd2u, 0x7cu, 0x56u, 0xe3u, 0xc6u, 0x78u, 0x1eu, 0xffu,
        0xadu, 0xe7u, 0x9bu, 0x49u, 0x63u, 0x96u, 0x4bu, 0xfbu, 0xfeu,
        0xccu, 0x59u, 0x2au, 0x6au, 0x08u, 0x83u, 0x28u, 0xc5u, 0x08u,
        0x07u, 0x2fu, 0x42u, 0x11u, 0x17u, 0x4cu, 0x14u, 0x07u, 0xceu,
        0xcdu, 0xa0u, 0xdau, 0x29u, 0x64u, 0xaau, 0xf2u, 0x65u, 0xd5u,
        0x85u, 0xacu, 0x99u, 0x45u, 0xe3u, 0x64u, 0x26u, 0xa6u, 0x0au,
        0x0eu, 0x76u, 0xd5u, 0xddu, 0xd9u, 0xa9u, 0xcbu, 0x24u, 0xebu,
        0x82u, 0xa5u, 0x60u, 0x08u, 0xbdu, 0x34u, 0x13u, 0x8eu, 0x0eu,
        0x91u, 0x81u, 0xd4u, 0xa6u, 0x1du, 0x35u, 0x00u};
    const std::uint8_t fseHuffmanExpected[] = {
        0x19u, 0x00u, 0x09u, 0x07u, 0x1fu, 0x1bu, 0x2bu, 0x02u, 0x0fu,
        0x00u, 0x07u, 0x13u, 0x00u, 0x06u, 0x1au, 0x14u, 0x07u, 0x17u,
        0x24u, 0x00u, 0x24u, 0x1du, 0x0cu, 0x05u, 0x33u, 0x0bu, 0x03u,
        0x03u, 0x27u, 0x17u, 0x24u, 0x1eu, 0x14u, 0x35u, 0x0du, 0x15u,
        0x25u, 0x18u, 0x28u, 0x16u, 0x1du, 0x01u, 0x07u, 0x0au, 0x02u,
        0x08u, 0x03u, 0x09u, 0x19u, 0x0du, 0x0du, 0x07u, 0x09u, 0x30u,
        0x1au, 0x18u, 0x05u, 0x1eu, 0x05u, 0x0du, 0x39u, 0x19u, 0x15u,
        0x1cu, 0x26u, 0x21u, 0x07u, 0x01u, 0x0bu, 0x09u, 0x07u, 0x31u,
        0x29u, 0x0bu, 0x1au, 0x0eu, 0x2du, 0x11u, 0x09u, 0x08u, 0x15u,
        0x09u, 0x16u, 0x2bu, 0x0eu, 0x07u, 0x3du, 0x13u, 0x03u, 0x01u,
        0x03u, 0x19u, 0x23u, 0x0fu, 0x02u, 0x0du, 0x3cu, 0x14u, 0x35u,
        0x28u, 0x00u, 0x1eu, 0x1cu, 0x14u, 0x09u, 0x19u, 0x03u, 0x10u,
        0x10u, 0x32u, 0x29u, 0x09u, 0x12u, 0x06u, 0x2du, 0x29u, 0x0au,
        0x19u, 0x18u, 0x05u, 0x21u, 0x14u, 0x22u, 0x14u, 0x00u, 0x0bu,
        0x00u, 0x2fu, 0x2au, 0x26u, 0x0au, 0x01u, 0x29u, 0x31u, 0x02u,
        0x12u, 0x02u, 0x20u, 0x21u, 0x04u, 0x11u, 0x15u, 0x09u, 0x29u,
        0x0fu, 0x07u, 0x14u, 0x1eu, 0x06u, 0x0au, 0x3bu, 0x1au, 0x10u,
        0x13u, 0x04u, 0x07u, 0x0cu, 0x17u, 0x07u, 0x07u, 0x02u, 0x19u,
        0x07u, 0x2cu, 0x28u, 0x02u, 0x08u, 0x1bu, 0x07u, 0x04u, 0x30u,
        0x16u, 0x11u, 0x22u, 0x24u, 0x06u, 0x03u, 0x0fu, 0x0fu, 0x11u,
        0x1eu, 0x1bu, 0x38u, 0x03u, 0x0eu, 0x0cu, 0x28u, 0x08u, 0x06u,
        0x10u, 0x0fu, 0x09u, 0x08u, 0x2eu, 0x10u, 0x28u, 0x15u, 0x01u,
        0x3eu, 0x26u, 0x35u, 0x2eu, 0x27u, 0x05u, 0x12u, 0x07u, 0x0eu,
        0x01u, 0x0du, 0x38u, 0x09u, 0x22u, 0x10u, 0x0fu, 0x33u, 0x3cu,
        0x15u, 0x1eu, 0x05u, 0x0au, 0x35u, 0x16u, 0x14u, 0x20u, 0x01u,
        0x16u, 0x13u, 0x27u, 0x05u, 0x33u, 0x02u, 0x06u, 0x17u, 0x1bu,
        0x08u, 0x03u, 0x2bu, 0x08u, 0x17u, 0x18u, 0x0fu, 0x16u, 0x13u,
        0x30u, 0x06u, 0x1eu, 0x08u, 0x0eu, 0x1bu, 0x0au, 0x0bu, 0x20u,
        0x02u, 0x11u, 0x3du, 0x3cu};
    assert(decoder.decode(compressedFseHuffmanLiterals,
                          sizeof(compressedFseHuffmanLiterals), decoded) ==
           RinCompression::ZstdResult::Ok &&
           decoded == std::vector<std::uint8_t>(
               fseHuffmanExpected,
               fseHuffmanExpected + sizeof(fseHuffmanExpected)));
    std::vector<std::uint8_t> truncatedFse(
        compressedFseHuffmanLiterals,
        compressedFseHuffmanLiterals + sizeof(compressedFseHuffmanLiterals));
    truncatedFse.pop_back();
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(truncatedFse.data(), truncatedFse.size(), decoded) ==
           RinCompression::ZstdResult::Malformed && decoded.empty());

    /* Size formats 2 and 3 use the same four-stream payload with wider
     * regenerated/compressed-size fields. */
    const std::uint8_t compressedHuffmanFourStreamsFormat2[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x08u,
        0x8du, 0x00u, 0x00u, 0x8au, 0x00u, 0x30u, 0x00u,
        0x80u, 0x10u, 0x01u, 0x00u, 0x01u, 0x00u,
        0x01u, 0x00u, 0x05u, 0x05u, 0x06u, 0x06u, 0x00u};
    assert(decoder.decode(compressedHuffmanFourStreamsFormat2,
                          sizeof(compressedHuffmanFourStreamsFormat2), decoded) ==
           RinCompression::ZstdResult::Ok && decoded == fourStreamExpected);

    const std::uint8_t compressedHuffmanFourStreamsFormat3[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x08u,
        0x95u, 0x00u, 0x00u, 0x8eu, 0x00u, 0x00u, 0x03u, 0x00u,
        0x80u, 0x10u, 0x01u, 0x00u, 0x01u, 0x00u,
        0x01u, 0x00u, 0x05u, 0x05u, 0x06u, 0x06u, 0x00u};
    assert(decoder.decode(compressedHuffmanFourStreamsFormat3,
                          sizeof(compressedHuffmanFourStreamsFormat3), decoded) ==
           RinCompression::ZstdResult::Ok && decoded == fourStreamExpected);

    /* Zstandard reserves the four-stream form for at least six regenerated
     * bytes.  A payload that happens to contain four decodable one-byte
     * streams is still malformed when its header advertises only four. */
    const std::uint8_t compressedHuffmanFourStreamsTooShort[] = {
        0x28u, 0xb5u, 0x2fu, 0xfdu, 0x20u, 0x08u,
        0x85u, 0x00u, 0x00u, 0x46u, 0xc0u, 0x00u,
        0x80u, 0x10u, 0x01u, 0x00u, 0x01u, 0x00u,
        0x01u, 0x00u, 0x05u, 0x05u, 0x06u, 0x06u, 0x00u};
    decoded.assign(1u, 0xa5u);
    assert(decoder.decode(compressedHuffmanFourStreamsTooShort,
                          sizeof(compressedHuffmanFourStreamsTooShort), decoded) ==
           RinCompression::ZstdResult::Malformed && decoded.empty());

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
