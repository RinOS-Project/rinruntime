/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded Zstandard frame subset for public consumers. */

#ifndef RINCOMPRESSION_ZSTD_HPP
#define RINCOMPRESSION_ZSTD_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace RinCompression {

using ZstdCancellationFunction = bool (*)(void* context);

enum class ZstdResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    Unsupported = -4,
    Cancelled = -5,
    ChecksumMismatch = -6,
};

/* This public codec handles the interoperable Zstandard frame envelope with
 * raw and RLE blocks. Entropy-compressed blocks and external dictionaries are
 * deliberately reported as Unsupported until a bounded decoder for those
 * algorithms is added; a caller must not treat that result as success. The
 * frame contains no filesystem, service, or publication policy. */
static constexpr std::size_t kZstdMaximumBytes = 268435456u;
static constexpr std::size_t kZstdMaximumBlockBytes = 128u * 1024u;
static constexpr std::size_t kZstdMaximumBlocks = 65536u;

namespace zstd_detail {

static inline std::uint32_t read32(const std::uint8_t* bytes)
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[2]) << 16u) |
           (static_cast<std::uint32_t>(bytes[3]) << 24u);
}

static inline std::uint64_t read64(const std::uint8_t* bytes)
{
    std::uint64_t result = 0u;
    for (std::size_t index = 0u; index < 8u; ++index)
        result |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
    return result;
}

static inline std::uint32_t read24(const std::uint8_t* bytes)
{
    return static_cast<std::uint32_t>(bytes[0]) |
           (static_cast<std::uint32_t>(bytes[1]) << 8u) |
           (static_cast<std::uint32_t>(bytes[2]) << 16u);
}

static inline std::uint32_t rotateLeft(std::uint32_t value, unsigned amount)
{
    return (value << amount) | (value >> (32u - amount));
}

static inline std::uint64_t xxh64Round(std::uint64_t accumulator,
                                       std::uint64_t value)
{
    accumulator += value * UINT64_C(0xc2b2ae3d27d4eb4f);
    accumulator = (accumulator << 31u) | (accumulator >> 33u);
    accumulator *= UINT64_C(0x9e3779b185ebca87);
    return accumulator;
}

static inline std::uint64_t xxh64MergeRound(std::uint64_t accumulator,
                                            std::uint64_t value)
{
    value = xxh64Round(0u, value);
    accumulator ^= value;
    accumulator = accumulator * UINT64_C(0x9e3779b185ebca87) +
                  UINT64_C(0x85ebca77c2b2ae63);
    return accumulator;
}

/* Zstandard content checksums use the low 32 bits of XXH64 with seed zero. */
static inline std::uint32_t xxh64Low32(const std::uint8_t* bytes,
                                       std::size_t size)
{
    constexpr std::uint64_t prime1 = UINT64_C(0x9e3779b185ebca87);
    constexpr std::uint64_t prime2 = UINT64_C(0xc2b2ae3d27d4eb4f);
    constexpr std::uint64_t prime3 = UINT64_C(0x165667b19e3779f9);
    constexpr std::uint64_t prime4 = UINT64_C(0x85ebca77c2b2ae63);
    constexpr std::uint64_t prime5 = UINT64_C(0x27d4eb2f165667c5);
    std::size_t position = 0u;
    std::uint64_t hash;

    if (size >= 32u) {
        std::uint64_t v1 = prime1 + prime2;
        std::uint64_t v2 = prime2;
        std::uint64_t v3 = 0u;
        std::uint64_t v4 = 0u - prime1;
        while (position + 32u <= size) {
            v1 = xxh64Round(v1, read64(bytes + position));
            v2 = xxh64Round(v2, read64(bytes + position + 8u));
            v3 = xxh64Round(v3, read64(bytes + position + 16u));
            v4 = xxh64Round(v4, read64(bytes + position + 24u));
            position += 32u;
        }
        hash = ((v1 << 1u) | (v1 >> 63u)) +
               ((v2 << 7u) | (v2 >> 57u)) +
               ((v3 << 12u) | (v3 >> 52u)) +
               ((v4 << 18u) | (v4 >> 46u));
        hash = xxh64MergeRound(hash, v1);
        hash = xxh64MergeRound(hash, v2);
        hash = xxh64MergeRound(hash, v3);
        hash = xxh64MergeRound(hash, v4);
    } else {
        hash = prime5;
    }
    hash += static_cast<std::uint64_t>(size);

    while (position + 8u <= size) {
        hash ^= xxh64Round(0u, read64(bytes + position));
        hash = ((hash << 27u) | (hash >> 37u)) * prime1 + prime4;
        position += 8u;
    }
    while (position + 4u <= size) {
        hash ^= static_cast<std::uint64_t>(read32(bytes + position)) * prime1;
        hash = ((hash << 23u) | (hash >> 41u)) * prime2 + prime3;
        position += 4u;
    }
    while (position < size) {
        hash ^= static_cast<std::uint64_t>(bytes[position]) * prime5;
        hash = ((hash << 11u) | (hash >> 53u)) * prime1;
        ++position;
    }
    hash ^= hash >> 33u;
    hash *= prime2;
    hash ^= hash >> 29u;
    hash *= prime3;
    hash ^= hash >> 32u;
    return static_cast<std::uint32_t>(hash);
}

static inline void append32(std::vector<std::uint8_t>& output,
                            std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value));
    output.push_back(static_cast<std::uint8_t>(value >> 8u));
    output.push_back(static_cast<std::uint8_t>(value >> 16u));
    output.push_back(static_cast<std::uint8_t>(value >> 24u));
}

static inline bool appendWithinLimit(std::vector<std::uint8_t>& output,
                                     const std::uint8_t* bytes,
                                     std::size_t size)
{
    if (output.size() > kZstdMaximumBytes ||
        size > kZstdMaximumBytes - output.size())
        return false;
    if (size != 0u) output.insert(output.end(), bytes, bytes + size);
    return true;
}

} // namespace zstd_detail

class ZstdFrameEncoder final {
    static bool cancelled(ZstdCancellationFunction function, void* context)
    {
        return function != nullptr && function(context);
    }

    static ZstdResult fail(std::vector<std::uint8_t>& output,
                           ZstdResult result)
    {
        output.clear();
        return result;
    }

    static bool appendHeader(std::vector<std::uint8_t>& output,
                             std::size_t inputSize)
    {
        const std::size_t headerSize = inputSize <= 255u
            ? 6u : inputSize <= 65791u ? 7u : 9u;
        if (headerSize > kZstdMaximumBytes ||
            output.size() > kZstdMaximumBytes - headerSize)
            return false;
        zstd_detail::append32(output, UINT32_C(0xfd2fb528));
        if (inputSize <= 255u) {
            output.push_back(0x20u);
            output.push_back(static_cast<std::uint8_t>(inputSize));
        } else if (inputSize <= 65791u) {
            output.push_back(0x60u);
            const std::uint16_t encoded =
                static_cast<std::uint16_t>(inputSize - 256u);
            output.push_back(static_cast<std::uint8_t>(encoded));
            output.push_back(static_cast<std::uint8_t>(encoded >> 8u));
        } else {
            output.push_back(0xa0u);
            zstd_detail::append32(output, static_cast<std::uint32_t>(inputSize));
        }
        return output.size() <= kZstdMaximumBytes;
    }

    static bool appendBlockHeader(std::vector<std::uint8_t>& output,
                                  std::size_t blockSize, unsigned type,
                                  bool last)
    {
        if (blockSize > kZstdMaximumBlockBytes || type > 1u ||
            output.size() > kZstdMaximumBytes - 3u)
            return false;
        const std::uint32_t header =
            (static_cast<std::uint32_t>(blockSize) << 3u) |
            (static_cast<std::uint32_t>(type) << 1u) | (last ? 1u : 0u);
        output.push_back(static_cast<std::uint8_t>(header));
        output.push_back(static_cast<std::uint8_t>(header >> 8u));
        output.push_back(static_cast<std::uint8_t>(header >> 16u));
        return true;
    }

public:
    ZstdResult encode(const std::uint8_t* input, std::size_t inputSize,
                      std::vector<std::uint8_t>& output) const
    {
        return encode(input, inputSize, output, nullptr, nullptr);
    }

    ZstdResult encode(const std::uint8_t* input, std::size_t inputSize,
                      std::vector<std::uint8_t>& output,
                      ZstdCancellationFunction cancellation,
                      void* cancellationContext) const
    {
        output.clear();
        if (input == nullptr && inputSize != 0u)
            return ZstdResult::InvalidArgument;
        if (inputSize > kZstdMaximumBytes)
            return ZstdResult::Limit;
        if (cancelled(cancellation, cancellationContext))
            return ZstdResult::Cancelled;
        if (!appendHeader(output, inputSize))
            return fail(output, ZstdResult::Limit);

        if (inputSize == 0u) {
            if (!appendBlockHeader(output, 0u, 0u, true))
                return fail(output, ZstdResult::Limit);
            return cancelled(cancellation, cancellationContext)
                ? fail(output, ZstdResult::Cancelled) : ZstdResult::Ok;
        }

        std::size_t offset = 0u;
        while (offset < inputSize) {
            if (cancelled(cancellation, cancellationContext))
                return fail(output, ZstdResult::Cancelled);
            const std::size_t remaining = inputSize - offset;
            const std::size_t blockSize = remaining > kZstdMaximumBlockBytes
                ? kZstdMaximumBlockBytes : remaining;
            bool repeated = true;
            for (std::size_t index = 1u; index < blockSize; ++index) {
                if ((index & 0xfffu) == 0u &&
                    cancelled(cancellation, cancellationContext))
                    return fail(output, ZstdResult::Cancelled);
                if (input[offset + index] != input[offset]) {
                    repeated = false;
                    break;
                }
            }
            const bool last = blockSize == remaining;
            const unsigned type = repeated ? 1u : 0u;
            if (!appendBlockHeader(output, blockSize, type, last))
                return fail(output, ZstdResult::Limit);
            if (type == 1u) {
                if (output.size() >= kZstdMaximumBytes)
                    return fail(output, ZstdResult::Limit);
                output.push_back(input[offset]);
            } else if (!zstd_detail::appendWithinLimit(
                           output, input + offset, blockSize)) {
                return fail(output, ZstdResult::Limit);
            }
            offset += blockSize;
        }
        return cancelled(cancellation, cancellationContext)
            ? fail(output, ZstdResult::Cancelled) : ZstdResult::Ok;
    }
};

class ZstdFrameDecoder final {
    struct Header final {
        std::size_t position = 0u;
        std::size_t contentSize = 0u;
        bool hasContentSize = false;
        bool contentChecksum = false;
        bool dictionary = false;
    };

    static bool cancelled(ZstdCancellationFunction function, void* context)
    {
        return function != nullptr && function(context);
    }

    static ZstdResult fail(std::vector<std::uint8_t>& output,
                           ZstdResult result)
    {
        output.clear();
        return result;
    }

    static ZstdResult parseHeader(const std::uint8_t* bytes, std::size_t size,
                                  std::size_t maximumOutputBytes,
                                  Header& header)
    {
        if (size < 5u || bytes[0] != 0x28u || bytes[1] != 0xb5u ||
            bytes[2] != 0x2fu || bytes[3] != 0xfdu)
            return ZstdResult::Malformed;
        const std::uint8_t descriptor = bytes[4];
        if ((descriptor & 0x08u) != 0u)
            return ZstdResult::Malformed;
        const bool singleSegment = (descriptor & 0x20u) != 0u;
        const unsigned frameSizeFlag = descriptor >> 6u;
        const unsigned dictionaryFlag = descriptor & 0x03u;
        std::size_t position = 5u;
        if (!singleSegment) {
            if (position >= size) return ZstdResult::Malformed;
            const std::uint8_t window = bytes[position++];
            const unsigned windowLog = (window >> 3u) + 10u;
            const std::uint64_t windowBase = UINT64_C(1) << windowLog;
            const std::uint64_t windowSize =
                windowBase + (windowBase / 8u) * (window & 0x07u);
            if (windowSize > kZstdMaximumBytes) return ZstdResult::Limit;
        }

        const std::size_t dictionaryBytes = dictionaryFlag == 0u
            ? 0u : dictionaryFlag == 1u ? 1u
            : dictionaryFlag == 2u ? 2u : 4u;
        if (dictionaryBytes > size - position)
            return ZstdResult::Malformed;
        header.dictionary = dictionaryFlag != 0u;
        position += dictionaryBytes;

        std::size_t contentSizeBytes = 0u;
        if (frameSizeFlag == 0u)
            contentSizeBytes = singleSegment ? 1u : 0u;
        else if (frameSizeFlag == 1u)
            contentSizeBytes = 2u;
        else if (frameSizeFlag == 2u)
            contentSizeBytes = 4u;
        else
            contentSizeBytes = 8u;
        if (contentSizeBytes > size - position)
            return ZstdResult::Malformed;
        if (contentSizeBytes != 0u) {
            std::uint64_t contentSize = 0u;
            if (contentSizeBytes == 1u)
                contentSize = bytes[position];
            else if (contentSizeBytes == 2u)
                contentSize = static_cast<std::uint64_t>(bytes[position]) |
                              (static_cast<std::uint64_t>(bytes[position + 1u])
                               << 8u);
            else if (contentSizeBytes == 4u)
                contentSize = zstd_detail::read32(bytes + position);
            else
                contentSize = zstd_detail::read64(bytes + position);
            if (frameSizeFlag == 1u) contentSize += 256u;
            if (contentSize > kZstdMaximumBytes ||
                contentSize > maximumOutputBytes)
                return ZstdResult::Limit;
            header.contentSize = static_cast<std::size_t>(contentSize);
            header.hasContentSize = true;
        }
        header.contentChecksum = (descriptor & 0x04u) != 0u;
        header.position = position + contentSizeBytes;
        return header.dictionary ? ZstdResult::Unsupported : ZstdResult::Ok;
    }

public:
    ZstdResult decode(const std::uint8_t* compressed,
                      std::size_t compressedSize,
                      std::vector<std::uint8_t>& output) const
    {
        return decode(compressed, compressedSize, output,
                      kZstdMaximumBytes, nullptr, nullptr);
    }

    ZstdResult decode(const std::uint8_t* compressed,
                      std::size_t compressedSize,
                      std::vector<std::uint8_t>& output,
                      std::size_t maximumOutputBytes,
                      ZstdCancellationFunction cancellation,
                      void* cancellationContext) const
    {
        output.clear();
        if (compressed == nullptr && compressedSize != 0u)
            return ZstdResult::InvalidArgument;
        if (compressedSize > kZstdMaximumBytes ||
            maximumOutputBytes > kZstdMaximumBytes)
            return ZstdResult::Limit;
        if (cancelled(cancellation, cancellationContext))
            return ZstdResult::Cancelled;

        Header header;
        const ZstdResult headerResult = parseHeader(
            compressed, compressedSize, maximumOutputBytes, header);
        if (headerResult != ZstdResult::Ok)
            return headerResult == ZstdResult::Unsupported
                ? ZstdResult::Unsupported : fail(output, headerResult);

        std::size_t position = header.position;
        std::size_t blockCount = 0u;
        bool last = false;
        while (!last) {
            if (cancelled(cancellation, cancellationContext))
                return fail(output, ZstdResult::Cancelled);
            if (blockCount >= kZstdMaximumBlocks)
                return fail(output, ZstdResult::Limit);
            ++blockCount;
            if (compressedSize - position < 3u)
                return fail(output, ZstdResult::Malformed);
            const std::uint32_t blockHeader =
                zstd_detail::read24(compressed + position);
            position += 3u;
            const std::size_t blockSize = blockHeader >> 3u;
            const unsigned blockType = (blockHeader >> 1u) & 0x03u;
            last = (blockHeader & 1u) != 0u;
            if (blockSize > kZstdMaximumBlockBytes)
                return fail(output, ZstdResult::Malformed);
            if (blockType == 0u) {
                if (blockSize > compressedSize - position)
                    return fail(output, ZstdResult::Malformed);
                if (blockSize > maximumOutputBytes - output.size())
                    return fail(output, ZstdResult::Limit);
                if (!zstd_detail::appendWithinLimit(
                        output, compressed + position, blockSize))
                    return fail(output, ZstdResult::Limit);
                position += blockSize;
            } else if (blockType == 1u) {
                if (position >= compressedSize)
                    return fail(output, ZstdResult::Malformed);
                if (blockSize > maximumOutputBytes - output.size())
                    return fail(output, ZstdResult::Limit);
                const std::uint8_t value = compressed[position++];
                for (std::size_t index = 0u; index < blockSize; ++index) {
                    if ((index & 0xfffu) == 0u &&
                        cancelled(cancellation, cancellationContext))
                        return fail(output, ZstdResult::Cancelled);
                    output.push_back(value);
                }
            } else if (blockType == 2u) {
                return fail(output, ZstdResult::Unsupported);
            } else {
                return fail(output, ZstdResult::Malformed);
            }
        }

        if (header.contentChecksum) {
            if (compressedSize - position < 4u)
                return fail(output, ZstdResult::Malformed);
            const std::uint32_t expected =
                zstd_detail::read32(compressed + position);
            position += 4u;
            if (zstd_detail::xxh64Low32(output.data(), output.size()) != expected)
                return fail(output, ZstdResult::ChecksumMismatch);
        }
        if (position != compressedSize ||
            (header.hasContentSize && output.size() != header.contentSize))
            return fail(output, ZstdResult::Malformed);
        return cancelled(cancellation, cancellationContext)
            ? fail(output, ZstdResult::Cancelled) : ZstdResult::Ok;
    }
};

} // namespace RinCompression

#endif /* RINCOMPRESSION_ZSTD_HPP */
