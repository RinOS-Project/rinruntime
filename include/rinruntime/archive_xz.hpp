/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded XZ stream structure inspection. */

#ifndef RINRUNTIME_ARCHIVE_XZ_HPP
#define RINRUNTIME_ARCHIVE_XZ_HPP

#include "archive_deflate.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace RinRuntime {

enum class ArchiveXzResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Unsupported = -5,
};

struct ArchiveXzSummary {
    std::size_t streamSize = 0u;
    std::size_t indexOffset = 0u;
    std::size_t indexSize = 0u;
    std::uint64_t uncompressedSize = 0u;
    std::uint64_t compressedSize = 0u;
    std::uint32_t blockCount = 0u;
    std::uint8_t checkType = 0u;
    std::uint8_t reserved[3] = {0u, 0u, 0u};
};

/*
 * This is deliberately an inspector, not an XZ decoder.  It verifies the
 * bounded stream envelope, header/footer/index CRCs, block-header CRCs,
 * block boundaries, and size accounting without opening a path or allocating
 * according to untrusted metadata.  A caller that needs decoded bytes must
 * provide a separate XZ owner/backend; the public runtime never pretends
 * that structural validation is decompression.
 */
class ArchiveXzReader final {
public:
    static constexpr std::size_t kMaxStreamBytes =
        static_cast<std::size_t>(RINRUNTIME_ARCHIVE_CONTENT_LIMIT);

    ArchiveXzResult inspect(const std::uint8_t* bytes, std::size_t size,
                            ArchiveXzSummary& output) const
    {
        output = {};
        if (bytes == nullptr) return ArchiveXzResult::InvalidArgument;
        if (size < kHeaderSize + kFooterSize)
            return ArchiveXzResult::Malformed;
        if (size > kMaxStreamBytes) return ArchiveXzResult::Limit;

        if (bytes[0] != 0xfdu || bytes[1] != 0x37u || bytes[2] != 0x7au ||
            bytes[3] != 0x58u || bytes[4] != 0x5au || bytes[5] != 0x00u)
            return ArchiveXzResult::Malformed;

        const std::uint8_t headerFlags[2] = {bytes[6], bytes[7]};
        const std::uint8_t checkType =
            static_cast<std::uint8_t>(headerFlags[1] & 0x0fu);
        if (headerFlags[0] != 0u || (headerFlags[1] & 0xf0u) != 0u)
            return ArchiveXzResult::Malformed;
        if (!checkTypeSupported(checkType))
            return ArchiveXzResult::Unsupported;
        if (readLe32(bytes + 8u) != rinruntime_archive_crc32(bytes + 6u, 2u))
            return ArchiveXzResult::CrcMismatch;

        const std::size_t footerOffset = size - kFooterSize;
        const std::size_t footerFlagsOffset = size - 4u;
        const std::size_t backwardSizeOffset = size - 8u;
        if (bytes[size - 2u] != static_cast<std::uint8_t>('Y') ||
            bytes[size - 1u] != static_cast<std::uint8_t>('Z'))
            return ArchiveXzResult::Malformed;
        if (bytes[footerFlagsOffset] != headerFlags[0] ||
            bytes[footerFlagsOffset + 1u] != headerFlags[1])
            return ArchiveXzResult::Malformed;
        if (readLe32(bytes + footerOffset) !=
            rinruntime_archive_crc32(bytes + backwardSizeOffset, 6u))
            return ArchiveXzResult::CrcMismatch;

        const std::uint32_t backwardSize = readLe32(bytes + backwardSizeOffset);
        const std::uint64_t indexSize64 =
            (static_cast<std::uint64_t>(backwardSize) + 1u) * 4u;
        if (indexSize64 < kMinimumIndexSize ||
            indexSize64 > footerOffset - kHeaderSize)
            return ArchiveXzResult::Malformed;
        const std::size_t indexSize = static_cast<std::size_t>(indexSize64);
        const std::size_t indexOffset = footerOffset - indexSize;
        if ((indexOffset & 3u) != 0u || indexOffset < kHeaderSize)
            return ArchiveXzResult::Malformed;
        if (readLe32(bytes + footerOffset - 4u) !=
            rinruntime_archive_crc32(bytes + indexOffset, indexSize - 4u))
            return ArchiveXzResult::CrcMismatch;
        if (bytes[indexOffset] != 0u)
            return ArchiveXzResult::Malformed;

        std::size_t cursor = indexOffset + 1u;
        const std::size_t indexDataEnd = footerOffset - 4u;
        std::uint64_t recordCount = 0u;
        if (!readVli(bytes, indexDataEnd, cursor, recordCount))
            return ArchiveXzResult::Malformed;
        if (recordCount > RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
            return ArchiveXzResult::Limit;

        std::array<std::uint64_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            indexedUnpadded{};
        std::array<std::uint64_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            indexedUncompressed{};
        std::uint64_t totalUncompressed = 0u;
        for (std::size_t index = 0u; index < recordCount; ++index) {
            if (!readVli(bytes, indexDataEnd, cursor, indexedUnpadded[index]) ||
                !readVli(bytes, indexDataEnd, cursor,
                         indexedUncompressed[index]) ||
                indexedUnpadded[index] == 0u)
                return ArchiveXzResult::Malformed;
            if (indexedUncompressed[index] > RINRUNTIME_ARCHIVE_CONTENT_LIMIT ||
                totalUncompressed >
                    RINRUNTIME_ARCHIVE_CONTENT_LIMIT - indexedUncompressed[index])
                return ArchiveXzResult::Limit;
            totalUncompressed += indexedUncompressed[index];
        }
        while (cursor < indexDataEnd) {
            if (bytes[cursor++] != 0u) return ArchiveXzResult::Malformed;
        }

        std::size_t blockOffset = kHeaderSize;
        std::uint64_t totalCompressed = 0u;
        std::size_t blockCount = 0u;
        while (blockOffset < indexOffset) {
            if (blockCount >= recordCount)
                return ArchiveXzResult::Malformed;
            const std::size_t blockStart = blockOffset;
            const std::size_t blockHeaderSize =
                (static_cast<std::size_t>(bytes[blockOffset]) + 1u) * 4u;
            if (blockHeaderSize < 8u ||
                blockHeaderSize > indexOffset - blockOffset)
                return ArchiveXzResult::Malformed;
            const std::size_t headerEnd = blockOffset + blockHeaderSize;
            const std::size_t headerDataEnd = headerEnd - 4u;
            const std::uint8_t blockFlags = bytes[blockOffset + 1u];
            if ((blockFlags & 0x3cu) != 0u)
                return ArchiveXzResult::Malformed;

            std::size_t headerCursor = blockOffset + 2u;
            std::uint64_t compressedSize = 0u;
            std::uint64_t uncompressedSize = 0u;
            const bool hasCompressedSize = (blockFlags & 0x40u) != 0u;
            const bool hasUncompressedSize = (blockFlags & 0x80u) != 0u;
            if (hasCompressedSize &&
                !readVli(bytes, headerDataEnd, headerCursor, compressedSize))
                return ArchiveXzResult::Malformed;
            if (hasUncompressedSize &&
                !readVli(bytes, headerDataEnd, headerCursor,
                         uncompressedSize))
                return ArchiveXzResult::Malformed;
            const std::size_t filterCount =
                static_cast<std::size_t>((blockFlags & 0x03u) + 1u);
            for (std::size_t filter = 0u; filter < filterCount; ++filter) {
                std::uint64_t filterId = 0u;
                std::uint64_t propertySize = 0u;
                (void)filterId;
                if (!readVli(bytes, headerDataEnd, headerCursor, filterId) ||
                    !readVli(bytes, headerDataEnd, headerCursor, propertySize) ||
                    propertySize > headerDataEnd - headerCursor)
                    return ArchiveXzResult::Malformed;
                headerCursor += static_cast<std::size_t>(propertySize);
            }
            if (headerCursor > headerDataEnd)
                return ArchiveXzResult::Malformed;
            while (headerCursor < headerDataEnd) {
                if (bytes[headerCursor++] != 0u)
                    return ArchiveXzResult::Malformed;
            }
            if (readLe32(bytes + headerDataEnd) !=
                rinruntime_archive_crc32(bytes + blockOffset,
                                         blockHeaderSize - 4u))
                return ArchiveXzResult::CrcMismatch;
            if (!hasCompressedSize)
                return ArchiveXzResult::Unsupported;
            if (compressedSize > RINRUNTIME_ARCHIVE_CONTENT_LIMIT ||
                totalCompressed >
                    RINRUNTIME_ARCHIVE_CONTENT_LIMIT - compressedSize)
                return ArchiveXzResult::Limit;
            if (hasUncompressedSize &&
                uncompressedSize > RINRUNTIME_ARCHIVE_CONTENT_LIMIT)
                return ArchiveXzResult::Limit;
            const std::size_t payloadOffset = headerEnd;
            if (compressedSize > static_cast<std::uint64_t>(
                                     indexOffset - payloadOffset))
                return ArchiveXzResult::Malformed;
            const std::size_t compressed =
                static_cast<std::size_t>(compressedSize);
            const std::size_t checkSize = checkSizeFor(checkType);
            const std::size_t afterCheck = payloadOffset + compressed + checkSize;
            if (afterCheck < payloadOffset || afterCheck > indexOffset)
                return ArchiveXzResult::Malformed;
            const std::size_t nextBlock = (afterCheck + 3u) & ~std::size_t(3u);
            if (nextBlock < afterCheck || nextBlock > indexOffset)
                return ArchiveXzResult::Malformed;
            for (std::size_t padding = afterCheck; padding < nextBlock;
                 ++padding) {
                if (bytes[padding] != 0u) return ArchiveXzResult::Malformed;
            }
            const std::uint64_t unpaddedSize =
                static_cast<std::uint64_t>(afterCheck - blockStart);
            if (indexedUnpadded[blockCount] != unpaddedSize ||
                (hasUncompressedSize &&
                 indexedUncompressed[blockCount] != uncompressedSize))
                return ArchiveXzResult::Malformed;
            totalCompressed += compressedSize;
            blockOffset = nextBlock;
            ++blockCount;
        }
        if (blockOffset != indexOffset || blockCount != recordCount)
            return ArchiveXzResult::Malformed;

        output.streamSize = size;
        output.indexOffset = indexOffset;
        output.indexSize = indexSize;
        output.uncompressedSize = totalUncompressed;
        output.compressedSize = totalCompressed;
        output.blockCount = static_cast<std::uint32_t>(blockCount);
        output.checkType = checkType;
        return ArchiveXzResult::Ok;
    }

private:
    static constexpr std::size_t kHeaderSize = 12u;
    static constexpr std::size_t kFooterSize = 12u;
    static constexpr std::size_t kMinimumIndexSize = 8u;

    static std::uint32_t readLe32(const std::uint8_t* bytes)
    {
        return static_cast<std::uint32_t>(bytes[0]) |
               static_cast<std::uint32_t>(bytes[1]) << 8u |
               static_cast<std::uint32_t>(bytes[2]) << 16u |
               static_cast<std::uint32_t>(bytes[3]) << 24u;
    }

    static bool checkTypeSupported(std::uint8_t checkType)
    {
        return checkType == 0u || checkType == 1u || checkType == 4u;
    }

    static std::size_t checkSizeFor(std::uint8_t checkType)
    {
        return checkType == 0u ? 0u : (checkType == 1u ? 4u : 8u);
    }

    static bool readVli(const std::uint8_t* bytes, std::size_t end,
                       std::size_t& cursor, std::uint64_t& output)
    {
        output = 0u;
        unsigned shift = 0u;
        for (unsigned count = 0u; count != 9u; ++count) {
            if (cursor >= end || shift >= 64u) return false;
            const std::uint8_t value = bytes[cursor++];
            const std::uint64_t payload = value & 0x7fu;
            if (shift == 63u && payload > 1u) return false;
            output |= payload << shift;
            if ((value & 0x80u) == 0u) return true;
            shift += 7u;
        }
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_XZ_HPP */
