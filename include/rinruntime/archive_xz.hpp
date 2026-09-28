/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded XZ stream structure inspection. */

#ifndef RINRUNTIME_ARCHIVE_XZ_HPP
#define RINRUNTIME_ARCHIVE_XZ_HPP

#include "archive_deflate.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace RinRuntime {

enum class ArchiveXzResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Unsupported = -5,
    Cancelled = -6,
    Deadline = -7,
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
            if (!hasCompressedSize) {
                const std::uint64_t indexedSize = indexedUnpadded[blockCount];
                const std::uint64_t fixedSize =
                    static_cast<std::uint64_t>(blockHeaderSize) +
                    static_cast<std::uint64_t>(checkSizeFor(checkType));
                if (indexedSize < fixedSize)
                    return ArchiveXzResult::Malformed;
                compressedSize = indexedSize - fixedSize;
            }
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
            const std::size_t payloadEnd = payloadOffset + compressed;
            const std::size_t checkOffset =
                (payloadEnd + 3u) & ~std::size_t(3u);
            const std::size_t afterCheck = checkOffset + checkSize;
            if (payloadEnd < payloadOffset || checkOffset < payloadEnd ||
                afterCheck < checkOffset || afterCheck > indexOffset)
                return ArchiveXzResult::Malformed;
            for (std::size_t padding = payloadEnd; padding < checkOffset;
                 ++padding) {
                if (bytes[padding] != 0u) return ArchiveXzResult::Malformed;
            }
            const std::uint64_t unpaddedSize =
                static_cast<std::uint64_t>(payloadEnd - blockStart) +
                static_cast<std::uint64_t>(checkSize);
            if (indexedUnpadded[blockCount] != unpaddedSize ||
                (hasUncompressedSize &&
                 indexedUncompressed[blockCount] != uncompressedSize))
                return ArchiveXzResult::Malformed;
            totalCompressed += compressedSize;
            blockOffset = afterCheck;
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

    /* Decode bounded LZMA2 chunks.  Stored chunks remain supported for
     * deterministic producers, while range-coded chunks use the same
     * caller-owned output, deadline, and cancellation boundary.  The public
     * reader still does not open paths or publish files. */
    ArchiveXzResult decodeStoredLzma2(const std::uint8_t* bytes,
                                      std::size_t size,
                                      std::string& output) const
    {
        return decodeStoredLzma2(bytes, size, output, nullptr, nullptr,
                                 nullptr, nullptr);
    }

    ArchiveXzResult decodeStoredLzma2(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeStoredLzma2(bytes, size, output, cancellation,
                                 cancellationContext, nullptr, nullptr);
    }

    ArchiveXzResult decodeStoredLzma2WithDeadline(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateDeadlineFunction deadline, void* deadlineContext) const
    {
        return decodeStoredLzma2(bytes, size, output, nullptr, nullptr,
                                 deadline, deadlineContext);
    }

    /* Decode one raw LZMA1 range-coded stream.  7z stores the five-byte LZMA
     * properties outside the packed stream, so this helper keeps the shared
     * bounded LZMA core available without making the XZ block parser a 7z
     * authority. */
    ArchiveXzResult decodeRawLzma(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::uint8_t properties, std::size_t dictionarySize,
        std::size_t expectedSize, std::string& output) const
    {
        return decodeRawLzma(compressed, compressedSize, properties,
                             dictionarySize, expectedSize, output, nullptr,
                             nullptr, nullptr, nullptr);
    }

    ArchiveXzResult decodeRawLzma(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::uint8_t properties, std::size_t dictionarySize,
        std::size_t expectedSize, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeRawLzma(compressed, compressedSize, properties,
                             dictionarySize, expectedSize, output,
                             cancellation, cancellationContext, nullptr,
                             nullptr);
    }

    ArchiveXzResult decodeRawLzmaWithDeadline(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::uint8_t properties, std::size_t dictionarySize,
        std::size_t expectedSize, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
        return decodeRawLzma(compressed, compressedSize, properties,
                             dictionarySize, expectedSize, output,
                             cancellation, cancellationContext, deadline,
                             deadlineContext);
    }

private:
    enum class LzmaStatus : int {
        Ok = 0,
        Malformed = -1,
        Limit = -2,
        Cancelled = -3,
        Deadline = -4,
    };

    struct LzmaRangeDecoder {
        const std::uint8_t* bytes = nullptr;
        std::size_t end = 0u;
        std::size_t cursor = 0u;
        std::uint32_t range = 0xffffffffu;
        std::uint32_t code = 0u;
        bool valid = true;

        bool initialize(const std::uint8_t* input, std::size_t inputSize)
        {
            bytes = input;
            end = inputSize;
            cursor = 0u;
            range = 0xffffffffu;
            code = 0u;
            valid = input != nullptr && inputSize >= 5u;
            if (!valid) return false;
            for (unsigned index = 0u; index != 5u; ++index)
                code = (code << 8u) | bytes[cursor++];
            return true;
        }

        bool normalize()
        {
            while (range < UINT32_C(0x01000000)) {
                if (cursor >= end) {
                    valid = false;
                    return false;
                }
                range <<= 8u;
                code = (code << 8u) | bytes[cursor++];
            }
            return true;
        }

        bool decodeBit(std::uint16_t& probability, unsigned& bit)
        {
            if (!normalize()) return false;
            const std::uint32_t bound =
                (range >> 11u) * static_cast<std::uint32_t>(probability);
            if (code < bound) {
                range = bound;
                probability = static_cast<std::uint16_t>(
                    probability + ((UINT16_C(2048) - probability) >> 5u));
                bit = 0u;
            } else {
                range -= bound;
                code -= bound;
                probability = static_cast<std::uint16_t>(
                    probability - (probability >> 5u));
                bit = 1u;
            }
            return true;
        }

        bool decodeDirect(unsigned count, std::uint32_t& value)
        {
            value = 0u;
            for (unsigned index = 0u; index != count; ++index) {
                if (!normalize()) return false;
                range >>= 1u;
                if (code >= range) {
                    code -= range;
                    value = (value << 1u) | 1u;
                } else {
                    value <<= 1u;
                }
            }
            return true;
        }
    };

    struct LzmaDecoder {
        static constexpr unsigned kNumStates = 12u;
        static constexpr unsigned kNumPosBitsMax = 4u;
        static constexpr unsigned kNumPosStatesMax = 1u << kNumPosBitsMax;
        static constexpr unsigned kNumLenToPosStates = 4u;
        static constexpr unsigned kNumAlignBits = 4u;
        static constexpr unsigned kStartPosModelIndex = 4u;
        static constexpr unsigned kEndPosModelIndex = 14u;
        static constexpr unsigned kNumFullDistances =
            1u << (kEndPosModelIndex >> 1u);
        static constexpr unsigned kNumLowLenSymbols = 1u << 3u;
        static constexpr unsigned kNumMidLenSymbols = 1u << 3u;
        static constexpr unsigned kNumHighLenSymbols = 1u << 8u;

        std::array<std::uint16_t, kNumStates * kNumPosStatesMax> isMatch{};
        std::array<std::uint16_t, kNumStates> isRep{};
        std::array<std::uint16_t, kNumStates> isRepG0{};
        std::array<std::uint16_t, kNumStates> isRepG1{};
        std::array<std::uint16_t, kNumStates> isRepG2{};
        std::array<std::uint16_t, kNumStates * kNumPosStatesMax>
            isRep0Long{};
        std::array<std::uint16_t, kNumLenToPosStates * 64u> posSlot{};
        /* The canonical model uses 114 entries, but the last reverse tree
         * reaches one shared sentinel index on malformed paths.  Keeping the
         * full 128-entry bounded table makes that path memory-safe while the
         * valid model still uses only the canonical prefix. */
        std::array<std::uint16_t, kNumFullDistances> specPos{};
        std::array<std::uint16_t, 1u << kNumAlignBits> align{};
        std::array<std::uint16_t, 2u> lenChoice{};
        std::array<std::uint16_t, kNumPosStatesMax * kNumLowLenSymbols>
            lenLow{};
        std::array<std::uint16_t, kNumPosStatesMax * kNumMidLenSymbols>
            lenMid{};
        std::array<std::uint16_t, kNumHighLenSymbols> lenHigh{};
        std::array<std::uint16_t, 2u> repLenChoice{};
        std::array<std::uint16_t, kNumPosStatesMax * kNumLowLenSymbols>
            repLenLow{};
        std::array<std::uint16_t, kNumPosStatesMax * kNumMidLenSymbols>
            repLenMid{};
        std::array<std::uint16_t, kNumHighLenSymbols> repLenHigh{};
        std::vector<std::uint16_t> literal{};
        unsigned literalContextBits = 0u;
        unsigned literalPositionBits = 0u;
        unsigned positionBits = 0u;
        unsigned state = 0u;
        std::uint32_t reps[4] = {0u, 0u, 0u, 0u};
        bool initialized = false;

        static void initializeProbabilities(std::uint16_t* values,
                                            std::size_t count)
        {
            for (std::size_t index = 0u; index != count; ++index)
                values[index] = UINT16_C(1024);
        }

        void resetState()
        {
            initializeProbabilities(isMatch.data(), isMatch.size());
            initializeProbabilities(isRep.data(), isRep.size());
            initializeProbabilities(isRepG0.data(), isRepG0.size());
            initializeProbabilities(isRepG1.data(), isRepG1.size());
            initializeProbabilities(isRepG2.data(), isRepG2.size());
            initializeProbabilities(isRep0Long.data(), isRep0Long.size());
            initializeProbabilities(posSlot.data(), posSlot.size());
            initializeProbabilities(specPos.data(), specPos.size());
            initializeProbabilities(align.data(), align.size());
            initializeProbabilities(lenChoice.data(), lenChoice.size());
            initializeProbabilities(lenLow.data(), lenLow.size());
            initializeProbabilities(lenMid.data(), lenMid.size());
            initializeProbabilities(lenHigh.data(), lenHigh.size());
            initializeProbabilities(repLenChoice.data(), repLenChoice.size());
            initializeProbabilities(repLenLow.data(), repLenLow.size());
            initializeProbabilities(repLenMid.data(), repLenMid.size());
            initializeProbabilities(repLenHigh.data(), repLenHigh.size());
            initializeProbabilities(literal.data(), literal.size());
            state = 0u;
            reps[0] = reps[1] = reps[2] = reps[3] = 0u;
        }

        LzmaStatus setProperties(std::uint8_t properties)
        {
            if (properties > 224u) return LzmaStatus::Malformed;
            unsigned remainder = properties;
            literalContextBits = remainder % 9u;
            remainder /= 9u;
            literalPositionBits = remainder % 5u;
            positionBits = remainder / 5u;
            if (literalContextBits > 8u || literalPositionBits > 4u ||
                positionBits > 4u)
                return LzmaStatus::Malformed;
            const std::size_t contexts =
                std::size_t(1u) << (literalContextBits + literalPositionBits);
            if (contexts > (static_cast<std::size_t>(-1) / 0x300u))
                return LzmaStatus::Limit;
            literal.assign(contexts * 0x300u, UINT16_C(1024));
            resetState();
            initialized = true;
            return LzmaStatus::Ok;
        }

        static unsigned lenToPosState(unsigned length)
        {
            const unsigned value = length - 2u;
            return value < (kNumLenToPosStates * 2u)
                       ? value >> 1u
                       : kNumLenToPosStates - 1u;
        }

        static void updateLiteralState(unsigned& value)
        {
            value = value < 4u ? 0u : (value < 10u ? value - 3u : value - 6u);
        }

        static void updateMatchState(unsigned& value)
        {
            value = value < 7u ? 7u : 10u;
        }

        static void updateRepState(unsigned& value)
        {
            value = value < 7u ? 8u : 11u;
        }

        static void updateShortRepState(unsigned& value)
        {
            value = value < 7u ? 9u : 11u;
        }

        static bool decodeBitTree(LzmaRangeDecoder& range,
                                  std::uint16_t* probabilities,
                                  unsigned bits, unsigned& value)
        {
            unsigned symbol = 1u;
            for (unsigned index = 0u; index != bits; ++index) {
                unsigned bit = 0u;
                if (!range.decodeBit(probabilities[symbol], bit)) return false;
                symbol = (symbol << 1u) | bit;
            }
            value = symbol - (1u << bits);
            return true;
        }

        static bool decodeReverseBitTree(LzmaRangeDecoder& range,
                                         std::uint16_t* probabilities,
                                         unsigned bits, unsigned& value)
        {
            unsigned symbol = 1u;
            value = 0u;
            for (unsigned index = 0u; index != bits; ++index) {
                unsigned bit = 0u;
                if (!range.decodeBit(probabilities[symbol], bit)) return false;
                symbol = (symbol << 1u) | bit;
                value |= bit << index;
            }
            return true;
        }

        static bool decodeLength(LzmaRangeDecoder& range, unsigned posState,
                                 std::array<std::uint16_t, 2u>& choice,
                                 std::array<std::uint16_t,
                                            kNumPosStatesMax *
                                                kNumLowLenSymbols>& low,
                                 std::array<std::uint16_t,
                                            kNumPosStatesMax *
                                                kNumMidLenSymbols>& mid,
                                 std::array<std::uint16_t,
                                            kNumHighLenSymbols>& high,
                                 unsigned& length)
        {
            unsigned bit = 0u;
            if (!range.decodeBit(choice[0], bit)) return false;
            if (bit == 0u) {
                unsigned value = 0u;
                if (!decodeBitTree(range, low.data() +
                                             posState * kNumLowLenSymbols,
                                   3u, value))
                    return false;
                length = value + 2u;
                return true;
            }
            if (!range.decodeBit(choice[1], bit)) return false;
            if (bit == 0u) {
                unsigned value = 0u;
                if (!decodeBitTree(range, mid.data() +
                                             posState * kNumMidLenSymbols,
                                   3u, value))
                    return false;
                length = value + 2u + kNumLowLenSymbols;
                return true;
            }
            unsigned value = 0u;
            if (!decodeBitTree(range, high.data(), 8u, value)) return false;
            length = value + 2u + kNumLowLenSymbols + kNumMidLenSymbols;
            return true;
        }

        bool decodeLiteral(LzmaRangeDecoder& range, std::string& output,
                           std::size_t historyStart)
        {
            if (!initialized || output.size() < historyStart) return false;
            const std::size_t position = output.size() - historyStart;
            const std::uint8_t previous = output.empty()
                                               ? 0u
                                               : static_cast<std::uint8_t>(
                                                     output.back());
            const unsigned context =
                ((static_cast<unsigned>(position) &
                  ((1u << literalPositionBits) - 1u)) <<
                 literalContextBits) |
                (static_cast<unsigned>(previous) >>
                 (8u - literalContextBits));
            std::uint16_t* probabilities = literal.data() + context * 0x300u;
            unsigned symbol = 1u;
            if (state < 7u) {
                while (symbol < 0x100u) {
                    unsigned bit = 0u;
                    if (!range.decodeBit(probabilities[symbol], bit))
                        return false;
                    symbol = (symbol << 1u) | bit;
                }
            } else {
                if (reps[0] >= output.size() - historyStart) return false;
                std::uint8_t match = static_cast<std::uint8_t>(
                    output[output.size() - reps[0] - 1u]);
                do {
                    const unsigned matchBit = (match >> 7u) & 1u;
                    match = static_cast<std::uint8_t>(match << 1u);
                    unsigned bit = 0u;
                    if (!range.decodeBit(
                            probabilities[((1u + matchBit) << 8u) + symbol],
                            bit))
                        return false;
                    symbol = (symbol << 1u) | bit;
                    if (matchBit != bit) {
                        while (symbol < 0x100u) {
                            if (!range.decodeBit(probabilities[symbol], bit))
                                return false;
                            symbol = (symbol << 1u) | bit;
                        }
                        break;
                    }
                } while (symbol < 0x100u);
            }
            output.push_back(static_cast<char>(symbol));
            updateLiteralState(state);
            return true;
        }

        bool decodeDistance(LzmaRangeDecoder& range, unsigned length,
                            std::uint32_t& distance)
        {
            const unsigned stateIndex = lenToPosState(length);
            unsigned slot = 0u;
            if (!decodeBitTree(range, posSlot.data() + stateIndex * 64u, 6u,
                               slot))
                return false;
            if (slot < kStartPosModelIndex) {
                distance = slot;
                return true;
            }
            const unsigned directBits = (slot >> 1u) - 1u;
            distance = (2u | (slot & 1u)) << directBits;
            if (slot < kEndPosModelIndex) {
                const unsigned index = distance - slot;
                unsigned value = 0u;
                if (!decodeReverseBitTree(range, specPos.data() + index,
                                          directBits, value))
                    return false;
                distance += value;
                return true;
            }
            std::uint32_t direct = 0u;
            if (!range.decodeDirect(directBits - kNumAlignBits, direct))
                return false;
            distance += direct << kNumAlignBits;
            unsigned aligned = 0u;
            if (!decodeReverseBitTree(range, align.data(), kNumAlignBits,
                                      aligned))
                return false;
            distance += aligned;
            return true;
        }

        LzmaStatus decodeChunk(const std::uint8_t* compressed,
                               std::size_t compressedSize,
                               std::size_t targetSize, std::string& output,
                               std::size_t historyStart,
                               std::size_t dictionarySize,
                               ArchiveDeflateCancellationFunction cancellation,
                               void* cancellationContext,
                               ArchiveDeflateDeadlineFunction deadline,
                               void* deadlineContext) {
            if (!initialized || compressed == nullptr || compressedSize < 5u)
                return LzmaStatus::Malformed;
            if (targetSize > kMaxStreamBytes - output.size())
                return LzmaStatus::Limit;
            LzmaRangeDecoder range;
            if (!range.initialize(compressed, compressedSize))
                return LzmaStatus::Malformed;
            const std::size_t targetEnd = output.size() + targetSize;
            while (output.size() < targetEnd) {
                if ((output.size() & 4095u) == 0u) {
                    if (deadline != nullptr && deadline(deadlineContext))
                        return LzmaStatus::Deadline;
                    if (cancellation != nullptr &&
                        cancellation(cancellationContext))
                        return LzmaStatus::Cancelled;
                }
                const unsigned positionState =
                    static_cast<unsigned>((output.size() - historyStart) &
                                          ((1u << positionBits) - 1u));
                unsigned bit = 0u;
                if (!range.decodeBit(
                        isMatch[state * kNumPosStatesMax + positionState],
                        bit))
                    return LzmaStatus::Malformed;
                if (bit == 0u) {
                    if (!decodeLiteral(range, output, historyStart))
                        return LzmaStatus::Malformed;
                    continue;
                }

                if (!range.decodeBit(isRep[state], bit))
                    return LzmaStatus::Malformed;
                unsigned length = 0u;
                std::uint32_t distance = 0u;
                if (bit != 0u) {
                    if (!range.decodeBit(isRepG0[state], bit))
                        return LzmaStatus::Malformed;
                    if (bit == 0u) {
                        if (!range.decodeBit(
                                isRep0Long[state * kNumPosStatesMax +
                                           positionState],
                                bit))
                                return LzmaStatus::Malformed;
                        distance = reps[0];
                        if (bit == 0u) {
                            updateShortRepState(state);
                            length = 1u;
                        } else {
                            updateRepState(state);
                            if (!decodeLength(range, positionState,
                                             repLenChoice, repLenLow,
                                             repLenMid, repLenHigh, length))
                                return LzmaStatus::Malformed;
                        }
                    } else {
                        if (!range.decodeBit(isRepG1[state], bit))
                            return LzmaStatus::Malformed;
                        if (bit == 0u) {
                            distance = reps[1];
                        } else {
                            if (!range.decodeBit(isRepG2[state], bit))
                                return LzmaStatus::Malformed;
                            if (bit == 0u) {
                                distance = reps[2];
                            } else {
                                distance = reps[3];
                                reps[3] = reps[2];
                            }
                            reps[2] = reps[1];
                        }
                        reps[1] = reps[0];
                        reps[0] = distance;
                        updateRepState(state);
                        if (!decodeLength(range, positionState, repLenChoice,
                                         repLenLow, repLenMid, repLenHigh,
                                         length))
                            return LzmaStatus::Malformed;
                    }
                } else {
                    reps[3] = reps[2];
                    reps[2] = reps[1];
                    reps[1] = reps[0];
                    updateMatchState(state);
                    if (!decodeLength(range, positionState, lenChoice, lenLow,
                                     lenMid, lenHigh, length) ||
                        !decodeDistance(range, length, distance))
                        return LzmaStatus::Malformed;
                    reps[0] = distance;
                }
                if (length > targetEnd - output.size())
                    return LzmaStatus::Malformed;
                const std::size_t available = output.size() - historyStart;
                const std::uint64_t distanceBytes =
                    static_cast<std::uint64_t>(distance) + 1u;
                if (distanceBytes > available ||
                    distanceBytes > dictionarySize)
                    return LzmaStatus::Malformed;
                for (unsigned copy = 0u; copy != length; ++copy) {
                    const std::size_t source = output.size() -
                                               static_cast<std::size_t>(
                                                   distanceBytes);
                    output.push_back(output[source]);
                }
            }
            return range.valid ? LzmaStatus::Ok : LzmaStatus::Malformed;
        }
    };

    ArchiveXzResult decodeStoredLzma2(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
        if (deadline != nullptr && deadline(deadlineContext))
            return ArchiveXzResult::Deadline;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return ArchiveXzResult::Cancelled;
        ArchiveXzSummary summary;
        ArchiveXzResult result = inspect(bytes, size, summary);
        if (result != ArchiveXzResult::Ok) return result;
        if (summary.checkType != 0u && summary.checkType != 1u &&
            summary.checkType != 4u)
            return ArchiveXzResult::Unsupported;

        std::string decoded;
        std::array<std::uint64_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            indexedUnpadded{};
        const std::size_t footerOffset = size - kFooterSize;
        const std::size_t indexDataEnd = footerOffset - 4u;
        std::size_t indexCursor = summary.indexOffset + 1u;
        std::uint64_t recordCount = 0u;
        if (!readVli(bytes, indexDataEnd, indexCursor, recordCount) ||
            recordCount != summary.blockCount)
            return ArchiveXzResult::Malformed;
        for (std::size_t index = 0u; index != recordCount; ++index) {
            std::uint64_t ignoredUncompressed = 0u;
            if (!readVli(bytes, indexDataEnd, indexCursor,
                         indexedUnpadded[index]) ||
                !readVli(bytes, indexDataEnd, indexCursor,
                         ignoredUncompressed))
                return ArchiveXzResult::Malformed;
        }
        std::size_t blockOffset = kHeaderSize;
        std::size_t blockIndex = 0u;
        while (blockOffset < summary.indexOffset) {
            if (deadline != nullptr && deadline(deadlineContext))
                return ArchiveXzResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveXzResult::Cancelled;
            const std::size_t blockHeaderSize =
                (static_cast<std::size_t>(bytes[blockOffset]) + 1u) * 4u;
            const std::size_t headerEnd = blockOffset + blockHeaderSize;
            const std::size_t headerDataEnd = headerEnd - 4u;
            const std::uint8_t blockFlags = bytes[blockOffset + 1u];

            std::size_t headerCursor = blockOffset + 2u;
            std::uint64_t compressedSize = 0u;
            std::uint64_t ignoredUncompressedSize = 0u;
            const bool hasCompressedSize = (blockFlags & 0x40u) != 0u;
            if (hasCompressedSize &&
                !readVli(bytes, headerDataEnd, headerCursor, compressedSize))
                return ArchiveXzResult::Malformed;
            if ((blockFlags & 0x80u) != 0u &&
                !readVli(bytes, headerDataEnd, headerCursor,
                         ignoredUncompressedSize))
                return ArchiveXzResult::Malformed;

            const std::size_t filterCount =
                static_cast<std::size_t>((blockFlags & 0x03u) + 1u);
            if (filterCount > 2u) return ArchiveXzResult::Unsupported;
            bool lzmaFilterPresent = false;
            std::uint8_t dictionaryProperty = 0u;
            std::size_t deltaDistance = 0u;
            bool x86FilterPresent = false;
            std::uint32_t x86StartOffset = 0u;
            bool armFilterPresent = false;
            bool armThumbFilterPresent = false;
            bool arm64FilterPresent = false;
            for (std::size_t filter = 0u; filter < filterCount; ++filter) {
                std::uint64_t filterId = 0u;
                std::uint64_t propertySize = 0u;
                if (!readVli(bytes, headerDataEnd, headerCursor, filterId) ||
                    !readVli(bytes, headerDataEnd, headerCursor, propertySize) ||
                    propertySize > headerDataEnd - headerCursor)
                    return ArchiveXzResult::Malformed;
                if (filterId == 0x21u) {
                    if (lzmaFilterPresent || propertySize != 1u ||
                        headerCursor >= headerDataEnd)
                        return ArchiveXzResult::Unsupported;
                    dictionaryProperty = bytes[headerCursor++];
                    lzmaFilterPresent = true;
                } else if (filterId == 0x03u) {
                    if (deltaDistance != 0u || propertySize != 1u ||
                        headerCursor >= headerDataEnd)
                        return ArchiveXzResult::Unsupported;
                    deltaDistance = static_cast<std::size_t>(
                        bytes[headerCursor++]) + 1u;
                } else if (filterId == 0x04u) {
                    if (x86FilterPresent || propertySize != 4u ||
                        propertySize > headerDataEnd - headerCursor)
                        return ArchiveXzResult::Unsupported;
                    x86StartOffset = readLe32(bytes + headerCursor);
                    headerCursor += 4u;
                    x86FilterPresent = true;
                } else if (filterId == 0x07u) {
                    if (armFilterPresent || propertySize != 0u)
                        return ArchiveXzResult::Unsupported;
                    armFilterPresent = true;
                } else if (filterId == 0x08u) {
                    if (armThumbFilterPresent || propertySize != 0u)
                        return ArchiveXzResult::Unsupported;
                    armThumbFilterPresent = true;
                } else if (filterId == 0x0au) {
                    if (arm64FilterPresent || propertySize != 0u)
                        return ArchiveXzResult::Unsupported;
                    arm64FilterPresent = true;
                } else {
                    return ArchiveXzResult::Unsupported;
                }
            }
            if (!lzmaFilterPresent) return ArchiveXzResult::Unsupported;
            if (dictionaryProperty > 40u) return ArchiveXzResult::Malformed;
            const std::uint64_t requestedDictionary =
                dictionaryProperty == 40u
                    ? static_cast<std::uint64_t>(kMaxStreamBytes)
                    : (static_cast<std::uint64_t>(2u) |
                       static_cast<std::uint64_t>(dictionaryProperty & 1u))
                          << (dictionaryProperty / 2u + 11u);
            const std::size_t dictionarySize =
                requestedDictionary > kMaxStreamBytes
                    ? kMaxStreamBytes
                    : static_cast<std::size_t>(requestedDictionary);
            while (headerCursor < headerDataEnd) {
                if (bytes[headerCursor++] != 0u)
                    return ArchiveXzResult::Malformed;
            }

            const std::size_t payloadOffset = headerEnd;
            if (!hasCompressedSize) {
                const std::uint64_t fixedSize =
                    static_cast<std::uint64_t>(blockHeaderSize) +
                    static_cast<std::uint64_t>(checkSizeFor(summary.checkType));
                if (blockIndex >= recordCount ||
                    indexedUnpadded[blockIndex] < fixedSize)
                    return ArchiveXzResult::Malformed;
                compressedSize = indexedUnpadded[blockIndex] - fixedSize;
            }
            const std::size_t payloadEnd =
                payloadOffset + static_cast<std::size_t>(compressedSize);
            const std::size_t blockOutputStart = decoded.size();
            std::size_t cursor = payloadOffset;
            std::size_t historyStart = blockOutputStart;
            LzmaDecoder lzma;
            bool streamEnded = false;
            while (cursor < payloadEnd) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return ArchiveXzResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return ArchiveXzResult::Cancelled;
                const std::uint8_t control = bytes[cursor++];
                if (control == 0u) {
                    streamEnded = true;
                    if (cursor != payloadEnd) return ArchiveXzResult::Malformed;
                    break;
                }
                if (control == 0x01u || control == 0x02u) {
                    if (payloadEnd - cursor < 2u)
                        return ArchiveXzResult::Malformed;
                    const std::size_t chunkSize =
                        static_cast<std::size_t>(bytes[cursor]) |
                        (static_cast<std::size_t>(bytes[cursor + 1u]) << 8u);
                    cursor += 2u;
                    const std::size_t chunkBytes = chunkSize + 1u;
                    if (chunkBytes > payloadEnd - cursor)
                        return ArchiveXzResult::Malformed;
                    if (decoded.size() > kMaxStreamBytes ||
                        chunkBytes > kMaxStreamBytes - decoded.size())
                        return ArchiveXzResult::Limit;
                    if (control == 0x01u) {
                        historyStart = decoded.size();
                        lzma.resetState();
                    }
                    std::size_t copied = 0u;
                    while (copied < chunkBytes) {
                        if (deadline != nullptr && deadline(deadlineContext))
                            return ArchiveXzResult::Deadline;
                        if (cancellation != nullptr &&
                            cancellation(cancellationContext))
                            return ArchiveXzResult::Cancelled;
                        const std::size_t part =
                            (chunkBytes - copied) > 65536u
                                ? 65536u
                                : chunkBytes - copied;
                        decoded.append(reinterpret_cast<const char*>(
                                           bytes + cursor + copied),
                                       part);
                        copied += part;
                    }
                    cursor += chunkBytes;
                    continue;
                }
                if (control < 0x80u) return ArchiveXzResult::Malformed;
                if (payloadEnd - cursor < 4u)
                    return ArchiveXzResult::Malformed;
                const std::size_t uncompressedSize =
                    (static_cast<std::size_t>(control & 0x1fu) << 16u) |
                    (static_cast<std::size_t>(bytes[cursor]) << 8u) |
                    static_cast<std::size_t>(bytes[cursor + 1u]);
                cursor += 2u;
                const std::size_t compressedSize =
                    (static_cast<std::size_t>(bytes[cursor]) << 8u) |
                    static_cast<std::size_t>(bytes[cursor + 1u]);
                cursor += 2u;
                const std::size_t chunkUncompressedSize =
                    uncompressedSize +
                    1u;
                const std::size_t compressedBytes = compressedSize + 1u;
                if (compressedBytes > payloadEnd - cursor)
                    return ArchiveXzResult::Malformed;
                if (control >= 0xc0u) {
                    if (cursor >= payloadEnd) return ArchiveXzResult::Malformed;
                    const LzmaStatus propertyResult =
                        lzma.setProperties(bytes[cursor++]);
                    if (propertyResult != LzmaStatus::Ok)
                        return propertyResult == LzmaStatus::Limit
                                   ? ArchiveXzResult::Limit
                                   : ArchiveXzResult::Malformed;
                } else if (!lzma.initialized) {
                    return ArchiveXzResult::Malformed;
                } else if (control >= 0xa0u) {
                    lzma.resetState();
                }
                if (control >= 0xe0u) historyStart = decoded.size();
                const LzmaStatus decodeResult = lzma.decodeChunk(
                    bytes + cursor, compressedBytes, chunkUncompressedSize,
                    decoded,
                    historyStart, dictionarySize, cancellation,
                    cancellationContext, deadline, deadlineContext);
                if (decodeResult != LzmaStatus::Ok) {
                    if (decodeResult == LzmaStatus::Limit)
                        return ArchiveXzResult::Limit;
                    if (decodeResult == LzmaStatus::Cancelled)
                        return ArchiveXzResult::Cancelled;
                    if (decodeResult == LzmaStatus::Deadline)
                        return ArchiveXzResult::Deadline;
                    return ArchiveXzResult::Malformed;
                }
                cursor += compressedBytes;
            }
            if (!streamEnded) return ArchiveXzResult::Malformed;
            if ((blockFlags & 0x80u) != 0u &&
                decoded.size() - blockOutputStart != ignoredUncompressedSize)
                return ArchiveXzResult::Malformed;
            const std::uint8_t* blockOutput =
                reinterpret_cast<const std::uint8_t*>(
                    decoded.data() + blockOutputStart);
            const std::size_t blockOutputSize =
                decoded.size() - blockOutputStart;
            if (deltaDistance != 0u) {
                for (std::size_t index = 0u; index < blockOutputSize; ++index) {
                    if (deadline != nullptr && deadline(deadlineContext))
                        return ArchiveXzResult::Deadline;
                    if (cancellation != nullptr &&
                        cancellation(cancellationContext))
                        return ArchiveXzResult::Cancelled;
                    const std::size_t absolute = blockOutputStart + index;
                    std::uint8_t value = static_cast<std::uint8_t>(
                        decoded[absolute]);
                    if (index >= deltaDistance)
                        value = static_cast<std::uint8_t>(
                            value + static_cast<std::uint8_t>(
                                        decoded[absolute - deltaDistance]));
                    decoded[absolute] = static_cast<char>(value);
                }
            }
            if (x86FilterPresent) {
                const ArchiveXzResult filterResult = applyX86Bcj(
                    decoded, blockOutputStart, blockOutputSize,
                    x86StartOffset, cancellation, cancellationContext,
                    deadline, deadlineContext);
                if (filterResult != ArchiveXzResult::Ok)
                    return filterResult;
            }
            if (armFilterPresent) {
                const ArchiveXzResult filterResult = applyArmBcj(
                    decoded, blockOutputStart, blockOutputSize,
                    cancellation, cancellationContext, deadline,
                    deadlineContext);
                if (filterResult != ArchiveXzResult::Ok)
                    return filterResult;
            }
            if (armThumbFilterPresent) {
                const ArchiveXzResult filterResult = applyArmThumbBcj(
                    decoded, blockOutputStart, blockOutputSize,
                    cancellation, cancellationContext, deadline,
                    deadlineContext);
                if (filterResult != ArchiveXzResult::Ok)
                    return filterResult;
            }
            if (arm64FilterPresent) {
                const ArchiveXzResult filterResult = applyArm64Bcj(
                    decoded, blockOutputStart, blockOutputSize,
                    cancellation, cancellationContext, deadline,
                    deadlineContext);
                if (filterResult != ArchiveXzResult::Ok)
                    return filterResult;
            }
            const std::size_t checkOffset =
                (payloadEnd + 3u) & ~std::size_t(3u);
            if (checkOffset < payloadEnd ||
                checkOffset + checkSizeFor(summary.checkType) >
                    summary.indexOffset)
                return ArchiveXzResult::Malformed;
            for (std::size_t padding = payloadEnd; padding < checkOffset;
                 ++padding) {
                if (bytes[padding] != 0u)
                    return ArchiveXzResult::Malformed;
            }
            if (summary.checkType == 1u &&
                readLe32(bytes + checkOffset) !=
                    rinruntime_archive_crc32(blockOutput, blockOutputSize))
                return ArchiveXzResult::CrcMismatch;
            if (summary.checkType == 4u &&
                readLe64(bytes + checkOffset) !=
                    crc64Xz(blockOutput, blockOutputSize))
                return ArchiveXzResult::CrcMismatch;
            const std::size_t afterCheck =
                checkOffset + checkSizeFor(summary.checkType);
            blockOffset = afterCheck;
            ++blockIndex;
        }

        if (decoded.size() != summary.uncompressedSize)
            return ArchiveXzResult::Malformed;
        output = std::move(decoded);
        return ArchiveXzResult::Ok;
    }

    ArchiveXzResult decodeRawLzma(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::uint8_t properties, std::size_t dictionarySize,
        std::size_t expectedSize, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
        if (compressed == nullptr || compressedSize < 5u)
            return ArchiveXzResult::InvalidArgument;
        if (expectedSize > kMaxStreamBytes) return ArchiveXzResult::Limit;
        if (dictionarySize == 0u) return ArchiveXzResult::Malformed;
        if (dictionarySize > kMaxStreamBytes)
            dictionarySize = kMaxStreamBytes;
        LzmaDecoder lzma;
        const LzmaStatus propertyResult = lzma.setProperties(properties);
        if (propertyResult != LzmaStatus::Ok)
            return propertyResult == LzmaStatus::Limit
                       ? ArchiveXzResult::Limit
                       : ArchiveXzResult::Malformed;
        if (deadline != nullptr && deadline(deadlineContext))
            return ArchiveXzResult::Deadline;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return ArchiveXzResult::Cancelled;
        std::string decoded;
        const LzmaStatus decodeResult = lzma.decodeChunk(
            compressed, compressedSize, expectedSize, decoded, 0u,
            dictionarySize, cancellation, cancellationContext, deadline,
            deadlineContext);
        if (decodeResult == LzmaStatus::Limit)
            return ArchiveXzResult::Limit;
        if (decodeResult == LzmaStatus::Cancelled)
            return ArchiveXzResult::Cancelled;
        if (decodeResult == LzmaStatus::Deadline)
            return ArchiveXzResult::Deadline;
        if (decodeResult != LzmaStatus::Ok || decoded.size() != expectedSize)
            return ArchiveXzResult::Malformed;
        output = std::move(decoded);
        return ArchiveXzResult::Ok;
    }

private:
    static bool isX86MsByte(std::uint8_t value)
    {
        return value == 0u || value == 0xffu;
    }

    static ArchiveXzResult applyX86Bcj(
        std::string& decoded, std::size_t absoluteOffset, std::size_t size,
        std::uint32_t startOffset,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext)
    {
        static constexpr std::uint32_t kMaskToBitNumber[5] = {0u, 1u, 2u,
                                                                2u, 3u};
        if (size < 5u) return ArchiveXzResult::Ok;

        auto* buffer = reinterpret_cast<std::uint8_t*>(decoded.data()) +
                       absoluteOffset;
        const std::uint32_t nowPosition =
            startOffset + static_cast<std::uint32_t>(absoluteOffset);
        std::uint32_t previousMask = 0u;
        std::uint32_t previousPosition = UINT32_MAX - 4u;
        const std::size_t limit = size - 5u;
        std::size_t bufferPosition = 0u;

        while (bufferPosition <= limit) {
            if (deadline != nullptr && deadline(deadlineContext))
                return ArchiveXzResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveXzResult::Cancelled;

            std::uint8_t byte = buffer[bufferPosition];
            if (byte != 0xe8u && byte != 0xe9u) {
                ++bufferPosition;
                continue;
            }

            const std::uint32_t instructionPosition =
                nowPosition + static_cast<std::uint32_t>(bufferPosition);
            const std::uint32_t offset = instructionPosition - previousPosition;
            previousPosition = instructionPosition;
            if (offset > 5u) {
                previousMask = 0u;
            } else {
                for (std::uint32_t index = 0u; index < offset; ++index) {
                    previousMask &= 0x77u;
                    previousMask <<= 1u;
                }
            }

            byte = buffer[bufferPosition + 4u];
            if (isX86MsByte(byte) && (previousMask >> 1u) <= 4u &&
                (previousMask >> 1u) != 3u) {
                std::uint32_t source =
                    (static_cast<std::uint32_t>(byte) << 24u) |
                    (static_cast<std::uint32_t>(buffer[bufferPosition + 3u])
                     << 16u) |
                    (static_cast<std::uint32_t>(buffer[bufferPosition + 2u])
                     << 8u) |
                    static_cast<std::uint32_t>(buffer[bufferPosition + 1u]);
                std::uint32_t destination = 0u;
                for (;;) {
                    destination = source - instructionPosition - 5u;
                    if (previousMask == 0u) break;
                    const std::uint32_t index =
                        kMaskToBitNumber[previousMask >> 1u];
                    byte = static_cast<std::uint8_t>(
                        destination >> (24u - index * 8u));
                    if (!isX86MsByte(byte)) break;
                    source = destination ^
                             ((UINT32_C(1) << (32u - index * 8u)) - 1u);
                }

                buffer[bufferPosition + 4u] = static_cast<std::uint8_t>(
                    ~(((destination >> 24u) & 1u) - 1u));
                buffer[bufferPosition + 3u] =
                    static_cast<std::uint8_t>(destination >> 16u);
                buffer[bufferPosition + 2u] =
                    static_cast<std::uint8_t>(destination >> 8u);
                buffer[bufferPosition + 1u] =
                    static_cast<std::uint8_t>(destination);
                bufferPosition += 5u;
                previousMask = 0u;
            } else {
                ++bufferPosition;
                previousMask |= 1u;
                if (isX86MsByte(byte)) previousMask |= 0x10u;
            }
        }
        return ArchiveXzResult::Ok;
    }

    static ArchiveXzResult applyArmBcj(
        std::string& decoded, std::size_t absoluteOffset, std::size_t size,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext)
    {
        size &= ~std::size_t(3u);
        auto* buffer = reinterpret_cast<std::uint8_t*>(decoded.data()) +
                       absoluteOffset;
        const std::uint32_t nowPosition =
            static_cast<std::uint32_t>(absoluteOffset);
        for (std::size_t position = 0u; position < size; position += 4u) {
            if (deadline != nullptr && deadline(deadlineContext))
                return ArchiveXzResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveXzResult::Cancelled;
            if (buffer[position + 3u] != 0xebu) continue;

            std::uint32_t source =
                (static_cast<std::uint32_t>(buffer[position + 2u]) << 16u) |
                (static_cast<std::uint32_t>(buffer[position + 1u]) << 8u) |
                static_cast<std::uint32_t>(buffer[position]);
            source <<= 2u;
            const std::uint32_t destination =
                (source - nowPosition - static_cast<std::uint32_t>(position) -
                 8u) >> 2u;
            buffer[position + 2u] =
                static_cast<std::uint8_t>(destination >> 16u);
            buffer[position + 1u] =
                static_cast<std::uint8_t>(destination >> 8u);
            buffer[position] = static_cast<std::uint8_t>(destination);
        }
        return ArchiveXzResult::Ok;
    }

    static ArchiveXzResult applyArmThumbBcj(
        std::string& decoded, std::size_t absoluteOffset, std::size_t size,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext)
    {
        if (size < 4u) return ArchiveXzResult::Ok;
        size -= 4u;
        auto* buffer = reinterpret_cast<std::uint8_t*>(decoded.data()) +
                       absoluteOffset;
        const std::uint32_t nowPosition =
            static_cast<std::uint32_t>(absoluteOffset);
        for (std::size_t position = 0u; position <= size; position += 2u) {
            if (deadline != nullptr && deadline(deadlineContext))
                return ArchiveXzResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveXzResult::Cancelled;
            if ((buffer[position + 1u] & 0xf8u) != 0xf0u ||
                (buffer[position + 3u] & 0xf8u) != 0xf8u)
                continue;

            std::uint32_t source =
                ((static_cast<std::uint32_t>(buffer[position + 1u]) & 7u)
                 << 19u) |
                (static_cast<std::uint32_t>(buffer[position]) << 11u) |
                ((static_cast<std::uint32_t>(buffer[position + 3u]) & 7u)
                 << 8u) |
                static_cast<std::uint32_t>(buffer[position + 2u]);
            source <<= 1u;
            const std::uint32_t destination =
                (source - nowPosition - static_cast<std::uint32_t>(position) -
                 4u) >> 1u;
            buffer[position + 1u] = static_cast<std::uint8_t>(
                0xf0u | ((destination >> 19u) & 7u));
            buffer[position] = static_cast<std::uint8_t>(destination >> 11u);
            buffer[position + 3u] = static_cast<std::uint8_t>(
                0xf8u | ((destination >> 8u) & 7u));
            buffer[position + 2u] = static_cast<std::uint8_t>(destination);
            position += 2u;
        }
        return ArchiveXzResult::Ok;
    }

    static ArchiveXzResult applyArm64Bcj(
        std::string& decoded, std::size_t absoluteOffset, std::size_t size,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext)
    {
        size &= ~std::size_t(3u);
        auto* buffer = reinterpret_cast<std::uint8_t*>(decoded.data()) +
                       absoluteOffset;
        const std::uint32_t nowPosition =
            static_cast<std::uint32_t>(absoluteOffset);
        for (std::size_t position = 0u; position < size; position += 4u) {
            if (deadline != nullptr && deadline(deadlineContext))
                return ArchiveXzResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveXzResult::Cancelled;

            const std::uint32_t source = readLe32(buffer + position);
            std::uint32_t instruction = source;
            std::uint32_t programCounter =
                nowPosition + static_cast<std::uint32_t>(position);
            if ((source >> 26u) == 0x25u) {
                /* BL: the immediate is a signed 26-bit word offset. */
                instruction = 0x94000000u;
                programCounter >>= 2u;
                instruction |= (source - programCounter) & 0x03ffffffu;
            } else if ((source & 0x9f000000u) == 0x90000000u) {
                /* ADRP: accept only the bounded +/-512 MiB range used by the
                 * simple filter to avoid rewriting arbitrary data. */
                const std::uint32_t immediate =
                    ((source >> 29u) & 3u) | ((source >> 3u) & 0x001ffffcu);
                if ((immediate + 0x00020000u) & 0x001c0000u) continue;
                instruction &= 0x9000001fu;
                programCounter >>= 12u;
                const std::uint32_t destination = immediate - programCounter;
                instruction |= (destination & 3u) << 29u;
                instruction |= (destination & 0x0003fffcu) << 3u;
                instruction |= (0u - (destination & 0x00020000u)) &
                               0x00e00000u;
            } else {
                continue;
            }

            buffer[position] = static_cast<std::uint8_t>(instruction);
            buffer[position + 1u] =
                static_cast<std::uint8_t>(instruction >> 8u);
            buffer[position + 2u] =
                static_cast<std::uint8_t>(instruction >> 16u);
            buffer[position + 3u] =
                static_cast<std::uint8_t>(instruction >> 24u);
        }
        return ArchiveXzResult::Ok;
    }

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

    static std::uint64_t readLe64(const std::uint8_t* bytes)
    {
        std::uint64_t value = 0u;
        for (unsigned index = 0u; index != 8u; ++index)
            value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8u);
        return value;
    }

    static std::uint64_t crc64Xz(const std::uint8_t* bytes, std::size_t size)
    {
        constexpr std::uint64_t polynomial = UINT64_C(0xc96c5795d7870f42);
        std::uint64_t crc = UINT64_MAX;
        for (std::size_t index = 0u; index != size; ++index) {
            crc ^= static_cast<std::uint64_t>(bytes[index]);
            for (unsigned bit = 0u; bit != 8u; ++bit)
                crc = (crc & 1u) != 0u ? (crc >> 1u) ^ polynomial
                                       : crc >> 1u;
        }
        return ~crc;
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
            if ((value & 0x80u) == 0u) {
                /* XZ VLI uses the minimum number of bytes.  A terminating
                 * zero payload after a continuation would be a second
                 * encoding of the same value and is invalid on the wire. */
                return count == 0u || payload != 0u;
            }
            shift += 7u;
        }
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_XZ_HPP */
