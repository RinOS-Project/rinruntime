/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded raw DEFLATE decoder for archive entries. */

#ifndef RINRUNTIME_ARCHIVE_DEFLATE_HPP
#define RINRUNTIME_ARCHIVE_DEFLATE_HPP

#include "archive_policy.h"
#include "../rincompression/deflate.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace RinRuntime {

using ArchiveDeflateSinkFunction = bool (*)(
    void* context, const std::uint8_t* bytes, std::size_t size);
using ArchiveDeflateCancellationFunction = bool (*)(void* context);
/* A bounded pull source for one exact raw-DEFLATE payload.  The callback may
 * return fewer bytes than requested, but must return false on I/O failure or
 * an end-of-input condition before source.compressedSize bytes are supplied. */
using ArchiveDeflateReadFunction = bool (*)(
    void* context, std::uint8_t* bytes, std::size_t capacity,
    std::size_t* bytesRead);

struct ArchiveDeflateSource {
    ArchiveDeflateReadFunction read = nullptr;
    void* context = nullptr;
    std::size_t compressedSize = 0u;
};

enum class ArchiveDeflateResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Cancelled = -5,
};

inline std::uint32_t rinruntime_archive_crc32(const std::uint8_t* bytes,
                                              std::size_t size)
{
    if (bytes == nullptr && size != 0u) return 0u;
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t index = 0u; index < size; ++index) {
        crc ^= bytes[index];
        for (int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1u) ^ (0xedb88320u &
                                  (0u - (crc & 1u)));
    }
    return crc ^ 0xffffffffu;
}

/*
 * Decode one raw DEFLATE stream without depending on a filesystem handle or
 * a host compression library.  The caller supplies the ZIP entry's exact
 * uncompressed size and CRC; output is published only after both the stream
 * and the bounded output have validated.  No allocation is proportional to
 * compressed or uncompressed input beyond the bounded result string.
 */
class ArchiveDeflateDecoder final {
public:
    ArchiveDeflateResult decode(const std::uint8_t* compressed,
                                std::size_t compressedSize,
                                std::size_t expectedSize,
                                std::uint32_t expectedCrc,
                                std::string& output) const
    {
        return decode(compressed, compressedSize, expectedSize, expectedCrc,
                      output, nullptr, nullptr);
    }

    ArchiveDeflateResult decode(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::size_t expectedSize, std::uint32_t expectedCrc,
        std::string& output, ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeInternal(compressed, compressedSize, expectedSize,
                              expectedCrc, &output, nullptr, nullptr,
                              cancellation, cancellationContext, nullptr,
                              nullptr);
    }

    ArchiveDeflateResult decode(
        const ArchiveDeflateSource& source, std::size_t expectedSize,
        std::uint32_t expectedCrc, std::string& output) const
    {
        return decode(source, expectedSize, expectedCrc, output, nullptr,
                      nullptr);
    }

    ArchiveDeflateResult decode(
        const ArchiveDeflateSource& source, std::size_t expectedSize,
        std::uint32_t expectedCrc, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeInternal(nullptr, source.compressedSize, expectedSize,
                              expectedCrc, &output, nullptr, nullptr,
                              cancellation, cancellationContext, source.read,
                              source.context);
    }

    /* Decode directly into a bounded caller-owned staging sink. The callback
     * receives chunks no larger than 64 KiB; it must write them durably or
     * return false. A failed decode never claims publication, so callers must
     * discard their staging object when this returns anything other than Ok. */
    ArchiveDeflateResult decodeToSink(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::size_t expectedSize, std::uint32_t expectedCrc,
        ArchiveDeflateSinkFunction sink, void* context) const
    {
        return decodeToSink(compressed, compressedSize, expectedSize,
                            expectedCrc, sink, context, nullptr, nullptr);
    }

    ArchiveDeflateResult decodeToSink(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::size_t expectedSize, std::uint32_t expectedCrc,
        ArchiveDeflateSinkFunction sink, void* context,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeInternal(compressed, compressedSize, expectedSize,
                              expectedCrc, nullptr, sink, context,
                              cancellation, cancellationContext, nullptr,
                              nullptr);
    }

    ArchiveDeflateResult decodeToSink(
        const ArchiveDeflateSource& source, std::size_t expectedSize,
        std::uint32_t expectedCrc, ArchiveDeflateSinkFunction sink,
        void* context) const
    {
        return decodeToSink(source, expectedSize, expectedCrc, sink, context,
                            nullptr, nullptr);
    }

    ArchiveDeflateResult decodeToSink(
        const ArchiveDeflateSource& source, std::size_t expectedSize,
        std::uint32_t expectedCrc, ArchiveDeflateSinkFunction sink,
        void* context, ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeInternal(nullptr, source.compressedSize, expectedSize,
                              expectedCrc, nullptr, sink, context,
                              cancellation, cancellationContext, source.read,
                              source.context);
    }

private:
    class DecodeOutput final {
    public:
        DecodeOutput(std::string* output, ArchiveDeflateSinkFunction sink,
                     void* context, std::size_t expectedSize,
                     ArchiveDeflateCancellationFunction cancellation,
                     void* cancellationContext)
            : output_(output), sink_(sink), context_(context),
              expectedSize_(expectedSize), cancellation_(cancellation),
              cancellationContext_(cancellationContext) {}

        bool write(std::uint8_t value)
        {
            if (cancellation_ != nullptr &&
                (size_ == 0u || (size_ & 4095u) == 0u) &&
                cancellation_(cancellationContext_)) {
                cancelled_ = true;
                return false;
            }
            if (size_ >= expectedSize_)
                return false;
            if (output_ != nullptr)
                output_->push_back(static_cast<char>(value));
            else {
                pending_[pendingSize_++] = value;
                if (pendingSize_ == sizeof(pending_) && !flush())
                    return false;
            }
            crc_ ^= value;
            for (unsigned bit = 0u; bit < 8u; ++bit)
                crc_ = (crc_ >> 1u) ^ (0xedb88320u &
                                       (0u - (crc_ & 1u)));
            ++size_;
            return true;
        }

        bool finish(std::uint32_t expectedCrc)
        {
            if (output_ == nullptr && !flush())
                return false;
            return size_ == expectedSize_ && (crc_ ^ 0xffffffffu) == expectedCrc;
        }

        bool sinkFailed() const { return sinkFailed_; }
        bool cancelled() const { return cancelled_; }

        void clear()
        {
            if (output_ != nullptr)
                output_->clear();
            pendingSize_ = 0u;
            size_ = 0u;
            crc_ = 0xffffffffu;
            sinkFailed_ = false;
            cancelled_ = false;
        }

        std::size_t size() const { return size_; }

    private:
        bool flush()
        {
            if (pendingSize_ == 0u)
                return true;
            if (sink_ == nullptr || context_ == nullptr ||
                !sink_(context_, pending_, pendingSize_)) {
                sinkFailed_ = true;
                return false;
            }
            pendingSize_ = 0u;
            return true;
        }

        std::string* output_ = nullptr;
        ArchiveDeflateSinkFunction sink_ = nullptr;
        void* context_ = nullptr;
        std::size_t expectedSize_ = 0u;
        std::size_t size_ = 0u;
        std::uint32_t crc_ = 0xffffffffu;
        std::uint8_t pending_[65536]{};
        std::size_t pendingSize_ = 0u;
        bool sinkFailed_ = false;
        ArchiveDeflateCancellationFunction cancellation_ = nullptr;
        void* cancellationContext_ = nullptr;
        bool cancelled_ = false;
    };

    ArchiveDeflateResult decodeInternal(
        const std::uint8_t* compressed, std::size_t compressedSize,
        std::size_t expectedSize, std::uint32_t expectedCrc,
        std::string* output, ArchiveDeflateSinkFunction sink,
        void* context, ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateReadFunction read,
        void* readContext) const
    {
        if (read != nullptr && compressed != nullptr)
            return ArchiveDeflateResult::InvalidArgument;
        if (read == nullptr && compressed == nullptr)
            return ArchiveDeflateResult::InvalidArgument;
        if (output == nullptr && (sink == nullptr || context == nullptr))
            return ArchiveDeflateResult::InvalidArgument;
        if (compressedSize == 0u)
            return ArchiveDeflateResult::InvalidArgument;
        if (expectedSize > static_cast<std::size_t>(
                               RINRUNTIME_ARCHIVE_CONTENT_LIMIT))
            return ArchiveDeflateResult::Limit;

        if (output != nullptr)
            output->clear();
        DecodeOutput decoded(output, sink, context, expectedSize,
                             cancellation, cancellationContext);
        if (cancellation != nullptr && cancellation(cancellationContext))
            return fail(decoded, ArchiveDeflateResult::Cancelled);
        Decoder reader(compressed, compressedSize, read, readContext);
        FixedDecodeEntry fixed[512];
        makeFixedDecodeTable(fixed);
        std::uint8_t window[32768];
        if (output != nullptr)
            output->reserve(expectedSize);
        std::size_t windowPosition = 0u;
        std::size_t blockCount = 0u;
        bool finalBlock = false;

        while (!finalBlock) {
            if (blockCount >= RINRUNTIME_ARCHIVE_DEFLATE_BLOCK_LIMIT)
                return fail(decoded, ArchiveDeflateResult::Limit);
            ++blockCount;
            std::uint32_t finalValue = 0u;
            std::uint32_t blockType = 0u;
            if (!reader.readBits(1, finalValue) ||
                !reader.readBits(2, blockType))
                return fail(decoded, ArchiveDeflateResult::Malformed);
            finalBlock = finalValue != 0u;
            if (blockType == 0u) {
                reader.alignByte();
                std::uint32_t length = 0u;
                std::uint32_t inverse = 0u;
                if (!reader.readBits(16, length) ||
                    !reader.readBits(16, inverse) ||
                    static_cast<std::uint16_t>(~static_cast<std::uint16_t>(length)) !=
                        static_cast<std::uint16_t>(inverse))
                    return fail(decoded, ArchiveDeflateResult::Malformed);
                for (std::uint32_t index = 0u; index < length; ++index) {
                    std::uint32_t value = 0u;
                    if (!reader.readBits(8, value) ||
                        !writeByte(static_cast<std::uint8_t>(value), window,
                                   windowPosition, decoded))
                        return fail(decoded, ArchiveDeflateResult::Malformed);
                }
                continue;
            }
            if (blockType == 3u)
                return fail(decoded, ArchiveDeflateResult::Malformed);

            HuffmanTable literalTable;
            HuffmanTable distanceTable;
            const bool dynamic = blockType == 2u;
            if (dynamic && !readDynamicTables(reader, literalTable,
                                              distanceTable))
                return fail(decoded, ArchiveDeflateResult::Malformed);

            while (true) {
                int symbol = -1;
                const bool decodedSymbol = dynamic
                    ? decodeHuffmanSymbol(reader, literalTable, symbol)
                    : decodeFixedSymbol(reader, fixed, symbol);
                if (!decodedSymbol)
                    return fail(decoded, ArchiveDeflateResult::Malformed);
                if (symbol < 256) {
                    if (!writeByte(static_cast<std::uint8_t>(symbol), window,
                                   windowPosition, decoded))
                        return fail(decoded, ArchiveDeflateResult::Malformed);
                    continue;
                }
                if (symbol == 256) break;
                std::uint32_t length = 0u;
                if (!readLength(reader, symbol, length))
                    return fail(decoded, ArchiveDeflateResult::Malformed);
                int distanceCode = -1;
                if (dynamic) {
                    if (!decodeHuffmanSymbol(reader, distanceTable,
                                             distanceCode))
                        return fail(decoded, ArchiveDeflateResult::Malformed);
                } else {
                    std::uint32_t encodedDistance = 0u;
                    if (!reader.readBits(5, encodedDistance))
                        return fail(decoded, ArchiveDeflateResult::Malformed);
                    distanceCode = static_cast<int>(reverseBits(encodedDistance, 5));
                }
                if (!inflateMatch(reader, length, distanceCode, window,
                                  windowPosition, decoded))
                    return fail(decoded, ArchiveDeflateResult::Malformed);
            }
        }

        if (!reader.cleanEnd() || decoded.size() != expectedSize)
            return fail(decoded, ArchiveDeflateResult::Malformed);
        if (!decoded.finish(expectedCrc))
            return fail(decoded, decoded.sinkFailed()
                              ? ArchiveDeflateResult::Malformed
                              : ArchiveDeflateResult::CrcMismatch);
        return ArchiveDeflateResult::Ok;
    }

    class Decoder final {
    public:
        Decoder(const std::uint8_t* bytes, std::size_t size,
                ArchiveDeflateReadFunction read = nullptr,
                void* readContext = nullptr)
            : bytes_(bytes), size_(size), read_(read), readContext_(readContext)
        {
        }

        bool readBits(int count, std::uint32_t& value)
        {
            if (count <= 0 || count > 16 || !ensure(count)) return false;
            value = static_cast<std::uint32_t>(bits_ &
                                               ((1ull << count) - 1ull));
            bits_ >>= count;
            bitCount_ -= count;
            return true;
        }

        bool peekPadded(int count, int minimum, std::uint32_t& value)
        {
            while (bitCount_ < count && loadByte()) {}
            if (bitCount_ < minimum) return false;
            value = static_cast<std::uint32_t>(bits_ &
                                               ((1ull << count) - 1ull));
            return true;
        }

        bool dropBits(int count)
        {
            if (count < 0 || bitCount_ < count) return false;
            bits_ >>= count;
            bitCount_ -= count;
            return true;
        }

        void alignByte()
        {
            const int discard = bitCount_ & 7;
            bits_ >>= discard;
            bitCount_ -= discard;
        }

        bool cleanEnd() const
        {
            return position_ == size_ && source_buffer_offset_ ==
                       source_buffer_size_ && bitCount_ < 8 && bits_ == 0u;
        }


    private:
        bool ensure(int count)
        {
            while (bitCount_ < count && loadByte()) {}
            return bitCount_ >= count;
        }

        bool loadByte()
        {
            std::uint8_t byte = 0u;
            if (position_ >= size_ || bitCount_ > 56) return false;
            if (read_ == nullptr) {
                byte = bytes_[position_++];
            } else {
                if (source_buffer_offset_ == source_buffer_size_) {
                    std::size_t bytesRead = 0u;
                    const std::size_t remaining = size_ - source_bytes_read_;
                    const std::size_t capacity = remaining <
                        sizeof(source_buffer_) ? remaining : sizeof(source_buffer_);
                    if (capacity == 0u ||
                        !read_(readContext_, source_buffer_, capacity,
                               &bytesRead) || bytesRead == 0u ||
                        bytesRead > capacity)
                        return false;
                    source_bytes_read_ += bytesRead;
                    source_buffer_offset_ = 0u;
                    source_buffer_size_ = bytesRead;
                }
                byte = source_buffer_[source_buffer_offset_++];
                ++position_;
            }
            bits_ |= static_cast<std::uint64_t>(byte) << bitCount_;
            bitCount_ += 8;
            return true;
        }

        const std::uint8_t* bytes_ = nullptr;
        std::size_t size_ = 0u;
        ArchiveDeflateReadFunction read_ = nullptr;
        void* readContext_ = nullptr;
        std::uint8_t source_buffer_[4096] = {};
        std::size_t source_buffer_offset_ = 0u;
        std::size_t source_buffer_size_ = 0u;
        std::size_t source_bytes_read_ = 0u;
        std::size_t position_ = 0u;
        std::uint64_t bits_ = 0u;
        int bitCount_ = 0;
    };

    struct FixedDecodeEntry {
        int symbol = -1;
        std::uint8_t bits = 0u;
    };

    struct HuffmanTable {
        std::uint16_t count[16] = {};
        std::uint16_t symbols[320] = {};
        int symbolCount = 0;
    };

    static ArchiveDeflateResult fail(DecodeOutput& output,
                                     ArchiveDeflateResult result)
    {
        const bool cancelled = output.cancelled();
        output.clear();
        return cancelled ? ArchiveDeflateResult::Cancelled : result;
    }

    static std::uint32_t reverseBits(std::uint32_t value, int count)
    {
        std::uint32_t reversed = 0u;
        for (int index = 0; index < count; ++index) {
            reversed = (reversed << 1u) | (value & 1u);
            value >>= 1u;
        }
        return reversed;
    }

    static void makeFixedDecodeTable(FixedDecodeEntry table[512])
    {
        for (int index = 0; index < 512; ++index) table[index] = FixedDecodeEntry();
        for (int symbol = 0; symbol < 288; ++symbol) {
            std::uint32_t code = 0u;
            int length = 0;
            if (symbol <= 143) {
                code = 0x30u + static_cast<std::uint32_t>(symbol); length = 8;
            } else if (symbol <= 255) {
                code = 0x190u + static_cast<std::uint32_t>(symbol - 144); length = 9;
            } else if (symbol <= 279) {
                code = static_cast<std::uint32_t>(symbol - 256); length = 7;
            } else {
                code = 0xc0u + static_cast<std::uint32_t>(symbol - 280); length = 8;
            }
            const std::uint32_t reversed = reverseBits(code, length);
            const int variants = 1 << (9 - length);
            for (int suffix = 0; suffix < variants; ++suffix) {
                const int slot = static_cast<int>(reversed |
                    (static_cast<std::uint32_t>(suffix) << length));
                table[slot].symbol = symbol;
                table[slot].bits = static_cast<std::uint8_t>(length);
            }
        }
    }

    static bool decodeFixedSymbol(Decoder& reader,
                                  const FixedDecodeEntry table[512],
                                  int& symbol)
    {
        std::uint32_t lookup = 0u;
        if (!reader.peekPadded(9, 7, lookup)) return false;
        const FixedDecodeEntry& decoded = table[lookup];
        if (decoded.symbol < 0 || !reader.dropBits(decoded.bits)) return false;
        symbol = decoded.symbol;
        return true;
    }

    static bool buildHuffmanTable(const std::uint8_t* lengths, int count,
                                  HuffmanTable& table)
    {
        for (int index = 0; index < 16; ++index) table.count[index] = 0u;
        table.symbolCount = 0;
        for (int symbol = 0; symbol < count; ++symbol) {
            if (lengths[symbol] > 15u) return false;
            if (lengths[symbol]) {
                ++table.count[lengths[symbol]];
                ++table.symbolCount;
            }
        }
        int remaining = 1;
        for (int bits = 1; bits <= 15; ++bits) {
            remaining = (remaining << 1) - table.count[bits];
            if (remaining < 0) return false;
        }
        std::uint16_t offsets[16] = {};
        for (int bits = 1; bits < 15; ++bits)
            offsets[bits + 1] = offsets[bits] + table.count[bits];
        for (int symbol = 0; symbol < count; ++symbol) {
            const std::uint8_t length = lengths[symbol];
            if (length) table.symbols[offsets[length]++] =
                static_cast<std::uint16_t>(symbol);
        }
        return true;
    }

    static bool decodeHuffmanSymbol(Decoder& reader, const HuffmanTable& table,
                                    int& symbol)
    {
        std::uint32_t code = 0u;
        std::uint32_t first = 0u;
        std::uint32_t index = 0u;
        for (int length = 1; length <= 15; ++length) {
            std::uint32_t bit = 0u;
            if (!reader.readBits(1, bit)) return false;
            code |= bit;
            const std::uint32_t count = table.count[length];
            if (code >= first && code - first < count) {
                const std::uint32_t position = index + code - first;
                if (position >= static_cast<std::uint32_t>(table.symbolCount))
                    return false;
                symbol = table.symbols[position];
                return true;
            }
            index += count;
            first = (first + count) << 1u;
            code <<= 1u;
        }
        return false;
    }

    static bool readDynamicTables(Decoder& reader, HuffmanTable& literalTable,
                                  HuffmanTable& distanceTable)
    {
        static const std::uint8_t order[19] = {
            16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
        std::uint32_t value = 0u;
        if (!reader.readBits(5, value)) return false;
        const int literalCount = static_cast<int>(value) + 257;
        if (!reader.readBits(5, value)) return false;
        const int distanceCount = static_cast<int>(value) + 1;
        if (!reader.readBits(4, value)) return false;
        const int codeLengthCount = static_cast<int>(value) + 4;
        if (literalCount > 286 || distanceCount > 32) return false;

        std::uint8_t codeLengths[19] = {};
        for (int index = 0; index < codeLengthCount; ++index) {
            if (!reader.readBits(3, value)) return false;
            codeLengths[order[index]] = static_cast<std::uint8_t>(value);
        }
        HuffmanTable codeLengthTable;
        if (!buildHuffmanTable(codeLengths, 19, codeLengthTable) ||
            codeLengthTable.symbolCount == 0)
            return false;

        std::uint8_t allLengths[320] = {};
        const int total = literalCount + distanceCount;
        int index = 0;
        while (index < total) {
            int symbol = -1;
            if (!decodeHuffmanSymbol(reader, codeLengthTable, symbol)) return false;
            if (symbol <= 15) {
                allLengths[index++] = static_cast<std::uint8_t>(symbol);
                continue;
            }
            int repeat = 0;
            std::uint8_t repeatedValue = 0u;
            if (symbol == 16) {
                if (index == 0 || !reader.readBits(2, value)) return false;
                repeat = static_cast<int>(value) + 3;
                repeatedValue = allLengths[index - 1];
            } else if (symbol == 17) {
                if (!reader.readBits(3, value)) return false;
                repeat = static_cast<int>(value) + 3;
            } else if (symbol == 18) {
                if (!reader.readBits(7, value)) return false;
                repeat = static_cast<int>(value) + 11;
            } else return false;
            if (index + repeat > total) return false;
            while (repeat-- > 0) allLengths[index++] = repeatedValue;
        }
        if (allLengths[256] == 0u ||
            !buildHuffmanTable(allLengths, literalCount, literalTable) ||
            !buildHuffmanTable(allLengths + literalCount, distanceCount,
                               distanceTable))
            return false;
        return true;
    }

    static bool writeByte(std::uint8_t value, std::uint8_t window[32768],
                          std::size_t& windowPosition, DecodeOutput& output)
    {
        window[windowPosition++ & 32767u] = value;
        return output.write(value);
    }

    static bool readLength(Decoder& reader, int lengthSymbol,
                           std::uint32_t& length)
    {
        static const std::uint16_t lengthBase[29] = {
            3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,
            115,131,163,195,227,258};
        static const std::uint8_t lengthExtra[29] = {
            0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
        const int index = lengthSymbol - 257;
        if (index < 0 || index >= 29) return false;
        std::uint32_t extra = 0u;
        if (lengthExtra[index] &&
            !reader.readBits(lengthExtra[index], extra)) return false;
        length = static_cast<std::uint32_t>(lengthBase[index]) + extra;
        return true;
    }

    static bool inflateMatch(Decoder& reader, std::uint32_t length,
                             int distanceCode,
                             std::uint8_t window[32768], std::size_t& windowPosition,
                             DecodeOutput& output)
    {
        static const std::uint16_t distanceBase[30] = {
            1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,
            1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
        static const std::uint8_t distanceExtra[30] = {
            0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
        if (distanceCode < 0 || distanceCode >= 30) return false;
        std::uint32_t value = 0u;
        if (distanceExtra[distanceCode] &&
            !reader.readBits(distanceExtra[distanceCode], value)) return false;
        const std::uint32_t distance = distanceBase[distanceCode] + value;
        if (!distance || distance > output.size() || distance > 32768u) return false;
        for (std::uint32_t index = 0u; index < length; ++index) {
            const std::uint8_t byte = window[(windowPosition - distance) & 32767u];
            if (!writeByte(byte, window, windowPosition, output)) return false;
        }
        return true;
    }

};

enum class ArchiveDeflateEncodeResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
};

/* Compatibility wrapper for archive authoring helpers.  The generic
 * `rincompression` encoder remains the public format-independent baseline;
 * the named helpers below retain the existing archive API and are bounded,
 * deterministic authoring strategies with no filesystem or service owner. */
class ArchiveDeflateEncoder final {
    static ArchiveDeflateResult map(RinCompression::DeflateResult result)
    {
        switch (result) {
        case RinCompression::DeflateResult::Ok:
            return ArchiveDeflateResult::Ok;
        case RinCompression::DeflateResult::InvalidArgument:
            return ArchiveDeflateResult::InvalidArgument;
        case RinCompression::DeflateResult::Limit:
            return ArchiveDeflateResult::Limit;
        case RinCompression::DeflateResult::Cancelled:
            return ArchiveDeflateResult::Cancelled;
        }
        return ArchiveDeflateResult::Malformed;
    }

public:
    ArchiveDeflateResult encode(const std::uint8_t* input,
                                std::size_t inputSize,
                                std::vector<std::uint8_t>& output) const
    {
        return encode(input, inputSize, output, nullptr, nullptr);
    }

    ArchiveDeflateResult encode(
        const std::uint8_t* input, std::size_t inputSize,
        std::vector<std::uint8_t>& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return map(RinCompression::DeflateEncoder().encode(
            input, inputSize, output, cancellation, cancellationContext));
    }

    ArchiveDeflateEncodeResult encodeFixedRuns(
        const std::uint8_t* data, std::size_t size,
        std::vector<std::uint8_t>& output) const
    {
        output.clear();
        if (data == nullptr && size != 0u)
            return ArchiveDeflateEncodeResult::InvalidArgument;
        if (size > static_cast<std::size_t>(UINT32_MAX) ||
            size > static_cast<std::size_t>(RINRUNTIME_ARCHIVE_CONTENT_LIMIT))
            return ArchiveDeflateEncodeResult::Limit;

        BitWriter writer(output);
        writer.write(1u, 1u); /* final block */
        writer.write(1u, 2u); /* fixed Huffman */
        std::size_t offset = 0u;
        while (offset < size) {
            const std::uint8_t value = data[offset];
            std::size_t run = 1u;
            while (offset + run < size && data[offset + run] == value)
                ++run;
            fixedSymbol(writer, value);
            --run;
            while (run >= 3u) {
                const int length = run > 258u ? 258 : static_cast<int>(run);
                fixedRun(writer, length);
                run -= static_cast<std::size_t>(length);
            }
            while (run != 0u) {
                fixedSymbol(writer, value);
                --run;
            }
            offset += 1u;
            while (offset < size && data[offset] == value) ++offset;
        }
        fixedSymbol(writer, 256);
        writer.finish();
        return finish(size, output);
    }

    ArchiveDeflateEncodeResult encodeDynamicLiterals(
        const std::uint8_t* data, std::size_t size,
        std::vector<std::uint8_t>& output) const
    {
        output.clear();
        if (data == nullptr && size != 0u)
            return ArchiveDeflateEncodeResult::InvalidArgument;
        if (size > static_cast<std::size_t>(UINT32_MAX) ||
            size > static_cast<std::size_t>(RINRUNTIME_ARCHIVE_CONTENT_LIMIT))
            return ArchiveDeflateEncodeResult::Limit;

        BitWriter writer(output);
        writer.write(1u, 1u);  /* final block */
        writer.write(2u, 2u);  /* dynamic Huffman */
        writer.write(29u, 5u); /* 286 literal/length codes */
        writer.write(0u, 5u);  /* one distance code */
        writer.write(14u, 4u); /* 18 code-length codes */
        static const std::uint8_t codeLengthLengths[18] = {
            0u, 0u, 0u, 2u, 0u, 0u, 2u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u};
        for (std::uint8_t length : codeLengthLengths)
            writer.write(length, 3u);
        for (unsigned index = 0u; index < 257u; ++index)
            writer.write(1u, 2u); /* code-length symbol 9 */
        for (unsigned index = 257u; index < 286u; ++index)
            writer.write(0u, 2u); /* code-length symbol 0 */
        writer.write(2u, 2u);     /* code-length symbol 1 */
        for (std::size_t index = 0u; index < size; ++index)
            writer.write(reverseBits(data[index], 9u), 9u);
        writer.write(reverseBits(256u, 9u), 9u); /* end-of-block */
        writer.finish();
        return finish(size, output);
    }

private:
    class BitWriter final {
    public:
        explicit BitWriter(std::vector<std::uint8_t>& output)
            : output_(output) {}

        void write(std::uint32_t value, unsigned count)
        {
            bits_ |= static_cast<std::uint64_t>(value) << bitCount_;
            bitCount_ += count;
            while (bitCount_ >= 8u) {
                output_.push_back(static_cast<std::uint8_t>(bits_));
                bits_ >>= 8u;
                bitCount_ -= 8u;
            }
        }

        void finish()
        {
            if (bitCount_ != 0u)
                output_.push_back(static_cast<std::uint8_t>(bits_));
            bits_ = 0u;
            bitCount_ = 0u;
        }

    private:
        std::vector<std::uint8_t>& output_;
        std::uint64_t bits_ = 0u;
        unsigned bitCount_ = 0u;
    };

    static std::uint32_t reverseBits(std::uint32_t value, unsigned count)
    {
        std::uint32_t result = 0u;
        for (unsigned index = 0u; index < count; ++index) {
            result = (result << 1u) | (value & 1u);
            value >>= 1u;
        }
        return result;
    }

    static void fixedSymbol(BitWriter& writer, int symbol)
    {
        std::uint32_t code = 0u;
        unsigned length = 0u;
        if (symbol <= 143) {
            code = 0x30u + static_cast<std::uint32_t>(symbol);
            length = 8u;
        } else if (symbol <= 255) {
            code = 0x190u + static_cast<std::uint32_t>(symbol - 144);
            length = 9u;
        } else if (symbol <= 279) {
            code = static_cast<std::uint32_t>(symbol - 256);
            length = 7u;
        } else {
            code = 0xc0u + static_cast<std::uint32_t>(symbol - 280);
            length = 8u;
        }
        writer.write(reverseBits(code, length), length);
    }

    static void fixedRun(BitWriter& writer, int length)
    {
        static const std::uint16_t bases[29] = {
            3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
            31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195,
            227, 258};
        static const std::uint8_t extras[29] = {
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3,
            3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
        int index = 0;
        while (index < 28 && length >= bases[index + 1]) ++index;
        fixedSymbol(writer, 257 + index);
        if (extras[index] != 0u)
            writer.write(static_cast<std::uint32_t>(length - bases[index]),
                         extras[index]);
        writer.write(0u, 5u); /* distance code 0, distance 1 */
    }

    static ArchiveDeflateEncodeResult finish(
        std::size_t inputSize, std::vector<std::uint8_t>& output)
    {
        if (output.size() > static_cast<std::size_t>(
                                RINRUNTIME_ARCHIVE_CONTENT_LIMIT) ||
            (inputSize != 0u &&
             !rinruntime_archive_compression_ratio_valid(output.size(),
                                                          inputSize))) {
            output.clear();
            return ArchiveDeflateEncodeResult::Limit;
        }
        return ArchiveDeflateEncodeResult::Ok;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_DEFLATE_HPP */
