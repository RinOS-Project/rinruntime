/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded RFC 1952 wrapper for raw DEFLATE. */

#ifndef RINRUNTIME_ARCHIVE_GZIP_HPP
#define RINRUNTIME_ARCHIVE_GZIP_HPP

#include "archive_deflate.hpp"

namespace RinRuntime {

enum class ArchiveGzipResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    SinkFailure = -5,
    Cancelled = -6,
};

using ArchiveGzipReadFunction = bool (*)(
    void* context, std::uint8_t* bytes, std::size_t capacity,
    std::size_t* bytesRead);

/* A caller-owned sequential source for one complete GZIP member.  The
 * compressedSize value includes the RFC 1952 header, DEFLATE payload, and
 * eight-byte trailer. */
struct ArchiveGzipSource {
    ArchiveGzipReadFunction read = nullptr;
    void* context = nullptr;
    std::size_t compressedSize = 0u;
};

class ArchiveGzipReader final {
public:
    ArchiveGzipResult decode(const std::uint8_t* bytes, std::size_t size,
                             std::string& output) const
    {
        return decode(bytes, size, output, nullptr, nullptr);
    }

    ArchiveGzipResult decode(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        Header header;
        /* A failed parse or admission must not leave a previous successful
         * decode visible to the caller.  This is also required for the
         * oversized ISIZE path, which returns before DEFLATE owns output. */
        output.clear();
        const ArchiveGzipResult headerResult = parseHeader(bytes, size, header);
        if (headerResult != ArchiveGzipResult::Ok) {
            return headerResult;
        }
        const std::size_t expectedSize = static_cast<std::size_t>(header.size);
        if (header.size > RINRUNTIME_ARCHIVE_CONTENT_LIMIT)
            return failOutput(output, ArchiveGzipResult::Limit);
        if (cancellation != nullptr && cancellation(cancellationContext))
            return failOutput(output, ArchiveGzipResult::Cancelled);
        const ArchiveDeflateResult result = decoder_.decode(
            bytes + header.deflateOffset, header.deflateSize, expectedSize,
            header.crc, output, cancellation, cancellationContext);
        if (result == ArchiveDeflateResult::CrcMismatch)
            return ArchiveGzipResult::CrcMismatch;
        if (result == ArchiveDeflateResult::Cancelled)
            return failOutput(output, ArchiveGzipResult::Cancelled);
        if (result != ArchiveDeflateResult::Ok)
            return failOutput(output, result == ArchiveDeflateResult::Limit
                                         ? ArchiveGzipResult::Limit
                                         : ArchiveGzipResult::Malformed);
        if (static_cast<std::uint32_t>(output.size()) != header.size)
            return failOutput(output, ArchiveGzipResult::Malformed);
        return ArchiveGzipResult::Ok;
    }

    ArchiveGzipResult decode(const ArchiveGzipSource& source,
                             std::uint8_t* compressedBuffer,
                             std::size_t compressedCapacity,
                             std::string& output) const
    {
        return decode(source, compressedBuffer, compressedCapacity, output,
                      nullptr, nullptr);
    }

    ArchiveGzipResult decode(
        const ArchiveGzipSource& source, std::uint8_t* compressedBuffer,
        std::size_t compressedCapacity, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        output.clear();
        const ArchiveGzipResult sourceResult = stageSource(
            source, compressedBuffer, compressedCapacity, cancellation,
            cancellationContext);
        if (sourceResult != ArchiveGzipResult::Ok) return sourceResult;
        return decode(compressedBuffer, source.compressedSize, output,
                      cancellation, cancellationContext);
    }

    ArchiveGzipResult decodeToSink(
        const std::uint8_t* bytes, std::size_t size,
        ArchiveDeflateSinkFunction sink, void* context) const
    {
        return decodeToSink(bytes, size, sink, context, nullptr, nullptr);
    }

    ArchiveGzipResult decodeToSink(
        const std::uint8_t* bytes, std::size_t size,
        ArchiveDeflateSinkFunction sink, void* context,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        Header header;
        SinkState state{sink, context, 0u};
        const ArchiveGzipResult headerResult = parseHeader(bytes, size, header);
        if (headerResult != ArchiveGzipResult::Ok) return headerResult;
        if (header.size > RINRUNTIME_ARCHIVE_CONTENT_LIMIT)
            return ArchiveGzipResult::Limit;
        if (sink == nullptr) return ArchiveGzipResult::InvalidArgument;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return ArchiveGzipResult::Cancelled;
        const ArchiveDeflateResult result = decoder_.decodeToSink(
            bytes + header.deflateOffset, header.deflateSize,
            static_cast<std::size_t>(header.size), header.crc,
            forwardSink, &state, cancellation, cancellationContext);
        if (result == ArchiveDeflateResult::CrcMismatch)
            return ArchiveGzipResult::CrcMismatch;
        if (result == ArchiveDeflateResult::Cancelled)
            return ArchiveGzipResult::Cancelled;
        if (result != ArchiveDeflateResult::Ok)
            return state.failed ? ArchiveGzipResult::SinkFailure
                                 : (result == ArchiveDeflateResult::Limit
                                        ? ArchiveGzipResult::Limit
                                        : ArchiveGzipResult::Malformed);
        return state.size == header.size ? ArchiveGzipResult::Ok
                                         : ArchiveGzipResult::Malformed;
    }

    ArchiveGzipResult decodeToSink(
        const ArchiveGzipSource& source, std::uint8_t* compressedBuffer,
        std::size_t compressedCapacity, ArchiveDeflateSinkFunction sink,
        void* context) const
    {
        return decodeToSink(source, compressedBuffer, compressedCapacity, sink,
                            context, nullptr, nullptr);
    }

    ArchiveGzipResult decodeToSink(
        const ArchiveGzipSource& source, std::uint8_t* compressedBuffer,
        std::size_t compressedCapacity, ArchiveDeflateSinkFunction sink,
        void* context, ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        const ArchiveGzipResult sourceResult = stageSource(
            source, compressedBuffer, compressedCapacity, cancellation,
            cancellationContext);
        if (sourceResult != ArchiveGzipResult::Ok) return sourceResult;
        return decodeToSink(compressedBuffer, source.compressedSize, sink,
                            context, cancellation, cancellationContext);
    }

private:
    struct Header {
        std::size_t deflateOffset = 0u;
        std::size_t deflateSize = 0u;
        std::uint32_t crc = 0u;
        std::uint32_t size = 0u;
    };

    struct SinkState {
        ArchiveDeflateSinkFunction sink;
        void* context;
        std::uint64_t size;
        bool failed = false;
    };

    static ArchiveGzipResult failOutput(std::string& output,
                                        ArchiveGzipResult result)
    {
        output.clear();
        return result;
    }

    static ArchiveGzipResult stageSource(
        const ArchiveGzipSource& source, std::uint8_t* compressedBuffer,
        std::size_t compressedCapacity,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext)
    {
        std::size_t offset = 0u;
        if (source.read == nullptr || source.compressedSize == 0u ||
            source.compressedSize > RINRUNTIME_ARCHIVE_CONTENT_LIMIT ||
            compressedBuffer == nullptr ||
            compressedCapacity < source.compressedSize)
            return compressedCapacity < source.compressedSize
                       ? ArchiveGzipResult::Limit
                       : ArchiveGzipResult::InvalidArgument;
        while (offset < source.compressedSize) {
            const std::size_t remaining = source.compressedSize - offset;
            const std::size_t capacity = remaining < 4096u ? remaining : 4096u;
            std::size_t bytesRead = 0u;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return ArchiveGzipResult::Cancelled;
            if (!source.read(source.context, compressedBuffer + offset,
                             capacity, &bytesRead) || bytesRead == 0u ||
                bytesRead > capacity)
                return ArchiveGzipResult::Malformed;
            offset += bytesRead;
        }
        return ArchiveGzipResult::Ok;
    }

    static std::uint32_t get32(const std::uint8_t* bytes)
    {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8u) |
               (static_cast<std::uint32_t>(bytes[2]) << 16u) |
               (static_cast<std::uint32_t>(bytes[3]) << 24u);
    }

    static std::uint16_t get16(const std::uint8_t* bytes)
    {
        return static_cast<std::uint16_t>(bytes[0]) |
               static_cast<std::uint16_t>(bytes[1] << 8u);
    }

    static std::uint16_t headerCrc16(const std::uint8_t* bytes,
                                     std::size_t size)
    {
        return static_cast<std::uint16_t>(
            rinruntime_archive_crc32(bytes, size) & 0xffffu);
    }

    static ArchiveGzipResult parseHeader(const std::uint8_t* bytes,
                                         std::size_t size, Header& header)
    {
        std::size_t offset = 10u;
        if (bytes == nullptr || size < 18u) return ArchiveGzipResult::InvalidArgument;
        const std::uint8_t flags = bytes[3];
        if (bytes[0] != 0x1fu || bytes[1] != 0x8bu || bytes[2] != 8u ||
            (flags & 0xe0u) != 0u)
            return ArchiveGzipResult::Malformed;
        if ((flags & 0x04u) != 0u) {
            if (offset > size - 2u) return ArchiveGzipResult::Malformed;
            const std::size_t extraSize = get16(bytes + offset);
            offset += 2u;
            if (extraSize > size - offset) return ArchiveGzipResult::Malformed;
            offset += extraSize;
        }
        for (std::uint8_t flag = 0x08u; flag <= 0x10u; flag <<= 1u) {
            if ((flags & flag) == 0u) continue;
            while (offset < size && bytes[offset] != 0u) ++offset;
            if (offset >= size) return ArchiveGzipResult::Malformed;
            ++offset;
        }
        if ((flags & 0x02u) != 0u) {
            if (offset > size - 2u ||
                get16(bytes + offset) != headerCrc16(bytes, offset))
                return ArchiveGzipResult::Malformed;
            offset += 2u;
        }
        if (offset > size - 8u) return ArchiveGzipResult::Malformed;
        header.deflateOffset = offset;
        header.deflateSize = size - offset - 8u;
        header.crc = get32(bytes + size - 8u);
        header.size = get32(bytes + size - 4u);
        if (header.deflateSize == 0u) return ArchiveGzipResult::Malformed;
        return ArchiveGzipResult::Ok;
    }

    static bool forwardSink(void* context, const std::uint8_t* bytes,
                            std::size_t size)
    {
        SinkState* state = static_cast<SinkState*>(context);
        if (state == nullptr || state->sink == nullptr ||
            bytes == nullptr || size == 0u ||
            state->size > UINT64_MAX - size ||
            !state->sink(state->context, bytes, size)) {
            if (state != nullptr) state->failed = true;
            return false;
        }
        state->size += size;
        return true;
    }

    ArchiveDeflateDecoder decoder_;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_GZIP_HPP */

