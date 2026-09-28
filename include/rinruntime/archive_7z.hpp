/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded 7z envelope inspection. */

#ifndef RINRUNTIME_ARCHIVE_7Z_HPP
#define RINRUNTIME_ARCHIVE_7Z_HPP

#include "archive_deflate.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace RinRuntime {

enum class Archive7zResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Unsupported = -5,
    Cancelled = -6,
    Deadline = -7,
};

struct Archive7zSummary {
    std::size_t streamSize = 0u;
    std::size_t nextHeaderOffset = 0u;
    std::size_t nextHeaderSize = 0u;
    std::uint8_t majorVersion = 0u;
    std::uint8_t minorVersion = 0u;
    std::uint8_t reserved[2] = {0u, 0u};
};

/*
 * The public reader checks the 7z envelope and exposes one deliberately small
 * caller-owned decode subset.  It does not decrypt headers, materialize named
 * entries, open paths, or publish files.  Those operations stay with an
 * authenticated private archive owner.
 */
class Archive7zReader final {
public:
    static constexpr std::size_t kSignatureHeaderSize = 32u;
    static constexpr std::size_t kMaxStreamBytes =
        static_cast<std::size_t>(RINRUNTIME_ARCHIVE_CONTENT_LIMIT);

    Archive7zResult inspect(const std::uint8_t* bytes, std::size_t size,
                            Archive7zSummary& output) const
    {
        output = {};
        if (bytes == nullptr) return Archive7zResult::InvalidArgument;
        if (size < kSignatureHeaderSize) return Archive7zResult::Malformed;
        if (size > kMaxStreamBytes) return Archive7zResult::Limit;
        static constexpr std::uint8_t kSignature[6] = {
            0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
        for (std::size_t index = 0u; index != 6u; ++index)
            if (bytes[index] != kSignature[index])
                return Archive7zResult::Malformed;
        const std::uint8_t major = bytes[6];
        const std::uint8_t minor = bytes[7];
        if (major != 0u) return Archive7zResult::Unsupported;
        if (readLe32(bytes + 8u) !=
            rinruntime_archive_crc32(bytes + 12u, 20u))
            return Archive7zResult::CrcMismatch;

        const std::uint64_t nextOffset = readLe64(bytes + 12u);
        const std::uint64_t nextSize = readLe64(bytes + 20u);
        if (nextOffset > static_cast<std::uint64_t>(size -
                                                     kSignatureHeaderSize))
            return Archive7zResult::Malformed;
        const std::uint64_t available =
            static_cast<std::uint64_t>(size - kSignatureHeaderSize) -
            nextOffset;
        if (nextSize > available) return Archive7zResult::Malformed;
        if (nextSize > RINRUNTIME_ARCHIVE_CONTENT_LIMIT)
            return Archive7zResult::Limit;
        const std::size_t nextHeaderOffset =
            kSignatureHeaderSize + static_cast<std::size_t>(nextOffset);
        const std::size_t nextHeaderSize = static_cast<std::size_t>(nextSize);
        if (nextHeaderOffset + nextHeaderSize != size)
            return Archive7zResult::Malformed;
        if (readLe32(bytes + 28u) !=
            rinruntime_archive_crc32(bytes + nextHeaderOffset,
                                     nextHeaderSize))
            return Archive7zResult::CrcMismatch;

        output.streamSize = size;
        output.nextHeaderOffset = nextHeaderOffset;
        output.nextHeaderSize = nextHeaderSize;
        output.majorVersion = major;
        output.minorVersion = minor;
        return Archive7zResult::Ok;
    }

    /* Decode a single non-empty stream using one 7z Copy coder (method 0x00).
     * This bounded subset is useful for caller-owned test/resource bytes and
     * intentionally has no path, filename, filesystem, or service authority.
     * LZMA/Deflate/other coder chains, encryption, multiple folders/streams,
     * and external headers remain explicit Unsupported results. */
    Archive7zResult decodeStored(const std::uint8_t* bytes, std::size_t size,
                                 std::string& output) const
    {
        return decodeStored(bytes, size, output, nullptr, nullptr, nullptr,
                            nullptr);
    }

    Archive7zResult decodeStored(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        return decodeStored(bytes, size, output, cancellation,
                            cancellationContext, nullptr, nullptr);
    }

    Archive7zResult decodeStoredWithDeadline(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateDeadlineFunction deadline, void* deadlineContext) const
    {
        return decodeStored(bytes, size, output, nullptr, nullptr, deadline,
                            deadlineContext);
    }

private:
    Archive7zResult decodeStored(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
        if (deadline != nullptr && deadline(deadlineContext))
            return Archive7zResult::Deadline;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return Archive7zResult::Cancelled;
        Archive7zSummary summary;
        Archive7zResult result = inspect(bytes, size, summary);
        if (result != Archive7zResult::Ok) return result;

        std::size_t cursor = summary.nextHeaderOffset;
        const std::size_t end = summary.nextHeaderOffset +
                                summary.nextHeaderSize;
        std::uint64_t pack_position = 0u;
        std::uint64_t pack_size = 0u;
        std::uint64_t unpack_size = 0u;
        std::uint32_t pack_crc = 0u;
        std::uint32_t folder_crc = 0u;
        bool pack_crc_defined = false;
        bool folder_crc_defined = false;

        if (!takeByte(bytes, end, cursor, 0x01u))
            return Archive7zResult::Malformed;
        if (!takeByte(bytes, end, cursor, 0x04u))
            return Archive7zResult::Unsupported;

        if (!takeByte(bytes, end, cursor, 0x06u) ||
            !readEncodedUInt64(bytes, end, cursor, pack_position))
            return Archive7zResult::Malformed;
        std::uint64_t pack_stream_count = 0u;
        if (!readEncodedUInt64(bytes, end, cursor, pack_stream_count))
            return Archive7zResult::Malformed;
        if (pack_stream_count != 1u)
            return Archive7zResult::Unsupported;
        if (!takeByte(bytes, end, cursor, 0x09u) ||
            !readEncodedUInt64(bytes, end, cursor, pack_size))
            return Archive7zResult::Malformed;
        if (pack_size > static_cast<std::uint64_t>(kMaxStreamBytes))
            return Archive7zResult::Limit;
        if (cursor < end && bytes[cursor] == 0x0au) {
            ++cursor;
            if (!readCrc(bytes, end, cursor, pack_crc_defined, pack_crc))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u))
            return Archive7zResult::Malformed;

        if (!takeByte(bytes, end, cursor, 0x07u) ||
            !takeByte(bytes, end, cursor, 0x0bu))
            return Archive7zResult::Unsupported;
        std::uint64_t folder_count = 0u;
        if (!readEncodedUInt64(bytes, end, cursor, folder_count))
            return Archive7zResult::Malformed;
        if (folder_count != 1u) return Archive7zResult::Unsupported;
        if (cursor >= end) return Archive7zResult::Malformed;
        if (bytes[cursor++] != 0u) return Archive7zResult::Unsupported;

        std::uint64_t coder_count = 0u;
        if (!readEncodedUInt64(bytes, end, cursor, coder_count))
            return Archive7zResult::Malformed;
        if (coder_count != 1u || cursor >= end)
            return Archive7zResult::Unsupported;
        const std::uint8_t coder_flags = bytes[cursor++];
        if (coder_flags != 0x01u || cursor >= end || bytes[cursor++] != 0u)
            return Archive7zResult::Unsupported;

        if (!takeByte(bytes, end, cursor, 0x0cu) ||
            !readEncodedUInt64(bytes, end, cursor, unpack_size))
            return Archive7zResult::Malformed;
        if (unpack_size > static_cast<std::uint64_t>(kMaxStreamBytes))
            return Archive7zResult::Limit;
        if (cursor < end && bytes[cursor] == 0x0au) {
            ++cursor;
            if (!readCrc(bytes, end, cursor, folder_crc_defined, folder_crc))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u))
            return Archive7zResult::Malformed;

        /* A one-folder/one-stream archive has no need for SubStreamsInfo. */
        if (cursor >= end) return Archive7zResult::Malformed;
        if (bytes[cursor] == 0x08u) {
            ++cursor;
            std::uint64_t substream_count = 1u;
            while (cursor < end && bytes[cursor] != 0u) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
                const std::uint8_t property = bytes[cursor++];
                if (property == 0x0du) {
                    if (!readEncodedUInt64(bytes, end, cursor,
                                           substream_count))
                        return Archive7zResult::Malformed;
                    if (substream_count != 1u)
                        return Archive7zResult::Unsupported;
                } else if (property == 0x09u) {
                    std::uint64_t substream_size = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor,
                                           substream_size))
                        return Archive7zResult::Malformed;
                    if (substream_size != unpack_size)
                        return Archive7zResult::Malformed;
                } else if (property == 0x0au) {
                    bool defined = false;
                    std::uint32_t crc = 0u;
                    if (!readCrc(bytes, end, cursor, defined, crc))
                        return Archive7zResult::Malformed;
                    if (defined && folder_crc_defined && crc != folder_crc)
                        return Archive7zResult::CrcMismatch;
                    if (defined && !folder_crc_defined) {
                        folder_crc = crc;
                        folder_crc_defined = true;
                    }
                } else {
                    return Archive7zResult::Unsupported;
                }
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u))
            return Archive7zResult::Malformed;

        /* FilesInfo is parsed only far enough to prove that this is one
         * non-empty file.  Names and other metadata are not public output. */
        if (cursor < end && bytes[cursor] == 0x05u) {
            ++cursor;
            std::uint64_t file_count = 0u;
            if (!readEncodedUInt64(bytes, end, cursor, file_count))
                return Archive7zResult::Malformed;
            if (file_count != 1u) return Archive7zResult::Unsupported;
            while (cursor < end && bytes[cursor] != 0u) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
                const std::uint8_t property = bytes[cursor++];
                std::uint64_t property_size = 0u;
                if (!readEncodedUInt64(bytes, end, cursor, property_size) ||
                    property_size > static_cast<std::uint64_t>(end - cursor))
                    return Archive7zResult::Malformed;
                const std::size_t property_end =
                    cursor + static_cast<std::size_t>(property_size);
                if (property == 0x0eu) {
                    const std::size_t bitmap_size = 1u;
                    if (property_size != bitmap_size ||
                        bytes[cursor] != 0u)
                        return Archive7zResult::Unsupported;
                } else if (property == 0x0fu || property == 0x10u) {
                    return Archive7zResult::Unsupported;
                }
                cursor = property_end;
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u) || cursor != end)
            return Archive7zResult::Malformed;
        if (pack_size != unpack_size)
            return Archive7zResult::Unsupported;
        /* The public subset deliberately exposes non-empty resources only;
         * keep an empty 7z file on the private archive-owner path instead of
         * silently treating it as a successful decode. */
        if (pack_size == 0u)
            return Archive7zResult::Unsupported;
        if (pack_position > static_cast<std::uint64_t>(size -
                                                        kSignatureHeaderSize))
            return Archive7zResult::Malformed;
        const std::uint64_t pack_start64 =
            static_cast<std::uint64_t>(kSignatureHeaderSize) + pack_position;
        if (pack_start64 > static_cast<std::uint64_t>(summary.nextHeaderOffset) ||
            pack_size > static_cast<std::uint64_t>(summary.nextHeaderOffset) -
                             pack_start64)
            return Archive7zResult::Malformed;
        const std::size_t pack_start = static_cast<std::size_t>(pack_start64);
        const std::size_t decoded_size = static_cast<std::size_t>(pack_size);
        std::uint32_t actual_crc = 0xffffffffu;
        for (std::size_t index = 0u; index < decoded_size; ++index) {
            if ((index & 4095u) == 0u) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
            }
            actual_crc ^= bytes[pack_start + index];
            for (int bit = 0; bit < 8; ++bit)
                actual_crc = (actual_crc >> 1u) ^
                             (0xedb88320u & (0u - (actual_crc & 1u)));
        }
        actual_crc ^= 0xffffffffu;
        if ((pack_crc_defined && actual_crc != pack_crc) ||
            (folder_crc_defined && actual_crc != folder_crc))
            return Archive7zResult::CrcMismatch;

        std::string decoded;
        std::size_t copied = 0u;
        while (copied < decoded_size) {
            if (deadline != nullptr && deadline(deadlineContext))
                return Archive7zResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return Archive7zResult::Cancelled;
            const std::size_t part =
                (decoded_size - copied) > 65536u
                    ? 65536u
                    : decoded_size - copied;
            decoded.append(reinterpret_cast<const char*>(bytes + pack_start +
                                                         copied),
                           part);
            copied += part;
        }
        output = decoded;
        return Archive7zResult::Ok;
    }

private:
    static bool takeByte(const std::uint8_t* bytes, std::size_t end,
                         std::size_t& cursor, std::uint8_t expected)
    {
        return cursor < end && bytes[cursor++] == expected;
    }

    static bool readEncodedUInt64(const std::uint8_t* bytes, std::size_t end,
                                  std::size_t& cursor, std::uint64_t& value)
    {
        if (cursor >= end) return false;
        const std::uint8_t first = bytes[cursor++];
        unsigned additional = 0u;
        while (additional < 8u &&
               (first & static_cast<std::uint8_t>(0x80u >> additional)) !=
                   0u)
            ++additional;
        value = additional == 8u
                    ? 0u
                    : static_cast<std::uint64_t>(
                          first & static_cast<std::uint8_t>(
                                      (1u << (7u - additional)) - 1u));
        for (unsigned index = 0u; index != additional; ++index) {
            if (cursor >= end) return false;
            value = (value << 8u) | bytes[cursor++];
        }
        if (additional != 0u &&
            value < (UINT64_C(1) << (7u * additional)))
            return false;
        return true;
    }

    static bool readCrc(const std::uint8_t* bytes, std::size_t end,
                        std::size_t& cursor, bool& defined,
                        std::uint32_t& value)
    {
        if (cursor >= end) return false;
        const std::uint8_t all_defined = bytes[cursor++];
        if (all_defined != 0u && all_defined != 1u) return false;
        defined = all_defined != 0u;
        if (all_defined == 0u) {
            if (cursor >= end) return false;
            const std::uint8_t bitmap = bytes[cursor++];
            defined = (bitmap & 1u) != 0u;
            if ((bitmap & 0xfeu) != 0u) return false;
        }
        if (!defined) {
            value = 0u;
            return true;
        }
        if (end - cursor < 4u) return false;
        value = readLe32(bytes + cursor);
        cursor += 4u;
        return true;
    }

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
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_7Z_HPP */
