/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded 7z envelope inspection. */

#ifndef RINRUNTIME_ARCHIVE_7Z_HPP
#define RINRUNTIME_ARCHIVE_7Z_HPP

#include "archive_deflate.hpp"
#include "archive_xz.hpp"

#include <array>
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

    /* Decode a bounded linear 7z pipeline of up to four one-in/one-out Copy,
     * Delta, and LZMA coders, plus a single empty regular file with no packed
     * stream.
     * BindPairs are validated before any coder runs.  This subset is useful
     * for caller-owned test/resource bytes and intentionally has no path,
     * filename, filesystem, or service authority.  Multi-stream coders,
     * encryption, multiple folders/streams/entries, directories, and
     * external headers remain explicit Unsupported results. */
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
        static constexpr std::size_t kMaxCoders = 4u;
        std::uint64_t coder_count = 0u;
        std::array<std::uint64_t, kMaxCoders> coder_methods{};
        std::array<bool, kMaxCoders> lzma_coders{};
        std::array<bool, kMaxCoders> lzma2_coders{};
        std::array<std::uint8_t, kMaxCoders> lzma2_properties{};
        std::array<bool, kMaxCoders> raw_filter_coders{};
        std::array<std::array<std::uint8_t, 4u>, kMaxCoders>
            filter_properties{};
        std::array<std::size_t, kMaxCoders> filter_property_sizes{};
        std::array<std::array<std::uint8_t, 5u>, kMaxCoders>
            lzma_properties{};
        std::array<std::size_t, kMaxCoders> lzma_dictionary_sizes{};
        std::array<std::uint64_t, kMaxCoders> coder_unpack_sizes{};
        std::array<int, kMaxCoders> input_sources{};
        std::array<bool, kMaxCoders> output_bound{};
        input_sources.fill(-1);
        std::size_t final_output_index = kMaxCoders;
        int packed_input_index = -1;
        bool stream_info_present = false;
        bool empty_stream = false;
        bool empty_file = false;

        if (!takeByte(bytes, end, cursor, 0x01u))
            return Archive7zResult::Malformed;
        if (!takeByte(bytes, end, cursor, 0x04u))
            return Archive7zResult::Unsupported;

        if (cursor >= end) return Archive7zResult::Malformed;
        if (bytes[cursor] == 0x00u) {
            ++cursor;
        } else {
            stream_info_present = true;
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

            if (!readEncodedUInt64(bytes, end, cursor, coder_count))
                return Archive7zResult::Malformed;
            if (coder_count == 0u || coder_count > kMaxCoders)
                return Archive7zResult::Unsupported;
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder) {
                if (cursor >= end) return Archive7zResult::Malformed;
                const std::uint8_t coder_flags = bytes[cursor++];
                const unsigned method_size = coder_flags & 0x0fu;
                const bool complex_coder = (coder_flags & 0x10u) != 0u;
                const bool has_properties = (coder_flags & 0x20u) != 0u;
                if (method_size == 0u || method_size > 8u ||
                    (coder_flags & 0xc0u) != 0u ||
                    method_size > end - cursor)
                    return Archive7zResult::Unsupported;
                std::uint64_t method = 0u;
                for (unsigned index = 0u; index != method_size; ++index)
                    method |= static_cast<std::uint64_t>(bytes[cursor++])
                              << (index * 8u);
                if (complex_coder) {
                    std::uint64_t input_streams = 0u;
                    std::uint64_t output_streams = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor,
                                           input_streams) ||
                        !readEncodedUInt64(bytes, end, cursor,
                                           output_streams) ||
                        input_streams != 1u || output_streams != 1u)
                        return Archive7zResult::Unsupported;
                }
                if (has_properties) {
                    std::uint64_t property_size = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor, property_size) ||
                        property_size > static_cast<std::uint64_t>(end - cursor))
                        return Archive7zResult::Malformed;
                    if (method == UINT64_C(0x010103) &&
                        property_size == 5u) {
                        for (std::size_t index = 0u; index != 5u; ++index)
                            lzma_properties[coder][index] =
                                bytes[cursor + index];
                        const std::uint32_t dictionary =
                            static_cast<std::uint32_t>(
                                lzma_properties[coder][1u]) |
                            static_cast<std::uint32_t>(
                                lzma_properties[coder][2u]) << 8u |
                            static_cast<std::uint32_t>(
                                lzma_properties[coder][3u]) << 16u |
                            static_cast<std::uint32_t>(
                                lzma_properties[coder][4u]) << 24u;
                        if (dictionary == 0u) return Archive7zResult::Malformed;
                        if (dictionary > kMaxStreamBytes)
                            return Archive7zResult::Limit;
                        lzma_dictionary_sizes[coder] =
                            static_cast<std::size_t>(dictionary);
                        lzma_coders[coder] = true;
                        cursor += 5u;
                    } else if (method == UINT64_C(0x21) &&
                               property_size == 1u) {
                        lzma2_properties[coder] = bytes[cursor++];
                        lzma2_coders[coder] = true;
                    } else if (method >= 0x03u && method <= 0x0bu &&
                               property_size ==
                                   (method == 0x03u
                                        ? 1u
                                        : method == 0x04u ? 4u : 0u)) {
                        const std::size_t filter_size =
                            static_cast<std::size_t>(property_size);
                        for (std::size_t index = 0u; index != filter_size;
                             ++index)
                            filter_properties[coder][index] =
                                bytes[cursor + index];
                        filter_property_sizes[coder] = filter_size;
                        raw_filter_coders[coder] = true;
                        cursor += filter_size;
                    } else {
                        return Archive7zResult::Unsupported;
                    }
                } else if (method >= 0x05u && method <= 0x0bu) {
                    raw_filter_coders[coder] = true;
                } else if (method != 0u) {
                    return Archive7zResult::Unsupported;
                }
                coder_methods[coder] = method;
            }

            /* With one stream per coder, the folder has coder_count - 1
             * bindings and exactly one packed input and one final output. */
            for (std::size_t pair = 0u;
                 pair + 1u < static_cast<std::size_t>(coder_count); ++pair) {
                std::uint64_t in_index = 0u;
                std::uint64_t out_index = 0u;
                if (!readEncodedUInt64(bytes, end, cursor, in_index) ||
                    !readEncodedUInt64(bytes, end, cursor, out_index) ||
                    in_index >= coder_count || out_index >= coder_count)
                    return Archive7zResult::Unsupported;
                const std::size_t in = static_cast<std::size_t>(in_index);
                const std::size_t out = static_cast<std::size_t>(out_index);
                if (input_sources[in] != -1 || output_bound[out])
                    return Archive7zResult::Unsupported;
                input_sources[in] = static_cast<int>(out);
                output_bound[out] = true;
            }
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder) {
                if (input_sources[coder] == -1) {
                    if (packed_input_index != -1)
                        return Archive7zResult::Unsupported;
                    packed_input_index = static_cast<int>(coder);
                }
                if (!output_bound[coder]) {
                    if (final_output_index != kMaxCoders)
                        return Archive7zResult::Unsupported;
                    final_output_index = coder;
                }
            }
            if (packed_input_index == -1 || final_output_index == kMaxCoders)
                return Archive7zResult::Unsupported;

            if (!takeByte(bytes, end, cursor, 0x0cu) ||
                coder_count == 0u)
                return Archive7zResult::Malformed;
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder) {
                if (!readEncodedUInt64(bytes, end, cursor,
                                       coder_unpack_sizes[coder]))
                    return Archive7zResult::Malformed;
                if (coder_unpack_sizes[coder] >
                    static_cast<std::uint64_t>(kMaxStreamBytes))
                    return Archive7zResult::Limit;
            }
            unpack_size = coder_unpack_sizes[final_output_index];
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
        }

        /* FilesInfo is parsed only far enough to prove that this is one
         * non-empty file or one empty regular file.  Names and other metadata
         * are not public output. */
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
                        bytes[cursor] != 1u)
                        return Archive7zResult::Unsupported;
                    empty_stream = true;
                } else if (property == 0x0fu) {
                    const std::size_t bitmap_size = 1u;
                    if (property_size != bitmap_size ||
                        bytes[cursor] != 1u)
                        return Archive7zResult::Unsupported;
                    empty_file = true;
                } else if (property == 0x10u) {
                    return Archive7zResult::Unsupported;
                }
                cursor = property_end;
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u) || cursor != end)
            return Archive7zResult::Malformed;
        if (!stream_info_present) {
            if (!empty_stream || !empty_file || pack_size != 0u ||
                unpack_size != 0u)
                return Archive7zResult::Unsupported;
            output.clear();
            return Archive7zResult::Ok;
        }
        if (empty_stream || empty_file)
            return Archive7zResult::Malformed;
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
        const std::size_t packed_size = static_cast<std::size_t>(pack_size);
        std::uint32_t actual_pack_crc = 0xffffffffu;
        for (std::size_t index = 0u; index < packed_size; ++index) {
            if ((index & 4095u) == 0u) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
            }
            actual_pack_crc ^= bytes[pack_start + index];
            for (int bit = 0; bit < 8; ++bit)
                actual_pack_crc = (actual_pack_crc >> 1u) ^
                                  (0xedb88320u &
                                   (0u - (actual_pack_crc & 1u)));
        }
        actual_pack_crc ^= 0xffffffffu;
        if (pack_crc_defined && actual_pack_crc != pack_crc)
            return Archive7zResult::CrcMismatch;

        std::array<std::string, kMaxCoders> coder_outputs{};
        std::array<bool, kMaxCoders> coder_completed{};
        for (std::size_t step = 0u;
             step < static_cast<std::size_t>(coder_count); ++step) {
            bool progressed = false;
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder) {
                if (coder_completed[coder]) continue;
                const int source = input_sources[coder];
                if (source >= 0 &&
                    !coder_completed[static_cast<std::size_t>(source)])
                    continue;
                const std::uint8_t* input = nullptr;
                std::size_t input_size = 0u;
                if (source < 0) {
                    if (static_cast<int>(coder) != packed_input_index)
                        return Archive7zResult::Unsupported;
                    input = bytes + pack_start;
                    input_size = packed_size;
                } else {
                    const std::string& source_output =
                        coder_outputs[static_cast<std::size_t>(source)];
                    input = reinterpret_cast<const std::uint8_t*>(
                        source_output.data());
                    input_size = source_output.size();
                }
                const std::size_t expected_size = static_cast<std::size_t>(
                    coder_unpack_sizes[coder]);
                std::string& coder_output = coder_outputs[coder];
                if (coder_methods[coder] == 0u) {
                    if (input_size != expected_size)
                        return Archive7zResult::Malformed;
                    std::size_t copied = 0u;
                    while (copied < input_size) {
                        if (deadline != nullptr && deadline(deadlineContext))
                            return Archive7zResult::Deadline;
                        if (cancellation != nullptr &&
                            cancellation(cancellationContext))
                            return Archive7zResult::Cancelled;
                        const std::size_t part =
                            (input_size - copied) > 65536u
                                ? 65536u
                                : input_size - copied;
                        coder_output.append(
                            reinterpret_cast<const char*>(input + copied),
                            part);
                        copied += part;
                    }
                } else if (lzma2_coders[coder] &&
                           coder_methods[coder] == UINT64_C(0x21)) {
                    ArchiveXzReader lzma2_reader;
                    const ArchiveXzResult lzma2_result =
                        lzma2_reader.decodeRawLzma2(
                            input, input_size, lzma2_properties[coder],
                            expected_size, coder_output, cancellation,
                            cancellationContext, deadline, deadlineContext);
                    if (lzma2_result == ArchiveXzResult::Cancelled)
                        return Archive7zResult::Cancelled;
                    if (lzma2_result == ArchiveXzResult::Deadline)
                        return Archive7zResult::Deadline;
                    if (lzma2_result == ArchiveXzResult::Limit)
                        return Archive7zResult::Limit;
                    if (lzma2_result == ArchiveXzResult::Unsupported)
                        return Archive7zResult::Unsupported;
                    if (lzma2_result != ArchiveXzResult::Ok)
                        return Archive7zResult::Malformed;
                } else if (raw_filter_coders[coder]) {
                    if (input_size != expected_size)
                        return Archive7zResult::Malformed;
                    ArchiveXzReader filter_reader;
                    const ArchiveXzResult filter_result =
                        filter_reader.decodeRawFilter(
                            static_cast<std::uint8_t>(coder_methods[coder]),
                            filter_property_sizes[coder] == 0u
                                ? nullptr
                                : filter_properties[coder].data(),
                            filter_property_sizes[coder], input, input_size,
                            coder_output, cancellation, cancellationContext,
                            deadline, deadlineContext);
                    if (filter_result == ArchiveXzResult::Cancelled)
                        return Archive7zResult::Cancelled;
                    if (filter_result == ArchiveXzResult::Deadline)
                        return Archive7zResult::Deadline;
                    if (filter_result == ArchiveXzResult::Limit)
                        return Archive7zResult::Limit;
                    if (filter_result == ArchiveXzResult::Unsupported)
                        return Archive7zResult::Unsupported;
                    if (filter_result != ArchiveXzResult::Ok)
                        return Archive7zResult::Malformed;
                } else if (lzma_coders[coder] &&
                           coder_methods[coder] == UINT64_C(0x010103)) {
                    ArchiveXzReader lzma_reader;
                    const ArchiveXzResult lzma_result =
                        lzma_reader.decodeRawLzmaWithDeadline(
                            input, input_size, lzma_properties[coder][0u],
                            lzma_dictionary_sizes[coder], expected_size,
                            coder_output, cancellation, cancellationContext,
                            deadline, deadlineContext);
                    if (lzma_result == ArchiveXzResult::Cancelled)
                        return Archive7zResult::Cancelled;
                    if (lzma_result == ArchiveXzResult::Deadline)
                        return Archive7zResult::Deadline;
                    if (lzma_result == ArchiveXzResult::Limit)
                        return Archive7zResult::Limit;
                    if (lzma_result != ArchiveXzResult::Ok)
                        return Archive7zResult::Malformed;
                } else {
                    return Archive7zResult::Unsupported;
                }
                if (coder_output.size() != expected_size)
                    return Archive7zResult::Malformed;
                coder_completed[coder] = true;
                progressed = true;
            }
            if (!progressed) return Archive7zResult::Unsupported;
            bool all_completed = true;
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder)
                if (!coder_completed[coder]) all_completed = false;
            if (all_completed) break;
        }
        if (!coder_completed[final_output_index])
            return Archive7zResult::Unsupported;
        const std::string& decoded = coder_outputs[final_output_index];
        if (decoded.size() != static_cast<std::size_t>(unpack_size))
            return Archive7zResult::Malformed;
        if (folder_crc_defined &&
            rinruntime_archive_crc32(
                reinterpret_cast<const std::uint8_t*>(decoded.data()),
                decoded.size()) != folder_crc)
            return Archive7zResult::CrcMismatch;
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
