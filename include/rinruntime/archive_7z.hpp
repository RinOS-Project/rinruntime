/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded 7z envelope inspection. */

#ifndef RINRUNTIME_ARCHIVE_7Z_HPP
#define RINRUNTIME_ARCHIVE_7Z_HPP

#include "archive_deflate.hpp"
#include "archive_policy.h"
#include "archive_xz.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#    include <new>
#endif
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

struct Archive7zEntrySummary {
    std::size_t offset = 0u;
    std::size_t size = 0u;
    bool directory = false;
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
        entry_count_ = 0u;
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

    /* Decode a bounded 7z pipeline of up to four one-in/one-out Copy, Delta,
     * and LZMA coders, or one BCJ2 coder with four packed input streams, plus
     * bounded linear Copy／raw-filter folders of up to two coders containing
     * regular substreams, plus empty
     * regular files/directories with no packed stream.
     * BindPairs are validated before any coder runs.  A multi-entry folder is
     * exposed as bounded slices of the decoded folder stream, with
     * `FilesInfo`-described empty files/directories interleaved in file order.
     * This subset is useful
     * for caller-owned test/resource bytes and intentionally has no path,
     * filename, filesystem, or service authority.  Multi-stream coders,
     * arbitrary multi-stream graphs, multi-folder coder chains, encryption,
     * empty entries in a non-empty folder, and external headers remain
     * explicit Unsupported results. */
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

    std::size_t entryCount() const { return entry_count_; }

    const Archive7zEntrySummary* entry(std::size_t index) const
    {
        if (index >= entry_count_) return nullptr;
        return &entries_[index];
    }

private:
    Archive7zResult decodeStored(
        const std::uint8_t* bytes, std::size_t size, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
        entry_count_ = 0u;
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
        std::size_t pack_stream_count = 0u;
        static constexpr std::size_t kMaxPackedStreams = 4u;
        std::array<std::uint64_t, kMaxPackedStreams> pack_sizes{};
        std::array<bool, kMaxPackedStreams> pack_crc_defined{};
        std::array<std::uint32_t, kMaxPackedStreams> pack_crcs{};
        std::uint64_t unpack_size = 0u;
        std::uint32_t folder_crc = 0u;
        bool folder_crc_defined = false;
        std::uint64_t substream_count = 1u;
        std::array<std::uint64_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            substream_sizes{};
        std::array<bool, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            substream_crc_defined{};
        std::array<std::uint32_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            substream_crcs{};
        bool substream_sizes_present = false;
        bool substream_crcs_present = false;
        bool substream_count_present = false;
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
        std::array<std::size_t, kMaxPackedStreams> packed_stream_inputs{};
        input_sources.fill(-1);
        std::size_t final_output_index = kMaxCoders;
        int packed_input_index = -1;
        bool stream_info_present = false;
        bool bcj2_folder = false;
        std::uint64_t file_count = 0u;
        std::array<bool, RINRUNTIME_ARCHIVE_ENTRY_LIMIT> file_empty_stream{};
        std::array<bool, RINRUNTIME_ARCHIVE_ENTRY_LIMIT> file_empty_regular{};
        std::size_t empty_stream_count = 0u;
        bool files_info_present = false;
        bool empty_stream_present = false;
        bool empty_file_present = false;

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
            std::uint64_t encoded_pack_stream_count = 0u;
            if (!readEncodedUInt64(bytes, end, cursor,
                                   encoded_pack_stream_count))
                return Archive7zResult::Malformed;
            if (encoded_pack_stream_count == 0u ||
                encoded_pack_stream_count > kMaxPackedStreams ||
                (encoded_pack_stream_count != 1u &&
                 encoded_pack_stream_count != 2u &&
                 encoded_pack_stream_count != 3u &&
                 encoded_pack_stream_count != 4u))
                return Archive7zResult::Unsupported;
            pack_stream_count =
                static_cast<std::size_t>(encoded_pack_stream_count);
            if (!takeByte(bytes, end, cursor, 0x09u) ||
                pack_stream_count == 0u)
                return Archive7zResult::Malformed;
            for (std::size_t stream = 0u; stream < pack_stream_count;
                 ++stream) {
                if (!readEncodedUInt64(bytes, end, cursor,
                                       pack_sizes[stream]))
                    return Archive7zResult::Malformed;
                if (pack_sizes[stream] >
                    static_cast<std::uint64_t>(kMaxStreamBytes) ||
                    pack_size > static_cast<std::uint64_t>(kMaxStreamBytes) -
                                     pack_sizes[stream])
                    return Archive7zResult::Limit;
                pack_size += pack_sizes[stream];
            }
            if (cursor < end && bytes[cursor] == 0x0au) {
                ++cursor;
                if (!readCrcs(bytes, end, cursor, pack_stream_count,
                              pack_crc_defined, pack_crcs))
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
            if (cursor >= end) return Archive7zResult::Malformed;
            if (bytes[cursor++] != 0u) return Archive7zResult::Unsupported;
            if (folder_count != 1u) {
                return decodeSimpleFolders(
                    bytes, size, summary.nextHeaderOffset, end, cursor,
                    pack_position, pack_stream_count, pack_sizes,
                    pack_crc_defined, pack_crcs, folder_count, output,
                    cancellation, cancellationContext, deadline,
                    deadlineContext);
            }

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
                std::array<std::uint8_t, 8u> method_bytes{};
                for (unsigned index = 0u; index != method_size; ++index)
                    method_bytes[index] = bytes[cursor++];
                for (unsigned index = 0u; index != method_size; ++index)
                    method |= static_cast<std::uint64_t>(method_bytes[index])
                              << (index * 8u);
                const bool is_bcj2_method =
                    method_size == 4u && method_bytes[0u] == 0x03u &&
                    method_bytes[1u] == 0x03u && method_bytes[2u] == 0x01u &&
                    method_bytes[3u] == 0x1bu;
                if (complex_coder) {
                    std::uint64_t input_streams = 0u;
                    std::uint64_t output_streams = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor,
                                           input_streams) ||
                        !readEncodedUInt64(bytes, end, cursor,
                                           output_streams))
                        return Archive7zResult::Unsupported;
                    if (is_bcj2_method && input_streams == 4u &&
                        output_streams == 1u) {
                        if (coder_count != 1u || pack_stream_count != 4u ||
                            has_properties)
                            return Archive7zResult::Unsupported;
                        bcj2_folder = true;
                    } else if (input_streams != 1u || output_streams != 1u) {
                        return Archive7zResult::Unsupported;
                    }
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
                } else if (is_bcj2_method) {
                    if (!complex_coder || !bcj2_folder)
                        return Archive7zResult::Unsupported;
                } else if (method >= 0x05u && method <= 0x0bu) {
                    raw_filter_coders[coder] = true;
                } else if (method != 0u) {
                    return Archive7zResult::Unsupported;
                }
                coder_methods[coder] = method;
            }

            if (bcj2_folder) {
                /* A single BCJ2 coder has one output, four inputs, no bonds,
                 * and an explicit packed-stream index for each input. */
                for (std::size_t stream = 0u; stream != 4u; ++stream) {
                    std::uint64_t input_index = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor, input_index) ||
                        input_index >= 4u)
                        return Archive7zResult::Unsupported;
                    for (std::size_t prior = 0u; prior < stream; ++prior)
                        if (packed_stream_inputs[prior] ==
                            static_cast<std::size_t>(input_index))
                            return Archive7zResult::Unsupported;
                    packed_stream_inputs[stream] =
                        static_cast<std::size_t>(input_index);
                }
                final_output_index = 0u;
            } else {
                if (pack_stream_count != 1u)
                    return Archive7zResult::Unsupported;
                /* With one stream per coder, the folder has coder_count - 1
                 * bindings and exactly one packed input and one final output. */
                for (std::size_t pair = 0u;
                     pair + 1u < static_cast<std::size_t>(coder_count);
                     ++pair) {
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
                if (packed_input_index == -1 ||
                    final_output_index == kMaxCoders)
                    return Archive7zResult::Unsupported;
            }

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

            /* A one-folder/one-stream archive has no need for SubStreamsInfo.
             * When present, this bounded reader accepts only the standard
             * single-folder substream layout: the decoded folder stream is
             * split into regular entries after the folder coder runs. */
            if (cursor >= end) return Archive7zResult::Malformed;
            if (bytes[cursor] == 0x08u) {
                ++cursor;
                while (cursor < end && bytes[cursor] != 0u) {
                    if (deadline != nullptr && deadline(deadlineContext))
                        return Archive7zResult::Deadline;
                    if (cancellation != nullptr &&
                        cancellation(cancellationContext))
                        return Archive7zResult::Cancelled;
                    const std::uint8_t property = bytes[cursor++];
                    if (property == 0x0du) {
                        if (substream_count_present ||
                            substream_sizes_present ||
                            substream_crcs_present)
                            return Archive7zResult::Malformed;
                        substream_count_present = true;
                        if (!readEncodedUInt64(bytes, end, cursor,
                                               substream_count))
                            return Archive7zResult::Malformed;
                        if (substream_count == 0u ||
                            substream_count > RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
                            return Archive7zResult::Unsupported;
                    } else if (property == 0x09u) {
                        if (substream_sizes_present || substream_count == 0u)
                            return Archive7zResult::Malformed;
                        substream_sizes_present = true;
                        std::uint64_t total = 0u;
                        for (std::uint64_t index = 0u;
                             index + 1u < substream_count; ++index) {
                            std::uint64_t substream_size = 0u;
                            if (!readEncodedUInt64(bytes, end, cursor,
                                                   substream_size) ||
                                substream_size > unpack_size ||
                                total > unpack_size - substream_size)
                                return Archive7zResult::Malformed;
                            substream_sizes[static_cast<std::size_t>(index)] =
                                substream_size;
                            total += substream_size;
                        }
                        if (total > unpack_size)
                            return Archive7zResult::Malformed;
                        substream_sizes[static_cast<std::size_t>(
                            substream_count - 1u)] = unpack_size - total;
                    } else if (property == 0x0au) {
                        if (substream_crcs_present || substream_count == 0u)
                            return Archive7zResult::Malformed;
                        substream_crcs_present = true;
                        if (!readCrcs(bytes, end, cursor,
                                      static_cast<std::size_t>(substream_count),
                                      substream_crc_defined,
                                      substream_crcs))
                            return Archive7zResult::Malformed;
                    } else {
                        return Archive7zResult::Unsupported;
                    }
                }
                if (!takeByte(bytes, end, cursor, 0x00u))
                    return Archive7zResult::Malformed;
                if (substream_count > 1u && !substream_sizes_present)
                    return Archive7zResult::Unsupported;
                if (!substream_sizes_present && substream_count == 1u)
                    substream_sizes[0u] = unpack_size;
            } else {
                substream_sizes[0u] = unpack_size;
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
            if (substream_count == 1u && substream_crcs_present &&
                substream_crc_defined[0u] && folder_crc_defined &&
                substream_crcs[0u] != folder_crc)
                return Archive7zResult::CrcMismatch;
        }

        /* FilesInfo is parsed only far enough to map decoded substreams to
         * regular files.  Names and other metadata are intentionally not
         * public output.  Empty regular files/directories may be interleaved
         * with the decoded substreams or may be the whole archive. */
        if (cursor < end && bytes[cursor] == 0x05u) {
            files_info_present = true;
            ++cursor;
            if (!readEncodedUInt64(bytes, end, cursor, file_count))
                return Archive7zResult::Malformed;
            if (file_count == 0u ||
                file_count > RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
                return Archive7zResult::Unsupported;
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
                    const std::size_t count =
                        static_cast<std::size_t>(file_count);
                    const std::size_t bitmap_size = (count + 7u) / 8u;
                    if (empty_stream_present || property_size != bitmap_size ||
                        bitmap_size > end - cursor)
                        return Archive7zResult::Malformed;
                    empty_stream_present = true;
                    empty_stream_count = 0u;
                    for (std::size_t byte = 0u; byte < bitmap_size; ++byte) {
                        const std::uint8_t bitmap = bytes[cursor + byte];
                        const std::size_t first = byte * 8u;
                        for (std::size_t bit = 0u;
                             bit != 8u && first + bit < count; ++bit) {
                            const bool empty =
                                (bitmap & static_cast<std::uint8_t>(1u << bit)) !=
                                0u;
                            file_empty_stream[first + bit] = empty;
                            if (empty) ++empty_stream_count;
                        }
                        if (first + 8u > count &&
                            (bitmap & static_cast<std::uint8_t>(
                                           0xffu << (count - first))) != 0u)
                            return Archive7zResult::Malformed;
                    }
                } else if (property == 0x0fu) {
                    if (!empty_stream_present || empty_file_present)
                        return Archive7zResult::Malformed;
                    const std::size_t bitmap_size =
                        (empty_stream_count + 7u) / 8u;
                    if (property_size != bitmap_size ||
                        bitmap_size > end - cursor)
                        return Archive7zResult::Malformed;
                    std::array<bool, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
                        empty_file_ordinal{};
                    for (std::size_t byte = 0u; byte < bitmap_size; ++byte) {
                        const std::uint8_t bitmap = bytes[cursor + byte];
                        const std::size_t first = byte * 8u;
                        for (std::size_t bit = 0u;
                             bit != 8u && first + bit < empty_stream_count;
                             ++bit)
                            empty_file_ordinal[first + bit] =
                                (bitmap & static_cast<std::uint8_t>(
                                               1u << bit)) != 0u;
                        if (first + 8u > empty_stream_count &&
                            (bitmap & static_cast<std::uint8_t>(
                                           0xffu << (empty_stream_count -
                                                     first))) != 0u)
                            return Archive7zResult::Malformed;
                    }
                    std::size_t ordinal = 0u;
                    for (std::size_t file = 0u;
                         file < static_cast<std::size_t>(file_count); ++file) {
                        if (!file_empty_stream[file]) continue;
                        file_empty_regular[file] = empty_file_ordinal[ordinal++];
                    }
                    empty_file_present = true;
                } else if (property == 0x10u) {
                    return Archive7zResult::Unsupported;
                }
                cursor = property_end;
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
            if (stream_info_present) {
                if (file_count < substream_count ||
                    empty_stream_count != file_count - substream_count ||
                    (empty_stream_count != 0u && !empty_file_present) ||
                    (empty_stream_count == 0u && empty_file_present))
                    return Archive7zResult::Unsupported;
            } else if (!empty_stream_present || !empty_file_present ||
                       empty_stream_count != file_count) {
                return Archive7zResult::Unsupported;
            }
        } else if (substream_count > 1u) {
            return Archive7zResult::Unsupported;
        }
        if (!takeByte(bytes, end, cursor, 0x00u) || cursor != end)
            return Archive7zResult::Malformed;

        const auto publish_entries = [&](const std::string& decoded)
            -> Archive7zResult {
            if (decoded.size() != static_cast<std::size_t>(unpack_size))
                return Archive7zResult::Malformed;
            if (folder_crc_defined &&
                rinruntime_archive_crc32(
                    reinterpret_cast<const std::uint8_t*>(decoded.data()),
                    decoded.size()) != folder_crc)
                return Archive7zResult::CrcMismatch;
            if (substream_count == 0u ||
                substream_count > RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
                return Archive7zResult::Unsupported;
            const std::size_t published_count = files_info_present
                                                    ? static_cast<std::size_t>(
                                                          file_count)
                                                    : static_cast<std::size_t>(
                                                          substream_count);
            if (published_count == 0u ||
                published_count > RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
                return Archive7zResult::Unsupported;
            std::size_t offset = 0u;
            std::size_t substream_index = 0u;
            for (std::size_t index = 0u; index < published_count; ++index) {
                if (files_info_present && file_empty_stream[index]) {
                    entries_[index] = {0u, 0u, !file_empty_regular[index]};
                    continue;
                }
                if (substream_index >= static_cast<std::size_t>(
                                           substream_count))
                    return Archive7zResult::Malformed;
                const std::uint64_t entry_size64 =
                    substream_sizes[substream_index];
                if (offset > decoded.size() || entry_size64 > unpack_size ||
                    entry_size64 > static_cast<std::uint64_t>(decoded.size() -
                                                               offset))
                    return Archive7zResult::Malformed;
                const std::size_t entry_size =
                    static_cast<std::size_t>(entry_size64);
                if (entry_size == 0u)
                    return Archive7zResult::Unsupported;
                if (substream_crc_defined[substream_index] &&
                    rinruntime_archive_crc32(
                        reinterpret_cast<const std::uint8_t*>(
                            decoded.data() + offset),
                        entry_size) != substream_crcs[substream_index])
                    return Archive7zResult::CrcMismatch;
                entries_[index] = {offset, entry_size, false};
                offset += entry_size;
                ++substream_index;
            }
            if (substream_index != static_cast<std::size_t>(substream_count) ||
                offset != decoded.size())
                return Archive7zResult::Malformed;
            entry_count_ = published_count;
            return Archive7zResult::Ok;
        };
        if (!stream_info_present) {
            if (!files_info_present || file_count == 0u || pack_size != 0u ||
                unpack_size != 0u)
                return Archive7zResult::Unsupported;
            output.clear();
            for (std::size_t index = 0u;
                 index < static_cast<std::size_t>(file_count); ++index)
                entries_[index] = {0u, 0u, !file_empty_regular[index]};
            entry_count_ = static_cast<std::size_t>(file_count);
            return Archive7zResult::Ok;
        }
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
        std::array<std::size_t, kMaxPackedStreams> pack_starts{};
        std::size_t pack_offset = pack_start;
        for (std::size_t stream = 0u; stream < pack_stream_count;
             ++stream) {
            pack_starts[stream] = pack_offset;
            if (pack_offset > summary.nextHeaderOffset)
                return Archive7zResult::Malformed;
            if (pack_sizes[stream] >
                static_cast<std::uint64_t>(summary.nextHeaderOffset -
                                           pack_offset))
                return Archive7zResult::Malformed;
            pack_offset += static_cast<std::size_t>(pack_sizes[stream]);
        }
        if (pack_offset != pack_start + static_cast<std::size_t>(pack_size))
            return Archive7zResult::Malformed;
        for (std::size_t stream = 0u; stream < pack_stream_count; ++stream) {
            const std::size_t stream_size =
                static_cast<std::size_t>(pack_sizes[stream]);
            std::uint32_t actual_pack_crc = 0xffffffffu;
            for (std::size_t index = 0u; index < stream_size; ++index) {
                if ((index & 4095u) == 0u) {
                    if (deadline != nullptr && deadline(deadlineContext))
                        return Archive7zResult::Deadline;
                    if (cancellation != nullptr &&
                        cancellation(cancellationContext))
                        return Archive7zResult::Cancelled;
                }
                actual_pack_crc ^= bytes[pack_starts[stream] + index];
                for (int bit = 0; bit < 8; ++bit)
                    actual_pack_crc = (actual_pack_crc >> 1u) ^
                                      (0xedb88320u &
                                       (0u - (actual_pack_crc & 1u)));
            }
            actual_pack_crc ^= 0xffffffffu;
            if (pack_crc_defined[stream] &&
                actual_pack_crc != pack_crcs[stream])
                return Archive7zResult::CrcMismatch;
        }

        if (bcj2_folder) {
            std::array<const std::uint8_t*, 4u> bcj2_streams{};
            std::array<std::size_t, 4u> bcj2_sizes{};
            for (std::size_t packed = 0u; packed != 4u; ++packed) {
                const std::size_t input = packed_stream_inputs[packed];
                bcj2_streams[input] = bytes + pack_starts[packed];
                bcj2_sizes[input] =
                    static_cast<std::size_t>(pack_sizes[packed]);
            }
            std::string decoded;
            const Archive7zResult bcj2_result = decodeBcj2(
                bcj2_streams, bcj2_sizes,
                static_cast<std::size_t>(unpack_size), decoded, cancellation,
                cancellationContext, deadline, deadlineContext);
            if (bcj2_result != Archive7zResult::Ok)
                return bcj2_result;
            if (folder_crc_defined &&
                rinruntime_archive_crc32(
                    reinterpret_cast<const std::uint8_t*>(decoded.data()),
                    decoded.size()) != folder_crc)
                return Archive7zResult::CrcMismatch;
            const Archive7zResult entry_result = publish_entries(decoded);
            if (entry_result != Archive7zResult::Ok) return entry_result;
            output = decoded;
            return Archive7zResult::Ok;
        }

        const std::size_t packed_size =
            static_cast<std::size_t>(pack_sizes[0u]);

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
        const Archive7zResult entry_result = publish_entries(decoded);
        if (entry_result != Archive7zResult::Ok) return entry_result;
        output = decoded;
        return Archive7zResult::Ok;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            entry_count_ = 0u;
            output.clear();
            return Archive7zResult::Limit;
        }
#endif
    }

    Archive7zResult decodeSimpleFolders(
        const std::uint8_t* bytes, std::size_t size,
        std::size_t next_header_offset, std::size_t end,
        std::size_t& cursor, std::uint64_t pack_position,
        std::size_t pack_stream_count,
        const std::array<std::uint64_t, 4u>& pack_sizes,
        const std::array<bool, 4u>& pack_crc_defined,
        const std::array<std::uint32_t, 4u>& pack_crcs,
        std::uint64_t folder_count, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext) const
    {
        static constexpr std::size_t kMaxFolders = 4u;
        if (folder_count < 2u || folder_count > kMaxFolders ||
            pack_stream_count != static_cast<std::size_t>(folder_count))
            return Archive7zResult::Unsupported;

        std::array<std::uint64_t, kMaxFolders> unpack_sizes{};
        std::array<bool, kMaxFolders> folder_crc_defined{};
        std::array<std::uint32_t, kMaxFolders> folder_crcs{};
        static constexpr std::size_t kMaxFolderCoders = 2u;
        std::array<std::size_t, kMaxFolders> folder_coder_counts{};
        std::array<std::array<std::uint64_t, kMaxFolderCoders>, kMaxFolders>
            folder_methods{};
        std::array<std::array<std::array<std::uint8_t, 4u>,
                               kMaxFolderCoders>,
                   kMaxFolders>
            folder_properties{};
        std::array<std::array<std::size_t, kMaxFolderCoders>, kMaxFolders>
            folder_property_sizes{};
        std::array<std::array<std::uint64_t, kMaxFolderCoders>, kMaxFolders>
            folder_coder_unpack_sizes{};
        std::array<std::size_t, kMaxFolders> substream_counts{};
        std::array<std::array<std::uint64_t,
                               RINRUNTIME_ARCHIVE_ENTRY_LIMIT>,
                   kMaxFolders>
            substream_sizes{};
        std::array<bool, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            substream_crc_defined{};
        std::array<std::uint32_t, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
            substream_crcs{};
        const std::size_t folders = static_cast<std::size_t>(folder_count);
        substream_counts.fill(1u);

        /* This deliberately bounded extension accepts at most two Copy or
         * raw filter coders per folder.  The folder input is mapped to the
         * packed stream with the same ordinal; the only accepted bond is the
         * linear second-coder <- first-coder pair. */
        for (std::size_t folder = 0u; folder < folders; ++folder) {
            if (deadline != nullptr && deadline(deadlineContext))
                return Archive7zResult::Deadline;
            if (cancellation != nullptr && cancellation(cancellationContext))
                return Archive7zResult::Cancelled;
            std::uint64_t coder_count = 0u;
            if (!readEncodedUInt64(bytes, end, cursor, coder_count))
                return Archive7zResult::Malformed;
            if (coder_count == 0u || coder_count > kMaxFolderCoders)
                return Archive7zResult::Unsupported;
            folder_coder_counts[folder] =
                static_cast<std::size_t>(coder_count);
            for (std::size_t coder = 0u;
                 coder < static_cast<std::size_t>(coder_count); ++coder) {
                if (cursor >= end) return Archive7zResult::Malformed;
                const std::uint8_t coder_flags = bytes[cursor++];
                const unsigned method_size = coder_flags & 0x0fu;
                const bool has_properties = (coder_flags & 0x20u) != 0u;
                if (method_size != 1u || (coder_flags & 0xd0u) != 0u ||
                    cursor >= end)
                    return Archive7zResult::Unsupported;
                const std::uint64_t method = bytes[cursor++];
                folder_methods[folder][coder] = method;
                std::size_t expected_property_size = 0u;
                if (method == 0u) {
                    if (has_properties) return Archive7zResult::Unsupported;
                } else if (method == 0x03u) {
                    expected_property_size = 1u;
                } else if (method == 0x04u) {
                    expected_property_size = 4u;
                } else if (method >= 0x05u && method <= 0x0bu) {
                    expected_property_size = 0u;
                } else {
                    return Archive7zResult::Unsupported;
                }
                if (has_properties) {
                    std::uint64_t property_size = 0u;
                    if (!readEncodedUInt64(bytes, end, cursor,
                                           property_size) ||
                        property_size != expected_property_size ||
                        property_size > folder_properties[folder][coder].size())
                        return Archive7zResult::Unsupported;
                    folder_property_sizes[folder][coder] =
                        static_cast<std::size_t>(property_size);
                    for (std::size_t index = 0u; index < property_size;
                         ++index)
                        folder_properties[folder][coder][index] =
                            bytes[cursor++];
                } else if (expected_property_size != 0u) {
                    return Archive7zResult::Unsupported;
                }
            }
            if (coder_count == 2u) {
                std::uint64_t input_index = 0u;
                std::uint64_t output_index = 0u;
                if (!readEncodedUInt64(bytes, end, cursor, input_index) ||
                    !readEncodedUInt64(bytes, end, cursor, output_index) ||
                    input_index != 1u || output_index != 0u)
                    return Archive7zResult::Unsupported;
            }
        }

        if (!takeByte(bytes, end, cursor, 0x0cu))
            return Archive7zResult::Malformed;
        std::uint64_t total_unpack_size = 0u;
        for (std::size_t folder = 0u; folder < folders; ++folder) {
            const std::size_t coder_count = folder_coder_counts[folder];
            for (std::size_t coder = 0u; coder < coder_count; ++coder) {
                if (!readEncodedUInt64(bytes, end, cursor,
                                       folder_coder_unpack_sizes[folder][coder]))
                    return Archive7zResult::Malformed;
                if (folder_coder_unpack_sizes[folder][coder] >
                    static_cast<std::uint64_t>(kMaxStreamBytes))
                    return Archive7zResult::Limit;
            }
            unpack_sizes[folder] =
                folder_coder_unpack_sizes[folder][coder_count - 1u];
            if (unpack_sizes[folder] >
                    static_cast<std::uint64_t>(kMaxStreamBytes) ||
                total_unpack_size >
                    static_cast<std::uint64_t>(kMaxStreamBytes) -
                        unpack_sizes[folder])
                return Archive7zResult::Limit;
            total_unpack_size += unpack_sizes[folder];
        }
        if (cursor < end && bytes[cursor] == 0x0au) {
            ++cursor;
            if (!readCrcs(bytes, end, cursor, folders, folder_crc_defined,
                          folder_crcs))
                return Archive7zResult::Malformed;
        }
        if (!takeByte(bytes, end, cursor, 0x00u))
            return Archive7zResult::Malformed;

        std::size_t total_substreams = folders;
        bool substream_counts_present = false;
        bool substream_sizes_present = false;
        bool substream_crcs_present = false;
        if (cursor < end && bytes[cursor] == 0x08u) {
            ++cursor;
            while (cursor < end && bytes[cursor] != 0u) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
                const std::uint8_t property = bytes[cursor++];
                if (property == 0x0du) {
                    if (substream_counts_present ||
                        substream_sizes_present || substream_crcs_present)
                        return Archive7zResult::Malformed;
                    substream_counts_present = true;
                    total_substreams = 0u;
                    for (std::size_t folder = 0u; folder < folders;
                         ++folder) {
                        std::uint64_t count = 0u;
                        if (!readEncodedUInt64(bytes, end, cursor, count) ||
                            count == 0u ||
                            count > RINRUNTIME_ARCHIVE_ENTRY_LIMIT ||
                            total_substreams >
                                RINRUNTIME_ARCHIVE_ENTRY_LIMIT -
                                    static_cast<std::size_t>(count))
                            return Archive7zResult::Unsupported;
                        substream_counts[folder] =
                            static_cast<std::size_t>(count);
                        total_substreams += static_cast<std::size_t>(count);
                    }
                } else if (property == 0x09u) {
                    if (substream_sizes_present || !substream_counts_present)
                        return Archive7zResult::Malformed;
                    substream_sizes_present = true;
                    for (std::size_t folder = 0u; folder < folders;
                         ++folder) {
                        const std::size_t count = substream_counts[folder];
                        std::uint64_t total = 0u;
                        for (std::size_t index = 0u; index + 1u < count;
                             ++index) {
                            std::uint64_t substream_size = 0u;
                            if (!readEncodedUInt64(bytes, end, cursor,
                                                   substream_size) ||
                                substream_size > unpack_sizes[folder] ||
                                total > unpack_sizes[folder] -
                                            substream_size)
                                return Archive7zResult::Malformed;
                            substream_sizes[folder][index] = substream_size;
                            total += substream_size;
                        }
                        substream_sizes[folder][count - 1u] =
                            unpack_sizes[folder] - total;
                    }
                } else if (property == 0x0au) {
                    if (substream_crcs_present)
                        return Archive7zResult::Malformed;
                    substream_crcs_present = true;
                    if (!readCrcs(bytes, end, cursor, total_substreams,
                                  substream_crc_defined, substream_crcs))
                        return Archive7zResult::Malformed;
                } else {
                    return Archive7zResult::Unsupported;
                }
            }
            if (!takeByte(bytes, end, cursor, 0x00u))
                return Archive7zResult::Malformed;
            if (!substream_sizes_present) {
                if (total_substreams != folders)
                    return Archive7zResult::Unsupported;
                for (std::size_t folder = 0u; folder < folders; ++folder)
                    substream_sizes[folder][0u] = unpack_sizes[folder];
            }
        } else {
            for (std::size_t folder = 0u; folder < folders; ++folder)
                substream_sizes[folder][0u] = unpack_sizes[folder];
        }
        if (substream_crcs_present &&
            total_substreams == folders) {
            for (std::size_t folder = 0u; folder < folders; ++folder) {
                if (folder_crc_defined[folder] &&
                    substream_crc_defined[folder] &&
                    substream_crcs[folder] != folder_crcs[folder])
                    return Archive7zResult::CrcMismatch;
            }
        }
        if (!takeByte(bytes, end, cursor, 0x00u) ||
            !takeByte(bytes, end, cursor, 0x05u))
            return Archive7zResult::Malformed;
        std::uint64_t file_count = 0u;
        if (!readEncodedUInt64(bytes, end, cursor, file_count) ||
            file_count != static_cast<std::uint64_t>(total_substreams))
            return Archive7zResult::Unsupported;
        if (!takeByte(bytes, end, cursor, 0x00u) ||
            !takeByte(bytes, end, cursor, 0x00u) || cursor != end)
            return Archive7zResult::Malformed;

        if (pack_position > static_cast<std::uint64_t>(
                                size - kSignatureHeaderSize))
            return Archive7zResult::Malformed;
        const std::uint64_t pack_start64 =
            static_cast<std::uint64_t>(kSignatureHeaderSize) + pack_position;
        if (pack_start64 > static_cast<std::uint64_t>(next_header_offset))
            return Archive7zResult::Malformed;
        std::size_t pack_offset = static_cast<std::size_t>(pack_start64);
        std::string combined;
        combined.reserve(static_cast<std::size_t>(total_unpack_size));
        for (std::size_t folder = 0u; folder < folders; ++folder) {
            if (pack_offset > next_header_offset ||
                pack_sizes[folder] > static_cast<std::uint64_t>(
                                         next_header_offset - pack_offset))
                return Archive7zResult::Malformed;
            const std::size_t packed_size =
                static_cast<std::size_t>(pack_sizes[folder]);
            if (pack_sizes[folder] != unpack_sizes[folder])
                return Archive7zResult::Malformed;
            std::uint32_t actual_crc = 0xffffffffu;
            for (std::size_t index = 0u; index < packed_size; ++index) {
                if ((index & 4095u) == 0u) {
                    if (deadline != nullptr && deadline(deadlineContext))
                        return Archive7zResult::Deadline;
                    if (cancellation != nullptr &&
                        cancellation(cancellationContext))
                        return Archive7zResult::Cancelled;
                }
                const std::uint8_t value = bytes[pack_offset + index];
                actual_crc ^= value;
                for (int bit = 0; bit < 8; ++bit)
                    actual_crc = (actual_crc >> 1u) ^
                                 (0xedb88320u &
                                  (0u - (actual_crc & 1u)));
            }
            actual_crc ^= 0xffffffffu;
            if (pack_crc_defined[folder] &&
                actual_crc != pack_crcs[folder])
                return Archive7zResult::CrcMismatch;
            const std::size_t folder_start = combined.size();
            std::string coder_input(
                reinterpret_cast<const char*>(bytes + pack_offset),
                packed_size);
            for (std::size_t coder = 0u;
                 coder < folder_coder_counts[folder]; ++coder) {
                if (deadline != nullptr && deadline(deadlineContext))
                    return Archive7zResult::Deadline;
                if (cancellation != nullptr &&
                    cancellation(cancellationContext))
                    return Archive7zResult::Cancelled;
                std::string coder_output;
                const std::uint64_t method = folder_methods[folder][coder];
                if (method == 0u) {
                    /* Copy preserves the bounded caller-owned buffer. */
                } else {
                    ArchiveXzReader filter_reader;
                    const ArchiveXzResult filter_result =
                        filter_reader.decodeRawFilter(
                            static_cast<std::uint8_t>(method),
                            folder_property_sizes[folder][coder] == 0u
                                ? nullptr
                                : folder_properties[folder][coder].data(),
                            folder_property_sizes[folder][coder],
                            reinterpret_cast<const std::uint8_t*>(
                                coder_input.data()),
                            coder_input.size(), coder_output, cancellation,
                            cancellationContext, deadline, deadlineContext);
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
                    coder_input.swap(coder_output);
                }
                if (coder_input.size() != static_cast<std::size_t>(
                                                folder_coder_unpack_sizes
                                                    [folder][coder]))
                    return Archive7zResult::Malformed;
            }
            if (coder_input.size() !=
                static_cast<std::size_t>(unpack_sizes[folder]))
                return Archive7zResult::Malformed;
            if (folder_crc_defined[folder] &&
                rinruntime_archive_crc32(
                    reinterpret_cast<const std::uint8_t*>(
                        coder_input.data()),
                    coder_input.size()) != folder_crcs[folder])
                return Archive7zResult::CrcMismatch;
            combined.append(coder_input);
            if (combined.size() - folder_start !=
                static_cast<std::size_t>(unpack_sizes[folder]))
                return Archive7zResult::Malformed;
            pack_offset += packed_size;
        }
        if (pack_offset != next_header_offset ||
            combined.size() != static_cast<std::size_t>(total_unpack_size))
            return Archive7zResult::Malformed;

        std::size_t offset = 0u;
        std::size_t entry_index = 0u;
        for (std::size_t folder = 0u; folder < folders; ++folder) {
            for (std::size_t substream = 0u;
                 substream < substream_counts[folder]; ++substream) {
                if (entry_index >= total_substreams)
                    return Archive7zResult::Malformed;
                const std::uint64_t entry_size64 =
                    substream_sizes[folder][substream];
                if (offset > combined.size() || entry_size64 == 0u ||
                    entry_size64 > static_cast<std::uint64_t>(
                                        combined.size() - offset))
                    return Archive7zResult::Unsupported;
                const std::size_t entry_size =
                    static_cast<std::size_t>(entry_size64);
                if (substream_crc_defined[entry_index] &&
                    rinruntime_archive_crc32(
                        reinterpret_cast<const std::uint8_t*>(
                            combined.data() + offset),
                        entry_size) != substream_crcs[entry_index])
                    return Archive7zResult::CrcMismatch;
                entries_[entry_index] = {offset, entry_size, false};
                offset += entry_size;
                ++entry_index;
            }
        }
        if (entry_index != total_substreams || offset != combined.size())
            return Archive7zResult::Malformed;
        entry_count_ = total_substreams;
        output.swap(combined);
        return Archive7zResult::Ok;
    }

private:
    static Archive7zResult decodeBcj2(
        const std::array<const std::uint8_t*, 4u>& streams,
        const std::array<std::size_t, 4u>& sizes, std::size_t expected_size,
        std::string& output, ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext, ArchiveDeflateDeadlineFunction deadline,
        void* deadlineContext)
    {
        if (expected_size > kMaxStreamBytes) return Archive7zResult::Limit;
        if (sizes[3u] < 5u || (sizes[1u] & 3u) != 0u ||
            (sizes[2u] & 3u) != 0u)
            return Archive7zResult::Malformed;

        static constexpr std::uint32_t kTopValue = UINT32_C(1) << 24u;
        static constexpr unsigned kNumBitModelTotalBits = 11u;
        static constexpr std::uint32_t kBitModelTotal = UINT32_C(1) << 11u;
        static constexpr unsigned kNumMoveBits = 5u;
        static constexpr unsigned kStreamMain = 0u;
        static constexpr unsigned kStreamCall = 1u;
        static constexpr unsigned kStreamJump = 2u;
        static constexpr unsigned kStreamRc = 3u;
        static constexpr unsigned kStateOrig0 = 4u;
        static constexpr unsigned kStateOrig3 = 7u;

        std::array<std::size_t, 4u> positions{};
        std::array<std::uint16_t, 258u> probabilities{};
        probabilities.fill(static_cast<std::uint16_t>(kBitModelTotal >> 1u));
        std::string decoded;
        decoded.reserve(expected_size);

        unsigned state = kStreamRc;
        std::uint32_t ip = 0u;
        std::uint32_t temp = 0u;
        std::uint32_t range = 0u;
        std::uint32_t code = 0u;

        const auto readRcByte = [&](std::uint8_t& value) {
            if (positions[kStreamRc] >= sizes[kStreamRc]) return false;
            value = streams[kStreamRc][positions[kStreamRc]++];
            return true;
        };

        for (;;) {
            const bool deadline_hit =
                deadline != nullptr && deadline(deadlineContext);
            const bool cancellation_hit =
                cancellation != nullptr && cancellation(cancellationContext);
            if (deadline_hit || cancellation_hit)
                return deadline_hit ? Archive7zResult::Deadline
                                    : Archive7zResult::Cancelled;

            std::uint32_t value = temp;
            if (range <= 5u) {
                for (; range != 5u; ++range) {
                    if (range == 1u && code != 0u)
                        return Archive7zResult::Malformed;
                    std::uint8_t next = 0u;
                    if (!readRcByte(next)) return Archive7zResult::Malformed;
                    code = (code << 8u) | next;
                }
                if (code == UINT32_C(0xffffffff))
                    return Archive7zResult::Malformed;
                range = UINT32_C(0xffffffff);
            }

            if (state == kStreamCall || state == kStreamJump) {
                const std::size_t branch_size = sizes[state];
                if (branch_size - positions[state] < 4u)
                    return Archive7zResult::Malformed;
                const std::uint8_t* branch =
                    streams[state] + positions[state];
                value = (static_cast<std::uint32_t>(branch[0u]) << 24u) |
                        (static_cast<std::uint32_t>(branch[1u]) << 16u) |
                        (static_cast<std::uint32_t>(branch[2u]) << 8u) |
                        static_cast<std::uint32_t>(branch[3u]);
                positions[state] += 4u;
                ip += 4u;
                value -= ip;
                state = kStateOrig0;
            }

            if (state >= kStateOrig0 && state <= kStateOrig3) {
                while (state <= kStateOrig3) {
                    if (decoded.size() >= expected_size)
                        return Archive7zResult::Malformed;
                    decoded.push_back(static_cast<char>(value & 0xffu));
                    value >>= 8u;
                    ++state;
                }
                temp = value;
                if (decoded.size() == expected_size) break;
            }

            bool marker = false;
            for (;;) {
                if (range < kTopValue) {
                    std::uint8_t next = 0u;
                    if (!readRcByte(next)) return Archive7zResult::Malformed;
                    range <<= 8u;
                    code = (code << 8u) | next;
                }
                if (positions[kStreamMain] >= sizes[kStreamMain]) {
                    state = kStreamMain;
                    break;
                }
                if (decoded.size() >= expected_size)
                    return Archive7zResult::Malformed;
                const std::uint8_t byte =
                    streams[kStreamMain][positions[kStreamMain]++];
                decoded.push_back(static_cast<char>(byte));
                value = (value << 24u) | byte;
                ++ip;
                const bool direct_marker =
                    ((static_cast<unsigned>(byte) + (0x100u - 0xe8u)) &
                     0xfeu) == 0u;
                const std::uint32_t marker_mask =
                    (static_cast<std::uint32_t>(1u) << 28u) - 1u;
                const bool overlapped_marker =
                    ((value - ((static_cast<std::uint32_t>(0x0fu) << 24u) +
                               0x80u)) &
                     (marker_mask << 4u)) == 0u;
                if (direct_marker || overlapped_marker) {
                    marker = true;
                    break;
                }
                if (decoded.size() == expected_size) {
                    state = positions[kStreamMain] == sizes[kStreamMain]
                                ? kStreamMain
                                : kStateOrig0;
                    break;
                }
            }

            if (decoded.size() == expected_size) break;
            if (!marker) return Archive7zResult::Malformed;

            const unsigned context = ((value + 0x17u) >> 6u) & 1u;
            const unsigned probability_index =
                ((0u - context) & static_cast<unsigned>(
                                      static_cast<std::uint8_t>(value >> 24u))) +
                context + ((value >> 5u) & 1u);
            if (probability_index >= probabilities.size())
                return Archive7zResult::Malformed;
            const std::uint32_t probability = probabilities[probability_index];
            const std::uint32_t bound =
                (range >> kNumBitModelTotalBits) * probability;
            if (code < bound) {
                range = bound;
                probabilities[probability_index] = static_cast<std::uint16_t>(
                    probability +
                    ((kBitModelTotal - probability) >> kNumMoveBits));
                temp = value;
                continue;
            }
            range -= bound;
            code -= bound;
            probabilities[probability_index] = static_cast<std::uint16_t>(
                probability - (probability >> kNumMoveBits));

            const unsigned branch_stream =
                (((value + 0x57u) >> 6u) & 1u) + kStreamCall;
            if (sizes[branch_stream] - positions[branch_stream] < 4u)
                return Archive7zResult::Malformed;
            const std::uint8_t* branch =
                streams[branch_stream] + positions[branch_stream];
            std::uint32_t target =
                (static_cast<std::uint32_t>(branch[0u]) << 24u) |
                (static_cast<std::uint32_t>(branch[1u]) << 16u) |
                (static_cast<std::uint32_t>(branch[2u]) << 8u) |
                static_cast<std::uint32_t>(branch[3u]);
            positions[branch_stream] += 4u;
            ip += 4u;
            target -= ip;
            if (expected_size < 4u || decoded.size() > expected_size - 4u)
                return Archive7zResult::Malformed;
            decoded.push_back(static_cast<char>(target & 0xffu));
            decoded.push_back(static_cast<char>((target >> 8u) & 0xffu));
            decoded.push_back(static_cast<char>((target >> 16u) & 0xffu));
            decoded.push_back(static_cast<char>((target >> 24u) & 0xffu));
            temp = target >> 24u;
        }

        for (std::size_t stream = 0u; stream != 4u; ++stream)
            if (positions[stream] != sizes[stream])
                return Archive7zResult::Malformed;
        output = decoded;
        return Archive7zResult::Ok;
    }

    template <std::size_t Capacity>
    static bool readCrcs(
        const std::uint8_t* bytes, std::size_t end, std::size_t& cursor,
        std::size_t count, std::array<bool, Capacity>& defined,
        std::array<std::uint32_t, Capacity>& values)
    {
        if (count == 0u || count > Capacity || cursor >= end) return false;
        const std::uint8_t all_defined = bytes[cursor++];
        if (all_defined > 1u) return false;
        defined.fill(all_defined != 0u);
        if (all_defined == 0u) {
            const std::size_t bitmap_size = (count + 7u) / 8u;
            if (bitmap_size > end - cursor) return false;
            for (std::size_t byte = 0u; byte != bitmap_size; ++byte) {
                const std::uint8_t bitmap = bytes[cursor++];
                const std::size_t first = byte * 8u;
                for (std::size_t bit = 0u; bit != 8u && first + bit < count;
                     ++bit)
                    defined[first + bit] = (bitmap & (1u << bit)) != 0u;
                if (first + 8u > count &&
                    (bitmap & static_cast<std::uint8_t>(
                                  0xffu << (count - first))))
                    return false;
            }
        }
        for (std::size_t index = 0u; index != count; ++index) {
            values[index] = 0u;
            if (!defined[index]) continue;
            if (end - cursor < 4u) return false;
            values[index] = readLe32(bytes + cursor);
            cursor += 4u;
        }
        return true;
    }

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
        if (additional == 8u) {
            value = 0u;
            if (end - cursor < 8u) return false;
            for (unsigned index = 0u; index != 8u; ++index)
                value |= static_cast<std::uint64_t>(bytes[cursor++])
                         << (index * 8u);
        } else {
            const std::uint8_t payload = static_cast<std::uint8_t>(
                first & static_cast<std::uint8_t>(
                            (1u << (7u - additional)) - 1u));
            value = 0u;
            for (unsigned index = 0u; index != additional; ++index) {
                if (cursor >= end) return false;
                value |= static_cast<std::uint64_t>(bytes[cursor++])
                         << (index * 8u);
            }
            value |= static_cast<std::uint64_t>(payload)
                     << (additional * 8u);
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

    mutable std::array<Archive7zEntrySummary, RINRUNTIME_ARCHIVE_ENTRY_LIMIT>
        entries_{};
    mutable std::size_t entry_count_ = 0u;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_7Z_HPP */
