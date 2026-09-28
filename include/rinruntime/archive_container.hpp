/* SPDX-License-Identifier: MIT */
/* Public, backend-independent bounded archive container adapter. */

#ifndef RINRUNTIME_ARCHIVE_CONTAINER_HPP
#define RINRUNTIME_ARCHIVE_CONTAINER_HPP

#include "archive_7z.hpp"
#include "archive_gzip.hpp"
#include "archive_targz.hpp"
#include "archive_tar.hpp"
#include "archive_zip.hpp"
#include "archive_xz.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <variant>
#include <vector>

namespace RinRuntime {

enum class ArchiveContainerKind : std::uint8_t {
    Unknown = 0,
    Zip = 1,
    Tar = 2,
    TarGzip = 3,
    SevenZip = 4,
    Xz = 5,
    Gzip = 6,
};

enum class ArchiveContainerResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    Unsupported = -4,
    Cancelled = -5,
    Deadline = -6,
};

struct ArchiveContainerEntry {
    std::string name;
    std::uint64_t size = 0u;
    std::uint16_t method = 0u;
    bool directory = false;
};

/*
 * Select one of the public memory-only archive readers from a bounded magic
 * probe, then expose a common metadata/read contract.  This class never opens
 * a filesystem path and never publishes an extracted member.  Package trust,
 * destination authority, rollback, and File Portal policy remain outside the
 * public codec layer.
 */
class ArchiveContainerReader final {
public:
    ArchiveContainerReader() = default;

    ArchiveContainerResult parse(const std::uint8_t* bytes, std::size_t size)
    {
        clear();
        if (bytes == nullptr || size == 0u)
            return ArchiveContainerResult::InvalidArgument;

        const ArchiveContainerKind detected = detect(bytes, size);
        if (detected == ArchiveContainerKind::Unknown)
            return ArchiveContainerResult::Unsupported;
        kind_ = detected;
#if defined(__cpp_exceptions) || defined(_CPPUNWIND)
        try {
#endif
            ArchiveContainerResult result = ArchiveContainerResult::Malformed;
            switch (kind_) {
            case ArchiveContainerKind::Zip:
                reader_.emplace<ArchiveZipReader>();
                result = map(std::get<ArchiveZipReader>(reader_).parse(
                    bytes, size));
                break;
            case ArchiveContainerKind::Tar:
                reader_.emplace<ArchiveTarReader>();
                result = map(std::get<ArchiveTarReader>(reader_).parse(
                    bytes, size));
                break;
            case ArchiveContainerKind::TarGzip:
                reader_.emplace<ArchiveTarGzipReader>();
                result = map(std::get<ArchiveTarGzipReader>(reader_).parse(
                    bytes, size));
                if (result != ArchiveContainerResult::Ok) {
                    ArchiveGzipReader gzipReader;
                    std::string gzipOutput;
                    const ArchiveContainerResult gzipResult = map(
                        gzipReader.decode(bytes, size, gzipOutput));
                    if (gzipResult == ArchiveContainerResult::Ok) {
                        reader_.emplace<ArchiveGzipReader>();
                        stream_.swap(gzipOutput);
                        kind_ = ArchiveContainerKind::Gzip;
                        result = ArchiveContainerResult::Ok;
                    } else {
                        result = gzipResult;
                    }
                }
                break;
            case ArchiveContainerKind::Gzip:
                reader_.emplace<ArchiveGzipReader>();
                result = map(std::get<ArchiveGzipReader>(reader_).decode(
                    bytes, size, stream_));
                break;
            case ArchiveContainerKind::SevenZip:
                reader_.emplace<Archive7zReader>();
                result = map(std::get<Archive7zReader>(reader_).decodeStored(
                    bytes, size, stream_));
                break;
            case ArchiveContainerKind::Xz:
                reader_.emplace<ArchiveXzReader>();
                result = map(std::get<ArchiveXzReader>(reader_)
                                 .decodeStoredLzma2(bytes, size, stream_));
                break;
            default:
                result = ArchiveContainerResult::Unsupported;
                break;
            }
            if (result != ArchiveContainerResult::Ok) {
                clear();
                return result;
            }
            rebuildEntries();
            return ArchiveContainerResult::Ok;
#if defined(__cpp_exceptions) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            clear();
            return ArchiveContainerResult::Limit;
        }
#endif
    }

    ArchiveContainerResult readEntry(std::size_t index,
                                     std::string& output) const
    {
        output.clear();
        if (index >= entries_.size())
            return ArchiveContainerResult::InvalidArgument;
#if defined(__cpp_exceptions) || defined(_CPPUNWIND)
        try {
#endif
            switch (kind_) {
            case ArchiveContainerKind::Zip:
                return map(std::get<ArchiveZipReader>(reader_).readEntry(
                    index, output));
            case ArchiveContainerKind::Tar:
                return map(std::get<ArchiveTarReader>(reader_).readEntry(
                    index, output));
            case ArchiveContainerKind::TarGzip: {
                if (entries_[index].directory) return ArchiveContainerResult::Ok;
                std::size_t size = 0u;
                const std::uint8_t* bytes =
                    std::get<ArchiveTarGzipReader>(reader_).data(index, &size);
                if (bytes == nullptr)
                    return ArchiveContainerResult::Malformed;
                output.assign(reinterpret_cast<const char*>(bytes), size);
                return ArchiveContainerResult::Ok;
            }
            case ArchiveContainerKind::SevenZip:
            case ArchiveContainerKind::Xz:
            case ArchiveContainerKind::Gzip:
                output = stream_;
                return ArchiveContainerResult::Ok;
            default:
                return ArchiveContainerResult::Unsupported;
            }
#if defined(__cpp_exceptions) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            output.clear();
            return ArchiveContainerResult::Limit;
        }
#endif
    }

    void clear()
    {
        kind_ = ArchiveContainerKind::Unknown;
        reader_.emplace<std::monostate>();
        stream_.clear();
        entries_.clear();
    }

    ArchiveContainerKind kind() const { return kind_; }
    bool empty() const { return entries_.empty(); }
    std::size_t size() const { return entries_.size(); }
    std::uint64_t totalContent() const
    {
        std::uint64_t total = 0u;
        for (const ArchiveContainerEntry& entry : entries_)
            total += entry.size;
        return total;
    }
    const std::vector<ArchiveContainerEntry>& entries() const
    {
        return entries_;
    }

private:
    static ArchiveContainerKind detect(const std::uint8_t* bytes,
                                       std::size_t size)
    {
        if (size >= 4u && bytes[0] == 0x50u && bytes[1] == 0x4bu &&
            ((bytes[2] == 0x03u && bytes[3] == 0x04u) ||
             (bytes[2] == 0x05u && bytes[3] == 0x06u) ||
             (bytes[2] == 0x07u && bytes[3] == 0x08u)))
            return ArchiveContainerKind::Zip;
        if (size >= 2u && bytes[0] == 0x1fu && bytes[1] == 0x8bu)
            return ArchiveContainerKind::TarGzip;
        if (size >= 262u && std::memcmp(bytes + 257u, "ustar", 5u) == 0)
            return ArchiveContainerKind::Tar;
        /* These are known archive envelopes, but their payload readers are
         * intentionally not silently substituted with a different format. */
        static const std::uint8_t seven_zip_signature[] = {
            0x37u, 0x7au, 0xbcu, 0xafu, 0x27u, 0x1cu};
        static const std::uint8_t xz_signature[] = {
            0xfdu, 0x37u, 0x7au, 0x58u, 0x5au, 0x00u};
        if ((size >= sizeof(seven_zip_signature) &&
             std::memcmp(bytes, seven_zip_signature,
                         sizeof(seven_zip_signature)) == 0) ||
            (size >= sizeof(xz_signature) &&
             std::memcmp(bytes, xz_signature, sizeof(xz_signature)) == 0))
            return size >= sizeof(seven_zip_signature) &&
                           std::memcmp(bytes, seven_zip_signature,
                                       sizeof(seven_zip_signature)) == 0
                       ? ArchiveContainerKind::SevenZip
                       : ArchiveContainerKind::Xz;
        return ArchiveContainerKind::Unknown;
    }

    static ArchiveContainerResult map(ArchiveZipResult result)
    {
        switch (result) {
        case ArchiveZipResult::Ok: return ArchiveContainerResult::Ok;
        case ArchiveZipResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case ArchiveZipResult::Limit: return ArchiveContainerResult::Limit;
        case ArchiveZipResult::Cancelled:
            return ArchiveContainerResult::Cancelled;
        case ArchiveZipResult::Deadline:
            return ArchiveContainerResult::Deadline;
        default: return ArchiveContainerResult::Malformed;
        }
    }

    static ArchiveContainerResult map(ArchiveTarResult result)
    {
        switch (result) {
        case ArchiveTarResult::Ok: return ArchiveContainerResult::Ok;
        case ArchiveTarResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case ArchiveTarResult::Limit: return ArchiveContainerResult::Limit;
        case ArchiveTarResult::Deadline:
            return ArchiveContainerResult::Deadline;
        default: return ArchiveContainerResult::Malformed;
        }
    }

    static ArchiveContainerResult map(ArchiveTarGzipResult result)
    {
        switch (result) {
        case ArchiveTarGzipResult::Ok: return ArchiveContainerResult::Ok;
        case ArchiveTarGzipResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case ArchiveTarGzipResult::Limit: return ArchiveContainerResult::Limit;
        case ArchiveTarGzipResult::CrcMismatch:
            return ArchiveContainerResult::Malformed;
        case ArchiveTarGzipResult::Cancelled:
            return ArchiveContainerResult::Cancelled;
        case ArchiveTarGzipResult::Deadline:
            return ArchiveContainerResult::Deadline;
        default: return ArchiveContainerResult::Malformed;
        }
    }

    static ArchiveContainerResult map(Archive7zResult result)
    {
        switch (result) {
        case Archive7zResult::Ok: return ArchiveContainerResult::Ok;
        case Archive7zResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case Archive7zResult::Limit: return ArchiveContainerResult::Limit;
        case Archive7zResult::Unsupported:
            return ArchiveContainerResult::Unsupported;
        case Archive7zResult::CrcMismatch:
        case Archive7zResult::Malformed:
        default: return ArchiveContainerResult::Malformed;
        }
    }

    static ArchiveContainerResult map(ArchiveGzipResult result)
    {
        switch (result) {
        case ArchiveGzipResult::Ok: return ArchiveContainerResult::Ok;
        case ArchiveGzipResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case ArchiveGzipResult::Limit: return ArchiveContainerResult::Limit;
        case ArchiveGzipResult::Cancelled:
            return ArchiveContainerResult::Cancelled;
        case ArchiveGzipResult::Deadline:
            return ArchiveContainerResult::Deadline;
        default: return ArchiveContainerResult::Malformed;
        }
    }

    static ArchiveContainerResult map(ArchiveXzResult result)
    {
        switch (result) {
        case ArchiveXzResult::Ok: return ArchiveContainerResult::Ok;
        case ArchiveXzResult::InvalidArgument:
            return ArchiveContainerResult::InvalidArgument;
        case ArchiveXzResult::Limit: return ArchiveContainerResult::Limit;
        case ArchiveXzResult::Unsupported:
            return ArchiveContainerResult::Unsupported;
        case ArchiveXzResult::CrcMismatch:
        case ArchiveXzResult::Malformed:
        default: return ArchiveContainerResult::Malformed;
        }
    }

    void rebuildEntries()
    {
        entries_.clear();
        switch (kind_) {
        case ArchiveContainerKind::Zip:
            for (const ArchiveZipEntry& entry :
                 std::get<ArchiveZipReader>(reader_).entries()) {
                entries_.push_back({entry.name, entry.uncompressedSize,
                                    entry.method, entry.directory});
            }
            break;
        case ArchiveContainerKind::Tar:
            for (const ArchiveTarEntry& entry :
                 std::get<ArchiveTarReader>(reader_).entries()) {
                entries_.push_back({entry.name, entry.size, 0u,
                                    entry.directory});
            }
            break;
        case ArchiveContainerKind::TarGzip:
            for (const ArchiveTarEntry& entry :
                 std::get<ArchiveTarGzipReader>(reader_).entries()) {
                entries_.push_back({entry.name, entry.size, 0u,
                                    entry.directory});
            }
            break;
        case ArchiveContainerKind::SevenZip:
        case ArchiveContainerKind::Xz:
        case ArchiveContainerKind::Gzip:
            entries_.push_back({"<stream>",
                                static_cast<std::uint64_t>(stream_.size()),
                                0u, false});
            break;
        default:
            break;
        }
    }

    ArchiveContainerKind kind_ = ArchiveContainerKind::Unknown;
    std::variant<std::monostate, ArchiveZipReader, ArchiveTarReader,
                 ArchiveTarGzipReader, Archive7zReader, ArchiveXzReader,
                 ArchiveGzipReader>
        reader_;
    std::string stream_;
    std::vector<ArchiveContainerEntry> entries_;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_CONTAINER_HPP */
