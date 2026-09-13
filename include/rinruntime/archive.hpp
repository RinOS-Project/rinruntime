/* SPDX-License-Identifier: MIT */
/* Backend-independent archive planning model shared by applications and
 * archive services.  Filesystem handles and codec state stay outside this
 * header so external toolkits can exchange bounded plans without RinOS GUI
 * dependencies. */

#ifndef RINRUNTIME_ARCHIVE_HPP
#define RINRUNTIME_ARCHIVE_HPP

#include <cstdint>
#include <string>
#include <vector>

#include "archive_policy.h"

namespace RinRuntime {

struct ArchiveSource {
    std::string name;
    std::string path;
    bool directory = false;
};

struct ArchiveEntry {
    std::string name;
    std::string sourcePath;
    std::uint32_t crc = 0;
    std::uint32_t compressedSize = 0;
    std::uint32_t uncompressedSize = 0;
    std::uint32_t localOffset = 0;
    std::uint16_t method = 8;
    bool directory = false;
};

struct ArchiveCreatedPath {
    std::string path;
    bool directory = false;
};

/* A codec- and filesystem-independent archive admission plan.  Applications
 * can build a plan before opening a destination or handing entries to a
 * service.  The plan owns only bounded metadata; source paths are labels for
 * an authenticated backend and are never opened here. */
class ArchivePlan final {
public:
    static constexpr std::size_t kMaxSourcePathBytes =
        RINRUNTIME_ARCHIVE_PATH_LIMIT;

    bool add(const ArchiveEntry& entry)
    {
        if (entries_.size() >= RINRUNTIME_ARCHIVE_ENTRY_LIMIT ||
            !entryValid(entry))
            return false;
        for (const ArchiveEntry& existing : entries_)
            if (existing.name == entry.name)
                return false;
        std::uint64_t next = 0u;
        if (!rinruntime_archive_content_add(totalContent_,
                                            entry.uncompressedSize, &next))
            return false;
        entries_.push_back(entry);
        totalContent_ = next;
        return true;
    }

    /* Add a source with the conventional directory suffix.  A source path
     * may be absolute because it is not an archive member name; it is still
     * bounded and rejects embedded NUL/control bytes. */
    bool addSource(const ArchiveSource& source)
    {
        if (!sourceValid(source)) return false;
        ArchiveEntry entry;
        entry.name = source.name;
        if (source.directory &&
            (entry.name.empty() || entry.name.back() != '/'))
            entry.name.push_back('/');
        entry.sourcePath = source.path;
        entry.directory = source.directory;
        entry.method = source.directory ? 0u : 8u;
        return add(entry);
    }

    void clear()
    {
        entries_.clear();
        totalContent_ = 0u;
    }

    bool empty() const { return entries_.empty(); }
    std::size_t size() const { return entries_.size(); }
    std::uint64_t totalContent() const { return totalContent_; }
    const std::vector<ArchiveEntry>& entries() const { return entries_; }

private:
    static bool sourcePathValid(const std::string& path)
    {
        if (path.empty() || path.size() > kMaxSourcePathBytes) return false;
        for (char value : path) {
            const unsigned char byte = static_cast<unsigned char>(value);
            if (byte == 0u || byte < 0x20u || byte == 0x7fu) return false;
        }
        return true;
    }

    static bool sourceValid(const ArchiveSource& source)
    {
        std::string memberName = source.name;
        int directory = 0;
        if (source.directory &&
            (memberName.empty() || memberName.back() != '/'))
            memberName.push_back('/');
        if (!sourcePathValid(source.path) ||
            !rinruntime_archive_path_valid(memberName.data(), memberName.size(),
                                           &directory, nullptr))
            return false;
        return (directory != 0) == source.directory;
    }

    static bool entryValid(const ArchiveEntry& entry)
    {
        int directory = 0;
        if (!sourcePathValid(entry.sourcePath) ||
            !rinruntime_archive_path_valid(entry.name.data(), entry.name.size(),
                                           &directory, nullptr) ||
            (directory != 0) != entry.directory ||
            !rinruntime_archive_method_supported(entry.method))
            return false;
        if (entry.directory)
            return entry.compressedSize == 0u &&
                   entry.uncompressedSize == 0u;
        return rinruntime_archive_compression_ratio_valid(
                   entry.compressedSize, entry.uncompressedSize) &&
               rinruntime_archive_range_within(
                   entry.localOffset, entry.compressedSize,
                   static_cast<std::uint64_t>(UINT32_MAX));
    }

    std::vector<ArchiveEntry> entries_;
    std::uint64_t totalContent_ = 0u;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_HPP */
