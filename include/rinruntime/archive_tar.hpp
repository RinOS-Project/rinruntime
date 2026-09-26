/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded ustar reader. */

#ifndef RINRUNTIME_ARCHIVE_TAR_HPP
#define RINRUNTIME_ARCHIVE_TAR_HPP

#include "archive_policy.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace RinRuntime {

enum class ArchiveTarResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    UnsupportedType = -4,
};

struct ArchiveTarEntry {
    std::string name;
    std::uint64_t dataOffset = 0u;
    std::uint64_t size = 0u;
    bool directory = false;
};

using ArchiveTarSinkFunction = bool (*)(
    void* context, const std::uint8_t* bytes, std::size_t size);

/*
 * Parse the strict ustar subset used by RinOS archive adapters.  The reader
 * accepts regular files and directories only.  PAX/GNU extension records and
 * symlinks are rejected so an archive cannot smuggle an alternate pathname or
 * filesystem traversal policy past the common admission layer.
 */
class ArchiveTarReader final {
public:
    ArchiveTarReader() = default;

    ArchiveTarResult parse(const std::uint8_t* bytes, std::size_t size)
    {
        clear();
        if (bytes == nullptr || size < kBlockSize * 2u)
            return ArchiveTarResult::InvalidArgument;
        if (size > static_cast<std::size_t>(
                       RINRUNTIME_ARCHIVE_CONTENT_LIMIT) + kBlockSize * 2u)
            return ArchiveTarResult::Limit;
        if ((size % kBlockSize) != 0u) return ArchiveTarResult::Malformed;

        std::uint64_t total = 0u;
        std::size_t position = 0u;
        bool ended = false;
        while (position <= size - kBlockSize) {
            const std::uint8_t* header = bytes + position;
            if (isZeroBlock(header)) {
                if (position > size - kBlockSize * 2u ||
                    !isZeroBlock(header + kBlockSize))
                    return fail(ArchiveTarResult::Malformed);
                position += kBlockSize * 2u;
                while (position < size) {
                    if (!isZeroBlock(bytes + position))
                        return fail(ArchiveTarResult::Malformed);
                    position += kBlockSize;
                }
                ended = true;
                break;
            }
            if (entries_.size() >= RINRUNTIME_ARCHIVE_ENTRY_LIMIT)
                return fail(ArchiveTarResult::Limit);
            if (!headerValid(header))
                return fail(ArchiveTarResult::Malformed);

            const std::size_t nameSize = fieldSize(header, 100u);
            const std::size_t prefixSize = fieldSize(header + 345u, 155u);
            if (nameSize == 0u || prefixSize > 155u ||
                nameSize + (prefixSize == 0u ? 0u : prefixSize + 1u) >
                    RINRUNTIME_ARCHIVE_PATH_LIMIT)
                return fail(ArchiveTarResult::Malformed);

            ArchiveTarEntry entry;
            if (prefixSize != 0u) {
                entry.name.assign(reinterpret_cast<const char*>(header + 345u),
                                  prefixSize);
                entry.name.push_back('/');
            }
            entry.name.append(reinterpret_cast<const char*>(header), nameSize);

            const std::uint8_t type = header[156u];
            if (type == 0u || type == static_cast<std::uint8_t>('0')) {
                entry.directory = false;
            } else if (type == static_cast<std::uint8_t>('5')) {
                entry.directory = true;
                if (entry.name.empty() || entry.name.back() != '/')
                    entry.name.push_back('/');
            } else {
                return fail(ArchiveTarResult::UnsupportedType);
            }
            if (fieldSize(header + 157u, 100u) != 0u)
                return fail(ArchiveTarResult::Malformed);
            if (!rinruntime_archive_path_valid(entry.name.data(),
                                               entry.name.size(), nullptr,
                                               nullptr))
                return fail(ArchiveTarResult::Malformed);

            std::uint64_t entrySize = 0u;
            if (!readOctal(header + 124u, 12u, &entrySize))
                return fail(ArchiveTarResult::Malformed);
            if (entry.directory && entrySize != 0u)
                return fail(ArchiveTarResult::Malformed);
            if (!rinruntime_archive_content_add(total, entrySize, &total))
                return fail(ArchiveTarResult::Limit);

            const std::size_t dataOffset = position + kBlockSize;
            if (entrySize > static_cast<std::uint64_t>(size - dataOffset))
                return fail(ArchiveTarResult::Malformed);
            const std::uint64_t paddedSize =
                ((entrySize + (kBlockSize - 1u)) / kBlockSize) * kBlockSize;
            if (paddedSize > static_cast<std::uint64_t>(size - dataOffset))
                return fail(ArchiveTarResult::Malformed);
            for (const ArchiveTarEntry& existing : entries_)
                if (existing.name == entry.name)
                    return fail(ArchiveTarResult::Malformed);

            entry.dataOffset = dataOffset;
            entry.size = entrySize;
            entries_.push_back(entry);
            position = dataOffset + static_cast<std::size_t>(paddedSize);
        }
        if (!ended) return fail(ArchiveTarResult::Malformed);
        bytes_ = bytes;
        size_ = size;
        totalContent_ = total;
        return ArchiveTarResult::Ok;
    }

    void clear()
    {
        bytes_ = nullptr;
        size_ = 0u;
        totalContent_ = 0u;
        entries_.clear();
    }

    bool empty() const { return entries_.empty(); }
    std::size_t size() const { return entries_.size(); }
    std::uint64_t totalContent() const { return totalContent_; }
    const std::vector<ArchiveTarEntry>& entries() const { return entries_; }

    const std::uint8_t* data(std::size_t index,
                             std::size_t* sizeOut = nullptr) const
    {
        if (sizeOut != nullptr) *sizeOut = 0u;
        if (index >= entries_.size() || entries_[index].directory ||
            bytes_ == nullptr) return nullptr;
        if (sizeOut != nullptr) *sizeOut =
            static_cast<std::size_t>(entries_[index].size);
        return bytes_ + static_cast<std::size_t>(entries_[index].dataOffset);
    }

    ArchiveTarResult readEntry(std::size_t index, std::string& output) const
    {
        std::size_t size = 0u;
        const std::uint8_t* bytes = data(index, &size);
        output.clear();
        if (index >= entries_.size()) return ArchiveTarResult::InvalidArgument;
        if (entries_[index].directory) return ArchiveTarResult::Ok;
        if (bytes == nullptr) return ArchiveTarResult::Malformed;
        output.assign(reinterpret_cast<const char*>(bytes), size);
        return ArchiveTarResult::Ok;
    }

    /* Stream one validated regular-file entry into a caller-owned staging
     * sink. The sink receives at most 64 KiB per callback and must durably
     * accept every chunk. A failed callback does not constitute publication;
     * the caller must discard its staging object. Directories produce no
     * callback and are considered successful after admission. */
    ArchiveTarResult readEntryToSink(std::size_t index,
                                     ArchiveTarSinkFunction sink,
                                     void* context) const
    {
        if (index >= entries_.size() || sink == nullptr || context == nullptr)
            return ArchiveTarResult::InvalidArgument;
        if (entries_[index].directory) return ArchiveTarResult::Ok;

        std::size_t size = 0u;
        const std::uint8_t* bytes = data(index, &size);
        if (bytes == nullptr) return ArchiveTarResult::Malformed;
        std::size_t offset = 0u;
        while (offset < size) {
            const std::size_t remaining = size - offset;
            const std::size_t chunk = remaining > 65536u
                ? 65536u : remaining;
            if (!sink(context, bytes + offset, chunk))
                return ArchiveTarResult::Malformed;
            offset += chunk;
        }
        return ArchiveTarResult::Ok;
    }

private:
    static constexpr std::size_t kBlockSize = 512u;

    static bool isZeroBlock(const std::uint8_t* block)
    {
        for (std::size_t index = 0u; index < kBlockSize; ++index)
            if (block[index] != 0u) return false;
        return true;
    }

    static std::size_t fieldSize(const std::uint8_t* field,
                                 std::size_t capacity)
    {
        std::size_t size = 0u;
        while (size < capacity && field[size] != 0u) ++size;
        return size;
    }

    static bool readOctal(const std::uint8_t* field, std::size_t capacity,
                          std::uint64_t* valueOut)
    {
        std::size_t index = 0u;
        std::uint64_t value = 0u;
        bool digit = false;
        if (field == nullptr || valueOut == nullptr || capacity == 0u)
            return false;
        while (index < capacity && field[index] == static_cast<std::uint8_t>(' '))
            ++index;
        while (index < capacity && field[index] >= static_cast<std::uint8_t>('0') &&
               field[index] <= static_cast<std::uint8_t>('7')) {
            const std::uint64_t digitValue = field[index] -
                static_cast<std::uint8_t>('0');
            if (value > (UINT64_MAX - digitValue) / 8u) return false;
            value = value * 8u + digitValue;
            digit = true;
            ++index;
        }
        if (!digit) return false;
        while (index < capacity) {
            if (field[index] != 0u && field[index] !=
                    static_cast<std::uint8_t>(' ')) return false;
            ++index;
        }
        *valueOut = value;
        return true;
    }

    static bool headerValid(const std::uint8_t* header)
    {
        static const char magic[] = "ustar";
        std::uint64_t storedChecksum = 0u;
        std::uint64_t checksum = 0u;
        for (std::size_t index = 0u; index < 5u; ++index)
            if (header[257u + index] !=
                static_cast<std::uint8_t>(magic[index])) return false;
        if (header[262u] != 0u && header[262u] !=
                static_cast<std::uint8_t>(' ')) return false;
        if (!readOctal(header + 148u, 8u, &storedChecksum)) return false;
        for (std::size_t index = 0u; index < kBlockSize; ++index) {
            if (index >= 148u && index < 156u)
                checksum += static_cast<std::uint8_t>(' ');
            else
                checksum += header[index];
        }
        return checksum == storedChecksum;
    }

    ArchiveTarResult fail(ArchiveTarResult result)
    {
        clear();
        return result;
    }

    const std::uint8_t* bytes_ = nullptr;
    std::size_t size_ = 0u;
    std::uint64_t totalContent_ = 0u;
    std::vector<ArchiveTarEntry> entries_;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_TAR_HPP */

