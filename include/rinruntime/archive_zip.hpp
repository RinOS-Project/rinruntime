/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded ZIP container admission. */

#ifndef RINRUNTIME_ARCHIVE_ZIP_HPP
#define RINRUNTIME_ARCHIVE_ZIP_HPP

#include "archive_policy.h"
#include "archive_deflate.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace RinRuntime {

enum class ArchiveZipResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    Cancelled = -4,
};

struct ArchiveZipEntry {
    std::string name;
    std::uint16_t flags = 0u;
    std::uint16_t method = 0u;
    std::uint32_t crc = 0u;
    std::uint32_t compressedSize = 0u;
    std::uint32_t uncompressedSize = 0u;
    std::uint32_t localOffset = 0u;
    std::size_t dataOffset = 0u;
    bool directory = false;
};

/*
 * Parse one ordinary (non-ZIP64, non-split, single-disk) ZIP image without
 * opening a file or allocating from archive-controlled lengths.  The caller
 * retains ownership of `bytes`; the returned entry names are bounded copies,
 * while compressedData() is a view into that caller-owned image.
 */
class ArchiveZipReader final {
public:
    ArchiveZipReader() = default;

    ArchiveZipResult parse(const std::uint8_t* bytes, std::size_t size)
    {
        clear();
        if (bytes == nullptr || size < 22u)
            return ArchiveZipResult::InvalidArgument;
        if (size > static_cast<std::size_t>(
                       RINRUNTIME_ARCHIVE_CONTENT_LIMIT))
            return ArchiveZipResult::Limit;

        std::size_t eocd = 0u;
        bool found = false;
        const std::size_t tailStart = size > 65557u ? size - 65557u : 0u;
        for (std::size_t candidate = size - 22u;; --candidate) {
            if (candidate < tailStart)
                break;
            if (get32(bytes + candidate) == 0x06054b50u) {
                const std::uint16_t comment = get16(bytes + candidate + 20u);
                if (candidate <= size - 22u &&
                    static_cast<std::size_t>(comment) <= size - candidate -
                                                           22u &&
                    candidate + 22u + comment == size) {
                    eocd = candidate;
                    found = true;
                    break;
                }
            }
            if (candidate == tailStart)
                break;
        }
        if (!found)
            return ArchiveZipResult::Malformed;

        const std::uint8_t* footer = bytes + eocd;
        const std::uint16_t disk = get16(footer + 4u);
        const std::uint16_t centralDisk = get16(footer + 6u);
        const std::uint16_t diskEntries = get16(footer + 8u);
        const std::uint16_t entryCount = get16(footer + 10u);
        const std::uint32_t centralSize = get32(footer + 12u);
        const std::uint32_t centralOffset = get32(footer + 16u);
        if (disk != 0u || centralDisk != 0u || diskEntries != entryCount ||
            !rinruntime_archive_entry_count_valid(entryCount) ||
            !rinruntime_archive_range_within(centralOffset, centralSize,
                                             static_cast<std::uint64_t>(eocd)))
            return ArchiveZipResult::Malformed;

        bytes_ = bytes;
        size_ = size;
        centralOffset_ = centralOffset;
        centralSize_ = centralSize;
        entries_.reserve(entryCount);
        std::uint64_t total = 0u;
        std::size_t position = centralOffset;
        for (std::uint16_t index = 0u; index < entryCount; ++index) {
            if (position > static_cast<std::size_t>(centralOffset) +
                              centralSize ||
                static_cast<std::size_t>(centralOffset) + centralSize -
                        position < 46u)
                return fail(ArchiveZipResult::Malformed);
            const std::uint8_t* header = bytes + position;
            if (get32(header) != 0x02014b50u)
                return fail(ArchiveZipResult::Malformed);
            const std::uint16_t flags = get16(header + 8u);
            const std::uint16_t method = get16(header + 10u);
            const std::uint16_t madeBy = get16(header + 4u);
            const std::uint32_t externalAttributes = get32(header + 38u);
            const std::uint16_t nameSize = get16(header + 28u);
            const std::uint16_t extraSize = get16(header + 30u);
            const std::uint16_t commentSize = get16(header + 32u);
            const std::size_t fixedEnd = position + 46u;
            const std::size_t variableSize = static_cast<std::size_t>(nameSize) +
                                              extraSize + commentSize;
            if (fixedEnd > size_ || variableSize > size_ - fixedEnd ||
                !rinruntime_archive_flags_supported(flags) ||
                /* The bounded reader has no data-descriptor parser.  Do not
                 * treat descriptor bytes as unverified archive padding. */
                (flags & 0x0008u) != 0u ||
                !rinruntime_archive_method_supported(method) ||
                /* Never pass a ZIP symlink or Windows reparse point to a
                 * filesystem consumer that may interpret external attrs. */
                ((madeBy >> 8u) == 3u &&
                 ((externalAttributes >> 16u) & 0xf000u) == 0xa000u) ||
                ((madeBy >> 8u) == 0u &&
                 (externalAttributes & UINT32_C(0x00000400)) != 0u) ||
                nameSize == 0u || nameSize > RINRUNTIME_ARCHIVE_PATH_LIMIT)
                return fail(ArchiveZipResult::Malformed);

            ArchiveZipEntry entry;
            entry.name.assign(reinterpret_cast<const char*>(header + 46u),
                              nameSize);
            int directory = 0;
            if (!rinruntime_archive_path_valid(entry.name.data(),
                                               entry.name.size(), &directory,
                                               nullptr))
                return fail(ArchiveZipResult::Malformed);
            entry.directory = directory != 0;
            entry.flags = flags;
            entry.method = method;
            entry.crc = get32(header + 16u);
            entry.compressedSize = get32(header + 20u);
            entry.uncompressedSize = get32(header + 24u);
            entry.localOffset = get32(header + 42u);
            if (entry.directory &&
                (entry.method != 0u || entry.compressedSize != 0u ||
                 entry.uncompressedSize != 0u))
                return fail(ArchiveZipResult::Malformed);
            if (!entry.directory && entry.method == 0u &&
                entry.compressedSize != entry.uncompressedSize)
                return fail(ArchiveZipResult::Malformed);
            if (!rinruntime_archive_compression_ratio_valid(
                    entry.compressedSize, entry.uncompressedSize) ||
                !rinruntime_archive_content_add(total, entry.uncompressedSize,
                                                &total))
                return fail(ArchiveZipResult::Limit);
            for (const ArchiveZipEntry& existing : entries_)
                if (existing.name == entry.name)
                    return fail(ArchiveZipResult::Malformed);
            if (entry.localOffset >= centralOffset_)
                return fail(ArchiveZipResult::Malformed);

            const std::size_t local = entry.localOffset;
            if (local > size_ || size_ - local < 30u ||
                get32(bytes_ + local) != 0x04034b50u)
                return fail(ArchiveZipResult::Malformed);
            const std::uint16_t localFlags = get16(bytes_ + local + 6u);
            const std::uint16_t localMethod = get16(bytes_ + local + 8u);
            const std::uint16_t localNameSize = get16(bytes_ + local + 26u);
            const std::uint16_t localExtraSize = get16(bytes_ + local + 28u);
            const std::uint32_t localCrc = get32(bytes_ + local + 14u);
            const std::uint32_t localCompressedSize =
                get32(bytes_ + local + 18u);
            const std::uint32_t localUncompressedSize =
                get32(bytes_ + local + 22u);
            const std::size_t localFixedEnd = local + 30u;
            if (!rinruntime_archive_flags_supported(localFlags) ||
                (localFlags & 0x0008u) != 0u || localFlags != flags ||
                localMethod != entry.method || localNameSize != nameSize ||
                localCrc != entry.crc ||
                localCompressedSize != entry.compressedSize ||
                localUncompressedSize != entry.uncompressedSize ||
                localFixedEnd > size_ ||
                localNameSize > size_ - localFixedEnd)
                return fail(ArchiveZipResult::Malformed);
            const std::size_t localNameEnd = localFixedEnd + localNameSize;
            if (localExtraSize > size_ - localNameEnd)
                return fail(ArchiveZipResult::Malformed);
            const std::size_t data = localNameEnd + localExtraSize;
            if (data > centralOffset_ ||
                entry.compressedSize > centralOffset_ - data ||
                ::memcmp(bytes_ + local + 30u, entry.name.data(), nameSize) !=
                    0)
                return fail(ArchiveZipResult::Malformed);
            const std::size_t dataEnd =
                data + static_cast<std::size_t>(entry.compressedSize);
            for (const ArchiveZipEntry& existing : entries_) {
                const std::size_t existingEnd =
                    existing.dataOffset +
                    static_cast<std::size_t>(existing.compressedSize);
                if (entry.localOffset < existingEnd &&
                    existing.localOffset < dataEnd)
                    return fail(ArchiveZipResult::Malformed);
            }
            entry.dataOffset = data;
            entries_.push_back(entry);
            position = fixedEnd + variableSize;
        }
        if (position != static_cast<std::size_t>(centralOffset_) + centralSize_)
            return fail(ArchiveZipResult::Malformed);
        totalContent_ = total;
        return ArchiveZipResult::Ok;
    }

    void clear()
    {
        bytes_ = nullptr;
        size_ = 0u;
        centralOffset_ = 0u;
        centralSize_ = 0u;
        totalContent_ = 0u;
        entries_.clear();
    }

    bool empty() const { return entries_.empty(); }
    std::size_t size() const { return entries_.size(); }
    std::uint64_t totalContent() const { return totalContent_; }
    const std::vector<ArchiveZipEntry>& entries() const { return entries_; }

    const std::uint8_t* compressedData(std::size_t index,
                                       std::size_t* sizeOut) const
    {
        if (sizeOut != nullptr)
            *sizeOut = 0u;
        if (index >= entries_.size() || sizeOut == nullptr)
            return nullptr;
        const ArchiveZipEntry& entry = entries_[index];
        *sizeOut = entry.compressedSize;
        return bytes_ + entry.dataOffset;
    }

    /* Extract one validated entry into a bounded caller-owned string.  This
     * is intentionally memory-only: filesystem publication and rollback stay
     * in the archive service, while codec and CRC policy remain reusable by
     * external toolkits. */
    ArchiveZipResult readEntry(std::size_t index, std::string& output) const
    {
        return readEntry(index, output, nullptr, nullptr);
    }

    ArchiveZipResult readEntry(
        std::size_t index, std::string& output,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        output.clear();
        if (index >= entries_.size())
            return ArchiveZipResult::InvalidArgument;
        const ArchiveZipEntry& entry = entries_[index];
        std::size_t compressedSize = 0u;
        const std::uint8_t* compressed = compressedData(index, &compressedSize);
        if (compressed == nullptr)
            return ArchiveZipResult::Malformed;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return ArchiveZipResult::Cancelled;
        if (entry.method == 0u) {
            if (compressedSize != entry.uncompressedSize ||
                entry.uncompressedSize > static_cast<std::uint32_t>(
                    RINRUNTIME_ARCHIVE_CONTENT_LIMIT) ||
                rinruntime_archive_crc32(compressed, compressedSize) !=
                    entry.crc)
                return ArchiveZipResult::Malformed;
            output.assign(reinterpret_cast<const char*>(compressed),
                          compressedSize);
            return ArchiveZipResult::Ok;
        }
        if (entry.method != 8u)
            return ArchiveZipResult::Malformed;
        ArchiveDeflateDecoder decoder;
        const ArchiveDeflateResult result = decoder.decode(
            compressed, compressedSize, entry.uncompressedSize, entry.crc,
            output, cancellation, cancellationContext);
        if (result == ArchiveDeflateResult::Ok)
            return ArchiveZipResult::Ok;
        if (result == ArchiveDeflateResult::Limit)
            return ArchiveZipResult::Limit;
        if (result == ArchiveDeflateResult::Cancelled)
            return ArchiveZipResult::Cancelled;
        output.clear();
        return ArchiveZipResult::Malformed;
    }

    /* Stream one validated entry into a caller-owned staging sink. The sink
     * receives at most 64 KiB per callback and must durably accept each
     * chunk. A non-Ok result never constitutes archive publication; callers
     * must discard their staging object on failure. */
    ArchiveZipResult readEntryToSink(std::size_t index,
                                     ArchiveDeflateSinkFunction sink,
                                     void* context) const
    {
        return readEntryToSink(index, sink, context, nullptr, nullptr);
    }

    ArchiveZipResult readEntryToSink(
        std::size_t index, ArchiveDeflateSinkFunction sink, void* context,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext) const
    {
        if (index >= entries_.size() || sink == nullptr || context == nullptr)
            return ArchiveZipResult::InvalidArgument;
        const ArchiveZipEntry& entry = entries_[index];
        std::size_t compressedSize = 0u;
        const std::uint8_t* compressed = compressedData(index, &compressedSize);
        if (compressed == nullptr)
            return ArchiveZipResult::Malformed;
        if (cancellation != nullptr && cancellation(cancellationContext))
            return ArchiveZipResult::Cancelled;
        if (entry.method == 0u) {
            if (compressedSize != entry.uncompressedSize ||
                rinruntime_archive_crc32(compressed, compressedSize) !=
                    entry.crc)
                return ArchiveZipResult::Malformed;
            std::size_t offset = 0u;
            while (offset < compressedSize) {
                if (cancellation != nullptr && cancellation(cancellationContext))
                    return ArchiveZipResult::Cancelled;
                const std::size_t chunk =
                    compressedSize - offset > 65536u
                        ? 65536u : compressedSize - offset;
                if (!sink(context, compressed + offset, chunk))
                    return ArchiveZipResult::Malformed;
                offset += chunk;
            }
            return ArchiveZipResult::Ok;
        }
        if (entry.method != 8u)
            return ArchiveZipResult::Malformed;
        ArchiveDeflateDecoder decoder;
        const ArchiveDeflateResult result = decoder.decodeToSink(
            compressed, compressedSize, entry.uncompressedSize, entry.crc,
            sink, context, cancellation, cancellationContext);
        if (result == ArchiveDeflateResult::Ok)
            return ArchiveZipResult::Ok;
        if (result == ArchiveDeflateResult::Limit)
            return ArchiveZipResult::Limit;
        if (result == ArchiveDeflateResult::Cancelled)
            return ArchiveZipResult::Cancelled;
        return ArchiveZipResult::Malformed;
    }

private:
    static std::uint16_t get16(const std::uint8_t* bytes)
    {
        return static_cast<std::uint16_t>(bytes[0]) |
               static_cast<std::uint16_t>(bytes[1]) << 8u;
    }

    static std::uint32_t get32(const std::uint8_t* bytes)
    {
        return static_cast<std::uint32_t>(bytes[0]) |
               static_cast<std::uint32_t>(bytes[1]) << 8u |
               static_cast<std::uint32_t>(bytes[2]) << 16u |
               static_cast<std::uint32_t>(bytes[3]) << 24u;
    }

    ArchiveZipResult fail(ArchiveZipResult result)
    {
        clear();
        return result;
    }

    const std::uint8_t* bytes_ = nullptr;
    std::size_t size_ = 0u;
    std::uint32_t centralOffset_ = 0u;
    std::uint32_t centralSize_ = 0u;
    std::uint64_t totalContent_ = 0u;
    std::vector<ArchiveZipEntry> entries_;
};

/*
 * Build a deterministic single-disk ZIP image without depending on a
 * filesystem or a compression library.  Entries are copied into the writer's
 * private image, so the caller may release its input after addStored(),
 * addDeflated(), or addDynamic() returns.  The writer exposes stored data,
 * fixed-Huffman runs, and a bounded dynamic-Huffman literal block.
 */
class ArchiveZipWriter final {
public:
    ArchiveZipWriter() = default;

    ArchiveZipResult addStored(const char* name, const std::uint8_t* data,
                               std::size_t size)
    {
        return addEntry(name, data, size, data, size, 0u);
    }

    ArchiveZipResult addDeflated(const char* name, const std::uint8_t* data,
                                 std::size_t size)
    {
        if (data == nullptr && size != 0u)
            return ArchiveZipResult::InvalidArgument;
        if (size == 0u)
            return addStored(name, nullptr, 0u);
        std::vector<std::uint8_t> compressed;
        if (!deflateRuns(data, size, compressed))
            return ArchiveZipResult::Limit;
        return addEntry(name, data, size, compressed.data(), compressed.size(),
                        8u);
    }

    /* Emit a deterministic dynamic-Huffman block containing literals only.
     * This deliberately does not pretend to be a full match finder: it gives
     * callers a standards-compliant dynamic authoring path while retaining
     * the fixed entry/content/ratio limits of the bounded writer. */
    ArchiveZipResult addDynamic(const char* name, const std::uint8_t* data,
                                std::size_t size)
    {
        if (data == nullptr && size != 0u)
            return ArchiveZipResult::InvalidArgument;
        if (size == 0u)
            return addStored(name, nullptr, 0u);
        std::vector<std::uint8_t> compressed;
        if (!dynamicLiterals(data, size, compressed))
            return ArchiveZipResult::Limit;
        return addEntry(name, data, size, compressed.data(), compressed.size(),
                        8u);
    }

    ArchiveZipResult finish(std::vector<std::uint8_t>& output) const
    {
        if (entries_.empty())
            return ArchiveZipResult::InvalidArgument;
        if (entries_.size() > RINRUNTIME_ARCHIVE_ENTRY_LIMIT ||
            image_.size() > static_cast<std::size_t>(UINT32_MAX))
            return ArchiveZipResult::Limit;

        std::vector<std::uint8_t> candidate = image_;
        const std::size_t centralOffset = candidate.size();
        for (const Entry& entry : entries_) {
            if (entry.name.size() > UINT16_MAX || candidate.size() > UINT32_MAX - 46u ||
                entry.name.size() > UINT32_MAX - candidate.size() - 46u)
                return ArchiveZipResult::Limit;
            put32(candidate, 0x02014b50u);
            put16(candidate, 20u); /* version made by */
            put16(candidate, 20u); /* version needed */
            put16(candidate, 0u);   /* flags */
            put16(candidate, entry.method);
            put16(candidate, 0u);   /* mod time */
            put16(candidate, 0u);   /* mod date */
            put32(candidate, entry.crc);
            put32(candidate, entry.compressedSize);
            put32(candidate, entry.uncompressedSize);
            put16(candidate, static_cast<std::uint16_t>(entry.name.size()));
            put16(candidate, 0u);   /* extra */
            put16(candidate, 0u);   /* comment */
            put16(candidate, 0u);   /* disk */
            put16(candidate, 0u);   /* internal attributes */
            put32(candidate, entry.directory ? 0x10u : 0u);
            put32(candidate, entry.localOffset);
            appendBytes(candidate,
                        reinterpret_cast<const std::uint8_t*>(entry.name.data()),
                        entry.name.size());
        }
        const std::size_t centralSize = candidate.size() - centralOffset;
        if (centralOffset > UINT32_MAX || centralSize > UINT32_MAX ||
            candidate.size() > RINRUNTIME_ARCHIVE_CONTENT_LIMIT ||
            entries_.size() > UINT16_MAX)
            return ArchiveZipResult::Limit;
        put32(candidate, 0x06054b50u);
        put16(candidate, 0u); /* disk */
        put16(candidate, 0u); /* central directory disk */
        put16(candidate, static_cast<std::uint16_t>(entries_.size()));
        put16(candidate, static_cast<std::uint16_t>(entries_.size()));
        put32(candidate, static_cast<std::uint32_t>(centralSize));
        put32(candidate, static_cast<std::uint32_t>(centralOffset));
        put16(candidate, 0u); /* comment length */
        output = candidate;
        return ArchiveZipResult::Ok;
    }

    void clear()
    {
        image_.clear();
        entries_.clear();
        totalContent_ = 0u;
    }

    std::size_t size() const { return entries_.size(); }
    std::uint64_t totalContent() const { return totalContent_; }

private:
    struct Entry {
        std::string name;
        std::uint16_t method = 0u;
        std::uint32_t crc = 0u;
        std::uint32_t compressedSize = 0u;
        std::uint32_t uncompressedSize = 0u;
        std::uint32_t localOffset = 0u;
        bool directory = false;
    };

    static void put16(std::vector<std::uint8_t>& output,
                      std::uint16_t value)
    {
        output.push_back(static_cast<std::uint8_t>(value));
        output.push_back(static_cast<std::uint8_t>(value >> 8u));
    }

    static void put32(std::vector<std::uint8_t>& output,
                      std::uint32_t value)
    {
        for (unsigned index = 0u; index < 4u; ++index)
            output.push_back(static_cast<std::uint8_t>(value >> (index * 8u)));
    }

    static void appendBytes(std::vector<std::uint8_t>& output,
                            const std::uint8_t* data, std::size_t size)
    {
        if (size == 0u) return;
        output.insert(output.end(), data, data + size);
    }

    static bool boundedNameLength(const char* name, std::size_t& size)
    {
        if (name == nullptr) return false;
        for (size = 0u; size <= RINRUNTIME_ARCHIVE_PATH_LIMIT; ++size)
            if (name[size] == '\0') return size != 0u;
        size = 0u;
        return false;
    }

    static std::uint32_t crc32(const std::uint8_t* data, std::size_t size)
    {
        std::uint32_t crc = 0xffffffffu;
        for (std::size_t index = 0u; index < size; ++index) {
            crc ^= data[index];
            for (unsigned bit = 0u; bit < 8u; ++bit)
                crc = (crc >> 1u) ^
                      (0xedb88320u & static_cast<std::uint32_t>(
                          -(static_cast<std::int32_t>(crc & 1u))));
        }
        return crc ^ 0xffffffffu;
    }

    static std::uint32_t reverseBits(std::uint32_t value, unsigned count)
    {
        std::uint32_t result = 0u;
        for (unsigned index = 0u; index < count; ++index) {
            result = (result << 1u) | (value & 1u);
            value >>= 1u;
        }
        return result;
    }

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
            0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
            2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
        int index = 0;
        while (index < 28 && length >= bases[index + 1]) ++index;
        fixedSymbol(writer, 257 + index);
        if (extras[index] != 0u)
            writer.write(static_cast<std::uint32_t>(length - bases[index]),
                         extras[index]);
        writer.write(0u, 5u); /* distance code 0, distance 1 */
    }

    static bool deflateRuns(const std::uint8_t* data, std::size_t size,
                            std::vector<std::uint8_t>& output)
    {
        if (data == nullptr || size == 0u || size > UINT32_MAX)
            return false;
        output.clear();
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
        return output.size() <= UINT32_MAX &&
               rinruntime_archive_compression_ratio_valid(output.size(), size);
    }

    static bool dynamicLiterals(const std::uint8_t* data, std::size_t size,
                                std::vector<std::uint8_t>& output)
    {
        if (data == nullptr || size == 0u || size > UINT32_MAX)
            return false;
        output.clear();
        BitWriter writer(output);
        writer.write(1u, 1u);  /* final block */
        writer.write(2u, 2u);  /* dynamic Huffman */
        writer.write(29u, 5u); /* 286 literal/length codes */
        writer.write(0u, 5u);  /* one distance code */
        writer.write(14u, 4u); /* 18 code-length codes */

        /* The code-length alphabet contains symbols 0, 1, and 9 at length 2.
         * The remaining entries in the prescribed order are unused. */
        static const std::uint8_t codeLengthLengths[18] = {
            0u, 0u, 0u, 2u, 0u, 0u, 2u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u};
        for (std::uint8_t length : codeLengthLengths)
            writer.write(length, 3u);

        /* Literal/length symbols 0..256 use nine-bit codes.  The remaining
         * 29 symbols are absent.  The sole distance symbol has one bit. */
        for (unsigned index = 0u; index < 257u; ++index)
            writer.write(1u, 2u); /* code-length symbol 9, reversed code 01 */
        for (unsigned index = 257u; index < 286u; ++index)
            writer.write(0u, 2u); /* code-length symbol 0 */
        writer.write(2u, 2u);     /* code-length symbol 1, reversed code 10 */

        for (std::size_t index = 0u; index < size; ++index)
            writer.write(reverseBits(data[index], 9u), 9u);
        writer.write(reverseBits(256u, 9u), 9u); /* end-of-block */
        writer.finish();
        return output.size() <= UINT32_MAX &&
               rinruntime_archive_compression_ratio_valid(output.size(), size);
    }

    ArchiveZipResult addEntry(const char* name, const std::uint8_t* data,
                              std::size_t size, const std::uint8_t* compressed,
                              std::size_t compressedSize,
                              std::uint16_t method)
    {
        int directory = 0;
        std::size_t nameSize = 0u;
        std::uint64_t newTotal = 0u;
        if (!boundedNameLength(name, nameSize) ||
            !rinruntime_archive_path_valid(name, nameSize, &directory, nullptr) ||
            (compressed == nullptr && compressedSize != 0u) ||
            size > UINT32_MAX || compressedSize > UINT32_MAX ||
            !rinruntime_archive_compression_ratio_valid(compressedSize, size))
            return ArchiveZipResult::InvalidArgument;
        if (!rinruntime_archive_content_add(totalContent_, size, &newTotal))
            return ArchiveZipResult::Limit;
        if (entries_.size() >= RINRUNTIME_ARCHIVE_ENTRY_LIMIT ||
            image_.size() > UINT32_MAX || image_.size() > UINT32_MAX - 30u ||
            nameSize > UINT32_MAX - image_.size() - 30u ||
            compressedSize > UINT32_MAX - image_.size() - 30u - nameSize)
            return ArchiveZipResult::Limit;
        for (const Entry& existing : entries_)
            if (existing.name == name)
                return ArchiveZipResult::Malformed;
        if (directory != 0 && (method != 0u || size != 0u || compressedSize != 0u))
            return ArchiveZipResult::Malformed;
        Entry entry;
        entry.name.assign(name);
        entry.method = method;
        entry.crc = crc32(data, size);
        entry.compressedSize = static_cast<std::uint32_t>(compressedSize);
        entry.uncompressedSize = static_cast<std::uint32_t>(size);
        entry.localOffset = static_cast<std::uint32_t>(image_.size());
        entry.directory = directory != 0;
        put32(image_, 0x04034b50u);
        put16(image_, 20u); /* version needed */
        put16(image_, 0u);  /* flags */
        put16(image_, method);
        put16(image_, 0u);  /* mod time */
        put16(image_, 0u);  /* mod date */
        put32(image_, entry.crc);
        put32(image_, entry.compressedSize);
        put32(image_, entry.uncompressedSize);
        put16(image_, static_cast<std::uint16_t>(entry.name.size()));
        put16(image_, 0u);  /* extra */
        appendBytes(image_, reinterpret_cast<const std::uint8_t*>(name),
                    entry.name.size());
        appendBytes(image_, compressed, compressedSize);
        entries_.push_back(entry);
        totalContent_ = newTotal;
        return ArchiveZipResult::Ok;
    }

    std::uint64_t totalContent_ = 0u;
    std::vector<std::uint8_t> image_;
    std::vector<Entry> entries_;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_ZIP_HPP */

