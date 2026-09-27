/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded 7z envelope inspection. */

#ifndef RINRUNTIME_ARCHIVE_7Z_HPP
#define RINRUNTIME_ARCHIVE_7Z_HPP

#include "archive_deflate.hpp"

#include <cstddef>
#include <cstdint>

namespace RinRuntime {

enum class Archive7zResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Unsupported = -5,
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
 * The public reader checks only the 7z envelope.  It does not interpret coder
 * chains, decrypt headers, allocate decoded entries, open paths, or publish
 * files.  Those operations stay with an authenticated private archive owner.
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
        if (bytes == nullptr || size < kSignatureHeaderSize)
            return Archive7zResult::InvalidArgument;
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

private:
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
