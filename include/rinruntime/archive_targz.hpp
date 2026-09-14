/* SPDX-License-Identifier: MIT */
/* Bounded TAR.GZ composition for the common archive layer. */

#ifndef RINRUNTIME_ARCHIVE_TARGZ_HPP
#define RINRUNTIME_ARCHIVE_TARGZ_HPP

#include "archive_gzip.hpp"
#include "archive_tar.hpp"

namespace RinRuntime {

enum class ArchiveTarGzipResult : int {
    Ok = 0,
    InvalidArgument = -1,
    Limit = -2,
    Malformed = -3,
    CrcMismatch = -4,
    Cancelled = -5,
};

/* Decode the complete bounded gzip member into an owned staging string and
 * then parse that exact image as strict ustar.  The TAR reader keeps views into
 * image_, so the result remains valid until the next decode or clear call. */
class ArchiveTarGzipReader final {
public:
    ArchiveTarGzipResult parse(const std::uint8_t* bytes, std::size_t size)
    {
        clear();
        const ArchiveGzipResult gzipResult = gzip_.decode(bytes, size, image_);
        if (gzipResult == ArchiveGzipResult::InvalidArgument)
            return ArchiveTarGzipResult::InvalidArgument;
        if (gzipResult == ArchiveGzipResult::Limit)
            return ArchiveTarGzipResult::Limit;
        if (gzipResult == ArchiveGzipResult::CrcMismatch)
            return ArchiveTarGzipResult::CrcMismatch;
        if (gzipResult != ArchiveGzipResult::Ok)
            return ArchiveTarGzipResult::Malformed;
        const ArchiveTarResult tarResult = tar_.parse(
            reinterpret_cast<const std::uint8_t*>(image_.data()), image_.size());
        if (tarResult == ArchiveTarResult::Limit) {
            clear();
            return ArchiveTarGzipResult::Limit;
        }
        if (tarResult != ArchiveTarResult::Ok) {
            clear();
            return ArchiveTarGzipResult::Malformed;
        }
        return ArchiveTarGzipResult::Ok;
    }

    ArchiveTarGzipResult parse(const ArchiveGzipSource& source,
                               std::uint8_t* compressedBuffer,
                               std::size_t compressedCapacity)
    {
        return parse(source, compressedBuffer, compressedCapacity, nullptr,
                     nullptr);
    }

    ArchiveTarGzipResult parse(
        const ArchiveGzipSource& source, std::uint8_t* compressedBuffer,
        std::size_t compressedCapacity,
        ArchiveDeflateCancellationFunction cancellation,
        void* cancellationContext)
    {
        clear();
        const ArchiveGzipResult gzipResult = gzip_.decode(
            source, compressedBuffer, compressedCapacity, image_, cancellation,
            cancellationContext);
        if (gzipResult == ArchiveGzipResult::InvalidArgument)
            return ArchiveTarGzipResult::InvalidArgument;
        if (gzipResult == ArchiveGzipResult::Limit)
            return ArchiveTarGzipResult::Limit;
        if (gzipResult == ArchiveGzipResult::CrcMismatch)
            return ArchiveTarGzipResult::CrcMismatch;
        if (gzipResult != ArchiveGzipResult::Ok)
            return gzipResult == ArchiveGzipResult::Cancelled
                       ? ArchiveTarGzipResult::Cancelled
                       : ArchiveTarGzipResult::Malformed;
        const ArchiveTarResult tarResult = tar_.parse(
            reinterpret_cast<const std::uint8_t*>(image_.data()), image_.size());
        if (tarResult == ArchiveTarResult::Limit) {
            clear();
            return ArchiveTarGzipResult::Limit;
        }
        if (tarResult != ArchiveTarResult::Ok) {
            clear();
            return ArchiveTarGzipResult::Malformed;
        }
        return ArchiveTarGzipResult::Ok;
    }

    void clear()
    {
        tar_.clear();
        image_.clear();
    }

    bool empty() const { return tar_.empty(); }
    std::size_t size() const { return tar_.size(); }
    std::uint64_t totalContent() const { return tar_.totalContent(); }
    const std::vector<ArchiveTarEntry>& entries() const
    {
        return tar_.entries();
    }
    const std::uint8_t* data(std::size_t index,
                             std::size_t* sizeOut = nullptr) const
    {
        return tar_.data(index, sizeOut);
    }

private:
    ArchiveGzipReader gzip_;
    ArchiveTarReader tar_;
    std::string image_;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ARCHIVE_TARGZ_HPP */

