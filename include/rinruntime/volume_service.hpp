/* SPDX-License-Identifier: MIT */
/* Backend-independent removable-volume snapshot and validation model. */

#ifndef RINRUNTIME_VOLUME_SERVICE_HPP
#define RINRUNTIME_VOLUME_SERVICE_HPP

#include "../../../../libs/libc/stdint.h"
#include "../../../../libs/libcxx/string.h"
#include "../../../../libs/libcxx/vector.h"

namespace RinRuntime {

/* A volume is represented by stable management identities and a broker-
 * provided mount path. Callers must not derive authority from the display
 * name or from a stale path after the snapshot changes. */
struct RemovableVolume {
    uint64_t diskId = 0u;
    uint64_t diskGeneration = 0u;
    uint64_t diskRevision = 0u;
    uint32_t partitionIndex = UINT32_MAX;
    uint32_t flags = 0u;
    uint64_t totalBytes = 0u;
    uint64_t usedBytes = 0u;
    std::string name;
    std::string filesystem;
    std::string mountPath;
};

class VolumeService {
public:
    static constexpr size_t kMaxVolumes = 32u;
    static constexpr size_t kMaxNameBytes = 64u;
    static constexpr size_t kMaxFilesystemBytes = 32u;
    static constexpr size_t kMaxMountPathBytes = 56u;

private:
    std::vector<RemovableVolume> volumes_;

    static bool boundedText(const std::string& value, size_t limit,
                            bool allowEmpty) {
        if (!allowEmpty && value.empty()) return false;
        if (value.size() >= limit) return false;
        for (unsigned char byte : value) {
            if (byte < 0x20u || byte == 0x7fu) return false;
        }
        return true;
    }

    static bool mountPathValid(const std::string& value) {
        if (value.empty()) return true;
        if (value.size() >= kMaxMountPathBytes || value.front() != '/')
            return false;
        if (value.find("//") != std::string::npos ||
            value.find("/./") != std::string::npos ||
            value.find("/../") != std::string::npos || value == "/." ||
            value == "/.." ||
            (value.size() >= 2u && value.compare(value.size() - 2u, 2u,
                                                 "/.") == 0) ||
            (value.size() >= 3u && value.compare(value.size() - 3u, 3u,
                                                 "/..") == 0) ||
            value.find('\\') != std::string::npos ||
            value.find('\0') != std::string::npos)
            return false;
        return boundedText(value, kMaxMountPathBytes, false);
    }

public:
    static bool valid(const RemovableVolume& volume) {
        if (volume.diskId == 0u || volume.diskGeneration == 0u ||
            volume.diskRevision == 0u || volume.flags == 0u ||
            volume.totalBytes == 0u || volume.usedBytes > volume.totalBytes)
            return false;
        return boundedText(volume.name, kMaxNameBytes, false) &&
               boundedText(volume.filesystem, kMaxFilesystemBytes, true) &&
               mountPathValid(volume.mountPath);
    }

    /* Replace only after every element has passed validation. */
    bool replace(const std::vector<RemovableVolume>& next) {
        if (next.size() > kMaxVolumes) return false;
        for (size_t index = 0u; index < next.size(); ++index) {
            if (!valid(next[index])) return false;
            for (size_t prior = 0u; prior < index; ++prior) {
                if (next[prior].diskId == next[index].diskId &&
                    next[prior].partitionIndex == next[index].partitionIndex)
                    return false;
            }
        }
        volumes_ = next;
        return true;
    }

    void clear() { volumes_.clear(); }
    const std::vector<RemovableVolume>& volumes() const { return volumes_; }
    bool empty() const { return volumes_.empty(); }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_VOLUME_SERVICE_HPP */
