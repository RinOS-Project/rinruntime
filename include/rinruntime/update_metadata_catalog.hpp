/* SPDX-License-Identifier: MIT */
/* Public repository-neutral update metadata catalog model. */
#ifndef RINRUNTIME_UPDATE_METADATA_CATALOG_HPP
#define RINRUNTIME_UPDATE_METADATA_CATALOG_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "update_metadata.hpp"

namespace RinRuntime {

static constexpr std::size_t kUpdateMetadataCatalogMaxUpdates = 32u;

/*
 * A bounded update snapshot for public consumers.  Generation and update IDs
 * identify metadata records only; they do not authenticate a repository,
 * select an artifact, or authorize staging, installation, or reboot.
 */
struct UpdateMetadataCatalog {
    std::uint64_t generation = 0u;
    std::vector<UpdateMetadata> updates;

    bool valid() const {
        if (generation == 0u ||
            updates.size() > kUpdateMetadataCatalogMaxUpdates)
            return false;
        for (std::size_t index = 0u; index < updates.size(); ++index) {
            const UpdateMetadata& update = updates[index];
            if (!update.valid() ||
                (index != 0u && updates[index - 1u].updateId >=
                                     update.updateId))
                return false;
        }
        return true;
    }

    const UpdateMetadata* find(std::string_view updateId) const {
        for (const UpdateMetadata& update : updates)
            if (update.updateId == updateId) return &update;
        return nullptr;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_UPDATE_METADATA_CATALOG_HPP */
