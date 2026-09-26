/* SPDX-License-Identifier: MIT */
/* Public repository-neutral application metadata catalog model. */
#ifndef RINRUNTIME_APPLICATION_METADATA_CATALOG_HPP
#define RINRUNTIME_APPLICATION_METADATA_CATALOG_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "application_metadata.hpp"

namespace RinRuntime {

static constexpr std::size_t kApplicationMetadataCatalogMaxApplications =
    64u;

/*
 * A repository-neutral application listing.  The generation is an opaque
 * snapshot identifier, not an authentication or launch authority.  URLs,
 * signatures, installed roots, and capability decisions remain private
 * repository/installer/launcher concerns.
 */
struct ApplicationMetadataCatalog {
    std::uint64_t generation = 0u;
    std::vector<ApplicationMetadata> applications;

    bool valid() const {
        if (generation == 0u ||
            applications.size() > kApplicationMetadataCatalogMaxApplications)
            return false;
        for (std::size_t index = 0u; index < applications.size(); ++index) {
            const ApplicationMetadata& application = applications[index];
            if (!application.valid() ||
                (index != 0u &&
                 applications[index - 1u].applicationId >=
                     application.applicationId))
                return false;
        }
        return true;
    }

    const ApplicationMetadata* find(std::string_view applicationId) const {
        for (const ApplicationMetadata& application : applications) {
            if (application.applicationId == applicationId) return &application;
        }
        return nullptr;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_CATALOG_HPP */
