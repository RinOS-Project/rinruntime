/* SPDX-License-Identifier: MIT */
/* Public repository-neutral package metadata catalog model. */
#ifndef RINRUNTIME_PACKAGE_METADATA_CATALOG_HPP
#define RINRUNTIME_PACKAGE_METADATA_CATALOG_HPP

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "package_metadata.hpp"

namespace RinRuntime {

static constexpr std::size_t kPackageMetadataCatalogMaxPackages = 64u;

/*
 * A bounded package listing shared by repository clients and package tools.
 * The generation identifies a snapshot only; it is not a signature,
 * publisher trust decision, installed-root authority, or install permission.
 * Those decisions remain with the private repository and installer owners.
 */
struct PackageMetadataCatalog {
    std::uint64_t generation = 0u;
    std::vector<PackageMetadata> packages;

    bool valid() const {
        if (generation == 0u ||
            packages.size() > kPackageMetadataCatalogMaxPackages)
            return false;
        for (std::size_t index = 0u; index < packages.size(); ++index) {
            const PackageMetadata& package = packages[index];
            if (!package.valid() ||
                (index != 0u && packages[index - 1u].packageId >=
                                     package.packageId))
                return false;
        }
        return true;
    }

    const PackageMetadata* find(std::string_view packageId) const {
        for (const PackageMetadata& package : packages)
            if (package.packageId == packageId) return &package;
        return nullptr;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PACKAGE_METADATA_CATALOG_HPP */
