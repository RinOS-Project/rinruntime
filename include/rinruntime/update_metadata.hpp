/* SPDX-License-Identifier: MIT */
/* Backend-independent, bounded update metadata for public consumers. */
#ifndef RINRUNTIME_UPDATE_METADATA_HPP
#define RINRUNTIME_UPDATE_METADATA_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "package_metadata.hpp"

namespace RinRuntime {

static constexpr std::size_t kUpdateMetadataMaxIdBytes = 63u;
static constexpr std::size_t kUpdateMetadataMaxReleaseNotesBytes = 1023u;
static constexpr std::size_t kUpdateMetadataMaxArtifacts = 16u;

enum class UpdateChannel : std::uint16_t {
    Stable = 1u,
    Beta = 2u,
    Nightly = 3u,
};

static constexpr std::uint32_t kUpdateMetadataFlagSecurity = 1u << 0;
static constexpr std::uint32_t kUpdateMetadataFlagReboot = 1u << 1;
static constexpr std::uint32_t kUpdateMetadataFlagMandatory = 1u << 2;
static constexpr std::uint32_t kUpdateMetadataFlagsAll =
    kUpdateMetadataFlagSecurity | kUpdateMetadataFlagReboot |
    kUpdateMetadataFlagMandatory;

struct UpdateArtifact {
    std::string packageId;
    PackageVersion version = {};
    PackageArchitecture architecture = PackageArchitecture::Any;
    std::uint64_t compressedSize = 0u;
    std::uint64_t installedSize = 0u;
    std::array<std::uint8_t, 32u> sha256 = {};

    bool valid() const {
        bool digestPresent = false;
        for (const std::uint8_t byte : sha256)
            if (byte != 0u) digestPresent = true;
        return PackageMetadata::validIdentifier(
                   packageId, kUpdateMetadataMaxIdBytes) &&
               version.valid() &&
               (architecture == PackageArchitecture::X86_64 ||
                architecture == PackageArchitecture::I686 ||
                architecture == PackageArchitecture::Any) &&
               compressedSize != 0u && installedSize != 0u && digestPresent;
    }
};

/*
 * This is metadata, not an updater or installer.  It intentionally contains
 * no URL, pathname, socket, signature, private key, staging handle, or
 * service capability.  A repository/updater owner authenticates this model
 * and binds each artifact to its own transport and install transaction.
 */
struct UpdateMetadata {
    std::string updateId;
    std::string productId;
    PackageVersion targetVersion = {};
    bool hasMinimumFromVersion = false;
    PackageVersion minimumFromVersion = {};
    UpdateChannel channel = UpdateChannel::Stable;
    std::uint32_t flags = 0u;
    std::uint64_t publishedAtUnixSeconds = 0u;
    std::string releaseNotes;
    std::vector<UpdateArtifact> artifacts;

    bool valid() const {
        const std::uint16_t channelValue =
            static_cast<std::uint16_t>(channel);
        if (!PackageMetadata::validIdentifier(
                updateId, kUpdateMetadataMaxIdBytes) ||
            !PackageMetadata::validIdentifier(
                productId, kUpdateMetadataMaxIdBytes) ||
            !targetVersion.valid() ||
            (hasMinimumFromVersion && !minimumFromVersion.valid()) ||
            (hasMinimumFromVersion &&
             PackageVersion::compare(minimumFromVersion, targetVersion) > 0) ||
            (channelValue < static_cast<std::uint16_t>(UpdateChannel::Stable) ||
             channelValue > static_cast<std::uint16_t>(UpdateChannel::Nightly)) ||
            (flags & ~kUpdateMetadataFlagsAll) != 0u ||
            publishedAtUnixSeconds == 0u ||
            !PackageMetadata::validText(
                releaseNotes, kUpdateMetadataMaxReleaseNotesBytes, true) ||
            artifacts.empty() || artifacts.size() > kUpdateMetadataMaxArtifacts)
            return false;

        for (std::size_t index = 0u; index < artifacts.size(); ++index) {
            const UpdateArtifact& artifact = artifacts[index];
            if (!artifact.valid() ||
                PackageVersion::compare(artifact.version, targetVersion) != 0 ||
                (index != 0u &&
                 (artifacts[index - 1u].packageId > artifact.packageId ||
                  (artifacts[index - 1u].packageId == artifact.packageId &&
                   static_cast<std::uint16_t>(
                       artifacts[index - 1u].architecture) >=
                       static_cast<std::uint16_t>(artifact.architecture)))))
                return false;
        }
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_UPDATE_METADATA_HPP */
