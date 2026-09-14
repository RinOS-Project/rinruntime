/* SPDX-License-Identifier: MIT */
/* Backend-independent ABI feature requirements for public consumers. */
#ifndef RINRUNTIME_ABI_FEATURE_MANIFEST_HPP
#define RINRUNTIME_ABI_FEATURE_MANIFEST_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

static constexpr std::size_t kAbiFeatureManifestMaxIdBytes = 63u;
static constexpr std::size_t kAbiFeatureManifestMaxFeatures = 64u;

struct AbiFeatureRequirement {
    std::string id;
    std::uint16_t minimumMajor = 0u;
    std::uint16_t minimumMinor = 0u;

    AbiFeatureRequirement() = default;
    AbiFeatureRequirement(const std::string& featureId,
                          std::uint16_t major,
                          std::uint16_t minor)
        : id(featureId), minimumMajor(major), minimumMinor(minor) {}

    bool valid() const {
        if (id.empty() || id.size() > kAbiFeatureManifestMaxIdBytes ||
            (minimumMajor == 0u && minimumMinor == 0u))
            return false;
        for (const unsigned char byte : id) {
            if (byte < 0x21u || byte == 0x7fu || byte == '/' ||
                byte == '\\' || byte == ':')
                return false;
        }
        return true;
    }
};

/*
 * This is deliberately a capability requirement model, not an ABI loader.
 * It contains no symbol addresses, handles, device probes, build evidence,
 * kernel policy, signature, or service transport.
 */
struct AbiFeatureManifest {
    std::uint16_t abiMajor = 0u;
    std::uint16_t abiMinor = 0u;
    std::string manifestId;
    std::vector<AbiFeatureRequirement> required;
    std::vector<AbiFeatureRequirement> optional;

    static bool validIdentifier(const std::string& value,
                                std::size_t maximum) {
        if (value.empty() || value.size() > maximum) return false;
        for (const unsigned char byte : value) {
            if (byte < 0x21u || byte == 0x7fu || byte == '/' ||
                byte == '\\' || byte == ':')
                return false;
        }
        return true;
    }

    static bool sortedUnique(const std::vector<AbiFeatureRequirement>& values) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!values[index].valid() ||
                (index != 0u && values[index - 1u].id >= values[index].id))
                return false;
        }
        return true;
    }

    bool valid() const {
        if (abiMajor == 0u || !validIdentifier(manifestId,
                                                kAbiFeatureManifestMaxIdBytes) ||
            required.size() > kAbiFeatureManifestMaxFeatures ||
            optional.size() > kAbiFeatureManifestMaxFeatures ||
            required.size() + optional.size() >
                kAbiFeatureManifestMaxFeatures ||
            !sortedUnique(required) || !sortedUnique(optional))
            return false;
        for (const AbiFeatureRequirement& requirement : required) {
            for (const AbiFeatureRequirement& candidate : optional)
                if (requirement.id == candidate.id) return false;
        }
        return true;
    }

    bool isRequired(const std::string& featureId) const {
        for (const AbiFeatureRequirement& requirement : required)
            if (requirement.id == featureId) return true;
        return false;
    }

    bool mentions(const std::string& featureId) const {
        if (isRequired(featureId)) return true;
        for (const AbiFeatureRequirement& requirement : optional)
            if (requirement.id == featureId) return true;
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ABI_FEATURE_MANIFEST_HPP */
