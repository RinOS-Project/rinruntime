/* SPDX-License-Identifier: MIT */
/* Backend-independent package metadata admission for public consumers. */
#ifndef RINRUNTIME_PACKAGE_METADATA_HPP
#define RINRUNTIME_PACKAGE_METADATA_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

static constexpr std::size_t kPackageMetadataMaxIdBytes = 63u;
static constexpr std::size_t kPackageMetadataMaxDisplayNameBytes = 63u;
static constexpr std::size_t kPackageMetadataMaxVersionBytes = 31u;
static constexpr std::size_t kPackageMetadataMaxDescriptionBytes = 255u;
static constexpr std::size_t kPackageMetadataMaxLicenseBytes = 63u;
static constexpr std::size_t kPackageMetadataMaxHomepageBytes = 191u;
static constexpr std::size_t kPackageMetadataMaxDependencies = 8u;
static constexpr std::size_t kPackageMetadataMaxProvides = 8u;
static constexpr std::size_t kPackageMetadataMaxEntryPoints = 8u;
static constexpr std::size_t kPackageMetadataMaxFiles = 64u;

enum class PackageArchitecture : std::uint16_t {
    X86_64 = 1u,
    I686 = 2u,
    Any = 3u,
};

enum class PackageClass : std::uint16_t {
    Application = 1u,
    Runtime = 2u,
    Library = 3u,
    Driver = 4u,
    SystemComponent = 5u,
    LanguagePack = 6u,
    Theme = 7u,
    DeveloperTool = 8u,
};

static constexpr std::uint32_t kPackageMetadataFlagSystem = 1u << 0;
static constexpr std::uint32_t kPackageMetadataFlagReboot = 1u << 1;
static constexpr std::uint32_t kPackageMetadataFlagSecurity = 1u << 2;
static constexpr std::uint32_t kPackageMetadataFlagsAll =
    kPackageMetadataFlagSystem | kPackageMetadataFlagReboot |
    kPackageMetadataFlagSecurity;

/* Numeric Rin versions use one to four decimal uint32 components. */
struct PackageVersion {
    std::uint32_t component[4] = {};
    std::uint8_t count = 0u;

    bool valid() const {
        return count >= 1u && count <= 4u;
    }

    static bool parse(const std::string& text, PackageVersion& output) {
        PackageVersion candidate = {};
        std::size_t start = 0u;
        if (text.empty() || text.size() > kPackageMetadataMaxVersionBytes)
            return false;
        while (start < text.size()) {
            if (candidate.count >= 4u) return false;
            std::size_t end = text.find('.', start);
            if (end == std::string::npos) end = text.size();
            if (end == start ||
                (end - start > 1u && text[start] == '0')) return false;
            std::uint64_t value = 0u;
            for (std::size_t index = start; index < end; ++index) {
                const char digit = text[index];
                if (digit < '0' || digit > '9') return false;
                value = value * 10u + static_cast<unsigned>(digit - '0');
                if (value > UINT32_MAX) return false;
            }
            candidate.component[candidate.count++] =
                static_cast<std::uint32_t>(value);
            if (end == text.size()) break;
            start = end + 1u;
        }
        if (!candidate.valid()) return false;
        output = candidate;
        return true;
    }

    static int compare(const PackageVersion& left, const PackageVersion& right) {
        for (std::size_t index = 0u; index < 4u; ++index) {
            const std::uint32_t lhs = index < left.count ? left.component[index] : 0u;
            const std::uint32_t rhs = index < right.count ? right.component[index] : 0u;
            if (lhs < rhs) return -1;
            if (lhs > rhs) return 1;
        }
        return 0;
    }
};

struct PackageMetadata;

struct PackageDependency {
    std::string name;
    bool hasMinimum = false;
    PackageVersion minimum = {};
    bool hasMaximum = false;
    PackageVersion maximum = {};

    bool valid(const std::string& owner = std::string()) const;
};

struct PackageEntryPoint {
    std::string name;
    std::string path;

    bool valid() const;
};

/*
 * This is deliberately a model, not an installer API. It contains no
 * pathname to an installed root, descriptor, signature, private key, or
 * service handle. Package builders and the kernel map this model to their
 * own authenticated wire formats; ordinary applications can use the same
 * validation and dependency ordering rules without importing those owners.
 */
struct PackageMetadata {
    std::string packageId;
    std::string displayName;
    PackageVersion version = {};
    PackageArchitecture architecture = PackageArchitecture::Any;
    PackageClass packageClass = PackageClass::Application;
    std::uint32_t flags = 0u;
    std::array<std::uint8_t, 32u> publisherKeyId = {};
    std::uint32_t publisherGeneration = 0u;
    std::string description;
    std::string license;
    std::string homepage;
    bool hasMinimumRinVersion = false;
    PackageVersion minimumRinVersion = {};
    bool hasMaximumRinVersion = false;
    PackageVersion maximumRinVersion = {};
    std::uint64_t installedSize = 0u;
    std::uint32_t ordinaryFileCount = 0u;
    std::vector<PackageDependency> dependencies;
    std::vector<PackageDependency> optionalDependencies;
    std::vector<std::string> conflicts;
    std::vector<std::string> provides;
    std::vector<PackageEntryPoint> entryPoints;

    static bool validIdentifier(const std::string& value, std::size_t maximum) {
        if (value.empty() || value.size() > maximum || value == "." ||
            value == "..")
            return false;
        for (const unsigned char byte : value) {
            if (byte < 0x20u || byte == 0x7fu || byte == '/' ||
                byte == '\\' || byte == ':')
                return false;
        }
        return true;
    }

    static bool validText(const std::string& value, std::size_t maximum,
                          bool allowEmpty) {
        if (value.size() > maximum || (!allowEmpty && value.empty()))
            return false;
        for (const unsigned char byte : value)
            if (byte < 0x20u || byte == 0x7fu) return false;
        return true;
    }

    static bool validRelativePath(const std::string& value) {
        if (value.empty() || value.size() > 191u || value.front() == '/' ||
            value.back() == '/')
            return false;
        std::size_t start = 0u;
        while (start < value.size()) {
            std::size_t end = value.find('/', start);
            if (end == std::string::npos) end = value.size();
            if (end == start || value.substr(start, end - start) == "." ||
                value.substr(start, end - start) == "..")
                return false;
            for (std::size_t index = start; index < end; ++index) {
                const unsigned char byte = static_cast<unsigned char>(value[index]);
                if (byte < 0x20u || byte == 0x7fu || byte == '\\' ||
                    byte == ':')
                    return false;
            }
            if (end == value.size()) break;
            start = end + 1u;
        }
        return true;
    }

    static bool sortedUnique(const std::vector<std::string>& values) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (index != 0u && values[index - 1u] >= values[index])
                return false;
            if (!validIdentifier(values[index], kPackageMetadataMaxIdBytes))
                return false;
        }
        return true;
    }

    static bool sortedUnique(const std::vector<PackageDependency>& values,
                             const std::string& owner) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!values[index].valid(owner) ||
                (index != 0u && values[index - 1u].name >= values[index].name))
                return false;
        }
        return true;
    }

    bool valid() const {
        if (!validIdentifier(packageId, kPackageMetadataMaxIdBytes) ||
            !validText(displayName, kPackageMetadataMaxDisplayNameBytes, false) ||
            !version.valid() ||
            (architecture != PackageArchitecture::X86_64 &&
             architecture != PackageArchitecture::I686 &&
             architecture != PackageArchitecture::Any) ||
            (static_cast<std::uint16_t>(packageClass) < 1u ||
             static_cast<std::uint16_t>(packageClass) > 8u) ||
            (flags & ~kPackageMetadataFlagsAll) != 0u ||
            !validText(description, kPackageMetadataMaxDescriptionBytes, true) ||
            !validText(license, kPackageMetadataMaxLicenseBytes, false) ||
            !validText(homepage, kPackageMetadataMaxHomepageBytes, true) ||
            (hasMinimumRinVersion && !minimumRinVersion.valid()) ||
            (hasMaximumRinVersion && !maximumRinVersion.valid()) ||
            (hasMinimumRinVersion && hasMaximumRinVersion &&
             PackageVersion::compare(minimumRinVersion, maximumRinVersion) >= 0) ||
            ordinaryFileCount > kPackageMetadataMaxFiles ||
            dependencies.size() > kPackageMetadataMaxDependencies ||
            optionalDependencies.size() > kPackageMetadataMaxDependencies ||
            conflicts.size() > kPackageMetadataMaxDependencies ||
            provides.size() > kPackageMetadataMaxProvides ||
            entryPoints.size() > kPackageMetadataMaxEntryPoints ||
            !sortedUnique(dependencies, packageId) ||
            !sortedUnique(optionalDependencies, packageId) ||
            !sortedUnique(conflicts) || !sortedUnique(provides))
            return false;
        bool publisherKeyZero = true;
        for (const std::uint8_t byte : publisherKeyId)
            if (byte != 0u) publisherKeyZero = false;
        if ((publisherGeneration == 0u) != publisherKeyZero) return false;
        for (std::size_t index = 0u; index < entryPoints.size(); ++index) {
            if (!entryPoints[index].valid() ||
                (index != 0u && entryPoints[index - 1u].name >=
                                     entryPoints[index].name))
                return false;
        }
        return true;
    }
};

inline bool PackageDependency::valid(const std::string& owner) const {
    if (!PackageMetadata::validIdentifier(name, kPackageMetadataMaxIdBytes) ||
        (!owner.empty() && name == owner) ||
        (hasMinimum && !minimum.valid()) ||
        (hasMaximum && !maximum.valid()))
        return false;
    return !hasMinimum || !hasMaximum ||
           PackageVersion::compare(minimum, maximum) < 0;
}

inline bool PackageEntryPoint::valid() const {
    return PackageMetadata::validIdentifier(name, kPackageMetadataMaxIdBytes) &&
           PackageMetadata::validRelativePath(path);
}

} // namespace RinRuntime

#endif /* RINRUNTIME_PACKAGE_METADATA_HPP */
