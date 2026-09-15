/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public package metadata model. */
#ifndef RINRUNTIME_PACKAGE_METADATA_JSON_HPP
#define RINRUNTIME_PACKAGE_METADATA_JSON_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rinjson/json.hpp>

#include "package_metadata.hpp"

namespace RinRuntime {

/* JSON decoding is separate from repository transport, signature
 * verification, installed-root publication, and kernel admission. */
class PackageMetadataJson final {
public:
    static constexpr std::size_t kMaximumBytes = 64u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 255u;
    static constexpr std::size_t kMaximumObjectMembers = 32u;
    static constexpr std::size_t kMaximumArrayElements = 64u;
    static constexpr std::size_t kMaximumNodes = 512u;
    static constexpr std::size_t kMaximumAllocationBytes = 256u * 1024u;

private:
    using Value = rinjson::Value;

    static const Value* field(const Value::Object& object,
                              std::string_view name) {
        const auto found = object.find(name);
        return found == object.end() ? nullptr : &found->second;
    }

    static bool readString(const Value* value, std::string& output) {
        if (value == nullptr || !value->isString() ||
            value->asString().size() > kMaximumStringBytes)
            return false;
        output = value->asString();
        return true;
    }

    static bool optionalString(const Value::Object& object,
                               std::string_view name,
                               std::string& output) {
        const Value* value = field(object, name);
        return value == nullptr || readString(value, output);
    }

    static bool readUnsigned(const Value* value, std::uint64_t maximum,
                             std::uint64_t& output) {
        if (value == nullptr || !value->isInteger()) return false;
        if (value->isSignedInteger()) {
            const std::int64_t parsed = value->asInteger();
            if (parsed < 0) return false;
            output = static_cast<std::uint64_t>(parsed);
        } else {
            output = value->asUnsignedInteger();
        }
        return output <= maximum;
    }

    static bool readVersion(const Value::Object& object, std::string_view name,
                            bool& present, PackageVersion& output) {
        const Value* value = field(object, name);
        if (value == nullptr) {
            present = false;
            output = {};
            return true;
        }
        std::string text;
        if (!readString(value, text) || !PackageVersion::parse(text, output))
            return false;
        present = true;
        return true;
    }

    static bool readArchitecture(const Value::Object& object,
                                 PackageArchitecture& output) {
        const Value* value = field(object, "architecture");
        if (value == nullptr) return true;
        std::string text;
        if (!readString(value, text)) return false;
        if (text == "x86_64") output = PackageArchitecture::X86_64;
        else if (text == "i686") output = PackageArchitecture::I686;
        else if (text == "any") output = PackageArchitecture::Any;
        else return false;
        return true;
    }

    static bool readClass(const Value::Object& object, PackageClass& output) {
        const Value* value = field(object, "class");
        if (value == nullptr) return true;
        std::string text;
        if (!readString(value, text)) return false;
        if (text == "application") output = PackageClass::Application;
        else if (text == "runtime") output = PackageClass::Runtime;
        else if (text == "library") output = PackageClass::Library;
        else if (text == "driver") output = PackageClass::Driver;
        else if (text == "system_component") output = PackageClass::SystemComponent;
        else if (text == "language_pack") output = PackageClass::LanguagePack;
        else if (text == "theme") output = PackageClass::Theme;
        else if (text == "developer_tool") output = PackageClass::DeveloperTool;
        else return false;
        return true;
    }

    static bool readStringArray(const Value::Object& object,
                                std::string_view name, std::size_t maximum,
                                std::vector<std::string>& output) {
        const Value* value = field(object, name);
        if (value == nullptr) return true;
        if (!value->isArray() || value->asArray().size() > maximum)
            return false;
        std::vector<std::string> candidate;
        candidate.reserve(value->asArray().size());
        for (const Value& item : value->asArray()) {
            std::string text;
            if (!readString(&item, text)) return false;
            candidate.push_back(std::move(text));
        }
        output = std::move(candidate);
        return true;
    }

    static bool readDigest(const Value::Object& object,
                           std::array<std::uint8_t, 32u>& output) {
        const Value* value = field(object, "publisher_key_id");
        if (value == nullptr) return true;
        std::string text;
        if (!readString(value, text) || text.size() != 64u) return false;
        std::array<std::uint8_t, 32u> candidate = {};
        const auto nibble = [](char byte, std::uint8_t& result) {
            if (byte >= '0' && byte <= '9')
                result = static_cast<std::uint8_t>(byte - '0');
            else if (byte >= 'a' && byte <= 'f')
                result = static_cast<std::uint8_t>(byte - 'a' + 10);
            else if (byte >= 'A' && byte <= 'F')
                result = static_cast<std::uint8_t>(byte - 'A' + 10);
            else
                return false;
            return true;
        };
        for (std::size_t index = 0u; index < candidate.size(); ++index) {
            std::uint8_t high = 0u;
            std::uint8_t low = 0u;
            if (!nibble(text[index * 2u], high) ||
                !nibble(text[index * 2u + 1u], low))
                return false;
            candidate[index] = static_cast<std::uint8_t>((high << 4u) | low);
        }
        output = candidate;
        return true;
    }

    static bool readDependencies(const Value::Object& object,
                                 std::string_view name, std::size_t maximum,
                                 std::vector<PackageDependency>& output) {
        const Value* value = field(object, name);
        if (value == nullptr) return true;
        if (!value->isArray() || value->asArray().size() > maximum)
            return false;
        std::vector<PackageDependency> candidate;
        candidate.reserve(value->asArray().size());
        for (const Value& item : value->asArray()) {
            if (!item.isObject()) return false;
            const Value::Object& dependencyObject = item.asObject();
            PackageDependency dependency;
            if (!readString(field(dependencyObject, "name"), dependency.name) ||
                !readVersion(dependencyObject, "minimum",
                             dependency.hasMinimum, dependency.minimum) ||
                !readVersion(dependencyObject, "maximum",
                             dependency.hasMaximum, dependency.maximum))
                return false;
            candidate.push_back(std::move(dependency));
        }
        output = std::move(candidate);
        return true;
    }

    static bool readEntryPoints(const Value::Object& object,
                                std::vector<PackageEntryPoint>& output) {
        const Value* value = field(object, "entry_points");
        if (value == nullptr) return true;
        if (!value->isArray() ||
            value->asArray().size() > kPackageMetadataMaxEntryPoints)
            return false;
        std::vector<PackageEntryPoint> candidate;
        candidate.reserve(value->asArray().size());
        for (const Value& item : value->asArray()) {
            if (!item.isObject()) return false;
            const Value::Object& entryObject = item.asObject();
            PackageEntryPoint entry;
            if (!readString(field(entryObject, "name"), entry.name) ||
                !readString(field(entryObject, "path"), entry.path))
                return false;
            candidate.push_back(std::move(entry));
        }
        output = std::move(candidate);
        return true;
    }

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, PackageMetadata& output,
                      std::string& error) {
        PackageMetadata candidate = {};
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "package metadata size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 12u;
            limits.maxStringBytes = kMaximumStringBytes;
            limits.maxArrayElements = kMaximumArrayElements;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "package metadata object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t number = 0u;
            std::string version;
            if (!readString(field(object, "package_id"), candidate.packageId) ||
                !readString(field(object, "display_name"), candidate.displayName) ||
                !readString(field(object, "version"), version) ||
                !PackageVersion::parse(version, candidate.version) ||
                !readString(field(object, "license"), candidate.license) ||
                !optionalString(object, "description", candidate.description) ||
                !optionalString(object, "homepage", candidate.homepage) ||
                !readArchitecture(object, candidate.architecture) ||
                !readClass(object, candidate.packageClass) ||
                !readDigest(object, candidate.publisherKeyId) ||
                !readVersion(object, "minimum_rin_version",
                             candidate.hasMinimumRinVersion,
                             candidate.minimumRinVersion) ||
                !readVersion(object, "maximum_rin_version",
                             candidate.hasMaximumRinVersion,
                             candidate.maximumRinVersion) ||
                !readDependencies(object, "dependencies",
                                  kPackageMetadataMaxDependencies,
                                  candidate.dependencies) ||
                !readDependencies(object, "optional_dependencies",
                                  kPackageMetadataMaxDependencies,
                                  candidate.optionalDependencies) ||
                !readStringArray(object, "conflicts",
                                 kPackageMetadataMaxDependencies,
                                 candidate.conflicts) ||
                !readStringArray(object, "provides", kPackageMetadataMaxProvides,
                                 candidate.provides) ||
                !readEntryPoints(object, candidate.entryPoints)) {
                error = "package metadata field type";
                return false;
            }
            if (field(object, "flags") != nullptr &&
                !readUnsigned(field(object, "flags"),
                              kPackageMetadataFlagsAll, number)) {
                error = "package metadata flags";
                return false;
            }
            candidate.flags = static_cast<std::uint32_t>(number);
            number = 0u;
            if (field(object, "publisher_generation") != nullptr &&
                !readUnsigned(field(object, "publisher_generation"),
                              UINT32_MAX, number)) {
                error = "package metadata publisher";
                return false;
            }
            candidate.publisherGeneration = static_cast<std::uint32_t>(number);
            number = 0u;
            if (field(object, "installed_size") != nullptr &&
                !readUnsigned(field(object, "installed_size"), UINT64_MAX,
                              number)) {
                error = "package metadata size";
                return false;
            }
            candidate.installedSize = number;
            number = 0u;
            if (field(object, "ordinary_file_count") != nullptr &&
                !readUnsigned(field(object, "ordinary_file_count"),
                              kPackageMetadataMaxFiles, number)) {
                error = "package metadata files";
                return false;
            }
            candidate.ordinaryFileCount = static_cast<std::uint32_t>(number);
            if (!candidate.valid()) {
                error = "package metadata validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "package metadata JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PACKAGE_METADATA_JSON_HPP */
