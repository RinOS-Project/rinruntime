/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public update metadata model. */
#ifndef RINRUNTIME_UPDATE_METADATA_JSON_HPP
#define RINRUNTIME_UPDATE_METADATA_JSON_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rinjson/json.hpp>

#include "update_metadata.hpp"

namespace RinRuntime {

/*
 * This parser only turns bounded, untrusted JSON into the backend-independent
 * UpdateMetadata model. It does not authenticate a repository, resolve a
 * URL, open a file, retain a signature, or stage an artifact.
 */
class UpdateMetadataJson final {
public:
    static constexpr std::size_t kMaximumBytes = 64u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 1023u;
    static constexpr std::size_t kMaximumObjectMembers = 16u;
    static constexpr std::size_t kMaximumArrayElements = 16u;
    static constexpr std::size_t kMaximumNodes = 256u;
    static constexpr std::size_t kMaximumAllocationBytes = 256u * 1024u;

private:
    using Value = rinjson::Value;

    static const Value* field(const Value::Object& object,
                              std::string_view name) {
        const auto found = object.find(name);
        return found == object.end() ? nullptr : &found->second;
    }

    static bool readString(const Value* value, std::string& output,
                           std::size_t maximum = kMaximumStringBytes) {
        if (value == nullptr || !value->isString() ||
            value->asString().size() > maximum)
            return false;
        output = value->asString();
        return true;
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

    static bool readVersion(const Value* value, PackageVersion& output) {
        std::string text;
        return readString(value, text, kPackageMetadataMaxVersionBytes) &&
               PackageVersion::parse(text, output);
    }

    static bool readArchitecture(const Value::Object& object,
                                 PackageArchitecture& output) {
        const Value* value = field(object, "architecture");
        if (value == nullptr) return true;
        std::string text;
        if (!readString(value, text, 16u)) return false;
        if (text == "x86_64") output = PackageArchitecture::X86_64;
        else if (text == "i686") output = PackageArchitecture::I686;
        else if (text == "any") output = PackageArchitecture::Any;
        else return false;
        return true;
    }

    static bool readDigest(const Value* value,
                           std::array<std::uint8_t, 32u>& output) {
        std::string text;
        if (!readString(value, text, 64u) || text.size() != 64u) return false;
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

    static bool readChannel(const Value::Object& object,
                            UpdateChannel& output) {
        const Value* value = field(object, "channel");
        if (value == nullptr) return true;
        std::string text;
        if (!readString(value, text, 16u)) return false;
        if (text == "stable") output = UpdateChannel::Stable;
        else if (text == "beta") output = UpdateChannel::Beta;
        else if (text == "nightly") output = UpdateChannel::Nightly;
        else return false;
        return true;
    }

    static bool readArtifacts(const Value::Object& object,
                              std::vector<UpdateArtifact>& output) {
        const Value* value = field(object, "artifacts");
        if (value == nullptr || !value->isArray() ||
            value->asArray().size() > kUpdateMetadataMaxArtifacts)
            return false;
        std::vector<UpdateArtifact> candidate;
        candidate.reserve(value->asArray().size());
        for (const Value& item : value->asArray()) {
            if (!item.isObject()) return false;
            const Value::Object& artifactObject = item.asObject();
            UpdateArtifact artifact;
            std::uint64_t number = 0u;
            if (!readString(field(artifactObject, "package_id"),
                            artifact.packageId, kUpdateMetadataMaxIdBytes) ||
                !readVersion(field(artifactObject, "version"),
                             artifact.version) ||
                !readArchitecture(artifactObject, artifact.architecture) ||
                !readUnsigned(field(artifactObject, "compressed_size"),
                              UINT64_MAX, number))
                return false;
            artifact.compressedSize = number;
            number = 0u;
            if (!readUnsigned(field(artifactObject, "installed_size"),
                              UINT64_MAX, number) ||
                !readDigest(field(artifactObject, "sha256"), artifact.sha256))
                return false;
            artifact.installedSize = number;
            candidate.push_back(std::move(artifact));
        }
        output = std::move(candidate);
        return true;
    }

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, UpdateMetadata& output,
                      std::string& error) {
        UpdateMetadata candidate = {};
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "update metadata size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 8u;
            limits.maxStringBytes = kMaximumStringBytes;
            limits.maxArrayElements = kMaximumArrayElements;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "update metadata object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::string version;
            std::uint64_t number = 0u;
            if (!readString(field(object, "update_id"), candidate.updateId,
                            kUpdateMetadataMaxIdBytes) ||
                !readString(field(object, "product_id"), candidate.productId,
                            kUpdateMetadataMaxIdBytes) ||
                !readString(field(object, "target_version"), version,
                            kPackageMetadataMaxVersionBytes) ||
                !PackageVersion::parse(version, candidate.targetVersion) ||
                !readChannel(object, candidate.channel) ||
                !readString(field(object, "release_notes"),
                            candidate.releaseNotes) ||
                !readArtifacts(object, candidate.artifacts)) {
                error = "update metadata field type";
                return false;
            }
            const Value* minimum = field(object, "minimum_from_version");
            if (minimum != nullptr) {
                candidate.hasMinimumFromVersion = true;
                if (!readVersion(minimum, candidate.minimumFromVersion)) {
                    error = "update metadata version";
                    return false;
                }
            }
            if (field(object, "flags") != nullptr &&
                !readUnsigned(field(object, "flags"),
                              kUpdateMetadataFlagsAll, number)) {
                error = "update metadata flags";
                return false;
            }
            candidate.flags = static_cast<std::uint32_t>(number);
            number = 0u;
            if (!readUnsigned(field(object, "published_at"), UINT64_MAX,
                              number)) {
                error = "update metadata published time";
                return false;
            }
            candidate.publishedAtUnixSeconds = number;
            if (!candidate.valid()) {
                error = "update metadata validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "update metadata JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_UPDATE_METADATA_JSON_HPP */
