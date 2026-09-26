/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public package metadata catalog model. */
#ifndef RINRUNTIME_PACKAGE_METADATA_CATALOG_JSON_HPP
#define RINRUNTIME_PACKAGE_METADATA_CATALOG_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <rinjson/json.hpp>

#include "package_metadata_catalog.hpp"
#include "package_metadata_json.hpp"

namespace RinRuntime {

/*
 * This parser accepts an untrusted snapshot only.  It does not authenticate
 * a repository, verify publisher signatures, select an artifact, or grant
 * install/launch authority.
 */
class PackageMetadataCatalogJson final {
public:
    static constexpr std::size_t kMaximumBytes = 4u * 1024u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 255u;
    static constexpr std::size_t kMaximumObjectMembers = 32u;
    static constexpr std::size_t kMaximumArrayElements =
        kPackageMetadataCatalogMaxPackages;
    static constexpr std::size_t kMaximumNodes = 16384u;
    static constexpr std::size_t kMaximumAllocationBytes = 8u * 1024u * 1024u;

private:
    using Value = rinjson::Value;

    static const Value* field(const Value::Object& object,
                              std::string_view name) {
        const auto found = object.find(name);
        return found == object.end() ? nullptr : &found->second;
    }

    static bool readUnsigned(const Value* value, std::uint64_t& output) {
        if (value == nullptr || !value->isInteger()) return false;
        if (value->isSignedInteger()) {
            const std::int64_t parsed = value->asInteger();
            if (parsed < 0) return false;
            output = static_cast<std::uint64_t>(parsed);
        } else {
            output = value->asUnsignedInteger();
        }
        return true;
    }

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, PackageMetadataCatalog& output,
                      std::string& error) {
        PackageMetadataCatalog candidate = {};
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "package catalog size";
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
                error = "package catalog object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t generation = 0u;
            if (!readUnsigned(field(object, "generation"), generation) ||
                generation == 0u) {
                error = "package catalog generation";
                return false;
            }
            const Value* packages = field(object, "packages");
            if (packages == nullptr || !packages->isArray() ||
                packages->asArray().size() > kPackageMetadataCatalogMaxPackages) {
                error = "package catalog packages";
                return false;
            }
            candidate.generation = generation;
            candidate.packages.reserve(packages->asArray().size());
            for (const Value& value : packages->asArray()) {
                PackageMetadata package;
                if (PackageMetadataJson::decodeValue(value, package) !=
                        PackageMetadataJson::DecodeResult::Success) {
                    error = "package catalog metadata";
                    return false;
                }
                candidate.packages.push_back(std::move(package));
            }
            if (!candidate.valid()) {
                error = "package catalog validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "package catalog JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PACKAGE_METADATA_CATALOG_JSON_HPP */
