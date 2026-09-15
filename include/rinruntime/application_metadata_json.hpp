/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public application metadata model. */
#ifndef RINRUNTIME_APPLICATION_METADATA_JSON_HPP
#define RINRUNTIME_APPLICATION_METADATA_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rinjson/json.hpp>

#include "../../../rinresource/include/rinresource/loader.h"
#include "application_metadata.hpp"

namespace RinRuntime {

/* This adapter decodes only a descriptor. Path, image, signature, and
 * installed-application authority remain private product owners. */
class ApplicationMetadataJson final {
public:
    static constexpr std::size_t kMaximumBytes = 16u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 255u;
    static constexpr std::size_t kMaximumObjectMembers = 16u;
    static constexpr std::size_t kMaximumNodes = 128u;
    static constexpr std::size_t kMaximumAllocationBytes = 64u * 1024u;

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

    static bool readBool(const Value* value, bool& output) {
        if (value == nullptr || !value->isBool()) return false;
        output = value->asBool();
        return true;
    }

    static bool readStringArray(const Value::Object& object,
                                std::string_view name,
                                std::vector<std::string>& output) {
        const Value* value = field(object, name);
        if (value == nullptr) return true;
        if (!value->isArray() ||
            value->asArray().size() > kApplicationMetadataMaxTags)
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

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, ApplicationMetadata& output,
                      std::string& error) {
        ApplicationMetadata candidate = {};
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "metadata size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 8u;
            limits.maxStringBytes = kMaximumStringBytes;
            limits.maxArrayElements = kApplicationMetadataMaxTags;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "metadata object";
                return false;
            }
            const Value::Object& object = document.asObject();
            if (!readString(field(object, "application_id"),
                            candidate.applicationId) ||
                !readString(field(object, "display_name"),
                            candidate.displayName) ||
                !readString(field(object, "entry_point"),
                            candidate.entryPoint) ||
                !optionalString(object, "icon_id", candidate.iconId) ||
                !optionalString(object, "description", candidate.description) ||
                !readStringArray(object, "categories", candidate.categories) ||
                !readStringArray(object, "mime_types", candidate.mimeTypes)) {
                error = "metadata field type";
                return false;
            }
            const Value* gui = field(object, "gui");
            if (gui != nullptr && !readBool(gui, candidate.gui)) {
                error = "metadata gui";
                return false;
            }
            if (!candidate.valid()) {
                error = "metadata validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "metadata JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }

    /* Resolve one public TYPE_APPLICATION resource into caller-owned storage
     * before parsing it.  The callback remains the filesystem/service owner;
     * this helper performs no allocation or path access of its own. */
    static bool parseResource(
        const RinResourceCatalogV1* catalog, std::uint32_t resourceId,
        RinResourceCatalogReadPathFunction readPath, void* context,
        std::uint8_t* source, std::size_t sourceCapacity,
        std::size_t* sourceSizeOut, ApplicationMetadata& output,
        std::string& error) {
        std::uint64_t loadedSize = 0u;
        output = {};
        error.clear();
        if (sourceSizeOut == nullptr) {
            error = "metadata resource size";
            return false;
        }
        *sourceSizeOut = 0u;
        const RinResourceCatalogStatus resourceStatus =
            rin_resource_catalog_load(
                catalog, RIN_RESOURCE_CATALOG_TYPE_APPLICATION, resourceId,
                readPath, context, source,
                static_cast<std::uint64_t>(sourceCapacity), &loadedSize);
        if (resourceStatus != RIN_RESOURCE_CATALOG_OK || loadedSize == 0u ||
            loadedSize > static_cast<std::uint64_t>(SIZE_MAX)) {
            error = "metadata resource";
            return false;
        }
        if (!parse(std::string_view(reinterpret_cast<const char*>(source),
                                    static_cast<std::size_t>(loadedSize)),
                   output, error)) {
            output = {};
            return false;
        }
        *sourceSizeOut = static_cast<std::size_t>(loadedSize);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_JSON_HPP */
