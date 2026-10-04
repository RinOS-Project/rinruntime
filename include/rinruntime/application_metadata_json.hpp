/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public application metadata model. */
#ifndef RINRUNTIME_APPLICATION_METADATA_JSON_HPP
#define RINRUNTIME_APPLICATION_METADATA_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
#    include <new>
#endif

#include <rinjson/json.hpp>

#include "../../../rinresource/include/rinresource/loader.h"
#include "application_metadata.hpp"

namespace RinRuntime {

class ApplicationMetadataCatalogJson;

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

    static void clearSource(std::uint8_t* source, std::size_t capacity) {
        if (source == nullptr) return;
        const std::size_t bounded =
            capacity < kMaximumBytes ? capacity : kMaximumBytes;
        volatile std::uint8_t* bytes = source;
        for (std::size_t index = 0u; index < bounded; ++index)
            bytes[index] = 0u;
    }

    enum class DecodeResult {
        Success,
        FieldType,
        GuiType,
    };

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

    static bool inputOverlaps(std::string_view input,
                              const std::string& value) {
        if (input.empty() || value.empty()) return false;
        const std::uintptr_t inputBegin =
            reinterpret_cast<std::uintptr_t>(input.data());
        const std::uintptr_t valueBegin =
            reinterpret_cast<std::uintptr_t>(value.data());
        const std::uintptr_t maximum =
            std::numeric_limits<std::uintptr_t>::max();
        if (inputBegin > maximum - input.size() ||
            valueBegin > maximum - value.capacity())
            return true;
        return inputBegin < valueBegin + value.capacity() &&
               valueBegin < inputBegin + input.size();
    }

    static bool inputOverlaps(std::string_view input,
                              const ApplicationMetadata& metadata,
                              const std::string& error) {
        if (inputOverlaps(input, error) ||
            inputOverlaps(input, metadata.applicationId) ||
            inputOverlaps(input, metadata.displayName) ||
            inputOverlaps(input, metadata.entryPoint) ||
            inputOverlaps(input, metadata.iconId) ||
            inputOverlaps(input, metadata.description))
            return true;
        for (const std::string& value : metadata.categories)
            if (inputOverlaps(input, value)) return true;
        for (const std::string& value : metadata.mimeTypes)
            if (inputOverlaps(input, value)) return true;
        return false;
    }

    static DecodeResult decodeValue(const Value& value,
                                    ApplicationMetadata& output) {
        if (!value.isObject()) return DecodeResult::FieldType;
        const Value::Object& object = value.asObject();
        ApplicationMetadata candidate = {};
        if (!readString(field(object, "application_id"),
                        candidate.applicationId) ||
            !readString(field(object, "display_name"),
                        candidate.displayName) ||
            !readString(field(object, "entry_point"),
                        candidate.entryPoint) ||
            !optionalString(object, "icon_id", candidate.iconId) ||
            !optionalString(object, "description", candidate.description) ||
            !readStringArray(object, "categories", candidate.categories) ||
            !readStringArray(object, "mime_types", candidate.mimeTypes))
            return DecodeResult::FieldType;
        const Value* gui = field(object, "gui");
        if (gui != nullptr && !readBool(gui, candidate.gui))
            return DecodeResult::GuiType;
        output = std::move(candidate);
        return DecodeResult::Success;
    }

    friend class ApplicationMetadataCatalogJson;

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, ApplicationMetadata& output,
                      std::string& error) {
        ApplicationMetadata candidate = {};
        if (inputOverlaps(input, output, error)) return false;
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
            const DecodeResult decodeResult = decodeValue(document, candidate);
            if (decodeResult == DecodeResult::FieldType) {
                error = "metadata field type";
                return false;
            }
            if (decodeResult == DecodeResult::GuiType) {
                error = "metadata gui";
                return false;
            }
            if (!candidate.valid()) {
                error = "metadata validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            try {
                error = "metadata JSON: ";
                error += exception.what();
            } catch (...) {
                error.clear();
            }
            return false;
        } catch (const std::bad_alloc&) {
            try {
                error = "metadata allocation";
            } catch (...) {
                error.clear();
            }
            return false;
        } catch (...) {
            error.clear();
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
        const std::size_t loadCapacity =
            sourceCapacity < kMaximumBytes ? sourceCapacity : kMaximumBytes;
        output = {};
        error.clear();
        clearSource(source, sourceCapacity);
        if (sourceSizeOut == nullptr) {
            error = "metadata resource size";
            return false;
        }
        *sourceSizeOut = 0u;
        const RinResourceCatalogStatus resourceStatus =
            rin_resource_catalog_load(
                catalog, RIN_RESOURCE_CATALOG_TYPE_APPLICATION, resourceId,
                readPath, context, source,
                static_cast<std::uint64_t>(loadCapacity), &loadedSize);
        if (resourceStatus != RIN_RESOURCE_CATALOG_OK || loadedSize == 0u ||
            loadedSize > static_cast<std::uint64_t>(SIZE_MAX)) {
            clearSource(source, sourceCapacity);
            error = "metadata resource";
            return false;
        }
        if (!parse(std::string_view(reinterpret_cast<const char*>(source),
                                    static_cast<std::size_t>(loadedSize)),
                   output, error)) {
            output = {};
            clearSource(source, sourceCapacity);
            return false;
        }
        *sourceSizeOut = static_cast<std::size_t>(loadedSize);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_JSON_HPP */
