/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public application metadata catalog model. */
#ifndef RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP
#define RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
#    include <new>
#endif

#include <rinjson/json.hpp>

#include "application_metadata_catalog.hpp"
#include "application_metadata_json.hpp"

namespace RinRuntime {

/*
 * This parser consumes an untrusted catalog snapshot only.  It does not
 * authenticate a repository, resolve a URL/path, verify a signature, or
 * authorize installation or launch.
 */
class ApplicationMetadataCatalogJson final {
public:
    static constexpr std::size_t kMaximumBytes = 256u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 255u;
    static constexpr std::size_t kMaximumObjectMembers = 16u;
    static constexpr std::size_t kMaximumArrayElements =
        kApplicationMetadataCatalogMaxApplications;
    static constexpr std::size_t kMaximumNodes = 4096u;
    static constexpr std::size_t kMaximumAllocationBytes = 512u * 1024u;

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
    static bool parse(std::string_view input,
                      ApplicationMetadataCatalog& output,
                      std::string& error) {
        ApplicationMetadataCatalog candidate = {};
        if (ApplicationMetadataJson::inputOverlaps(input, error))
            return false;
        for (const ApplicationMetadata& application : output.applications)
            if (ApplicationMetadataJson::inputOverlaps(input, application,
                                                       error))
                return false;
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "application catalog size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 10u;
            limits.maxStringBytes = kMaximumStringBytes;
            limits.maxArrayElements = kMaximumArrayElements;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "application catalog object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t generation = 0u;
            if (!readUnsigned(field(object, "generation"), generation) ||
                generation == 0u) {
                error = "application catalog generation";
                return false;
            }
            const Value* applications = field(object, "applications");
            if (applications == nullptr || !applications->isArray() ||
                applications->asArray().size() >
                    kApplicationMetadataCatalogMaxApplications) {
                error = "application catalog applications";
                return false;
            }
            candidate.generation = generation;
            candidate.applications.reserve(applications->asArray().size());
            for (const Value& value : applications->asArray()) {
                ApplicationMetadata application;
                if (ApplicationMetadataJson::decodeValue(value, application) !=
                        ApplicationMetadataJson::DecodeResult::Success ||
                    !application.valid()) {
                    error = "application catalog metadata";
                    return false;
                }
                candidate.applications.push_back(std::move(application));
            }
            if (!candidate.valid()) {
                error = "application catalog validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            try {
                error = "application catalog JSON: ";
                error += exception.what();
            } catch (...) {
                error.clear();
            }
            return false;
        } catch (const std::bad_alloc&) {
            try {
                error = "application catalog allocation";
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
        std::size_t* sourceSizeOut, ApplicationMetadataCatalog& output,
        std::string& error) {
        std::uint64_t loadedSize = 0u;
        const std::size_t loadCapacity =
            sourceCapacity < kMaximumBytes ? sourceCapacity : kMaximumBytes;
        output = {};
        error.clear();
        if (source != nullptr) {
            const std::size_t bounded =
                sourceCapacity < kMaximumBytes ? sourceCapacity : kMaximumBytes;
            volatile std::uint8_t* bytes = source;
            for (std::size_t index = 0u; index < bounded; ++index)
                bytes[index] = 0u;
        }
        if (sourceSizeOut == nullptr) {
            error = "application catalog resource size";
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
            if (source != nullptr) {
                const std::size_t bounded =
                    sourceCapacity < kMaximumBytes ? sourceCapacity : kMaximumBytes;
                volatile std::uint8_t* bytes = source;
                for (std::size_t index = 0u; index < bounded; ++index)
                    bytes[index] = 0u;
            }
            error = "application catalog resource";
            return false;
        }
        if (!parse(std::string_view(reinterpret_cast<const char*>(source),
                                    static_cast<std::size_t>(loadedSize)),
                    output, error)) {
            output = {};
            if (source != nullptr) {
                const std::size_t bounded =
                    sourceCapacity < kMaximumBytes ? sourceCapacity : kMaximumBytes;
                volatile std::uint8_t* bytes = source;
                for (std::size_t index = 0u; index < bounded; ++index)
                    bytes[index] = 0u;
            }
            return false;
        }
        *sourceSizeOut = static_cast<std::size_t>(loadedSize);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP */
