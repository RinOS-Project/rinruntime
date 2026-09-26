/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public application metadata catalog model. */
#ifndef RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP
#define RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

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
            error = "application catalog JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_CATALOG_JSON_HPP */
