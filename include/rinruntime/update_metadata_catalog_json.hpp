/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public update metadata catalog model. */
#ifndef RINRUNTIME_UPDATE_METADATA_CATALOG_JSON_HPP
#define RINRUNTIME_UPDATE_METADATA_CATALOG_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <rinjson/json.hpp>

#include "update_metadata_catalog.hpp"
#include "update_metadata_json.hpp"

namespace RinRuntime {

/* Repository authentication, signatures, transport, staging, and install
 * authority are deliberately outside this snapshot parser. */
class UpdateMetadataCatalogJson final {
public:
    static constexpr std::size_t kMaximumBytes = 2u * 1024u * 1024u;
    static constexpr std::size_t kMaximumStringBytes = 1023u;
    static constexpr std::size_t kMaximumObjectMembers = 16u;
    static constexpr std::size_t kMaximumArrayElements =
        kUpdateMetadataCatalogMaxUpdates;
    static constexpr std::size_t kMaximumNodes = 8192u;
    static constexpr std::size_t kMaximumAllocationBytes = 4u * 1024u * 1024u;

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
    static bool parse(std::string_view input, UpdateMetadataCatalog& output,
                      std::string& error) {
        UpdateMetadataCatalog candidate = {};
        error.clear();
        output = {};
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "update catalog size";
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
                error = "update catalog object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t generation = 0u;
            if (!readUnsigned(field(object, "generation"), generation) ||
                generation == 0u) {
                error = "update catalog generation";
                return false;
            }
            const Value* updates = field(object, "updates");
            if (updates == nullptr || !updates->isArray() ||
                updates->asArray().size() > kUpdateMetadataCatalogMaxUpdates) {
                error = "update catalog updates";
                return false;
            }
            candidate.generation = generation;
            candidate.updates.reserve(updates->asArray().size());
            for (const Value& value : updates->asArray()) {
                UpdateMetadata update;
                if (UpdateMetadataJson::decodeValue(value, update) !=
                        UpdateMetadataJson::DecodeResult::Success) {
                    error = "update catalog metadata";
                    return false;
                }
                candidate.updates.push_back(std::move(update));
            }
            if (!candidate.valid()) {
                error = "update catalog validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "update catalog JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_UPDATE_METADATA_CATALOG_JSON_HPP */
