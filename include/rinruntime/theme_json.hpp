/* SPDX-License-Identifier: MIT */
/* Bounded JSON/resource adapter for the public theme profile model. */
#ifndef RINRUNTIME_THEME_JSON_HPP
#define RINRUNTIME_THEME_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include <rinjson/json.hpp>

#include "../../../rinresource/include/rinresource/loader.h"
#include "theme.hpp"

namespace RinRuntime {

class ThemeProfileJson final {
public:
    static constexpr std::size_t kMaximumBytes = 16u * 1024u;
    static constexpr std::size_t kMaximumObjectMembers = 8u;
    static constexpr std::size_t kMaximumArrayElements = kThemeColorCount;
    static constexpr std::size_t kMaximumNodes = 64u;
    static constexpr std::size_t kMaximumAllocationBytes = 32u * 1024u;

private:
    using Value = rinjson::Value;

    static const Value* field(const Value::Object& object,
                              std::string_view name) {
        const auto found = object.find(name);
        return found == object.end() ? nullptr : &found->second;
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

    static bool readColors(const Value* value,
                           std::array<std::uint32_t, kThemeColorCount>& output) {
        if (value == nullptr || !value->isArray() ||
            value->asArray().size() != kThemeColorCount)
            return false;
        std::array<std::uint32_t, kThemeColorCount> candidate = {};
        for (std::size_t index = 0u; index < kThemeColorCount; ++index) {
            std::uint64_t color = 0u;
            if (!readUnsigned(&value->asArray()[index], UINT32_MAX, color))
                return false;
            candidate[index] = static_cast<std::uint32_t>(color);
        }
        output = candidate;
        return true;
    }

public:
    /* output is cleared before parsing and remains invalid on every failure. */
    static bool parse(std::string_view input, ThemeProfile& output,
                      std::string& error) {
        ThemeProfile candidate = {};
        output = {};
        error.clear();
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "theme JSON size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 4u;
            limits.maxStringBytes = 64u;
            limits.maxArrayElements = kMaximumArrayElements;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "theme JSON object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t number = 0u;
            if (!readUnsigned(field(object, "theme_id"), UINT32_MAX, number)) {
                error = "theme JSON id";
                return false;
            }
            candidate.id = static_cast<std::uint32_t>(number);
            number = 0u;
            const Value* flags = field(object, "flags");
            if (flags != nullptr && !readUnsigned(flags, UINT32_MAX, number)) {
                error = "theme JSON flags";
                return false;
            }
            candidate.flags = static_cast<std::uint32_t>(number);
            if (!readColors(field(object, "colors"), candidate.colors)) {
                error = "theme JSON colors";
                return false;
            }
            if (!candidate.valid()) {
                error = "theme JSON validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "theme JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = candidate;
        return true;
    }

    /* Resolve one public TYPE_THEME resource into caller-owned storage before
     * parsing. The callback remains the filesystem/service owner. */
    static bool parseResource(
        const RinResourceCatalogV1* catalog, std::uint32_t resourceId,
        RinResourceCatalogReadPathFunction readPath, void* context,
        std::uint8_t* source, std::size_t sourceCapacity,
        std::size_t* sourceSizeOut, ThemeProfile& output,
        std::string& error) {
        std::uint64_t loadedSize = 0u;
        output = {};
        error.clear();
        if (sourceSizeOut == nullptr) {
            error = "theme resource size";
            return false;
        }
        *sourceSizeOut = 0u;
        const RinResourceCatalogStatus resourceStatus =
            rin_resource_catalog_load(
                catalog, RIN_RESOURCE_CATALOG_TYPE_THEME, resourceId,
                readPath, context, source,
                static_cast<std::uint64_t>(sourceCapacity), &loadedSize);
        if (resourceStatus != RIN_RESOURCE_CATALOG_OK || loadedSize == 0u ||
            loadedSize > static_cast<std::uint64_t>(SIZE_MAX)) {
            error = "theme resource";
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

#endif /* RINRUNTIME_THEME_JSON_HPP */
