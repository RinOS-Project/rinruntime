/* SPDX-License-Identifier: MIT */
#include <cassert>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "../include/rinruntime/theme_json.hpp"

static std::string validJson() {
    std::string json =
        "{\"theme_id\":8,\"flags\":1,\"colors\":[";
    for (std::size_t index = 0u; index < RinRuntime::kThemeColorCount;
         ++index) {
        if (index != 0u) json += ',';
        json += std::to_string(0xff000000u + index);
    }
    json += "]}";
    return json;
}

static RinResourceCatalogStatus readThemePath(
    void* context, const char* path, std::uint32_t pathSize, std::uint8_t* output,
    std::uint64_t capacity, std::uint64_t* outputSize) {
    const std::string json = validJson();
    if (context != nullptr) {
        if (*static_cast<std::uint64_t*>(context) == UINT64_MAX)
            throw std::runtime_error("theme callback failed");
        *static_cast<std::uint64_t*>(context) = capacity;
    }
    assert(path != nullptr && pathSize == 15u &&
           std::string(path, pathSize) == "/res/theme.json");
    if (output == nullptr || outputSize == nullptr ||
        capacity < json.size())
        return RIN_RESOURCE_CATALOG_BUFFER_TOO_SMALL;
    std::memcpy(output, json.data(), json.size());
    *outputSize = json.size();
    return RIN_RESOURCE_CATALOG_OK;
}

int main() {
    RinRuntime::ThemeProfile profile;
    std::string error;
    assert(RinRuntime::ThemeProfileJson::parse(validJson(), profile, error));
    assert(error.empty());
    assert(profile.valid());
    assert(profile.dark());
    assert(profile.color(RinRuntime::ThemeColor::Selected) == 0xff000013u);

    assert(!RinRuntime::ThemeProfileJson::parse(
        "{\"theme_id\":8,\"colors\":[0]}", profile, error));
    assert(!profile.valid());
    assert(!error.empty());

    std::string malformed = validJson();
    malformed.insert(1u, "\"theme_id\":8,");
    assert(!RinRuntime::ThemeProfileJson::parse(malformed, profile, error));
    assert(!profile.valid());

    error = validJson();
    const std::string aliasedError = error;
    assert(!RinRuntime::ThemeProfileJson::parse(error, profile, error));
    assert(error == aliasedError);

    const std::string resourceJson = validJson();
    RinResourceCatalogEntryV1 entry = {};
    entry.struct_size = sizeof(entry);
    entry.version = RIN_RESOURCE_CATALOG_VERSION_1;
    entry.type = RIN_RESOURCE_CATALOG_TYPE_THEME;
    entry.resource_id = 7u;
    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_BLOB |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.data = reinterpret_cast<const std::uint8_t*>(resourceJson.data());
    entry.data_size = resourceJson.size();
    RinResourceCatalogV1 catalog = {};
    catalog.struct_size = sizeof(catalog);
    catalog.version = RIN_RESOURCE_CATALOG_VERSION_1;
    catalog.entries = &entry;
    catalog.entry_count = 1u;
    catalog.generation = 1u;
    std::vector<std::uint8_t> source(
        RinRuntime::ThemeProfileJson::kMaximumBytes + 1u);
    std::size_t loaded = 0u;
    profile.id = 42u;
    error = "stale theme error";
    assert(!RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, nullptr, nullptr, nullptr, 0u, &loaded, profile,
        error));
    assert(error == "theme resource buffer" && loaded == 0u &&
           !profile.valid());
    assert(RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, nullptr, nullptr, source.data(), source.size(), &loaded,
        profile, error));
    assert(loaded == resourceJson.size());
    assert(profile.valid());

    error = resourceJson;
    const std::string aliasedResourceError = error;
    loaded = 777u;
    assert(!RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, nullptr, nullptr,
        reinterpret_cast<std::uint8_t*>(error.data()), error.capacity(),
        &loaded, profile, error));
    assert(error == aliasedResourceError && loaded == 777u);

    const char path[] = "/res/theme.json";
    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_PATH |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.path = path;
    entry.path_size = sizeof(path) - 1u;
    entry.data = nullptr;
    entry.data_size = 0u;
    loaded = 0u;
    std::uint64_t observedCapacity = 0u;
    assert(RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, readThemePath, &observedCapacity, source.data(),
        source.size(), &loaded, profile, error));
    assert(loaded == resourceJson.size());
    assert(observedCapacity == RinRuntime::ThemeProfileJson::kMaximumBytes);
    assert(profile.valid());

    observedCapacity = UINT64_MAX;
    std::fill(source.begin(), source.end(), 0xa5u);
    loaded = SIZE_MAX;
    profile = {};
    assert(!RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, readThemePath, &observedCapacity, source.data(),
        source.size(), &loaded, profile, error));
    assert(error == "theme resource" && loaded == 0u && !profile.valid());
    for (std::size_t index = 0u;
         index < RinRuntime::ThemeProfileJson::kMaximumBytes; ++index)
        assert(source[index] == 0u);

    const std::string malformedResource = "{\"theme_id\":7}";
    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_BLOB |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.data = reinterpret_cast<const std::uint8_t*>(
        malformedResource.data());
    entry.data_size = malformedResource.size();
    std::fill(source.begin(), source.end(), 0xa5u);
    loaded = 123u;
    assert(!RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 7u, nullptr, nullptr, source.data(), source.size(), &loaded,
        profile, error));
    assert(loaded == 0u && !profile.valid());
    for (std::size_t index = 0u;
         index < RinRuntime::ThemeProfileJson::kMaximumBytes; ++index)
        assert(source[index] == 0u);

    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_PATH |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.data = nullptr;
    entry.data_size = 0u;
    loaded = 123u;
    assert(!RinRuntime::ThemeProfileJson::parseResource(
        &catalog, 8u, nullptr, nullptr, source.data(), source.size(), &loaded,
        profile, error));
    assert(loaded == 0u);
    assert(!profile.valid());
    return 0;
}
