/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>

#include "../include/rinruntime/application_metadata_json.hpp"

namespace {

struct ResourcePath {
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0u;
    unsigned calls = 0u;
};

RinResourceCatalogStatus readResourcePath(
    void* context, const char* path, std::uint32_t pathSize,
    std::uint8_t* output, std::uint64_t outputCapacity,
    std::uint64_t* outputSize) {
    auto* resource = static_cast<ResourcePath*>(context);
    if (resource == nullptr || path == nullptr || outputSize == nullptr ||
        pathSize != 29u || std::memcmp(path, "/apps/editor/application.json",
                                       pathSize) != 0)
        return RIN_RESOURCE_CATALOG_INVALID_ARGUMENT;
    ++resource->calls;
    if (output == nullptr || outputCapacity < resource->size)
        return RIN_RESOURCE_CATALOG_BUFFER_TOO_SMALL;
    std::memcpy(output, resource->bytes, resource->size);
    *outputSize = resource->size;
    return RIN_RESOURCE_CATALOG_OK;
}

} // namespace

int main() {
    RinRuntime::ApplicationMetadata output;
    std::string error;
    const std::string valid =
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":\"Rin Editor\","
        "\"entry_point\":\"bin/editor.rin\","
        "\"icon_id\":\"editor\",\"description\":\"Text editor\","
        "\"categories\":[\"development\",\"utility\"],"
        "\"mime_types\":[\"text/plain\"],\"gui\":true}";
    assert(RinRuntime::ApplicationMetadataJson::parse(valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.applicationId == "com.rinos.editor");
    assert(output.entryPoint == "bin/editor.rin");
    assert(output.gui);

    assert(!RinRuntime::ApplicationMetadataJson::parse(
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":\"Broken\","
        "\"entry_point\":\"../escape.rin\"}", output, error));
    assert(error == "metadata validation");
    assert(output.applicationId.empty());

    assert(!RinRuntime::ApplicationMetadataJson::parse(
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":7,\"entry_point\":\"bin/editor.rin\"}",
        output, error));
    assert(error == "metadata field type");

    const std::string resourceJson =
        "{\"application_id\":\"com.rinos.notes\","
        "\"display_name\":\"Rin Notes\","
        "\"entry_point\":\"bin/notes.rin\"}";
    std::uint8_t source[512] = {};
    std::uint8_t tooSmall[8] = {};
    ResourcePath resourcePath{
        reinterpret_cast<const std::uint8_t*>(resourceJson.data()),
        resourceJson.size(), 0u};
    RinResourceCatalogEntryV1 entry = {};
    entry.struct_size = sizeof(entry);
    entry.version = RIN_RESOURCE_CATALOG_VERSION_1;
    entry.type = RIN_RESOURCE_CATALOG_TYPE_APPLICATION;
    entry.resource_id = 7u;
    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_PATH |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.path = "/apps/editor/application.json";
    entry.path_size = 29u;
    RinResourceCatalogV1 catalog = {};
    catalog.struct_size = sizeof(catalog);
    catalog.version = RIN_RESOURCE_CATALOG_VERSION_1;
    catalog.entries = &entry;
    catalog.entry_count = 1u;
    catalog.generation = 1u;
    std::size_t sourceSize = SIZE_MAX;
    assert(RinRuntime::ApplicationMetadataJson::parseResource(
        &catalog, 7u, readResourcePath, &resourcePath, source,
        sizeof(source), &sourceSize, output, error));
    assert(sourceSize == resourceJson.size() && resourcePath.calls == 1u);
    assert(output.applicationId == "com.rinos.notes");

    sourceSize = SIZE_MAX;
    output.applicationId = "stale";
    assert(!RinRuntime::ApplicationMetadataJson::parseResource(
        &catalog, 7u, readResourcePath, &resourcePath, tooSmall,
        sizeof(tooSmall), &sourceSize, output, error));
    assert(sourceSize == 0u && output.applicationId.empty());
    return 0;
}
