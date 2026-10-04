/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "../include/rinruntime/application_metadata_catalog_json.hpp"

struct PathSource {
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0u;
    std::uint32_t calls = 0u;
    bool fail = false;
};

static RinResourceCatalogStatus readCatalogPath(
    void* context, const char* path, std::uint32_t pathSize,
    std::uint8_t* output, std::uint64_t outputCapacity,
    std::uint64_t* outputSize)
{
    auto* source = static_cast<PathSource*>(context);
    assert(source != nullptr && path != nullptr && outputSize != nullptr);
    assert(pathSize == 26u &&
           std::memcmp(path, "/applications/catalog.json", pathSize) == 0);
    ++source->calls;
    *outputSize = 0u;
    if (source->fail) return RIN_RESOURCE_CATALOG_IO_ERROR;
    if (source->bytes == nullptr || source->size > outputCapacity ||
        (source->size != 0u && output == nullptr))
        return RIN_RESOURCE_CATALOG_BUFFER_TOO_SMALL;
    std::memcpy(output, source->bytes, source->size);
    *outputSize = source->size;
    return RIN_RESOURCE_CATALOG_OK;
}

int main()
{
    RinRuntime::ApplicationMetadataCatalog output;
    std::string error;
    const std::string valid = R"json({
        "generation":7,
        "applications":[
            {"application_id":"com.rinos.editor",
             "display_name":"Rin Editor","entry_point":"bin/editor.rin",
             "categories":["development"],"mime_types":["text/plain"]},
            {"application_id":"com.rinos.notes",
             "display_name":"Rin Notes","entry_point":"bin/notes.rin",
             "gui":true}
        ]
    })json";

    assert(RinRuntime::ApplicationMetadataCatalogJson::parse(
        valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.generation == 7u);
    assert(output.applications.size() == 2u);
    assert(output.find("com.rinos.notes") != nullptr);
    assert(output.find("com.rinos.missing") == nullptr);

    output.applications[0].applicationId = valid;
    error = "preserve catalog alias";
    const std::string catalogAliasBefore = output.applications[0].applicationId;
    const std::string catalogErrorBefore = error;
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parse(
        std::string_view(output.applications[0].applicationId), output, error));
    assert(output.applications[0].applicationId == catalogAliasBefore &&
           error == catalogErrorBefore);

    output.generation = 99u;
    output.applications.clear();
    error = "stale";
    const std::string unsorted = R"json({
        "generation":8,
        "applications":[
            {"application_id":"com.rinos.notes",
             "display_name":"Rin Notes","entry_point":"bin/notes.rin"},
            {"application_id":"com.rinos.editor",
             "display_name":"Rin Editor","entry_point":"bin/editor.rin"}
        ]
    })json";
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parse(
        unsorted, output, error));
    assert(error == "application catalog validation");
    assert(output.generation == 0u && output.applications.empty());

    error = "stale";
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parse(
        "{\"generation\":0,\"applications\":[]}", output, error));
    assert(error == "application catalog generation");
    assert(output.generation == 0u && output.applications.empty());

    const std::string resourceJson = R"json({
        "generation":9,
        "applications":[
            {"application_id":"com.rinos.notes",
             "display_name":"Rin Notes","entry_point":"bin/notes.rin"}
        ]
    })json";
    RinResourceCatalogEntryV1 entry = {};
    entry.struct_size = sizeof(entry);
    entry.version = RIN_RESOURCE_CATALOG_VERSION_1;
    entry.type = RIN_RESOURCE_CATALOG_TYPE_APPLICATION;
    entry.resource_id = 7u;
    entry.flags = RIN_RESOURCE_CATALOG_SOURCE_BLOB |
                  RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    entry.data = reinterpret_cast<const std::uint8_t*>(resourceJson.data());
    entry.data_size = resourceJson.size();
    RinResourceCatalogV1 resourceCatalog = {};
    resourceCatalog.struct_size = sizeof(resourceCatalog);
    resourceCatalog.version = RIN_RESOURCE_CATALOG_VERSION_1;
    resourceCatalog.entries = &entry;
    resourceCatalog.entry_count = 1u;
    resourceCatalog.generation = 1u;
    std::vector<std::uint8_t> source(
        RinRuntime::ApplicationMetadataCatalogJson::kMaximumBytes);
    std::size_t sourceSize = 0u;
    assert(RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, nullptr, nullptr, source.data(), source.size(),
        &sourceSize, output, error));
    assert(sourceSize == resourceJson.size());
    assert(output.generation == 9u && output.find("com.rinos.notes") != nullptr);

    error = resourceJson;
    const std::string aliasedResourceError = error;
    sourceSize = 777u;
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, nullptr, nullptr,
        reinterpret_cast<std::uint8_t*>(error.data()), error.capacity(),
        &sourceSize, output, error));
    assert(error == aliasedResourceError && sourceSize == 777u);

    RinResourceCatalogEntryV1 pathEntry = entry;
    pathEntry.flags = RIN_RESOURCE_CATALOG_SOURCE_PATH |
                      RIN_RESOURCE_CATALOG_FLAG_IMMUTABLE;
    pathEntry.path = "/applications/catalog.json";
    pathEntry.path_size = 26u;
    pathEntry.data = nullptr;
    pathEntry.data_size = 0u;
    resourceCatalog.entries = &pathEntry;
    PathSource pathSource = {
        reinterpret_cast<const std::uint8_t*>(resourceJson.data()),
        resourceJson.size(), 0u, false};
    std::fill(source.begin(), source.end(), 0xa5u);
    sourceSize = 0u;
    assert(RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, readCatalogPath, &pathSource, source.data(),
        source.size(), &sourceSize, output, error));
    assert(pathSource.calls == 1u && sourceSize == resourceJson.size());
    assert(output.generation == 9u && output.find("com.rinos.notes") != nullptr);

    pathSource.fail = true;
    std::fill(source.begin(), source.end(), 0xa5u);
    sourceSize = SIZE_MAX;
    output.generation = 99u;
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, readCatalogPath, &pathSource, source.data(),
        source.size(), &sourceSize, output, error));
    assert(pathSource.calls == 2u && sourceSize == 0u &&
           output.generation == 0u && output.applications.empty());
    for (std::uint8_t byte : source) assert(byte == 0u);

    pathSource.fail = false;
    std::vector<std::uint8_t> tooSmall(resourceJson.size() - 1u, 0xa5u);
    sourceSize = SIZE_MAX;
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, readCatalogPath, &pathSource, tooSmall.data(),
        tooSmall.size(), &sourceSize, output, error));
    assert(pathSource.calls == 3u && sourceSize == 0u &&
           output.generation == 0u && output.applications.empty());
    for (std::uint8_t byte : tooSmall) assert(byte == 0u);

    resourceCatalog.entries = &entry;

    const std::string malformedResource =
        R"json({"generation":10,"applications":[{"application_id":7}]})json";
    entry.data = reinterpret_cast<const std::uint8_t*>(
        malformedResource.data());
    entry.data_size = malformedResource.size();
    std::fill(source.begin(), source.end(), 0xa5u);
    sourceSize = SIZE_MAX;
    output.generation = 99u;
    assert(!RinRuntime::ApplicationMetadataCatalogJson::parseResource(
        &resourceCatalog, 7u, nullptr, nullptr, source.data(), source.size(),
        &sourceSize, output, error));
    assert(sourceSize == 0u && output.generation == 0u &&
           output.applications.empty());
    for (std::uint8_t byte : source) assert(byte == 0u);
    return 0;
}
