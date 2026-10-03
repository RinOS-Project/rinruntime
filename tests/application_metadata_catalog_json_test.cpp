/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "../include/rinruntime/application_metadata_catalog_json.hpp"

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
