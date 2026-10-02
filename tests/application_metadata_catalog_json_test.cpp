/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

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
    return 0;
}
