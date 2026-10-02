/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/package_metadata_catalog_json.hpp"

int main()
{
    RinRuntime::PackageMetadataCatalog output;
    std::string error;
    const std::string valid = R"json({
        "generation":11,
        "packages":[
            {"package_id":"com.rinos.editor",
             "display_name":"Rin Editor","version":"1.2.0",
             "architecture":"any","class":"application",
             "license":"MIT"},
            {"package_id":"com.rinos.notes",
             "display_name":"Rin Notes","version":"2",
             "license":"MIT"}
        ]
    })json";

    assert(RinRuntime::PackageMetadataCatalogJson::parse(
        valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.generation == 11u);
    assert(output.packages.size() == 2u);
    assert(output.find("com.rinos.notes") != nullptr);
    assert(output.find("com.rinos.missing") == nullptr);

    output.generation = 99u;
    output.packages.clear();
    error = "stale";
    const std::string unsorted = R"json({
        "generation":12,
        "packages":[
            {"package_id":"com.rinos.notes",
             "display_name":"Rin Notes","version":"2","license":"MIT"},
            {"package_id":"com.rinos.editor",
             "display_name":"Rin Editor","version":"1.2.0","license":"MIT"}
        ]
    })json";
    assert(!RinRuntime::PackageMetadataCatalogJson::parse(
        unsorted, output, error));
    assert(error == "package catalog validation");
    assert(output.generation == 0u && output.packages.empty());

    error = "stale";
    assert(!RinRuntime::PackageMetadataCatalogJson::parse(
        "{\"generation\":0,\"packages\":[]}", output, error));
    assert(error == "package catalog generation");
    assert(output.generation == 0u && output.packages.empty());
    return 0;
}
