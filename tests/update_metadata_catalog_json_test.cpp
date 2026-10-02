/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/update_metadata_catalog_json.hpp"

int main()
{
    RinRuntime::UpdateMetadataCatalog output;
    std::string error;
    const std::string valid = R"json({
        "generation":23,
        "updates":[
            {"update_id":"org.rinos.viewer-1.2.0",
             "product_id":"org.rinos.viewer","target_version":"1.2.0",
             "channel":"stable","published_at":1770000000,
             "release_notes":"Security maintenance release",
             "artifacts":[{"package_id":"org.rinos.viewer",
                 "version":"1.2.0","architecture":"any",
                 "compressed_size":4096,"installed_size":8192,
                 "sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}]}
        ]
    })json";

    assert(RinRuntime::UpdateMetadataCatalogJson::parse(
        valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.generation == 23u);
    assert(output.updates.size() == 1u);
    assert(output.find("org.rinos.viewer-1.2.0") != nullptr);
    assert(output.find("org.rinos.missing") == nullptr);
    assert(output.updates.front().artifacts.front().sha256[31] == 0x1fu);

    output.generation = 99u;
    output.updates.clear();
    error = "stale";
    const std::string invalid = R"json({
        "generation":24,
        "updates":[
            {"update_id":"org.rinos.viewer-1.3.0",
             "product_id":"org.rinos.viewer","target_version":"1.3.0",
             "channel":"stable","published_at":1770000000,
             "release_notes":"Next release",
             "artifacts":[{"package_id":"org.rinos.viewer",
                 "version":"1.2.0","architecture":"any",
                 "compressed_size":4096,"installed_size":8192,
                 "sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}]}
        ]
    })json";
    assert(!RinRuntime::UpdateMetadataCatalogJson::parse(
        invalid, output, error));
    assert(error == "update catalog metadata");
    assert(output.generation == 0u && output.updates.empty());

    error = "stale";
    assert(!RinRuntime::UpdateMetadataCatalogJson::parse(
        "{\"generation\":0,\"updates\":[]}", output, error));
    assert(error == "update catalog generation");
    assert(output.generation == 0u && output.updates.empty());
    return 0;
}
