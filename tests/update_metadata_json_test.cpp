/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/update_metadata_json.hpp"

int main() {
    const std::string document = R"json({
        "update_id":"org.rinos.viewer-1.2.0",
        "product_id":"org.rinos.viewer",
        "target_version":"1.2.0",
        "minimum_from_version":"1.1",
        "channel":"stable",
        "flags":5,
        "published_at":1770000000,
        "release_notes":"Security maintenance release",
        "artifacts":[{
            "package_id":"org.rinos.viewer",
            "version":"1.2.0",
            "architecture":"x86_64",
            "compressed_size":4096,
            "installed_size":8192,
            "sha256":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        }]
    })json";

    RinRuntime::UpdateMetadata metadata;
    std::string error;
    assert(RinRuntime::UpdateMetadataJson::parse(document, metadata, error));
    assert(error.empty());
    assert(metadata.valid());
    assert(metadata.channel == RinRuntime::UpdateChannel::Stable);
    assert(metadata.artifacts.size() == 1u);
    assert(metadata.artifacts.front().architecture ==
           RinRuntime::PackageArchitecture::X86_64);
    assert(metadata.artifacts.front().sha256[31] == 0x1fu);

    metadata.productId = "retained only for the next successful parse";
    error = "stale";
    assert(!RinRuntime::UpdateMetadataJson::parse(
        "{\"update_id\":\"broken\",\"update_id\":\"duplicate\"}",
        metadata, error));
    assert(metadata.updateId.empty());
    assert(metadata.productId.empty());
    assert(!error.empty());

    std::string invalidDigest = document;
    invalidDigest.replace(document.find("000102"), 6u, "zzzzzz");
    assert(!RinRuntime::UpdateMetadataJson::parse(invalidDigest, metadata,
                                                  error));
    assert(metadata.artifacts.empty());
    assert(!error.empty());
    return 0;
}
