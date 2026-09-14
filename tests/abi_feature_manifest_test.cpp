/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/abi_feature_manifest.hpp"

int main() {
    RinRuntime::AbiFeatureManifest manifest;
    manifest.abiMajor = 1u;
    manifest.abiMinor = 4u;
    manifest.manifestId = "desktop-runtime";
    manifest.required.push_back(
        RinRuntime::AbiFeatureRequirement("rinbase.object", 1u, 0u));
    manifest.optional.push_back(
        RinRuntime::AbiFeatureRequirement("rinmedia.decode", 2u, 1u));

    assert(manifest.valid());
    assert(manifest.isRequired("rinbase.object"));
    assert(!manifest.isRequired("rinmedia.decode"));
    assert(manifest.mentions("rinmedia.decode"));

    manifest.optional.push_back(
        RinRuntime::AbiFeatureRequirement("rinbase.object", 1u, 1u));
    assert(!manifest.valid());

    manifest.optional.pop_back();
    manifest.required.push_back(
        RinRuntime::AbiFeatureRequirement("rinbase.aaa", 1u, 0u));
    assert(!manifest.valid());

    RinRuntime::AbiFeatureRequirement invalidId("bad/id", 1u, 0u);
    RinRuntime::AbiFeatureRequirement invalidVersion("zero-version", 0u, 0u);
    assert(!invalidId.valid());
    assert(!invalidVersion.valid());
    return 0;
}
