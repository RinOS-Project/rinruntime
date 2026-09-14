/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstdint>

#include "../include/rinruntime/update_metadata.hpp"

using RinRuntime::PackageArchitecture;
using RinRuntime::PackageVersion;
using RinRuntime::UpdateArtifact;
using RinRuntime::UpdateChannel;
using RinRuntime::UpdateMetadata;

static PackageVersion version(const char* text) {
    PackageVersion result = {};
    assert(PackageVersion::parse(text, result));
    return result;
}

static UpdateMetadata validMetadata() {
    UpdateMetadata result;
    result.updateId = "org.rinos.viewer-1.2.0";
    result.productId = "org.rinos.viewer";
    result.targetVersion = version("1.2.0");
    result.hasMinimumFromVersion = true;
    result.minimumFromVersion = version("1.1");
    result.channel = UpdateChannel::Stable;
    result.flags = RinRuntime::kUpdateMetadataFlagSecurity;
    result.publishedAtUnixSeconds = 1770000000u;
    result.releaseNotes = "Security maintenance release";

    UpdateArtifact artifact;
    artifact.packageId = "org.rinos.viewer";
    artifact.version = result.targetVersion;
    artifact.architecture = PackageArchitecture::Any;
    artifact.compressedSize = 128u;
    artifact.installedSize = 512u;
    artifact.sha256[0] = 0x5au;
    result.artifacts.push_back(artifact);
    return result;
}

int main() {
    UpdateMetadata metadata = validMetadata();
    assert(metadata.valid());
    assert(metadata.artifacts.front().valid());

    metadata.artifacts.front().sha256 = {};
    assert(!metadata.valid());

    metadata = validMetadata();
    metadata.artifacts.front().version = version("1.2.1");
    assert(!metadata.valid());

    metadata = validMetadata();
    UpdateArtifact duplicate = metadata.artifacts.front();
    metadata.artifacts.push_back(duplicate);
    assert(!metadata.valid());

    metadata = validMetadata();
    metadata.channel = static_cast<UpdateChannel>(99u);
    assert(!metadata.valid());
    metadata = validMetadata();
    metadata.flags = UINT32_C(1) << 31u;
    assert(!metadata.valid());

    metadata = validMetadata();
    metadata.releaseNotes.assign(1024u, 'x');
    assert(!metadata.valid());

    metadata = validMetadata();
    metadata.minimumFromVersion = version("2.0");
    assert(!metadata.valid());
    return 0;
}
