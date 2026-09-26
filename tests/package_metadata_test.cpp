/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstdint>
#include <string>

#include "../include/rinruntime/package_metadata.hpp"

using RinRuntime::PackageArchitecture;
using RinRuntime::PackageClass;
using RinRuntime::PackageDependency;
using RinRuntime::PackageEntryPoint;
using RinRuntime::PackageMetadata;
using RinRuntime::PackageVersion;

static PackageVersion version(const char* text) {
    PackageVersion result = {};
    assert(PackageVersion::parse(text, result));
    return result;
}

static PackageMetadata validMetadata() {
    PackageMetadata result;
    result.packageId = "org.rinos.viewer";
    result.displayName = "Rin Viewer";
    result.version = version("1.2.0");
    result.architecture = PackageArchitecture::Any;
    result.packageClass = PackageClass::Application;
    result.license = "MIT";
    PackageDependency dependency;
    dependency.name = "org.rinos.runtime";
    dependency.hasMinimum = true;
    dependency.minimum = version("2.0");
    result.dependencies.push_back(dependency);
    result.provides.push_back("org.rinos.viewer");
    result.entryPoints.push_back({"main", "bin/viewer.rin"});
    result.ordinaryFileCount = 3u;
    return result;
}

int main() {
    PackageVersion shortVersion = version("1.2");
    PackageVersion longVersion = version("1.2.0");
    assert(PackageVersion::compare(shortVersion, longVersion) == 0);
    assert(PackageVersion::compare(version("1.2.1"), longVersion) > 0);

    PackageVersion ignored = {};
    assert(!PackageVersion::parse("", ignored));
    assert(!PackageVersion::parse("01.2", ignored));
    assert(!PackageVersion::parse("1.2.3.4.5", ignored));
    assert(!PackageVersion::parse("4294967296", ignored));

    PackageMetadata metadata = validMetadata();
    assert(metadata.valid());
    assert(metadata.dependencies.front().valid(metadata.packageId));

    metadata.dependencies.push_back(metadata.dependencies.front());
    assert(!metadata.valid());
    metadata.dependencies.pop_back();
    metadata.entryPoints.front().path = "../escape.rin";
    assert(!metadata.valid());

    metadata = validMetadata();
    metadata.publisherGeneration = 7u;
    assert(!metadata.valid());
    metadata.publisherKeyId[0] = 1u;
    assert(metadata.valid());
    metadata.publisherGeneration = 0u;
    assert(!metadata.valid());

    PackageDependency self;
    self.name = metadata.packageId;
    assert(!self.valid(metadata.packageId));
    PackageEntryPoint badEntry = {"main", "/absolute.rin"};
    assert(!badEntry.valid());

    metadata = validMetadata();
    metadata.flags = 1u << 31;
    assert(!metadata.valid());
    return 0;
}
