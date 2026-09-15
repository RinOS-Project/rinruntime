/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/package_metadata_json.hpp"

int main() {
    RinRuntime::PackageMetadata output;
    std::string error;
    const std::string valid =
        "{\"package_id\":\"com.rinos.editor\","
        "\"display_name\":\"Rin Editor\",\"version\":\"1.2.0\","
        "\"architecture\":\"any\",\"class\":\"application\","
        "\"license\":\"MIT\",\"description\":\"Editor\","
        "\"dependencies\":[{\"name\":\"runtime\",\"minimum\":\"1.0\"}],"
        "\"entry_points\":[{\"name\":\"main\",\"path\":\"bin/editor.rin\"}]}";
    assert(RinRuntime::PackageMetadataJson::parse(valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.packageId == "com.rinos.editor");
    assert(output.version.component[1] == 2u);
    assert(output.entryPoints.size() == 1u);

    assert(!RinRuntime::PackageMetadataJson::parse(
        "{\"package_id\":\"com.rinos.editor\","
        "\"display_name\":\"Broken\",\"version\":\"1\","
        "\"license\":\"MIT\",\"entry_points\":[{"
        "\"name\":\"main\",\"path\":\"../escape.rin\"}]}",
        output, error));
    assert(error == "package metadata validation");
    assert(output.packageId.empty());

    assert(!RinRuntime::PackageMetadataJson::parse(
        "{\"package_id\":\"com.rinos.editor\","
        "\"display_name\":\"Broken\",\"version\":\"1\","
        "\"license\":\"MIT\",\"flags\":8}", output, error));
    assert(error == "package metadata flags");
    return 0;
}
