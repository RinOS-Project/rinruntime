/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/application_metadata_json.hpp"

int main() {
    RinRuntime::ApplicationMetadata output;
    std::string error;
    const std::string valid =
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":\"Rin Editor\","
        "\"entry_point\":\"bin/editor.rin\","
        "\"icon_id\":\"editor\",\"description\":\"Text editor\","
        "\"categories\":[\"development\",\"utility\"],"
        "\"mime_types\":[\"text/plain\"],\"gui\":true}";
    assert(RinRuntime::ApplicationMetadataJson::parse(valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.applicationId == "com.rinos.editor");
    assert(output.entryPoint == "bin/editor.rin");
    assert(output.gui);

    assert(!RinRuntime::ApplicationMetadataJson::parse(
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":\"Broken\","
        "\"entry_point\":\"../escape.rin\"}", output, error));
    assert(error == "metadata validation");
    assert(output.applicationId.empty());

    assert(!RinRuntime::ApplicationMetadataJson::parse(
        "{\"application_id\":\"com.rinos.editor\","
        "\"display_name\":7,\"entry_point\":\"bin/editor.rin\"}",
        output, error));
    assert(error == "metadata field type");
    return 0;
}
