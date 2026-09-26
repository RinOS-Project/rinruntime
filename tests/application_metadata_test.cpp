/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/application_metadata.hpp"

int main() {
    RinRuntime::ApplicationMetadata metadata;
    metadata.applicationId = "com.rinos.editor";
    metadata.displayName = "Rin Editor";
    metadata.entryPoint = "bin/editor.rin";
    metadata.iconId = "editor";
    metadata.categories.push_back("development");
    metadata.categories.push_back("utility");
    metadata.mimeTypes.push_back("text/plain");
    metadata.gui = true;

    assert(metadata.valid());

    metadata.entryPoint = "/bin/editor.rin";
    assert(!metadata.valid());
    metadata.entryPoint = "bin/editor.rin";
    metadata.categories.push_back("utility");
    assert(!metadata.valid());

    RinRuntime::ApplicationMetadata invalid;
    invalid.applicationId = "com/rinos/editor";
    invalid.displayName = "Invalid";
    invalid.entryPoint = "bin/main.rin";
    invalid.iconId = "main";
    assert(!invalid.valid());

    RinRuntime::ApplicationMetadata malformed = {};
    malformed.applicationId = "com.rinos.editor";
    malformed.displayName = "Rin";
    malformed.displayName.push_back(static_cast<char>(0xc0u));
    malformed.displayName.push_back(static_cast<char>(0xafu));
    malformed.displayName += "Editor";
    malformed.entryPoint = "bin/editor.rin";
    assert(!malformed.valid());
    malformed.displayName = "Rin Editor";
    malformed.entryPoint = "bin/\xE2\x28\xA1";
    assert(!malformed.valid());
    malformed.entryPoint = "bin/editor.rin";
    malformed.mimeTypes.push_back("text/\xED\xA0\x80");
    assert(!malformed.valid());
    return 0;
}
