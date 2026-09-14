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
    return 0;
}
