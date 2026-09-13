/* SPDX-License-Identifier: MIT */
#include <rinruntime/rinruntime.hpp>

#include <cassert>

int main() {
    RinRuntime::Button button("Open");
    assert(button.setAccessibilityName("Open"));
    assert(button.accessibilityDefaultName() == "Open");

    RinRuntime::TextEditorModel editor;
    assert(editor.setText("RinOS"));
    editor.moveEnd(false);
    assert(editor.insertCodepoint(0x1f680u));
    assert(editor.backspace());
    assert(editor.text() == "RinOS");

    RinRuntime::ArchivePlan plan;
    RinRuntime::ArchiveSource source{"app/main.rin", "main.rin", false};
    assert(plan.addSource(source));
    RinRuntime::ArchiveSource traversal{"../escape", "escape", false};
    assert(!plan.addSource(traversal));
    return 0;
}
