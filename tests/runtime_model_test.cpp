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

    RinRuntime::AccessibilityTree tree = {};
    tree.window = 7u;
    tree.generation = 3u;
    RinRuntime::AccessibilityNode root = {};
    root.id = 1u;
    root.metadata.role = RinRuntime::AccessibilityRole::Window;
    root.metadata.name = "Main";
    root.metadata.state = RinRuntime::ACCESSIBILITY_STATE_VISIBLE;
    root.metadata.actions = RinRuntime::ACCESSIBILITY_ACTION_NONE;
    tree.nodes.push_back(root);
    RinRuntime::AccessibilityWireSnapshotV1 wire = {};
    assert(RinRuntime::AccessibilityWireCodec::encode(tree, &wire));
    RinRuntime::AccessibilityTree decoded = {};
    assert(RinRuntime::AccessibilityWireCodec::decode(wire, &decoded));
    assert(decoded.nodes.size() == 1u && decoded.nodes[0].id == 1u);
    wire.nodes[0].name.bytes[0] = 0xffu;
    assert(!RinRuntime::AccessibilityWireCodec::decode(wire, &decoded));
    return 0;
}
