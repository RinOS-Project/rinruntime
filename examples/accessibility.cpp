/* SPDX-License-Identifier: MIT */
#include <rinruntime/accessibility_wire.hpp>
int main() {
    RinRuntime::AccessibilityTree tree = {};
    tree.window = 1u;
    tree.generation = 1u;
    RinRuntime::AccessibilityNode node = {};
    node.id = 1u;
    node.metadata.role = RinRuntime::AccessibilityRole::Window;
    tree.nodes.push_back(node);
    RinRuntime::AccessibilityWireSnapshotV1 wire = {};
    return RinRuntime::AccessibilityWireCodec::encode(tree, &wire) ? 0 : 1;
}
