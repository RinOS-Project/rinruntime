/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_ACCESSIBILITY_WIRE_HPP
#define RINRUNTIME_ACCESSIBILITY_WIRE_HPP

#include <cstdint>
#include <string>

#include "accessibility.hpp"

namespace RinRuntime {

constexpr uint16_t kAccessibilityWireVersion = 1u;
constexpr size_t kAccessibilityWireMaxNodes = 128u;
constexpr size_t kAccessibilityWireTextBytes = 256u;

struct AccessibilityWireTextV1 {
    uint16_t size = 0u;
    uint16_t reserved = 0u;
    uint8_t bytes[kAccessibilityWireTextBytes] = {};
};

struct AccessibilityWireNodeV1 {
    uint64_t id = 0u;
    uint64_t parent_id = 0u;
    uint16_t role = 0u;
    uint16_t reserved0 = 0u;
    uint32_t state = 0u;
    uint32_t actions = 0u;
    int32_t x = 0;
    int32_t y = 0;
    int32_t width = 0;
    int32_t height = 0;
    uint32_t cursor_start = 0u;
    uint32_t cursor_end = 0u;
    uint32_t selection_start = 0u;
    uint32_t selection_end = 0u;
    uint32_t editable_start = 0u;
    uint32_t editable_end = 0u;
    AccessibilityWireTextV1 name;
    AccessibilityWireTextV1 description;
    AccessibilityWireTextV1 value;
    uint64_t reserved[2] = {};
};

struct AccessibilityWireSnapshotV1 {
    uint32_t struct_size = sizeof(AccessibilityWireSnapshotV1);
    uint16_t version = kAccessibilityWireVersion;
    uint16_t flags = 0u;
    uint64_t window = 0u;
    uint64_t generation = 0u;
    uint32_t node_count = 0u;
    uint32_t reserved0 = 0u;
    AccessibilityWireNodeV1 nodes[kAccessibilityWireMaxNodes] = {};
};

class AccessibilityWireCodec final {
    static bool utf8(const uint8_t* bytes, size_t size) {
        size_t i = 0u;
        while (i < size) {
            const uint8_t lead = bytes[i++];
            uint32_t codepoint = 0u, remaining = 0u, minimum = 0u;
            if (lead < 0x80u) continue;
            if (lead >= 0xc2u && lead <= 0xdfu) {
                codepoint = lead & 0x1fu; remaining = 1u; minimum = 0x80u;
            } else if (lead >= 0xe0u && lead <= 0xefu) {
                codepoint = lead & 0x0fu; remaining = 2u; minimum = 0x800u;
            } else if (lead >= 0xf0u && lead <= 0xf4u) {
                codepoint = lead & 0x07u; remaining = 3u; minimum = 0x10000u;
            } else return false;
            if (remaining > size - i) return false;
            while (remaining-- != 0u) {
                const uint8_t next = bytes[i++];
                if ((next & 0xc0u) != 0x80u) return false;
                codepoint = (codepoint << 6u) | (next & 0x3fu);
            }
            if (codepoint < minimum || codepoint > 0x10ffffu ||
                (codepoint >= 0xd800u && codepoint <= 0xdfffu)) return false;
        }
        return true;
    }

    static bool text(const std::string& value, AccessibilityWireTextV1* out) {
        if (out == nullptr || value.size() > kAccessibilityWireTextBytes ||
            !utf8(reinterpret_cast<const uint8_t*>(value.data()), value.size()))
            return false;
        *out = {};
        out->size = static_cast<uint16_t>(value.size());
        for (size_t i = 0u; i < value.size(); ++i)
            out->bytes[i] = static_cast<uint8_t>(value[i]);
        return true;
    }

    static bool text(const AccessibilityWireTextV1& value, std::string* out) {
        if (out == nullptr || value.size > kAccessibilityWireTextBytes ||
            value.reserved != 0u || !utf8(value.bytes, value.size)) return false;
        for (size_t i = value.size; i < kAccessibilityWireTextBytes; ++i)
            if (value.bytes[i] != 0u) return false;
        out->assign(reinterpret_cast<const char*>(value.bytes), value.size);
        return true;
    }

    static bool range(size_t start, size_t end, size_t size) {
        return start <= end && end <= size && end <= UINT32_MAX;
    }

public:
    static bool encode(const AccessibilityTree& tree,
                       AccessibilityWireSnapshotV1* out) {
        if (out == nullptr || tree.window == 0u || tree.generation == 0u ||
            tree.nodes.empty() || tree.nodes.size() > kAccessibilityWireMaxNodes)
            return false;
        AccessibilityWireSnapshotV1 encoded = {};
        encoded.window = static_cast<uint64_t>(tree.window);
        encoded.generation = tree.generation;
        encoded.node_count = static_cast<uint32_t>(tree.nodes.size());
        for (size_t i = 0u; i < tree.nodes.size(); ++i) {
            const AccessibilityNode& source = tree.nodes[i];
            AccessibilityWireNodeV1& node = encoded.nodes[i];
            if (source.id == 0u ||
                static_cast<uint16_t>(source.metadata.role) >=
                    static_cast<uint16_t>(AccessibilityRole::ScrollView) + 1u ||
                (source.metadata.state & ~0x000007ffu) != 0u ||
                (source.metadata.actions & ~0x00000fffu) != 0u ||
                source.metadata.bounds.w < 0 || source.metadata.bounds.h < 0 ||
                !text(source.metadata.name, &node.name) ||
                !text(source.metadata.description, &node.description) ||
                !text(source.metadata.value, &node.value) ||
                !range(source.metadata.cursor.start, source.metadata.cursor.end,
                       source.metadata.value.size()) ||
                !range(source.metadata.selection.start, source.metadata.selection.end,
                       source.metadata.value.size()) ||
                !range(source.metadata.editableRange.start,
                       source.metadata.editableRange.end,
                       source.metadata.value.size())) return false;
            if (i == 0u ? source.parentId != 0u : source.parentId == 0u)
                return false;
            bool parent_found = i == 0u;
            for (size_t previous = 0u; previous < i; ++previous) {
                if (tree.nodes[previous].id == source.id) return false;
                if (tree.nodes[previous].id == source.parentId) parent_found = true;
            }
            if (!parent_found) return false;
            node.id = source.id;
            node.parent_id = source.parentId;
            node.role = static_cast<uint16_t>(source.metadata.role);
            node.state = source.metadata.state;
            node.actions = source.metadata.actions;
            node.x = source.metadata.bounds.x;
            node.y = source.metadata.bounds.y;
            node.width = source.metadata.bounds.w;
            node.height = source.metadata.bounds.h;
            node.cursor_start = static_cast<uint32_t>(source.metadata.cursor.start);
            node.cursor_end = static_cast<uint32_t>(source.metadata.cursor.end);
            node.selection_start = static_cast<uint32_t>(source.metadata.selection.start);
            node.selection_end = static_cast<uint32_t>(source.metadata.selection.end);
            node.editable_start = static_cast<uint32_t>(source.metadata.editableRange.start);
            node.editable_end = static_cast<uint32_t>(source.metadata.editableRange.end);
        }
        *out = encoded;
        return true;
    }

    static bool decode(const AccessibilityWireSnapshotV1& source,
                       AccessibilityTree* out) {
        if (out == nullptr || source.struct_size != sizeof(source) ||
            source.version != kAccessibilityWireVersion || source.flags != 0u ||
            source.window == 0u || source.generation == 0u ||
            source.node_count == 0u || source.node_count > kAccessibilityWireMaxNodes ||
            source.reserved0 != 0u) return false;
        AccessibilityTree decoded = {};
        decoded.window = static_cast<uintptr_t>(source.window);
        decoded.generation = source.generation;
        decoded.nodes.reserve(source.node_count);
        for (uint32_t i = 0u; i < source.node_count; ++i) {
            const AccessibilityWireNodeV1& wire = source.nodes[i];
            AccessibilityNode node = {};
            if (wire.id == 0u || wire.reserved0 != 0u ||
                (wire.state & ~0x000007ffu) != 0u ||
                (wire.actions & ~0x00000fffu) != 0u ||
                !text(wire.name, &node.metadata.name) ||
                !text(wire.description, &node.metadata.description) ||
                !text(wire.value, &node.metadata.value) ||
                wire.cursor_start > wire.cursor_end ||
                wire.cursor_end > wire.value.size ||
                wire.selection_start > wire.selection_end ||
                wire.selection_end > wire.value.size ||
                wire.editable_start > wire.editable_end ||
                wire.editable_end > wire.value.size ||
                wire.reserved[0] != 0u || wire.reserved[1] != 0u)
                return false;
            if (i == 0u ? wire.parent_id != 0u : wire.parent_id == 0u)
                return false;
            bool parent_found = i == 0u;
            for (const AccessibilityNode& previous : decoded.nodes) {
                if (previous.id == wire.id) return false;
                if (previous.id == wire.parent_id) parent_found = true;
            }
            if (!parent_found) return false;
            node.id = wire.id;
            node.parentId = wire.parent_id;
            node.metadata.role = static_cast<AccessibilityRole>(wire.role);
            node.metadata.state = wire.state;
            node.metadata.actions = wire.actions;
            node.metadata.bounds = Rect(wire.x, wire.y, wire.width, wire.height);
            node.metadata.cursor = {wire.cursor_start, wire.cursor_end};
            node.metadata.selection = {wire.selection_start, wire.selection_end};
            node.metadata.editableRange = {wire.editable_start, wire.editable_end};
            decoded.nodes.push_back(node);
        }
        *out = decoded;
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ACCESSIBILITY_WIRE_HPP */
