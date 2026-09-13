/* SPDX-License-Identifier: MIT */
/*
 * RinRuntime accessibility model.
 *
 * This header deliberately contains no graphics, window-server or application
 * policy dependency.  GUI frameworks provide an AccessibilityProvider, while
 * the desktop-facing registry only exchanges copied snapshots.
 */

#ifndef RINRUNTIME_ACCESSIBILITY_HPP
#define RINRUNTIME_ACCESSIBILITY_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

struct Rect {
    int32_t x;
    int32_t y;
    int32_t w;
    int32_t h;

    Rect() : x(0), y(0), w(0), h(0) {}
    Rect(int32_t left, int32_t top, int32_t width, int32_t height)
        : x(left), y(top), w(width), h(height) {}

    bool contains(int32_t pointX, int32_t pointY) const {
        return w >= 0 && h >= 0 && pointX >= x && pointY >= y &&
               (int64_t)pointX < (int64_t)x + w &&
               (int64_t)pointY < (int64_t)y + h;
    }

    Rect inset(int32_t distance) const {
        return Rect(x + distance, y + distance, w - distance * 2,
                    h - distance * 2);
    }
};

enum class AccessibilityRole : uint16_t {
    Window,
    Group,
    Button,
    Label,
    TextField,
    TextArea,
    CheckBox,
    Slider,
    ProgressBar,
    TabList,
    ComboBox,
    RadioButton,
    Menu,
    MenuItem,
    Dialog,
    List,
    Tree,
    Table,
    ScrollView
};

enum AccessibilityState : uint32_t {
    ACCESSIBILITY_STATE_VISIBLE   = 0x00000001u,
    ACCESSIBILITY_STATE_ENABLED   = 0x00000002u,
    ACCESSIBILITY_STATE_FOCUSABLE = 0x00000004u,
    ACCESSIBILITY_STATE_FOCUSED   = 0x00000008u,
    ACCESSIBILITY_STATE_EDITABLE  = 0x00000010u,
    ACCESSIBILITY_STATE_CHECKED   = 0x00000020u,
    ACCESSIBILITY_STATE_EXPANDED  = 0x00000040u,
    ACCESSIBILITY_STATE_SELECTED  = 0x00000080u,
    ACCESSIBILITY_STATE_MODAL     = 0x00000100u,
    /* The desktop bridge redacts value and text ranges before storage. */
    ACCESSIBILITY_STATE_SENSITIVE = 0x00000200u,
    /* Focus reached through keyboard or assistive technology.  Pointer
     * focus remains FOCUSED but is not focus-visible. */
    ACCESSIBILITY_STATE_FOCUS_VISIBLE = 0x00000400u
};

enum AccessibilityAction : uint32_t {
    ACCESSIBILITY_ACTION_NONE      = 0x00000000u,
    ACCESSIBILITY_ACTION_FOCUS     = 0x00000001u,
    ACCESSIBILITY_ACTION_ACTIVATE  = 0x00000002u,
    ACCESSIBILITY_ACTION_SET_VALUE = 0x00000004u,
    ACCESSIBILITY_ACTION_INCREMENT = 0x00000008u,
    ACCESSIBILITY_ACTION_DECREMENT = 0x00000010u,
    ACCESSIBILITY_ACTION_EXPAND    = 0x00000020u,
    ACCESSIBILITY_ACTION_COLLAPSE  = 0x00000040u,
    ACCESSIBILITY_ACTION_SELECT    = 0x00000080u,
    ACCESSIBILITY_ACTION_DISMISS   = 0x00000100u,
    ACCESSIBILITY_ACTION_SCROLL_FORWARD = 0x00000200u,
    ACCESSIBILITY_ACTION_SCROLL_BACKWARD = 0x00000400u
};

struct AccessibilityTextRange {
    size_t start;
    size_t end;
};

struct AccessibilityMetadata {
    AccessibilityRole role;
    std::string name;
    std::string description;
    std::string value;
    uint32_t state;
    uint32_t actions;
    Rect bounds;
    AccessibilityTextRange cursor;
    AccessibilityTextRange selection;
    AccessibilityTextRange editableRange;
};

struct AccessibilityNode {
    uint64_t id;
    uint64_t parentId;
    AccessibilityMetadata metadata;
};

struct AccessibilityTree {
    uintptr_t window;
    uint64_t generation;
    std::vector<AccessibilityNode> nodes;
};

/* An application retains ownership of its provider.  The registry never
 * exposes the provider or any live widget pointer to a caller. */
class AccessibilityProvider {
public:
    virtual ~AccessibilityProvider() = default;
    virtual AccessibilityTree accessibilityTree() const = 0;
    virtual bool focusAccessibilityNode(uint64_t nodeId) = 0;
    /* Implementations may override this for non-focus actions.  The default
     * deliberately permits only the action that every provider already has. */
    virtual bool performAccessibilityAction(uint64_t nodeId,
                                            AccessibilityAction action) {
        return action == ACCESSIBILITY_ACTION_FOCUS &&
               focusAccessibilityNode(nodeId);
    }
    /* SET_VALUE is intentionally a distinct path: an empty replacement is
     * meaningful, so callers must not encode it as a missing action value. */
    virtual bool performAccessibilityActionValue(uint64_t nodeId,
                                                 AccessibilityAction action,
                                                 const std::string& value) {
        if (action == ACCESSIBILITY_ACTION_SET_VALUE) return false;
        if (!value.empty()) return false;
        return performAccessibilityAction(nodeId, action);
    }
};

class AccessibilityDesktopService {
    struct Registration {
        uintptr_t handle;
        AccessibilityProvider* provider;
    };

    static std::vector<Registration>& registrations() {
        static std::vector<Registration> value;
        return value;
    }

public:
    static void registerWindow(uintptr_t handle, AccessibilityProvider* provider) {
        std::vector<Registration>& values = registrations();
        if (handle == 0u || !provider) return;
        for (auto& value : values) {
            if (value.handle == handle) {
                value.provider = provider;
                return;
            }
        }
        values.push_back({handle, provider});
    }

    static void unregisterWindow(uintptr_t handle,
                                 const AccessibilityProvider* provider) {
        std::vector<Registration>& values = registrations();
        if (handle == 0u || !provider) return;
        size_t index = 0u;
        while (index < values.size()) {
            if (values[index].handle == handle && values[index].provider == provider) {
                values.erase(values.begin() + (ptrdiff_t)index);
                return;
            }
            ++index;
        }
    }

    static bool getTree(uintptr_t handle, AccessibilityTree* output) {
        if (handle == 0u || !output) return false;
        for (const auto& value : registrations()) {
            if (value.handle == handle && value.provider) {
                *output = value.provider->accessibilityTree();
                return true;
            }
        }
        return false;
    }

    /* Generation-bound helpers are intended for GUI automation and host
     * tests.  They operate on the same provider registry as the desktop
     * bridge, but never expose a live Widget pointer to the caller. */
    static bool findNode(uintptr_t handle, uint64_t generation,
                         uint64_t nodeId, AccessibilityNode* output) {
        AccessibilityTree tree = {};
        if (!output || nodeId == 0u || !getTree(handle, &tree) ||
            tree.generation != generation)
            return false;
        for (const auto& node : tree.nodes) {
            if (node.id == nodeId) {
                *output = node;
                return true;
            }
        }
        return false;
    }

    static bool performAction(uintptr_t handle, uint64_t generation,
                              uint64_t nodeId, AccessibilityAction action,
                              const std::string& value = "") {
        if (handle == 0u || generation == 0u || nodeId == 0u ||
            static_cast<uint32_t>(action) == 0u ||
            (static_cast<uint32_t>(action) &
             (static_cast<uint32_t>(action) - 1u)) != 0u)
            return false;
        for (const auto& registration : registrations()) {
            if (registration.handle != handle || !registration.provider)
                continue;
            AccessibilityNode node = {};
            AccessibilityTree tree = registration.provider->accessibilityTree();
            if (tree.generation != generation) return false;
            bool found = false;
            for (const auto& candidate : tree.nodes) {
                if (candidate.id == nodeId) {
                    node = candidate;
                    found = true;
                    break;
                }
            }
            if (!found || (node.metadata.actions &
                           static_cast<uint32_t>(action)) == 0u)
                return false;
            return registration.provider->performAccessibilityActionValue(
                nodeId, action, value);
        }
        return false;
    }

    static bool focusNode(uintptr_t handle, uint64_t nodeId) {
        if (handle == 0u || nodeId == 0u) return false;
        for (const auto& value : registrations()) {
            if (value.handle == handle && value.provider)
                return value.provider->focusAccessibilityNode(nodeId);
        }
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ACCESSIBILITY_HPP */
