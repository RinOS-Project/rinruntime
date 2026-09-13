/* SPDX-License-Identifier: MIT */
/* Backend-independent state and accessibility contract for reusable widgets. */

#ifndef RINRUNTIME_WIDGET_HPP
#define RINRUNTIME_WIDGET_HPP

#include "display_policy.hpp"
#include "event.hpp"
#include "text_input.hpp"

namespace RinRuntime {

/* Public Accessibility strings use the same scalar-valid UTF-8 rule as
 * editable text.  Keeping this helper in the base widget header lets generic
 * SemanticWidget users share the admission boundary without importing a
 * renderer-specific adapter. */
inline bool strictUtf8TextValid(const std::string& value) {
    TextInputModel validator;
    return validator.setText(value);
}

/*
 * Widget owns the portable part of a control: geometry, visibility, enabled
 * state, layout weight and accessibility projection.  It intentionally has no
 * renderer, native window handle, allocator policy or event loop dependency.
 * A toolkit may derive from it directly, while RinApp supplies drawing and
 * tree ownership in its own adapter.
 */
class Widget {
protected:
    Rect bounds;
    bool visible = true;
    bool enabled = true;
    std::string accessibilityName;
    std::string accessibilityDescription;
    bool accessibilityFocused = false;
    bool accessibilityFocusVisible = false;
    uint32_t layoutWeight = 0u;

public:
    virtual ~Widget() = default;

    /* Input is intentionally part of the portable contract.  A renderer or
     * native toolkit may route its backend events here without inheriting a
     * RinOS window class. */
    virtual bool handleEvent(const Event&) { return false; }

    void setBounds(const Rect& value) { bounds = value; }
    Rect getBounds() const { return bounds; }

    void setVisible(bool value) { visible = value; }
    bool isVisible() const { return visible; }
    void setEnabled(bool value) { enabled = value; }
    bool isEnabled() const { return enabled; }

    void setLayoutWeight(uint32_t value) { layoutWeight = value; }
    uint32_t getLayoutWeight() const { return layoutWeight; }
    virtual LayoutSize minimumLayoutSize() const { return {0, 0}; }

    /* These conversions deliberately take an explicit surface policy rather
     * than keep global display state in a reusable widget. */
    bool physicalBounds(const DisplayAccessibilityPolicy& policy,
                        Rect* output) const {
        return policy.logicalToPhysical(bounds, output);
    }
    bool effectiveMinimumLayoutSize(const DisplayAccessibilityPolicy& policy,
                                    LayoutSize* output) const {
        return policy.scaleLayoutSize(minimumLayoutSize(), output);
    }

    bool setAccessibilityName(const std::string& value) {
        if (!strictUtf8TextValid(value)) return false;
        accessibilityName = value;
        return true;
    }
    bool setAccessibilityDescription(const std::string& value) {
        if (!strictUtf8TextValid(value)) return false;
        accessibilityDescription = value;
        return true;
    }
    /* Focus controllers own when this changes; it is public so a non-RinOS
     * toolkit can share the same accessibility focus state. */
    void setAccessibilityFocused(bool value) { accessibilityFocused = value; }
    bool hasAccessibilityFocus() const { return accessibilityFocused; }
    void setAccessibilityFocusVisible(bool value) {
        accessibilityFocusVisible = value;
    }
    bool hasAccessibilityFocusVisible() const {
        return accessibilityFocused && accessibilityFocusVisible;
    }

    virtual AccessibilityRole accessibilityRole() const {
        return AccessibilityRole::Group;
    }
    virtual std::string accessibilityDefaultName() const { return ""; }
    virtual std::string accessibilityValue() const { return ""; }
    virtual uint32_t accessibilityExtraState() const { return 0u; }
    virtual uint32_t accessibilityActions() const {
        return ACCESSIBILITY_ACTION_NONE;
    }
    virtual bool acceptsKeyboardFocus() const { return false; }
    virtual bool isTextEditable() const { return false; }
    virtual bool setAccessibilityValue(const std::string&) { return false; }
    virtual AccessibilityTextRange accessibilityCursor() const { return {0u, 0u}; }
    virtual AccessibilityTextRange accessibilitySelection() const { return {0u, 0u}; }
    virtual AccessibilityTextRange accessibilityEditableRange() const {
        return {0u, 0u};
    }

    AccessibilityMetadata accessibilityMetadata() const {
        AccessibilityMetadata metadata = {};
        metadata.role = accessibilityRole();
        metadata.name = accessibilityName.empty() ? accessibilityDefaultName()
                                                  : accessibilityName;
        metadata.description = accessibilityDescription;
        metadata.value = accessibilityValue();
        metadata.state = (visible ? ACCESSIBILITY_STATE_VISIBLE : 0u) |
                         (enabled ? ACCESSIBILITY_STATE_ENABLED : 0u) |
                         (acceptsKeyboardFocus() ? ACCESSIBILITY_STATE_FOCUSABLE : 0u) |
                         (accessibilityFocused ? ACCESSIBILITY_STATE_FOCUSED : 0u) |
                         (hasAccessibilityFocusVisible() ?
                              ACCESSIBILITY_STATE_FOCUS_VISIBLE : 0u) |
                         (isTextEditable() ? ACCESSIBILITY_STATE_EDITABLE : 0u) |
                         accessibilityExtraState();
        metadata.actions = accessibilityActions();
        if (acceptsKeyboardFocus()) metadata.actions |= ACCESSIBILITY_ACTION_FOCUS;
        metadata.bounds = bounds;
        metadata.cursor = accessibilityCursor();
        metadata.selection = accessibilitySelection();
        metadata.editableRange = accessibilityEditableRange();
        return metadata;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_WIDGET_HPP */
