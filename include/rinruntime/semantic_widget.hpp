/* SPDX-License-Identifier: MIT */
/* Rendering-independent semantic widget adapter for external toolkits. */

#ifndef RINRUNTIME_SEMANTIC_WIDGET_HPP
#define RINRUNTIME_SEMANTIC_WIDGET_HPP

#include "widget.hpp"

#include <functional>
#include <utility>

namespace RinRuntime {

/*
 * SemanticWidget is useful when a toolkit already owns painting and child
 * layout but wants the common keyboard/accessibility behavior.  It keeps only
 * bounded-widget semantics in the public runtime and never stores a native
 * handle, filesystem path, or service capability.
 */
class SemanticWidget : public Widget {
    AccessibilityRole role_ = AccessibilityRole::Group;
    std::string value_;
    uint32_t extraState_ = 0u;
    uint32_t actions_ = ACCESSIBILITY_ACTION_NONE;
    bool keyboardFocusable_ = false;
    bool textEditable_ = false;
    std::function<bool()> activate_;
    std::function<bool(const std::string&)> setValue_;

public:
    explicit SemanticWidget(AccessibilityRole role = AccessibilityRole::Group)
        : role_(role) {}

    bool configure(const std::string& name, const std::string& value,
                   const std::string& description, uint32_t extraState,
                   uint32_t actions, bool focusable, bool editable) {
        if (!strictUtf8TextValid(name) || !strictUtf8TextValid(value) ||
            !strictUtf8TextValid(description))
            return false;
        value_ = value;
        extraState_ = extraState;
        actions_ = actions;
        keyboardFocusable_ = focusable;
        textEditable_ = editable;
        setAccessibilityName(name);
        setAccessibilityDescription(description);
        return true;
    }

    void setRole(AccessibilityRole role) { role_ = role; }
    void setActivate(std::function<bool()> callback) {
        activate_ = std::move(callback);
    }
    void setValueHandler(std::function<bool(const std::string&)> callback) {
        setValue_ = std::move(callback);
    }

    const std::string& value() const { return value_; }
    bool activate() { return activate_ ? activate_() : false; }

    AccessibilityRole accessibilityRole() const override { return role_; }
    std::string accessibilityValue() const override { return value_; }
    uint32_t accessibilityExtraState() const override { return extraState_; }
    uint32_t accessibilityActions() const override { return actions_; }
    bool acceptsKeyboardFocus() const override { return keyboardFocusable_; }
    bool isTextEditable() const override { return textEditable_; }

    bool setAccessibilityValue(const std::string& value) override {
        if (!textEditable_ || !strictUtf8TextValid(value) || !setValue_ ||
            !setValue_(value)) return false;
        value_ = value;
        return true;
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled()) return false;
        if (event.type == EventType::MouseDown)
            return getBounds().contains(event.x, event.y);
        if (event.type == EventType::KeyDown && hasAccessibilityFocus() &&
            (event.key == 0x0du || event.key == 0x20u))
            return activate();
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_SEMANTIC_WIDGET_HPP */
