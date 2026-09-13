/* SPDX-License-Identifier: MIT */
/* Backend-independent, fail-closed permission prompt model. */

#ifndef RINRUNTIME_PERMISSION_PROMPT_HPP
#define RINRUNTIME_PERMISSION_PROMPT_HPP

#include "text_input.hpp"
#include "widget.hpp"

namespace RinRuntime {

enum class PermissionPromptDecision : uint8_t {
    Pending = 0,
    Allow = 1,
    Block = 2,
    Dismissed = 3,
};

/*
 * A permission prompt owns only decision state and semantic metadata. It has
 * no renderer or capability authority; callers must authenticate the origin
 * and apply the decision in their policy/service layer. Block is the default
 * keyboard action so Enter cannot grant a sensitive capability accidentally.
 */
class PermissionPrompt final : public Widget {
public:
    static constexpr size_t kMaxOriginBytes = 255u;
    static constexpr size_t kMaxPermissionBytes = 63u;
    static constexpr size_t kMaxDescriptionBytes = 1024u;

private:
    std::string origin_;
    std::string permission_;
    std::string description_;
    PermissionPromptDecision decision_ = PermissionPromptDecision::Dismissed;
    PermissionPromptDecision defaultDecision_ = PermissionPromptDecision::Block;
    std::function<void(PermissionPromptDecision)> onDecision_;

    static bool validUtf8Text(const std::string& value, size_t maximum) {
        return value.size() <= maximum && TextInputModel().setText(value);
    }

    static bool validPermission(const std::string& value) {
        if (value.empty() || value.size() > kMaxPermissionBytes) return false;
        for (unsigned char byte : value) {
            const bool alpha = (byte >= static_cast<unsigned char>('a') &&
                                byte <= static_cast<unsigned char>('z')) ||
                               (byte >= static_cast<unsigned char>('A') &&
                                byte <= static_cast<unsigned char>('Z'));
            const bool digit = byte >= static_cast<unsigned char>('0') &&
                               byte <= static_cast<unsigned char>('9');
            if (!alpha && !digit && byte != static_cast<unsigned char>('.') &&
                byte != static_cast<unsigned char>('-') &&
                byte != static_cast<unsigned char>('_')) return false;
        }
        return true;
    }

    bool resolve(PermissionPromptDecision decision) {
        if (decision_ != PermissionPromptDecision::Pending ||
            (decision != PermissionPromptDecision::Allow &&
             decision != PermissionPromptDecision::Block &&
             decision != PermissionPromptDecision::Dismissed)) return false;
        decision_ = decision;
        setVisible(false);
        auto callback = onDecision_;
        if (callback) callback(decision_);
        return true;
    }

public:
    PermissionPrompt() = default;

    bool request(const std::string& origin, const std::string& permission,
                 const std::string& description = "") {
        if (decision_ == PermissionPromptDecision::Pending ||
            !validUtf8Text(origin, kMaxOriginBytes) ||
            !validPermission(permission) ||
            !validUtf8Text(description, kMaxDescriptionBytes)) return false;
        origin_ = origin;
        permission_ = permission;
        description_ = description;
        decision_ = PermissionPromptDecision::Pending;
        setAccessibilityDescription(promptDescriptionForAccessibility());
        setVisible(true);
        return true;
    }

    void setDefaultDecision(PermissionPromptDecision decision) {
        if (decision == PermissionPromptDecision::Allow ||
            decision == PermissionPromptDecision::Block)
            defaultDecision_ = decision;
    }

    void setOnDecision(std::function<void(PermissionPromptDecision)> callback) {
        onDecision_ = std::move(callback);
    }

    const std::string& origin() const { return origin_; }
    const std::string& permission() const { return permission_; }
    const std::string& description() const { return description_; }
    PermissionPromptDecision decision() const { return decision_; }
    bool isPending() const {
        return decision_ == PermissionPromptDecision::Pending;
    }

    bool allow() { return resolve(PermissionPromptDecision::Allow); }
    bool block() { return resolve(PermissionPromptDecision::Block); }
    bool dismiss() { return resolve(PermissionPromptDecision::Dismissed); }

    AccessibilityRole accessibilityRole() const override {
        return AccessibilityRole::Dialog;
    }
    std::string accessibilityDefaultName() const override {
        return "Permission request";
    }
    std::string accessibilityValue() const override { return permission_; }
    std::string promptDescriptionForAccessibility() const {
        if (!description_.empty()) return origin_ + ": " + description_;
        return origin_;
    }
    uint32_t accessibilityExtraState() const override {
        return isPending() ? ACCESSIBILITY_STATE_MODAL : 0u;
    }
    uint32_t accessibilityActions() const override {
        return isPending() ? (ACCESSIBILITY_ACTION_ACTIVATE |
                              ACCESSIBILITY_ACTION_DISMISS)
                           : ACCESSIBILITY_ACTION_NONE;
    }
    bool acceptsKeyboardFocus() const override { return isPending(); }
    LayoutSize minimumLayoutSize() const override {
        return enforceControlTarget({320, 160});
    }

    bool handleEvent(const Event& event) override {
        if (!isVisible() || !isEnabled() || !isPending() ||
            event.type != EventType::KeyDown || !hasAccessibilityFocus())
            return false;
        if (event.key == 0x1bu) return dismiss();
        if (event.key == 0x0du || event.key == 0x20u)
            return resolve(defaultDecision_);
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PERMISSION_PROMPT_HPP */
