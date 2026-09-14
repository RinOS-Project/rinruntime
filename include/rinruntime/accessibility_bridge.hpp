/* SPDX-License-Identifier: MIT */
/* Renderer-independent bridge for composing application and WebContent
 * accessibility trees. */

#ifndef RINRUNTIME_ACCESSIBILITY_BRIDGE_HPP
#define RINRUNTIME_ACCESSIBILITY_BRIDGE_HPP

#include "accessibility.hpp"

namespace RinRuntime {

static constexpr std::size_t ACCESSIBILITY_BRIDGE_MAX_NODES = 128u;

class AccessibilityTreeBridge final : public AccessibilityProvider {
    AccessibilityProvider* chrome_ = nullptr;
    AccessibilityProvider* webContent_ = nullptr;
    Rect webContentViewport_;

    static constexpr std::uint64_t WEB_CONTENT_ID_TAG = UINT64_C(1) << 63u;

    static bool validTreeRoot(const AccessibilityTree& tree) {
        return tree.window != 0u && tree.generation != 0u &&
               !tree.nodes.empty() && tree.nodes.size() <=
                   ACCESSIBILITY_BRIDGE_MAX_NODES && tree.nodes[0].id != 0u &&
               tree.nodes[0].parentId == 0u;
    }

    static bool validNodeIds(const AccessibilityTree& tree,
                             bool reserveWebTag) {
        for (std::size_t index = 0u; index < tree.nodes.size(); ++index) {
            const AccessibilityNode& node = tree.nodes[index];
            if (node.id == 0u || (reserveWebTag &&
                                  (node.id & WEB_CONTENT_ID_TAG) != 0u))
                return false;
            if (index == 0u) {
                if (node.parentId != 0u) return false;
                continue;
            }
            if (node.parentId == 0u) return false;
            bool parentFound = false;
            for (std::size_t previous = 0u; previous < index; ++previous) {
                if (tree.nodes[previous].id == node.id) return false;
                if (tree.nodes[previous].id == node.parentId)
                    parentFound = true;
            }
            if (!parentFound) return false;
        }
        return true;
    }

    static bool offsetBounds(const Rect& source, const Rect& offset,
                             Rect* output) {
        if (output == nullptr || source.w < 0 || source.h < 0) return false;
        const std::int64_t x = static_cast<std::int64_t>(source.x) + offset.x;
        const std::int64_t y = static_cast<std::int64_t>(source.y) + offset.y;
        const std::int64_t right = x + source.w;
        const std::int64_t bottom = y + source.h;
        if (x < INT32_MIN || x > INT32_MAX || y < INT32_MIN || y > INT32_MAX ||
            right < INT32_MIN || right > INT32_MAX || bottom < INT32_MIN ||
            bottom > INT32_MAX)
            return false;
        *output = Rect(static_cast<std::int32_t>(x), static_cast<std::int32_t>(y),
                       source.w, source.h);
        return true;
    }

    static std::uint64_t composeGeneration(std::uint64_t chromeGeneration,
                                           std::uint64_t webGeneration) {
        std::uint64_t value = chromeGeneration ^ UINT64_C(0x9e3779b97f4a7c15);
        value ^= webGeneration + UINT64_C(0x517cc1b727220a95) +
                 (value << 6u) + (value >> 2u);
        value ^= value >> 30u;
        value *= UINT64_C(0xbf58476d1ce4e5b9);
        value ^= value >> 27u;
        value *= UINT64_C(0x94d049bb133111eb);
        value ^= value >> 31u;
        return value == 0u ? 1u : value;
    }

    static std::uint64_t webId(std::uint64_t id) {
        return id | WEB_CONTENT_ID_TAG;
    }
    static std::uint64_t untagWebId(std::uint64_t id) {
        return id & ~WEB_CONTENT_ID_TAG;
    }

    bool compose(AccessibilityTree* output) const {
        if (output == nullptr || chrome_ == nullptr) return false;
        AccessibilityTree chrome = chrome_->accessibilityTree();
        if (!validTreeRoot(chrome) || !validNodeIds(chrome, true)) return false;
        if (chrome.nodes.size() >= ACCESSIBILITY_BRIDGE_MAX_NODES &&
            webContent_ != nullptr)
            return false;

        AccessibilityTree web;
        const bool hasWeb = webContent_ != nullptr;
        if (hasWeb) {
            web = webContent_->accessibilityTree();
            if (!validTreeRoot(web) || !validNodeIds(web, true) ||
                (web.window != 0u && web.window != chrome.window) ||
                chrome.nodes.size() + web.nodes.size() >
                    ACCESSIBILITY_BRIDGE_MAX_NODES)
                return false;
        }

        AccessibilityTree result = chrome;
        if (!hasWeb) {
            *output = static_cast<AccessibilityTree&&>(result);
            return true;
        }
        result.generation = composeGeneration(chrome.generation, web.generation);
        for (std::size_t index = 0u; index < web.nodes.size(); ++index) {
            const AccessibilityNode& source = web.nodes[index];
            AccessibilityNode node = source;
            node.id = webId(source.id);
            node.parentId = index == 0u ? chrome.nodes[0].id
                                        : webId(source.parentId);
            if (!offsetBounds(source.metadata.bounds, webContentViewport_,
                              &node.metadata.bounds))
                return false;
            result.nodes.push_back(static_cast<AccessibilityNode&&>(node));
        }
        *output = static_cast<AccessibilityTree&&>(result);
        return true;
    }

    bool dispatch(std::uint64_t nodeId, AccessibilityAction action,
                  const std::string& value, bool withValue) {
        if (nodeId == 0u) return false;
        if ((nodeId & WEB_CONTENT_ID_TAG) != 0u) {
            if (webContent_ == nullptr || untagWebId(nodeId) == 0u) return false;
            return withValue
                ? webContent_->performAccessibilityActionValue(
                      untagWebId(nodeId), action, value)
                : webContent_->performAccessibilityAction(untagWebId(nodeId),
                                                           action);
        }
        if (chrome_ == nullptr) return false;
        return withValue ? chrome_->performAccessibilityActionValue(
                               nodeId, action, value)
                         : chrome_->performAccessibilityAction(nodeId, action);
    }

public:
    AccessibilityTreeBridge(AccessibilityProvider* chrome,
                             AccessibilityProvider* webContent = nullptr)
        : chrome_(chrome), webContent_(webContent) {}

    void setWebContentProvider(AccessibilityProvider* provider) {
        webContent_ = provider;
    }
    void setWebContentViewport(const Rect& viewport) {
        webContentViewport_ = viewport;
    }

    AccessibilityTree accessibilityTree() const override {
        AccessibilityTree output;
        if (!compose(&output)) return AccessibilityTree();
        return output;
    }

    bool focusAccessibilityNode(std::uint64_t nodeId) override {
        if (nodeId == 0u) return false;
        if ((nodeId & WEB_CONTENT_ID_TAG) != 0u)
            return webContent_ != nullptr && untagWebId(nodeId) != 0u &&
                   webContent_->focusAccessibilityNode(untagWebId(nodeId));
        return chrome_ != nullptr && chrome_->focusAccessibilityNode(nodeId);
    }

    bool performAccessibilityAction(std::uint64_t nodeId,
                                    AccessibilityAction action) override {
        return dispatch(nodeId, action, "", false);
    }

    bool performAccessibilityActionValue(
        std::uint64_t nodeId, AccessibilityAction action,
        const std::string& value) override {
        return dispatch(nodeId, action, value, true);
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_ACCESSIBILITY_BRIDGE_HPP */
