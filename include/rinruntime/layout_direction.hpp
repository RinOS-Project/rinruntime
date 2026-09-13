/* SPDX-License-Identifier: MIT */
/* Backend-independent logical direction helpers for RinRuntime. */

#ifndef RINRUNTIME_LAYOUT_DIRECTION_HPP
#define RINRUNTIME_LAYOUT_DIRECTION_HPP

#include "accessibility.hpp"

namespace RinRuntime {

/* Logical inline direction is deliberately independent of locale or text
 * shaping. A toolkit chooses it from its current locale/layout policy and
 * passes it through every horizontal layout operation. */
enum class LayoutDirection : uint8_t {
    LeftToRight,
    RightToLeft
};

inline bool isRightToLeft(LayoutDirection direction) {
    return direction == LayoutDirection::RightToLeft;
}

/* Return the physical x coordinate of a child whose leading edge is at the
 * logical inline start. Invalid extents never wrap into a valid coordinate. */
inline bool logicalStartX(const Rect& bounds, int32_t childWidth,
                         LayoutDirection direction, int32_t* output) {
    int64_t value;
    if (!output || bounds.w < 0 || childWidth < 0 || childWidth > bounds.w)
        return false;
    value = isRightToLeft(direction)
                ? (int64_t)bounds.x + bounds.w - childWidth
                : bounds.x;
    if (value < INT32_MIN || value > INT32_MAX) return false;
    *output = (int32_t)value;
    return true;
}

/* Return the physical x coordinate of a child whose trailing edge is at the
 * logical inline end. */
inline bool logicalEndX(const Rect& bounds, int32_t childWidth,
                        LayoutDirection direction, int32_t* output) {
    int64_t value;
    if (!output || bounds.w < 0 || childWidth < 0 || childWidth > bounds.w)
        return false;
    value = isRightToLeft(direction)
                ? bounds.x
                : (int64_t)bounds.x + bounds.w - childWidth;
    if (value < INT32_MIN || value > INT32_MAX) return false;
    *output = (int32_t)value;
    return true;
}

/* Mirror an already-laid-out child inside a horizontal container. The child
 * must be wholly inside the container; no clipped or overflowing rect is
 * silently transformed. */
inline bool mirrorHorizontalRect(const Rect& bounds, const Rect& child,
                                Rect* output) {
    int64_t relativeLeft;
    int64_t mirroredLeft;
    if (!output || bounds.w < 0 || bounds.h < 0 || child.w < 0 || child.h < 0)
        return false;
    if ((int64_t)child.x < bounds.x || (int64_t)child.y < bounds.y ||
        (int64_t)child.x + child.w > (int64_t)bounds.x + bounds.w ||
        (int64_t)child.y + child.h > (int64_t)bounds.y + bounds.h)
        return false;
    relativeLeft = (int64_t)child.x - bounds.x;
    mirroredLeft = (int64_t)bounds.x + bounds.w - relativeLeft - child.w;
    if (mirroredLeft < INT32_MIN || mirroredLeft > INT32_MAX) return false;
    *output = Rect((int32_t)mirroredLeft, child.y, child.w, child.h);
    return true;
}

} // namespace RinRuntime

#endif /* RINRUNTIME_LAYOUT_DIRECTION_HPP */
