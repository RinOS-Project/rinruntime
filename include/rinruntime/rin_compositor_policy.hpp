/* SPDX-License-Identifier: MIT */
/* Allocation-free policy primitives shared by compositor tests and service. */
#pragma once

#include <stdint.h>
#include "../../public-base/RinOS-SDK/include/rin/compositor_protocol.h"

struct RinCompositorRectPolicy {
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
};

static inline bool rin_compositor_rect_empty(const RinCompositorRectPolicy& r)
{
    return r.w == 0u || r.h == 0u;
}

static inline bool rin_compositor_rect_contains(
    const RinCompositorRectPolicy& r, int32_t x, int32_t y)
{
    return !rin_compositor_rect_empty(r) &&
           (int64_t)x >= r.x && (int64_t)y >= r.y &&
           (int64_t)x < (int64_t)r.x + r.w &&
           (int64_t)y < (int64_t)r.y + r.h;
}

static inline bool rin_compositor_role_is_shell(uint32_t role)
{
    return role == RIN_COMPOSITOR_ROLE_DESKTOP ||
           role == RIN_COMPOSITOR_ROLE_PANEL;
}

static inline bool rin_compositor_role_is_popup(uint32_t role)
{
    return role == RIN_COMPOSITOR_ROLE_POPUP ||
           role == RIN_COMPOSITOR_ROLE_MENU ||
           role == RIN_COMPOSITOR_ROLE_DIALOG ||
           role == RIN_COMPOSITOR_ROLE_TOOLTIP ||
           role == RIN_COMPOSITOR_ROLE_NOTIFICATION;
}

static inline int32_t rin_compositor_role_default_z(uint32_t role)
{
    switch (role) {
        case RIN_COMPOSITOR_ROLE_DESKTOP: return -30000;
        case RIN_COMPOSITOR_ROLE_PANEL: return 20000;
        case RIN_COMPOSITOR_ROLE_POPUP: return 30000;
        case RIN_COMPOSITOR_ROLE_MENU: return 31000;
        case RIN_COMPOSITOR_ROLE_DIALOG: return 32000;
        case RIN_COMPOSITOR_ROLE_TOOLTIP: return 33000;
        case RIN_COMPOSITOR_ROLE_NOTIFICATION: return 34000;
        case RIN_COMPOSITOR_ROLE_CURSOR: return 40000;
        default: return 0;
    }
}

static inline bool rin_compositor_z_allowed(uint32_t role, int32_t z)
{
    if (role == RIN_COMPOSITOR_ROLE_DESKTOP)
        return z >= -32768 && z <= -20000;
    if (role == RIN_COMPOSITOR_ROLE_PANEL)
        return z >= 10000 && z <= 29999;
    if (rin_compositor_role_is_popup(role))
        return z >= 30000 && z <= 39999;
    if (role == RIN_COMPOSITOR_ROLE_CURSOR)
        return z >= 40000;
    return z >= -19999 && z <= 9999;
}

/* The compositor has one pointer capture and one keyboard grab per active
 * foreground session.  The helper makes the focus-stealing rules explicit. */
struct RinCompositorInputPolicy {
    uint32_t focused_surface = 0u;
    uint32_t pointer_capture = 0u;
    uint32_t keyboard_grab = 0u;
    uint32_t modal_surface = 0u;
};

static inline void rin_compositor_input_clear_surface(
    RinCompositorInputPolicy& policy, uint32_t surface_id)
{
    if (policy.focused_surface == surface_id) policy.focused_surface = 0u;
    if (policy.pointer_capture == surface_id) policy.pointer_capture = 0u;
    if (policy.keyboard_grab == surface_id) policy.keyboard_grab = 0u;
    if (policy.modal_surface == surface_id) policy.modal_surface = 0u;
}

static inline bool rin_compositor_focus_allowed(
    const RinCompositorInputPolicy& policy, uint32_t surface_id,
    bool visible, bool foreground)
{
    (void)policy;
    return surface_id != 0u && visible && foreground;
}

static inline uint32_t rin_compositor_pointer_target(
    const RinCompositorInputPolicy& policy, uint32_t hit_surface)
{
    /* A modal surface is the strongest input boundary.  Capture/grab state
     * from the pre-modal interaction must not leak around it. */
    if (policy.modal_surface != 0u)
        return hit_surface == policy.modal_surface ? hit_surface : 0u;
    return policy.pointer_capture != 0u ? policy.pointer_capture : hit_surface;
}

static inline uint32_t rin_compositor_keyboard_target(
    const RinCompositorInputPolicy& policy)
{
    return policy.modal_surface != 0u ? policy.modal_surface :
           (policy.keyboard_grab != 0u ? policy.keyboard_grab :
                                         policy.focused_surface);
}

static inline bool rin_compositor_damage_overlaps_or_touches(
    const RinCompositorRectPolicy& left,
    const RinCompositorRectPolicy& right)
{
    return (int64_t)left.x <= (int64_t)right.x + right.w &&
           (int64_t)right.x <= (int64_t)left.x + left.w &&
           (int64_t)left.y <= (int64_t)right.y + right.h &&
           (int64_t)right.y <= (int64_t)left.y + left.h;
}

static inline RinCompositorRectPolicy rin_compositor_damage_union(
    const RinCompositorRectPolicy& left,
    const RinCompositorRectPolicy& right)
{
    int64_t right_edge = (int64_t)left.x + left.w;
    int64_t bottom_edge = (int64_t)left.y + left.h;
    int64_t other_right = (int64_t)right.x + right.w;
    int64_t other_bottom = (int64_t)right.y + right.h;
    RinCompositorRectPolicy result{};
    result.x = left.x < right.x ? left.x : right.x;
    result.y = left.y < right.y ? left.y : right.y;
    if (other_right > right_edge) right_edge = other_right;
    if (other_bottom > bottom_edge) bottom_edge = other_bottom;
    result.w = right_edge - result.x > UINT32_MAX ? UINT32_MAX :
               (uint32_t)(right_edge - result.x);
    result.h = bottom_edge - result.y > UINT32_MAX ? UINT32_MAX :
               (uint32_t)(bottom_edge - result.y);
    return result;
}
