/* SPDX-License-Identifier: MIT */
/* Bounded, allocation-free client-coordinate clipping for RinGUI. */

#ifndef RINOS_RIN_GUI_CLIP_STACK_H
#define RINOS_RIN_GUI_CLIP_STACK_H

#include <stdint.h>

#define RIN_GUI_CLIP_STACK_MAX_DEPTH 8u

/* right and bottom are exclusive.  Empty rectangles are valid stack entries:
 * they intentionally suppress all following drawing until their matching pop. */
typedef struct RinGuiClipRect {
    int32_t left;
    int32_t top;
    int32_t right;
    int32_t bottom;
} RinGuiClipRect;

typedef struct RinGuiClipStack {
    uint32_t depth;
    RinGuiClipRect entries[RIN_GUI_CLIP_STACK_MAX_DEPTH];
} RinGuiClipStack;

static inline void rin_gui_clip_stack_reset(RinGuiClipStack* stack) {
    if (!stack) return;
    stack->depth = 0u;
}

static inline int rin_gui_clip_rect_contains(const RinGuiClipRect* rect,
                                             int32_t x, int32_t y) {
    return rect && x >= rect->left && x < rect->right &&
           y >= rect->top && y < rect->bottom;
}

static inline int rin_gui_clip_stack_current(const RinGuiClipStack* stack,
                                             int32_t client_width,
                                             int32_t client_height,
                                             RinGuiClipRect* rect_out) {
    if (!stack || !rect_out || client_width <= 0 || client_height <= 0)
        return 0;
    if (stack->depth == 0u) {
        rect_out->left = 0;
        rect_out->top = 0;
        rect_out->right = client_width;
        rect_out->bottom = client_height;
    } else {
        *rect_out = stack->entries[stack->depth - 1u];
    }
    return 1;
}

/* Returns 1 on push, 0 for malformed input, and -1 when the fixed stack is
 * full.  The supplied rect is intersected with both the current clip and the
 * client area, so no caller can widen a parent viewport. */
static inline int rin_gui_clip_stack_push(RinGuiClipStack* stack,
                                          int32_t client_width,
                                          int32_t client_height,
                                          int32_t x, int32_t y,
                                          int32_t width, int32_t height) {
    RinGuiClipRect base;
    RinGuiClipRect next;
    int64_t right;
    int64_t bottom;
    if (!stack || width <= 0 || height <= 0 || client_width <= 0 ||
        client_height <= 0)
        return 0;
    if (stack->depth >= RIN_GUI_CLIP_STACK_MAX_DEPTH) return -1;
    if (!rin_gui_clip_stack_current(stack, client_width, client_height, &base))
        return 0;
    right = (int64_t)x + (int64_t)width;
    bottom = (int64_t)y + (int64_t)height;
    if (right < INT32_MIN || right > INT32_MAX ||
        bottom < INT32_MIN || bottom > INT32_MAX)
        return 0;
    next.left = x < 0 ? 0 : (x > client_width ? client_width : x);
    next.top = y < 0 ? 0 : (y > client_height ? client_height : y);
    next.right = right > client_width ? client_width : (int32_t)right;
    next.bottom = bottom > client_height ? client_height : (int32_t)bottom;
    if (next.left < base.left) next.left = base.left;
    if (next.top < base.top) next.top = base.top;
    if (next.right > base.right) next.right = base.right;
    if (next.bottom > base.bottom) next.bottom = base.bottom;
    if (next.right < next.left) next.left = next.right;
    if (next.bottom < next.top) next.top = next.bottom;
    stack->entries[stack->depth++] = next;
    return 1;
}

static inline int rin_gui_clip_stack_pop(RinGuiClipStack* stack) {
    if (!stack || stack->depth == 0u) return 0;
    --stack->depth;
    return 1;
}

#endif /* RINOS_RIN_GUI_CLIP_STACK_H */
