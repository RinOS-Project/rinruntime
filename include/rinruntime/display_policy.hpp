/* SPDX-License-Identifier: MIT */
/*
 * Display and accessibility policy shared by backend-independent widgets.
 *
 * Applications retain logical (device-independent) layout coordinates.  A
 * renderer selects one policy for a surface and asks the model to convert
 * sizes and bounds immediately before drawing or hit testing.  This keeps
 * monitor DPI, user font preference and high-contrast settings out of
 * application-specific controls.
 */

#ifndef RINRUNTIME_DISPLAY_POLICY_HPP
#define RINRUNTIME_DISPLAY_POLICY_HPP

#include "layout.hpp"

namespace RinRuntime {

struct DisplayScale {
    uint32_t numerator = 1u;
    uint32_t denominator = 1u;

    /* A bounded range prevents invalid settings from overflowing coordinates.
     * It includes the common 100%, 125%, 150%, 175% and 200% DPI values. */
    bool valid() const {
        return numerator != 0u && denominator != 0u &&
               (uint64_t)numerator <= (uint64_t)denominator * 8u &&
               (uint64_t)denominator <= (uint64_t)numerator * 8u;
    }

    bool scaleCoordinate(int32_t logical, int32_t* physical) const {
        int64_t product;
        int64_t rounded;

        if (!physical || !valid()) return false;
        product = (int64_t)logical * numerator;
        if (product >= 0)
            rounded = (product + (int64_t)denominator / 2) / denominator;
        else
            rounded = (product - (int64_t)denominator / 2) / denominator;
        if (rounded < INT32_MIN || rounded > INT32_MAX) return false;
        *physical = (int32_t)rounded;
        return true;
    }

    bool scaleSize(int32_t logical, int32_t* physical) const {
        if (logical < 0) return false;
        return scaleCoordinate(logical, physical);
    }
};

struct WidgetColor {
    uint8_t red;
    uint8_t green;
    uint8_t blue;
    uint8_t alpha;
};

/* Renderers map these semantic roles to their own brush/font primitives. */
struct WidgetColorPalette {
    WidgetColor background;
    WidgetColor foreground;
    WidgetColor disabledForeground;
    WidgetColor accent;
    WidgetColor focusOutline;
};

enum class HighContrastSurface : uint8_t {
    Light,
    Dark
};

inline WidgetColorPalette highContrastPalette(HighContrastSurface surface) {
    if (surface == HighContrastSurface::Dark) {
        return {{0u, 0u, 0u, 255u}, {255u, 255u, 255u, 255u},
                {160u, 160u, 160u, 255u}, {0u, 255u, 255u, 255u},
                {255u, 255u, 0u, 255u}};
    }
    return {{255u, 255u, 255u, 255u}, {0u, 0u, 0u, 255u},
            {96u, 96u, 96u, 255u}, {0u, 0u, 160u, 255u},
            {0u, 0u, 0u, 255u}};
}

struct DisplayAccessibilityPolicy {
    DisplayScale uiScale = {};
    DisplayScale fontScale = {};
    bool highContrast = false;
    bool reducedMotion = false;

    bool valid() const { return uiScale.valid() && fontScale.valid(); }

    bool logicalToPhysical(const Rect& logical, Rect* physical) const {
        Rect result;

        if (!physical || logical.w < 0 || logical.h < 0 || !valid() ||
            !uiScale.scaleCoordinate(logical.x, &result.x) ||
            !uiScale.scaleCoordinate(logical.y, &result.y) ||
            !uiScale.scaleSize(logical.w, &result.w) ||
            !uiScale.scaleSize(logical.h, &result.h))
            return false;
        *physical = result;
        return true;
    }

    bool scaleLayoutSize(LayoutSize logical, LayoutSize* physical) const {
        LayoutSize result;

        if (!physical || !valid() ||
            !uiScale.scaleSize(logical.width, &result.width) ||
            !uiScale.scaleSize(logical.height, &result.height))
            return false;
        *physical = result;
        return true;
    }

    bool scaleFontPixels(int32_t logicalPixels, int32_t* physicalPixels) const {
        if (!valid()) return false;
        return fontScale.scaleSize(logicalPixels, physicalPixels);
    }

    bool scaleControlTarget(ControlTargetPolicy logical,
                            ControlTargetPolicy* physical) const {
        ControlTargetPolicy result;

        if (!physical || !valid() ||
            !uiScale.scaleSize(logical.minimumWidth, &result.minimumWidth) ||
            !uiScale.scaleSize(logical.minimumHeight, &result.minimumHeight))
            return false;
        *physical = result;
        return true;
    }

    /* Reduced motion means a state transition is presented immediately. */
    uint32_t animationDurationMillis(uint32_t requestedMillis) const {
        return reducedMotion ? 0u : requestedMillis;
    }

    WidgetColorPalette palette(HighContrastSurface surface) const {
        if (highContrast) return highContrastPalette(surface);
        if (surface == HighContrastSurface::Dark) {
            return {{32u, 32u, 32u, 255u}, {240u, 240u, 240u, 255u},
                    {144u, 144u, 144u, 255u}, {80u, 168u, 255u, 255u},
                    {112u, 192u, 255u, 255u}};
        }
        return {{255u, 255u, 255u, 255u}, {32u, 32u, 32u, 255u},
                {112u, 112u, 112u, 255u}, {0u, 96u, 200u, 255u},
                {0u, 96u, 200u, 255u}};
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_DISPLAY_POLICY_HPP */
