/* SPDX-License-Identifier: MIT */
/* Backend-independent window surface layout policy for RinRuntime. */

#ifndef RINRUNTIME_WINDOW_LAYOUT_HPP
#define RINRUNTIME_WINDOW_LAYOUT_HPP

#include <utility>

#include "layout.hpp"

namespace RinRuntime {

/* Keep callers from accidentally turning an untrusted window count into an
 * unbounded allocation.  A desktop normally has far fewer tiled windows, and
 * callers can partition larger sets themselves. */
static const uint32_t kMaxTiledWindows = 64u;

inline bool validWorkArea(const Rect& workArea) {
    return workArea.w > 0 && workArea.h > 0 &&
           (int64_t)workArea.x + workArea.w <= INT32_MAX &&
           (int64_t)workArea.y + workArea.h <= INT32_MAX;
}

inline bool maximizeWindowBounds(const Rect& workArea, Rect* output) {
    if (!output || !validWorkArea(workArea)) return false;
    *output = workArea;
    return true;
}

/* Position existing windows on a responsive diagonal.  The step is derived
 * from the work-area minimum dimension and each window is clamped to the
 * area, so cascade placement never relies on a fixed desktop pixel size. */
inline bool cascadeWindowBounds(const Rect& workArea,
                                const std::vector<Rect>& windows,
                                std::vector<Rect>* output) {
    std::vector<Rect> result;
    int32_t step;

    if (!output || !validWorkArea(workArea) ||
        windows.size() > kMaxTiledWindows)
        return false;
    step = workArea.w < workArea.h ? workArea.w / 12 : workArea.h / 12;
    if (step < 8) step = 8;
    if (step > 64) step = 64;
    result.reserve(windows.size());
    for (size_t index = 0u; index < windows.size(); ++index) {
        const Rect& source = windows[index];
        if (source.w <= 0 || source.h <= 0) return false;
        int32_t width = source.w > workArea.w ? workArea.w : source.w;
        int32_t height = source.h > workArea.h ? workArea.h : source.h;
        int32_t maxX = workArea.w - width;
        int32_t maxY = workArea.h - height;
        int64_t diagonal = (int64_t)step * (int64_t)index;
        int32_t offsetX = maxX > 0 ? (int32_t)(diagonal % (maxX + 1)) : 0;
        int32_t offsetY = maxY > 0 ? (int32_t)(diagonal % (maxY + 1)) : 0;
        result.push_back(Rect(workArea.x + offsetX, workArea.y + offsetY,
                              width, height));
    }
    *output = std::move(result);
    return true;
}

/* Partition a work area into deterministic grid-aligned tiles.  Integer
 * boundaries are computed from the original area for every column/row, so
 * remainder pixels are distributed without overlap or trailing gaps inside
 * each occupied grid cell. */
inline bool tileWindowBounds(const Rect& workArea, uint32_t windowCount,
                             std::vector<Rect>* output) {
    std::vector<Rect> result;
    uint32_t columns;
    uint32_t rows;

    if (!output || !validWorkArea(workArea) ||
        windowCount > kMaxTiledWindows)
        return false;
    if (windowCount == 0u) {
        output->clear();
        return true;
    }

    columns = 1u;
    while ((uint64_t)columns * columns < windowCount) ++columns;
    rows = (windowCount + columns - 1u) / columns;

    result.reserve(windowCount);
    for (uint32_t index = 0u; index < windowCount; ++index) {
        uint32_t column = index % columns;
        uint32_t row = index / columns;
        int32_t left = (int32_t)((int64_t)workArea.x +
                                 (int64_t)workArea.w * column / columns);
        int32_t right = (int32_t)((int64_t)workArea.x +
                                  (int64_t)workArea.w * (column + 1u) /
                                      columns);
        int32_t top = (int32_t)((int64_t)workArea.y +
                                (int64_t)workArea.h * row / rows);
        int32_t bottom = (int32_t)((int64_t)workArea.y +
                                   (int64_t)workArea.h * (row + 1u) / rows);
        result.push_back(Rect(left, top, right - left, bottom - top));
    }
    *output = std::move(result);
    return true;
}

} // namespace RinRuntime

#endif /* RINRUNTIME_WINDOW_LAYOUT_HPP */
