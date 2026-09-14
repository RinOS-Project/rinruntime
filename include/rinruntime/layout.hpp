/* SPDX-License-Identifier: MIT */
/* Backend-independent common layout primitives for RinRuntime. */

#ifndef RINRUNTIME_LAYOUT_HPP
#define RINRUNTIME_LAYOUT_HPP

#include <utility>

#include "layout_direction.hpp"

namespace RinRuntime {

struct LayoutSize {
    int32_t width;
    int32_t height;
};

struct ControlTargetPolicy {
    int32_t minimumWidth;
    int32_t minimumHeight;
};

static const ControlTargetPolicy kDefaultControlTarget = {32, 32};

inline LayoutSize enforceControlTarget(LayoutSize requested,
                                       ControlTargetPolicy policy =
                                           kDefaultControlTarget) {
    LayoutSize result = requested;
    if (result.width < policy.minimumWidth) result.width = policy.minimumWidth;
    if (result.height < policy.minimumHeight) result.height = policy.minimumHeight;
    return result;
}

struct LayoutItem {
    LayoutSize minimum;
    uint32_t weight;
    bool visible;
};

/* Text controls do not own a font backend in RinRuntime.  Keep their layout
 * contract deterministic by using the toolkit's nominal advance and by
 * preserving UTF-8 scalar boundaries when a localized label is elided. */
static const int32_t kDefaultTextAdvance = 8;
static const int32_t kDefaultLocalizedLabelMaxWidth = 320;

namespace text_detail {

inline size_t scalarLength(const unsigned char* value, size_t remaining) {
    if (!value || remaining == 0u) return 0u;
    if (value[0] < 0x80u) return 1u;
    if (value[0] >= 0xc2u && value[0] <= 0xdfu)
        return remaining >= 2u && (value[1] & 0xc0u) == 0x80u ? 2u : 1u;
    if (value[0] >= 0xe0u && value[0] <= 0xefu) {
        if (remaining < 3u || (value[1] & 0xc0u) != 0x80u ||
            (value[2] & 0xc0u) != 0x80u)
            return 1u;
        if (value[0] == 0xe0u && value[1] < 0xa0u) return 1u;
        if (value[0] == 0xedu && value[1] >= 0xa0u) return 1u;
        return 3u;
    }
    if (value[0] >= 0xf0u && value[0] <= 0xf4u) {
        if (remaining < 4u || (value[1] & 0xc0u) != 0x80u ||
            (value[2] & 0xc0u) != 0x80u ||
            (value[3] & 0xc0u) != 0x80u)
            return 1u;
        if (value[0] == 0xf0u && value[1] < 0x90u) return 1u;
        if (value[0] == 0xf4u && value[1] >= 0x90u) return 1u;
        return 4u;
    }
    return 1u;
}

inline size_t prefixBytes(const std::string& text, size_t scalarCount) {
    size_t offset = 0u;
    size_t count = 0u;
    while (offset < text.size() && count < scalarCount) {
        size_t length = scalarLength(
            reinterpret_cast<const unsigned char*>(text.data() + offset),
            text.size() - offset);
        if (length == 0u) break;
        offset += length;
        ++count;
    }
    return offset;
}

} // namespace text_detail

inline size_t utf8ScalarCount(const std::string& text) {
    size_t offset = 0u;
    size_t count = 0u;
    while (offset < text.size()) {
        size_t length = text_detail::scalarLength(
            reinterpret_cast<const unsigned char*>(text.data() + offset),
            text.size() - offset);
        if (length == 0u) break;
        offset += length;
        ++count;
    }
    return count;
}

inline int32_t textPixelWidth(const std::string& text,
                              int32_t advance = kDefaultTextAdvance) {
    if (advance <= 0) return 0;
    size_t count = utf8ScalarCount(text);
    int64_t width = (int64_t)count * advance;
    return width > INT32_MAX ? INT32_MAX : (int32_t)width;
}

inline LayoutSize localizedTextMinimumLayoutSize(
    const std::string& text, int32_t height = 20,
    int32_t maxWidth = kDefaultLocalizedLabelMaxWidth,
    int32_t advance = kDefaultTextAdvance) {
    int32_t width = textPixelWidth(text, advance);
    if (maxWidth >= 0 && width > maxWidth) width = maxWidth;
    return enforceControlTarget({width, height});
}

inline std::string ellipsizeText(const std::string& text, int32_t width,
                                 int32_t advance = kDefaultTextAdvance) {
    if (width <= 0 || advance <= 0) return "";
    size_t capacity = (size_t)(width / advance);
    size_t count = utf8ScalarCount(text);
    if (count <= capacity) return text;
    if (capacity <= 3u) {
        size_t bytes = text_detail::prefixBytes(text, capacity);
        return text.substr(0u, bytes);
    }
    size_t bytes = text_detail::prefixBytes(text, capacity - 3u);
    std::string result;
    result.append(text.data(), bytes);
    result.append("...");
    return result;
}

namespace detail {

inline bool validBounds(const Rect& bounds) {
    return bounds.w >= 0 && bounds.h >= 0 &&
           (int64_t)bounds.x + bounds.w <= INT32_MAX &&
           (int64_t)bounds.y + bounds.h <= INT32_MAX;
}

inline bool validItems(const std::vector<LayoutItem>& items) {
    for (const auto& item : items) {
        if (item.minimum.width < 0 || item.minimum.height < 0) return false;
    }
    return true;
}

inline bool assignLinearSizes(const std::vector<LayoutItem>& items,
                              bool horizontal, int32_t available,
                              int32_t gap, std::vector<int32_t>* sizes) {
    size_t visibleCount = 0u;
    int64_t required = 0;
    uint64_t totalWeight = 0u;
    int64_t extra;
    int64_t assigned = 0;
    size_t index;

    if (!sizes || available < 0 || gap < 0 || !validItems(items)) return false;
    sizes->clear();
    sizes->resize(items.size(), 0);
    for (const auto& item : items) {
        if (!item.visible) continue;
        ++visibleCount;
        required += horizontal ? item.minimum.width : item.minimum.height;
        totalWeight += item.weight;
    }
    if (visibleCount == 0u) return true;
    required += (int64_t)(visibleCount - 1u) * gap;
    if (required > available) return false;

    for (index = 0u; index < items.size(); ++index) {
        const LayoutItem& item = items[index];
        int64_t share = 0;
        if (!item.visible) continue;
        if (totalWeight != 0u)
            share = ((int64_t)available - required) * item.weight / totalWeight;
        (*sizes)[index] = (horizontal ? item.minimum.width : item.minimum.height) +
                          (int32_t)share;
        assigned += share;
    }

    extra = (int64_t)available - required - assigned;
    for (index = 0u; extra > 0 && index < items.size(); ++index) {
        if (items[index].visible && items[index].weight != 0u) {
            ++(*sizes)[index];
            --extra;
        }
    }
    return true;
}

} // namespace detail

inline bool layoutHBox(const Rect& bounds, const std::vector<LayoutItem>& items,
                       int32_t gap, std::vector<Rect>* output,
                       LayoutDirection direction = LayoutDirection::LeftToRight) {
    std::vector<int32_t> widths;
    std::vector<Rect> result;
    int64_t position;
    size_t index;

    if (!output || !detail::validBounds(bounds) ||
        !detail::assignLinearSizes(items, true, bounds.w, gap, &widths))
        return false;
    result.resize(items.size(), Rect(0, 0, 0, 0));
    position = direction == LayoutDirection::LeftToRight
                   ? bounds.x
                   : (int64_t)bounds.x + bounds.w;
    for (index = 0u; index < items.size(); ++index) {
        if (!items[index].visible) continue;
        if (direction == LayoutDirection::LeftToRight) {
            result[index] = Rect((int32_t)position, bounds.y, widths[index], bounds.h);
            position += (int64_t)widths[index] + gap;
        } else {
            position -= widths[index];
            result[index] = Rect((int32_t)position, bounds.y, widths[index], bounds.h);
            position -= gap;
        }
    }
    *output = std::move(result);
    return true;
}

inline bool layoutVBox(const Rect& bounds, const std::vector<LayoutItem>& items,
                       int32_t gap, std::vector<Rect>* output) {
    std::vector<int32_t> heights;
    std::vector<Rect> result;
    int64_t position;
    size_t index;

    if (!output || !detail::validBounds(bounds) ||
        !detail::assignLinearSizes(items, false, bounds.h, gap, &heights))
        return false;
    result.resize(items.size(), Rect(0, 0, 0, 0));
    position = bounds.y;
    for (index = 0u; index < items.size(); ++index) {
        if (!items[index].visible) continue;
        result[index] = Rect(bounds.x, (int32_t)position, bounds.w, heights[index]);
        position += (int64_t)heights[index] + gap;
    }
    *output = std::move(result);
    return true;
}

inline bool layoutGrid(const Rect& bounds, const std::vector<LayoutItem>& items,
                       uint32_t columns, int32_t horizontalGap, int32_t verticalGap,
                       std::vector<Rect>* output,
                       LayoutDirection direction = LayoutDirection::LeftToRight) {
    std::vector<int32_t> columnWidths;
    std::vector<int32_t> rowHeights;
    std::vector<Rect> result;
    size_t visibleCount = 0u;
    size_t rows;
    int64_t widthRequired = 0;
    int64_t heightRequired = 0;
    int64_t widthExtra;
    int64_t heightExtra;
    size_t itemIndex;
    size_t visibleIndex = 0u;

    if (!output || !detail::validBounds(bounds) || !detail::validItems(items) ||
        columns == 0u || horizontalGap < 0 || verticalGap < 0) return false;
    for (const auto& item : items) if (item.visible) ++visibleCount;
    result.resize(items.size(), Rect(0, 0, 0, 0));
    if (visibleCount == 0u) {
        *output = std::move(result);
        return true;
    }
    rows = (visibleCount + columns - 1u) / columns;
    columnWidths.resize(columns, 0);
    rowHeights.resize(rows, 0);
    for (itemIndex = 0u; itemIndex < items.size(); ++itemIndex) {
        size_t column;
        size_t row;
        if (!items[itemIndex].visible) continue;
        column = visibleIndex % columns;
        row = visibleIndex / columns;
        if (items[itemIndex].minimum.width > columnWidths[column])
            columnWidths[column] = items[itemIndex].minimum.width;
        if (items[itemIndex].minimum.height > rowHeights[row])
            rowHeights[row] = items[itemIndex].minimum.height;
        ++visibleIndex;
    }
    for (const auto value : columnWidths) widthRequired += value;
    for (const auto value : rowHeights) heightRequired += value;
    widthRequired += (int64_t)(columns - 1u) * horizontalGap;
    heightRequired += (int64_t)(rows - 1u) * verticalGap;
    if (widthRequired > bounds.w || heightRequired > bounds.h) return false;
    widthExtra = bounds.w - widthRequired;
    heightExtra = bounds.h - heightRequired;
    for (itemIndex = 0u; itemIndex < columns; ++itemIndex)
        columnWidths[itemIndex] += (int32_t)(widthExtra / columns +
            (itemIndex < (size_t)(widthExtra % columns) ? 1 : 0));
    for (itemIndex = 0u; itemIndex < rows; ++itemIndex)
        rowHeights[itemIndex] += (int32_t)(heightExtra / rows +
            (itemIndex < (size_t)(heightExtra % rows) ? 1 : 0));

    visibleIndex = 0u;
    for (itemIndex = 0u; itemIndex < items.size(); ++itemIndex) {
        size_t column;
        size_t row;
        int64_t x;
        int64_t y = bounds.y;
        size_t cursor;
        if (!items[itemIndex].visible) continue;
        column = visibleIndex % columns;
        row = visibleIndex / columns;
        if (direction == LayoutDirection::LeftToRight) {
            x = bounds.x;
            for (cursor = 0u; cursor < column; ++cursor)
                x += (int64_t)columnWidths[cursor] + horizontalGap;
        } else {
            x = (int64_t)bounds.x + bounds.w;
            for (cursor = 0u; cursor <= column; ++cursor)
                x -= columnWidths[cursor] + (cursor == column ? 0 : horizontalGap);
        }
        for (cursor = 0u; cursor < row; ++cursor)
            y += (int64_t)rowHeights[cursor] + verticalGap;
        result[itemIndex] = Rect((int32_t)x, (int32_t)y,
                                 columnWidths[column], rowHeights[row]);
        ++visibleIndex;
    }
    *output = std::move(result);
    return true;
}

inline bool layoutStack(const Rect& bounds, const std::vector<LayoutItem>& items,
                        std::vector<Rect>* output) {
    std::vector<Rect> result;
    if (!output || !detail::validBounds(bounds) || !detail::validItems(items))
        return false;
    result.resize(items.size(), Rect(0, 0, 0, 0));
    for (size_t index = 0u; index < items.size(); ++index) {
        if (items[index].visible) result[index] = bounds;
    }
    *output = std::move(result);
    return true;
}

} // namespace RinRuntime

#endif /* RINRUNTIME_LAYOUT_HPP */
