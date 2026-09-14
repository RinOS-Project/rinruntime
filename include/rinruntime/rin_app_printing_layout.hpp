/* SPDX-License-Identifier: MIT */
/* Geometry policy for the renderer-independent print preview overlay. */
#pragma once

#include <algorithm>
#include <cstdint>

namespace Rin {

struct PrintPreviewLayout {
    static constexpr int logicalWidth = 700;
    static constexpr int logicalHeight = 550;

    int originX = 0;
    int originY = 0;
    int width = logicalWidth;
    int height = logicalHeight;

    static PrintPreviewLayout forSurface(int surfaceWidth, int surfaceHeight)
    {
        PrintPreviewLayout result;
        if (surfaceWidth <= 0 || surfaceHeight <= 0) {
            result.width = 0;
            result.height = 0;
            return result;
        }

        auto const maxWidthByHeight = static_cast<int>(
            std::min<int64_t>(surfaceWidth,
                static_cast<int64_t>(surfaceHeight) * logicalWidth / logicalHeight));
        result.width = std::max(1, maxWidthByHeight);
        result.height = std::max(1, static_cast<int>(
            (static_cast<int64_t>(result.width) * logicalHeight + logicalWidth / 2) /
            logicalWidth));
        result.originX = (surfaceWidth - result.width) / 2;
        result.originY = (surfaceHeight - result.height) / 2;
        return result;
    }

    bool valid() const
    {
        return width > 0 && height > 0 && originX >= 0 && originY >= 0;
    }

    int x(int logical) const
    {
        return originX + static_cast<int>(static_cast<int64_t>(logical) * width / logicalWidth);
    }

    int y(int logical) const
    {
        return originY + static_cast<int>(static_cast<int64_t>(logical) * height / logicalHeight);
    }

    int right(int logical) const { return x(logical); }
    int bottom(int logical) const { return y(logical); }

    int w(int logicalX, int logicalWidthValue) const
    {
        return std::max(1, x(logicalX + logicalWidthValue) - x(logicalX));
    }

    int h(int logicalY, int logicalHeightValue) const
    {
        return std::max(1, y(logicalY + logicalHeightValue) - y(logicalY));
    }

    int radius(int logicalRadius) const
    {
        return std::max(1, w(0, logicalRadius));
    }
};

} // namespace Rin
