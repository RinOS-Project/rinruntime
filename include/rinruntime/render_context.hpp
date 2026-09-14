/* SPDX-License-Identifier: MIT */
/* Thread-local C++ render context over the public C frame ABI. */
#pragma once

#include <cstdint>
#include "../../../aquamarine/aq_types.h"
#include "window.h"

namespace RinRuntime {

/* All returned pointers are borrowed.  They are non-null only while the
 * calling thread owns an active frame started by beginNativeFrame.  A client
 * must finish the frame before presenting or using a different window. */
AqSurface* currentRenderSurface() noexcept;
const AqFont* currentRenderFont() noexcept;
RinRuntimeGuiHandle currentRenderWindow() noexcept;
std::int32_t currentFrameWidth() noexcept;
std::int32_t currentFrameHeight() noexcept;
float currentFrameScale() noexcept;
bool currentFrameValid() noexcept;

int beginNativeFrame(RinRuntimeGuiHandle handle) noexcept;
int endNativeFrame() noexcept;
int pushRenderClip(std::int32_t x, std::int32_t y,
                   std::int32_t width, std::int32_t height) noexcept;
int popRenderClip() noexcept;
int readRenderPixel(std::int32_t x, std::int32_t y,
                    std::uint32_t* color) noexcept;

class ScopedRenderClip final {
public:
    ScopedRenderClip(std::int32_t x, std::int32_t y,
                     std::int32_t width, std::int32_t height) noexcept;
    ~ScopedRenderClip() noexcept;

    ScopedRenderClip(const ScopedRenderClip&) = delete;
    ScopedRenderClip& operator=(const ScopedRenderClip&) = delete;
    bool active() const noexcept { return active_; }

private:
    bool active_ = false;
};

} // namespace RinRuntime

/* Source compatibility for existing RinRuntime widgets.  Private frame
 * bookkeeping types are intentionally not part of this surface. */
namespace Rin {
using RinRuntime::beginNativeFrame;
using RinRuntime::currentFrameHeight;
using RinRuntime::currentFrameScale;
using RinRuntime::currentFrameValid;
using RinRuntime::currentFrameWidth;
using RinRuntime::currentRenderFont;
using RinRuntime::currentRenderSurface;
using RinRuntime::endNativeFrame;
using RinRuntime::popRenderClip;
using RinRuntime::pushRenderClip;
using RinRuntime::readRenderPixel;
} // namespace Rin
