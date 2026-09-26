/* SPDX-License-Identifier: MIT */
/* Thread-local C++ render context over the public C frame ABI. */
#pragma once

#include <cstdint>
#include "../../../aquamarine/aq_types.h"
#include "window.h"

namespace RinRuntime {

/* A product or application owner may provide a borrowed, already-authorized
 * UI font.  RinRuntime only stores the returned font pointer for the process
 * lifetime; the callback owns its resource bytes and must keep the font alive
 * until process shutdown.  The callback has no path, descriptor, or service
 * authority in its contract, so ordinary applications may provide their own
 * resource owner without importing the Desktop adapter. */
using SystemUiFontLoaderFunction = const AqFont* (*)(void* context);

/* Register the optional font owner before the first call to systemUiFont().
 * The public runtime itself falls back to Aquamarine's built-in font when no
 * owner is registered or the owner cannot provide a font. */
int setSystemUiFontLoader(SystemUiFontLoaderFunction loader,
                          void* context = nullptr) noexcept;

/* All returned pointers are borrowed.  They are non-null only while the
 * calling thread owns an active frame started by beginNativeFrame.  A client
 * must finish the frame before presenting or using a different window. */
AqSurface* currentRenderSurface() noexcept;
const AqFont* currentRenderFont() noexcept;
/* Process-wide locale-selected font used by native UI outside a render
 * context, such as desktop-owned compositor surfaces. */
const AqFont* systemUiFont() noexcept;
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
using RinRuntime::systemUiFont;
using RinRuntime::setSystemUiFontLoader;
using RinRuntime::endNativeFrame;
using RinRuntime::popRenderClip;
using RinRuntime::pushRenderClip;
using RinRuntime::readRenderPixel;
} // namespace Rin
