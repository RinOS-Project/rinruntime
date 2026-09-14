/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>
#include <aquamarine.h>

int main() {
    RinRuntime::Window window("Hello", 100, 100, 640, 480);
    window.onPaint([] {
        AqSurface* surface = RinRuntime::currentRenderSurface();
        if (surface) aq_surface_clear(surface, AQ_RGB(24, 32, 48));
    });
    return window.paint() == RIN_SUCCESS ? 0 : 1;
}
