/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>
#include <rinruntime/render_context.hpp>
#include <aquamarine.h>

int main() {
    RinRuntime::Window window("Clipping", 100, 100, 640, 480);
    window.onPaint([](AqSurface& surface) {
        aq_surface_clear(&surface, AQ_BLACK);
        RinRuntime::ScopedRenderClip clip(20, 20, 300, 180);
        if (clip.active()) aq_fill_rect(&surface, 0, 0, 640, 480, AQ_RED);
    });
    return window.paint() == RIN_SUCCESS ? 0 : 1;
}
