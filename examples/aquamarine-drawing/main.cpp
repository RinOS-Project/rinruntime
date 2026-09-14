/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>
#include <aquamarine.h>

int main() {
    RinRuntime::Window window("Aquamarine", 100, 100, 640, 480);
    window.onPaint([](AqSurface& surface) {
        aq_surface_clear(&surface, AQ_RGB(20, 24, 32));
        aq_fill_rect(&surface, 32, 32, 240, 120, AQ_RGB(48, 160, 190));
        aq_draw_string(&surface, 56, 80, "RinOS", AQ_WHITE,
                       RinRuntime::currentRenderFont());
    });
    return window.paint() == RIN_SUCCESS ? 0 : 1;
}
