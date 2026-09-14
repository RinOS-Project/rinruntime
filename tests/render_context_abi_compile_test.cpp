/* SPDX-License-Identifier: MIT */
#include <rinruntime/render_context.hpp>
#include <rinruntime/window.hpp>

int main() {
    RinRuntime::WindowOptions options;
    options.width = 320;
    options.height = 240;
    RinRuntime::ScopedRenderClip clip(0, 0, 10, 10);
    return clip.active() || !options.visible ? 0 : 0;
}
