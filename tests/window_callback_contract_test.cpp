/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstdint>

#include <rinruntime/window.hpp>

extern "C" RinRuntimeGuiHandle wnd_create(const char*, int, int, int, int) {
    return 1u;
}

extern "C" int wnd_poll_native(RinRuntimeGuiHandle,
                                RinGuiNativeEventV1* event,
                                std::uint32_t*) {
    *event = RinGuiNativeEventV1{};
    event->struct_size = sizeof(*event);
    event->version = RIN_GUI_NATIVE_EVENT_VERSION;
    event->type = 2u;
    return 1;
}

extern "C" void wnd_close(RinRuntimeGuiHandle) {}

namespace RinRuntime {

int beginNativeFrame(RinRuntimeGuiHandle) noexcept {
    return RIN_SUCCESS;
}

AqSurface* currentRenderSurface() noexcept {
    static AqSurface surface{};
    return &surface;
}

int endNativeFrame() noexcept {
    return RIN_SUCCESS;
}

} // namespace RinRuntime

int main() {
    RinRuntime::Window window("callback-test", 0, 0, 320, 200);
    assert(window.valid());

    int callbackCount = 0;
    int nestedResult = RIN_SUCCESS;
    window.onEvent([&](const RinRuntime::WindowEvent&) {
        ++callbackCount;
        nestedResult = window.dispatch();
        return true;
    });

    assert(window.dispatch() == 1);
    assert(callbackCount == 1);
    assert(nestedResult == RIN_ERROR_BUSY);
    assert(window.dispatch() == 1);
    assert(callbackCount == 2);

    int paintCallbackCount = 0;
    int nestedPaintResult = RIN_SUCCESS;
    window.onPaint([&] {
        ++paintCallbackCount;
        nestedPaintResult = window.paint();
    });
    assert(window.paint() == RIN_SUCCESS);
    assert(paintCallbackCount == 1);
    assert(nestedPaintResult == RIN_ERROR_BUSY);
    assert(window.paint() == RIN_SUCCESS);
    assert(paintCallbackCount == 2);
    return 0;
}
