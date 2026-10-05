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

static RinRuntimeGuiCompletionCallback completion_callback = nullptr;
static void* completion_context = nullptr;

extern "C" int wnd_set_compositor_completion_callback(
    RinRuntimeGuiHandle, RinRuntimeGuiCompletionCallback callback,
    void* context) {
    completion_callback = callback;
    completion_context = context;
    return RIN_SUCCESS;
}

extern "C" int wnd_dispatch_compositor(std::uint32_t, std::uint32_t) {
    if (!completion_callback) return 0;
    RinRuntimeGuiCompletionV1 completion{};
    completion.struct_size = sizeof(completion);
    completion.version = RIN_SDK_STRUCT_VERSION_1;
    completion_callback(&completion, completion_context);
    return 1;
}

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

    int completionCallbackCount = 0;
    int nestedCompletionResult = RIN_SUCCESS;
    window.onCompositorCompletion([&](const RinRuntimeGuiCompletionV1&) {
        ++completionCallbackCount;
        nestedCompletionResult = wnd_dispatch_compositor(0u, 1u);
    });
    assert(wnd_dispatch_compositor(0u, 1u) == 1);
    assert(completionCallbackCount == 1);
    assert(nestedCompletionResult == 1);
    assert(wnd_dispatch_compositor(0u, 1u) == 1);
    assert(completionCallbackCount == 2);
    return 0;
}
