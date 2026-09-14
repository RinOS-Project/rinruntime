/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>

int main() {
    RinRuntime::Window window("Resize", 100, 100, 640, 480);
    window.onEvent([&window](const RinRuntime::WindowEvent& event) {
        if (event.abi.type == RIN_WINDOW_EVENT_RESIZE) {
            window.resize(static_cast<int>(event.abi.width),
                          static_cast<int>(event.abi.height));
        }
        return !event.isClose();
    });
    return window.valid() ? 0 : 1;
}
