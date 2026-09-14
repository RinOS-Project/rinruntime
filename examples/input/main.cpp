/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>

int main() {
    RinRuntime::Window window("Input", 100, 100, 640, 480);
    window.onEvent([](const RinRuntime::WindowEvent& event) {
        return !event.isClose();
    });
    return window.valid() ? 0 : 1;
}
