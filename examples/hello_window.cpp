/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.hpp>

int main() {
    RinRuntime::WindowOptions options;
    options.title = "RinOS Hello Window";
    options.width = 640;
    options.height = 480;
    RinRuntime::Window window(options);
    return window.valid() ? 0 : 1;
}
