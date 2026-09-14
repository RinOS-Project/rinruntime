/* SPDX-License-Identifier: MIT */
#include <rinruntime/render.h>

int main(void) {
    RinRuntimeGuiHandle window = wnd_create("C window", 100, 100, 640, 480);
    if (window == RIN_WINDOW_HANDLE_INVALID) return 1;
    wnd_show(window, 1);
    wnd_close(window);
    return 0;
}
