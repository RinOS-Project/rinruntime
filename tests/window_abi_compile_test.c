/* SPDX-License-Identifier: MIT */
#include <rinruntime/window.h>
#include <rinruntime/render.h>

_Static_assert(sizeof(RinRuntimeGuiHandle) == sizeof(RinHandle),
               "runtime and SDK window handles must match");
_Static_assert(sizeof(RinWindowGeometryV1) == 40u,
               "window geometry ABI drift");
_Static_assert(sizeof(RinWindowEventV1) == 88u,
               "window event ABI drift");

int main(void) {
    RinRenderTarget target;
    (void)target;
    return RIN_WINDOW_HANDLE_INVALID == 0u ? 0 : 1;
}
