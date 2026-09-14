/* SPDX-License-Identifier: MIT */
/* C frame helpers over the public window/render-target ABI. */
#include <rinruntime/render.h>

int rinruntime_begin_frame(RinRuntimeGuiHandle handle,
                           RinRenderTarget* target_out) {
    return wnd_acquire_render_target(handle, target_out);
}

int rinruntime_end_frame(RinRuntimeGuiHandle handle,
                         const RinRenderTarget* target) {
    int result = wnd_release_render_target(handle, target);
    if (result != RIN_SUCCESS) return result;
    return wnd_present(handle);
}
