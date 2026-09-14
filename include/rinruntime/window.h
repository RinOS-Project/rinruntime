/* SPDX-License-Identifier: MIT */
/* Public C window and native-event entry points. */
#ifndef RINRUNTIME_WINDOW_H
#define RINRUNTIME_WINDOW_H

#include <stdint.h>
#include <rin/abi.h>
#include <rin/gui/window_abi.h>
#include <rin/gui/event_abi.h>
#include <rin/gui/compositor_protocol.h>
#include <rin/render_target.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Kept as the source-compatible name used by the original runtime header. */
typedef RinWindowHandle RinRuntimeGuiHandle;

RinRuntimeGuiHandle wnd_create(const char* title, int x, int y, int w, int h);
RinRuntimeGuiHandle wnd_create_role(const char* title, int x, int y, int w, int h,
                                    uint32_t role, int opaque);
RinRuntimeGuiHandle wnd_create_flags(const char* title, int x, int y, int w, int h,
                                     uint32_t role, uint32_t flags);
RinRuntimeGuiHandle wnd_create_frameless(const char* title, int x, int y,
                                         int w, int h);
void wnd_close(RinRuntimeGuiHandle handle);
void wnd_show(RinRuntimeGuiHandle handle, int visible);
void wnd_title(RinRuntimeGuiHandle handle, const char* title);
int wnd_set_icon_path(RinRuntimeGuiHandle handle, const char* path);
void wnd_move(RinRuntimeGuiHandle handle, int x, int y);
void wnd_resize(RinRuntimeGuiHandle handle, int w, int h);
int wnd_get_position(RinRuntimeGuiHandle handle, int* x, int* y);
int wnd_get_size(RinRuntimeGuiHandle handle, int* width, int* height);
int wnd_get_geometry(RinRuntimeGuiHandle handle, RinWindowGeometryV1* geometry);
int wnd_poll(RinRuntimeGuiHandle handle, void* event);
int wnd_poll_native(RinRuntimeGuiHandle handle, RinGuiNativeEventV1* event,
                    uint32_t* packed_out);
int wnd_set_text_input_state(RinRuntimeGuiHandle handle,
                             const RinTextInputStateV1* state);
int wnd_get_text_composition(RinRuntimeGuiHandle handle,
                             RinTextCompositionV1* composition_out);
int wnd_set_text_composition(RinRuntimeGuiHandle handle,
                             const RinTextCompositionV1* composition);
int wnd_set_window_state(RinRuntimeGuiHandle handle, uint32_t state,
                         uint32_t workspace);
int wnd_set_pointer_capture(RinRuntimeGuiHandle handle, int enabled);
int wnd_set_keyboard_grab(RinRuntimeGuiHandle handle, int enabled);
int wnd_set_modal(RinRuntimeGuiHandle handle, int enabled);
int wnd_set_cursor(RinRuntimeGuiHandle handle, uint32_t cursor_type);
int wnd_get_frame_info(RinRuntimeGuiHandle handle,
                       RinCompositorFrameInfoV1* info);
int wnd_set_frame_callback(RinRuntimeGuiHandle handle, int enabled,
                           uint32_t max_inflight);
int wnd_ack_frame(RinRuntimeGuiHandle handle, uint64_t frame_sequence,
                  RinCompositorFrameInfoV1* next_frame_out);
int rinruntime_gui_get_outputs(RinCompositorOutputListV1* outputs);
int wnd_acquire_render_target(RinRuntimeGuiHandle handle,
                              RinRenderTarget* out_target);
int wnd_release_render_target(RinRuntimeGuiHandle handle,
                              const RinRenderTarget* target);
int wnd_present(RinRuntimeGuiHandle handle);
int wnd_is_focused(RinRuntimeGuiHandle handle);

/* Legacy query names remain ABI-compatible with the original runtime. */
int rinruntime_gui_get_size(RinRuntimeGuiHandle handle, int* width,
                            int* height);
int rinruntime_gui_is_focused(RinRuntimeGuiHandle handle);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_WINDOW_H */
