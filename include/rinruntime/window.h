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

#define RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX 1024u

/* Kept as the source-compatible name used by the original runtime header. */
typedef RinWindowHandle RinRuntimeGuiHandle;

typedef struct RinRuntimeGuiCompletionV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t request_type;
    int32_t status;
    RinRuntimeGuiHandle handle;
    uint64_t cookie;
    uint32_t payload_size;
    uint32_t reserved;
    uint8_t payload[RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX];
} RinRuntimeGuiCompletionV1;

typedef void (*RinRuntimeGuiCompletionCallback)(
    const RinRuntimeGuiCompletionV1* completion, void* context);

RinRuntimeGuiHandle wnd_create(const char* title, int x, int y, int w, int h);
RinRuntimeGuiHandle wnd_create_role(const char* title, int x, int y, int w, int h,
                                    uint32_t role, int opaque);
RinRuntimeGuiHandle wnd_create_flags(const char* title, int x, int y, int w, int h,
                                     uint32_t role, uint32_t flags);
RinRuntimeGuiHandle wnd_create_frameless(const char* title, int x, int y,
                                         int w, int h);
/* Surface creation stays synchronous. Live control, resize, input fallback,
 * and present traffic is queued. Int-returning mutation APIs report queue
 * admission; final compositor status is delivered asynchronously. */
/* On accepted close, wnd_close_async invalidates the local handle immediately;
 * the destroyed handle receives no later completion callback. */
int wnd_close_async(RinRuntimeGuiHandle handle);
void wnd_close(RinRuntimeGuiHandle handle);
int wnd_show_async(RinRuntimeGuiHandle handle, int visible);
void wnd_show(RinRuntimeGuiHandle handle, int visible);
int wnd_title_async(RinRuntimeGuiHandle handle, const char* title);
void wnd_title(RinRuntimeGuiHandle handle, const char* title);
int wnd_set_icon_path(RinRuntimeGuiHandle handle, const char* path);
int wnd_move_async(RinRuntimeGuiHandle handle, int x, int y);
void wnd_move(RinRuntimeGuiHandle handle, int x, int y);
int wnd_resize_async(RinRuntimeGuiHandle handle, int w, int h);
void wnd_resize(RinRuntimeGuiHandle handle, int w, int h);
int wnd_get_position(RinRuntimeGuiHandle handle, int* x, int* y);
int wnd_get_size(RinRuntimeGuiHandle handle, int* width, int* height);
int wnd_get_geometry(RinRuntimeGuiHandle handle, RinWindowGeometryV1* geometry);
/* Polls cached/ring input and makes a nonblocking async fallback request when
 * the shared input ring is unavailable. Fallback input may arrive next poll. */
int wnd_poll(RinRuntimeGuiHandle handle, void* event);
int wnd_poll_native(RinRuntimeGuiHandle handle, RinGuiNativeEventV1* event,
                    uint32_t* packed_out);
int wnd_set_text_input_state(RinRuntimeGuiHandle handle,
                             const RinTextInputStateV1* state);
/* The synchronous compositor queries wnd_get_text_composition,
 * wnd_get_frame_info, wnd_ack_frame, rinruntime_gui_get_outputs, and
 * wnd_export_gpu_image may wait up to the RPC deadline. UI loops should use
 * their async variants and dispatch completion events instead. Geometry and
 * focus getters are local cached reads. */
int wnd_get_text_composition(RinRuntimeGuiHandle handle,
                             RinTextCompositionV1* composition_out);
/* Async query variants report the compositor status and raw response bytes
 * through the registered callback. Validate payload_size and the ABI record
 * fields for request_type before using the response. */
int wnd_get_text_composition_async(RinRuntimeGuiHandle handle,
                                   uint64_t cookie);
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
int wnd_get_frame_info_async(RinRuntimeGuiHandle handle, uint64_t cookie);
int wnd_set_frame_callback(RinRuntimeGuiHandle handle, int enabled,
                           uint32_t max_inflight);
int wnd_ack_frame(RinRuntimeGuiHandle handle, uint64_t frame_sequence,
                  RinCompositorFrameInfoV1* next_frame_out);
int wnd_ack_frame_async(RinRuntimeGuiHandle handle, uint64_t frame_sequence,
                        uint64_t cookie);
int rinruntime_gui_get_outputs(RinCompositorOutputListV1* outputs);
int rinruntime_gui_get_outputs_async(RinRuntimeGuiHandle completion_handle,
                                     uint64_t cookie);
int wnd_acquire_render_target(RinRuntimeGuiHandle handle,
                              RinRenderTarget* out_target);
int wnd_release_render_target(RinRuntimeGuiHandle handle,
                              const RinRenderTarget* target);
int wnd_present(RinRuntimeGuiHandle handle);
int wnd_export_gpu_image(RinRuntimeGuiHandle handle,
                         RinCompositorGpuImageV1* image_out);
int wnd_export_gpu_image_async(RinRuntimeGuiHandle handle, uint64_t cookie);
int wnd_present_gpu(RinRuntimeGuiHandle handle,
                    const RinCompositorGpuPresentV1* present);
int wnd_is_focused(RinRuntimeGuiHandle handle);
/* Mutations return RIN_RESULT_OK when accepted into the bounded request queue.
 * Their final compositor status is reported through this callback from
 * wnd_poll_native() or wnd_dispatch_compositor(). Register before submitting
 * requests. Keep context alive until pending callbacks are dispatched, or
 * unregister it first. */
int wnd_set_compositor_completion_callback(
    RinRuntimeGuiHandle handle, RinRuntimeGuiCompletionCallback callback,
    void* context);
/* Dispatch queued completions and advance one nonblocking transport step.
 * timeout_ms is capped at 50 ms; the return value is the callbacks delivered. */
int wnd_dispatch_compositor(uint32_t timeout_ms, uint32_t max_completions);
/* Explicit recovery entry point after a transport failure. It reconnects and
 * synchronously rebinds live surfaces; call it from the application's
 * recovery path, not from a per-frame callback. */
int wnd_reconnect_compositor(void);

/* Legacy cached query names remain ABI-compatible with the original runtime. */
int rinruntime_gui_get_size(RinRuntimeGuiHandle handle, int* width,
                            int* height);
int rinruntime_gui_is_focused(RinRuntimeGuiHandle handle);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_WINDOW_H */
