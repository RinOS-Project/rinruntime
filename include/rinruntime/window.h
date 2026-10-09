/* SPDX-License-Identifier: MIT */
/* Public C window and native-event entry points. */
#ifndef RINRUNTIME_WINDOW_H
#define RINRUNTIME_WINDOW_H

#include <stdint.h>
#include <rin/abi.h>
#include <rin/ipc.h>
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

#define RIN_RUNTIME_COMPOSITOR_GPU_FRAME_V1_VERSION UINT32_C(1)
#define RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_V1_VERSION UINT32_C(1)

#define RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_FORMAT_BGRA8_BIT UINT32_C(0x1)
#define RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_FORMAT_RGBA8_BIT UINT32_C(0x2)

typedef enum RinRuntimeCompositorGpuPixelFormatV1 {
    RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 = 0,
    RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8 = 1
} RinRuntimeCompositorGpuPixelFormatV1;

/* An explicitly CPU-readable readback of an application GPU image. The
 * producer must wait for the GPU write to complete and perform the required
 * device-to-CPU visibility operation before calling the import API below.
 * RinRuntime copies the pixels synchronously; the source may be released
 * when that call returns. This is a Compositor handoff, not direct scanout. */
typedef struct RinRuntimeCompositorGpuFrameV1 {
    uint32_t struct_size;
    uint32_t version;
    const void* pixels;
    uint64_t bytes;
    uint32_t width;
    uint32_t height;
    uint32_t row_pitch;
    uint32_t format;
    uint64_t reserved[2];
} RinRuntimeCompositorGpuFrameV1;

/* Single-call local snapshot for a Vulkan/native-window WSI consumer. The
 * generation and extent are read from the same live Runtime surface record;
 * any resize/rebind after this query is rejected by the generation-bound
 * frame import API. These formats describe the CPU-readable Compositor
 * handoff, not formats accepted by direct scanout. */
typedef struct RinRuntimeCompositorGpuSurfaceV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t width;
    uint32_t height;
    uint32_t supported_frame_formats;
    uint32_t reserved0;
    uint64_t surface_generation;
    uint64_t reserved[2];
} RinRuntimeCompositorGpuSurfaceV1;

#define RIN_RUNTIME_GPU_READBACK_LEASE_V1_VERSION UINT32_C(1)
typedef struct RinRuntimeGpuReadbackLeaseV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t format;
    uint32_t width;
    uint32_t height;
    uint32_t row_pitch;
    uint64_t allocation_offset;
    uint64_t bytes;
    RinGpuCrossProcessCapabilityTokenV2 capability;
    uint64_t expected_surface_generation;
} RinRuntimeGpuReadbackLeaseV1;

#if defined(__cplusplus)
static_assert(sizeof(RinRuntimeGpuReadbackLeaseV1) == 88u,
              "RinRuntimeGpuReadbackLeaseV1 ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeGpuReadbackLeaseV1) == 88u,
               "RinRuntimeGpuReadbackLeaseV1 ABI drift");
#endif

#if defined(__cplusplus)
static_assert(sizeof(RinRuntimeCompositorGpuSurfaceV1) == 48u,
              "RinRuntimeCompositorGpuSurfaceV1 ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeCompositorGpuSurfaceV1) == 48u,
               "RinRuntimeCompositorGpuSurfaceV1 ABI drift");
#endif

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
/* Returns BUSY while the Compositor is still reading this surface's previous
 * submission from the current SHM slot. Do not access the slot until this
 * call succeeds; retry after a transient BUSY result. */
int wnd_acquire_render_target(RinRuntimeGuiHandle handle,
                              RinRenderTarget* out_target);
int wnd_release_render_target(RinRuntimeGuiHandle handle,
                              const RinRenderTarget* target);
int wnd_present(RinRuntimeGuiHandle handle);
/* Obtain the generation to pass back to wnd_import_gpu_readback_frame_v1.
 * BUSY means a resize/rebind is in progress; retry after it completes. */
int wnd_get_gpu_frame_generation_v1(RinRuntimeGuiHandle handle,
                                    uint64_t* generation_out);
int wnd_get_gpu_surface_v1(
    RinRuntimeGuiHandle handle,
    RinRuntimeCompositorGpuSurfaceV1* surface_out);
/* Explicit ordinary-window path for a completed CPU-readable GPU readback.
 * Copies into the current SHM slot and submits the existing Compositor
 * damage/commit transaction. The source is not retained after this returns;
 * the Compositor retains its SHM slot until its normal read-release sequence. */
int wnd_import_gpu_readback_frame_v1(
    RinRuntimeGuiHandle handle, uint64_t expected_generation,
    const RinRuntimeCompositorGpuFrameV1* frame);
/* Asynchronous explicit CPU-readable allocation handoff to an ordinary
 * Compositor window. The producer must finish GPU writes and CPU visibility
 * before submission. expected_surface_generation must come from a current
 * wnd_export_gpu_image result (repeat after resize). The capability must be
 * recipient-bound to the connected Compositor process with READ rights.
 * Compositor copies into a free SHM slot and releases the exact capability
 * lease before replying; release the source after a successful completion.
 * On error, do not assume the lease was released. This is not direct scanout
 * or an implicit software fallback. */
int wnd_present_gpu_readback_lease_v1(
    RinRuntimeGuiHandle handle,
    const RinRuntimeGpuReadbackLeaseV1* readback, uint64_t cookie);
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

/* Return the kernel-authenticated process identity of the Compositor peer
 * connected by RinRuntime. This is suitable for recipient-bound GPU
 * capability issuance; it is not derived from a window handle or caller PID. */
int wnd_get_compositor_peer_identity_v1(
    RinIpcPeerIdentityV1* identity_out);

/* Legacy cached query names remain ABI-compatible with the original runtime. */
int rinruntime_gui_get_size(RinRuntimeGuiHandle handle, int* width,
                            int* height);
int rinruntime_gui_is_focused(RinRuntimeGuiHandle handle);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_WINDOW_H */
