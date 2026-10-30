/* SPDX-License-Identifier: MIT */
/*
 * Native GUI runtime backend.
 *
 * Applications acquire a private compositor buffer as RinRenderTarget and
 * draw into it through Aquamarine.  This runtime owns only lifecycle, input,
 * buffer acquisition and presentation; it never owns drawing primitives.
 */
#include <rinruntime/window.h>
#include <rinruntime/drag_drop_client.h>
#include <rinruntime/detail/drag_drop_owner_protocol.h>
#include <rinruntime/poll_wait.h>
#include "private_service_socket.h"
#include "platform.h"
#include "compositor_gpu_bridge.h"
#include <rin/contract_abi.h>
#include <rin/ipc/shm_abi.h>
#include <rin/net/socket_abi.h>
#include <rin/file_portal_call.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/pidfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdbool.h>

#define RIN_RUNTIME_GUI_MAX_SURFACES 32u
#define RIN_RUNTIME_GUI_MAX_PAYLOAD 8192u
#define RIN_RUNTIME_GUI_MAX_BUFFER_BYTES (64u * 1024u * 1024u)
#define RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS 8000u
#define RIN_RUNTIME_GUI_IO_INTERRUPTION_LIMIT 32u
#define RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY 32u
#define RIN_RUNTIME_GUI_ASYNC_SECOND_PAYLOAD_MAX 512u

#define RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION UINT16_C(1)
#define RIN_RUNTIME_DRAG_DROP_BEGIN UINT32_C(0x8001)
#define RIN_RUNTIME_DRAG_DROP_ACCEPT UINT32_C(0x8002)
#define RIN_RUNTIME_DRAG_DROP UINT32_C(0x8003)
#define RIN_RUNTIME_DRAG_DROP_CANCEL UINT32_C(0x8004)
#define RIN_RUNTIME_DRAG_DROP_POLL UINT32_C(0x8005)
#define RIN_RUNTIME_DRAG_DROP_UPDATE UINT32_C(0x8009)
#define RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS 16u
#define RIN_RUNTIME_DRAG_DROP_MAX_PAYLOAD_BYTES (256u * 1024u)

typedef struct RinRuntimeDragDropWireBeginV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t session_id;
    uint64_t generation;
    uint32_t actions;
    uint32_t payload_count;
    uint64_t reserved[2];
    RinRuntimeDragDropPayloadV1 payloads[RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS];
} RinRuntimeDragDropWireBeginV1;

typedef struct RinRuntimeDragDropWireAcceptV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t offer_token;
    uint64_t generation;
    uint64_t target_handle;
    uint32_t action;
    uint32_t reserved0;
} RinRuntimeDragDropWireAcceptV1;

typedef struct RinRuntimeDragDropWireLeaseV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t offer_token;
    uint64_t generation;
    uint64_t reserved[2];
} RinRuntimeDragDropWireLeaseV1;

typedef struct RinRuntimeDragDropWireUpdateV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t offer_token;
    uint64_t generation;
    uint32_t action;
    uint32_t reserved0;
    uint64_t reserved[2];
} RinRuntimeDragDropWireUpdateV1;

typedef struct RinRuntimeDragDropWireUpdateResultV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t target_handle;
    uint32_t state;
    uint32_t action;
    uint64_t reserved[2];
} RinRuntimeDragDropWireUpdateResultV1;

typedef struct RinRuntimeDragDropWirePollV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint32_t surface_id;
    uint32_t reserved[3];
} RinRuntimeDragDropWirePollV1;

typedef struct RinRuntimeDragDropWirePublicationV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint32_t has_publication;
    uint32_t payload_count;
    uint64_t offer_token;
    uint64_t generation;
    uint64_t origin_peer;
    uint64_t target_handle;
    uint32_t action;
    uint32_t state;
    RinRuntimeDragDropPayloadV1 payloads[RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS];
} RinRuntimeDragDropWirePublicationV1;

_Static_assert(sizeof(RinRuntimeDragDropPayloadV1) == 408u,
               "drag/drop payload ABI drift");
_Static_assert(sizeof(RinRuntimeDragDropWireBeginV1) == 6576u,
               "drag/drop begin wire ABI drift");
_Static_assert(sizeof(RinRuntimeDragDropWirePublicationV1) == 6584u,
               "drag/drop publication wire ABI drift");

#if defined(__GNUC__) || defined(__clang__)
#define RIN_RUNTIME_OPTIONAL_WEAK __attribute__((weak))
#else
#define RIN_RUNTIME_OPTIONAL_WEAK
#endif

/* RinOS applications provide this through the process runtime.  Keeping the
 * symbol weak leaves the public host library usable by callers that provide
 * an explicit wnd_set_icon_path() value instead. */
extern const char* rin_process_argv(int index) RIN_RUNTIME_OPTIONAL_WEAK;

typedef struct RinRuntimeGuiSurface {
    uint32_t active;
    RinRuntimeGuiHandle handle_token;
    uint32_t handle_generation;
    uint32_t id;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint64_t bytes;
    int32_t x;
    int32_t y;
    uint32_t visible;
    uint32_t focused;
    uint32_t role;
    uint32_t surface_flags;
    uint32_t cursor_type;
    uint32_t cursor_surface_enabled;
    uint32_t cursor_surface_visible;
    int32_t cursor_hotspot_x;
    int32_t cursor_hotspot_y;
    uint64_t cursor_generation;
    uint32_t window_state;
    uint32_t workspace;
    uint32_t pointer_capture;
    uint32_t keyboard_grab;
    uint32_t modal;
    uint32_t frame_callback_enabled;
    uint32_t frame_callback_max_inflight;
    uint32_t draw_slot;
    uint32_t front_slot;
    uint64_t frame_sequence;
    uint64_t slot_submitted_sequence[RIN_COMPOSITOR_MAX_BUFFERS];
    uint64_t render_target_generation;
    uint64_t compositor_surface_generation;
    uint32_t render_target_acquired;
    uint32_t render_target_slot;
    uint32_t frame_present_pending;
    uint32_t gpu_readback_pending;
    uint32_t copy_front_before_draw;
    uint32_t resize_pending;
    uint32_t input_poll_pending;
    uint32_t input_event_ready;
    int32_t input_error;
    RinGuiNativeEventV1 pending_input_event;
    uint64_t acquired_generation;
    uint8_t* acquired_pixels;
    RinRuntimeGuiCompletionCallback completion_callback;
    void* completion_context;
    int shm_handles[RIN_COMPOSITOR_MAX_BUFFERS];
    uint8_t* pixels[RIN_COMPOSITOR_MAX_BUFFERS];
    RinTextInputStateV1 text_input;
    RinTextCompositionV1 text_composition;
    char title[128];
    char icon_path[256];
    char shm_names[RIN_COMPOSITOR_MAX_BUFFERS][RIN_SHM_NAME_MAX];
} RinRuntimeGuiSurface;

typedef struct RinRuntimeGuiAsyncJob {
    uint32_t type;
    uint32_t payload_size;
    uint32_t second_type;
    uint32_t second_payload_size;
    uint32_t reply_capacity;
    uint32_t result_kind;
    RinRuntimeGuiHandle handle;
    uint64_t cookie;
    uint8_t payload[RIN_RUNTIME_GUI_MAX_PAYLOAD];
    uint8_t second_payload[RIN_RUNTIME_GUI_ASYNC_SECOND_PAYLOAD_MAX];
    int old_shm_handles[RIN_COMPOSITOR_MAX_BUFFERS];
    uint8_t* old_pixels[RIN_COMPOSITOR_MAX_BUFFERS];
} RinRuntimeGuiAsyncJob;

typedef enum RinRuntimeGuiAsyncStage {
    RIN_RUNTIME_GUI_ASYNC_IDLE = 0,
    RIN_RUNTIME_GUI_ASYNC_SEND_HEADER,
    RIN_RUNTIME_GUI_ASYNC_SEND_PAYLOAD,
    RIN_RUNTIME_GUI_ASYNC_RECEIVE_HEADER,
    RIN_RUNTIME_GUI_ASYNC_RECEIVE_PAYLOAD
} RinRuntimeGuiAsyncStage;

typedef struct RinRuntimeGuiAsyncState {
    RinRuntimeGuiAsyncJob jobs[RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY];
    uint32_t head;
    uint32_t count;
    RinCompositorHeader request;
    RinCompositorHeader reply;
    uint32_t stage;
    uint32_t operation_index;
    uint32_t offset;
    uint32_t reply_offset;
    uint64_t started_ms;
    uint8_t reply_payload[RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX];
} RinRuntimeGuiAsyncState;

enum {
    RIN_RUNTIME_GUI_ASYNC_RESULT_NONE = 0u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_FRAME = 1u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_FRAME = 2u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE = 3u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_QUERY = 4u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_INPUT = 5u,
    RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_READBACK = 6u
};

_Static_assert(sizeof(RinCompositorAttachBuffersV2) <=
                   RIN_RUNTIME_GUI_ASYNC_SECOND_PAYLOAD_MAX,
               "async resize attachment exceeds its bounded job payload");
_Static_assert(sizeof(RinTextCompositionV1) <=
                   RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX,
               "async text composition exceeds its bounded completion payload");
_Static_assert(sizeof(RinCompositorFrameInfoV1) <=
                   RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX,
               "async frame info exceeds its bounded completion payload");
_Static_assert(sizeof(RinCompositorInputEventV1) <=
                   RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX,
               "async input event exceeds its bounded completion payload");
_Static_assert(sizeof(RinCompositorOutputListV1) <=
                   RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX,
               "async output list exceeds its bounded completion payload");
_Static_assert(sizeof(RinCompositorGpuImageV1) <=
                   RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX,
               "async GPU image exceeds its bounded completion payload");

static int g_compositor_fd = -1;
static uint32_t g_compositor_protocol_version =
    RIN_COMPOSITOR_PROTOCOL_VERSION;
static uint64_t g_compositor_features = 0u;
static uint32_t g_next_request_id = 1u;
static RinRuntimeGuiAsyncState g_async_requests;
typedef struct RinRuntimeGuiCompletionDispatch {
    RinRuntimeGuiCompletionV1 completion;
} RinRuntimeGuiCompletionDispatch;
#define RIN_RUNTIME_GUI_COMPLETION_CAPACITY 64u
static RinRuntimeGuiCompletionDispatch
    g_async_completions[RIN_RUNTIME_GUI_COMPLETION_CAPACITY];
static uint32_t g_async_completion_head;
static uint32_t g_async_completion_count;
static uint32_t g_async_readback_completion_reservations;
static uint32_t g_next_name_id = 1u;
static uint32_t g_compositor_reconnect_count = 0u;
static uint32_t g_handle_generations[RIN_RUNTIME_GUI_MAX_SURFACES];
static RinRuntimeGuiSurface g_surfaces[RIN_RUNTIME_GUI_MAX_SURFACES];
static uint64_t g_next_render_target_generation = 1u;
static int g_input_ring_handle = -1;
static void* g_input_ring_address;
static uint32_t g_input_ring_bytes;
static sem_t* g_input_ring_wake;
static uint64_t g_input_ring_generation;
static char g_input_ring_shm_name[RIN_SHM_NAME_MAX];
static char g_input_ring_wake_name[64];
#define RIN_RUNTIME_INPUT_BATCH_CAPACITY 8u
static RinCompositorInputRingEventV1
    g_input_ring_batch[RIN_RUNTIME_INPUT_BATCH_CAPACITY];
static uint32_t g_input_ring_batch_count;
static uint32_t g_input_ring_batch_index;

static int runtime_request_id_valid(uint32_t request_id)
{
    return request_id != 0u && request_id != UINT32_MAX;
}

static int runtime_connect(void);
static int runtime_setup_input_ring(void);
static int runtime_request(uint32_t type, const void* payload,
                           uint32_t payload_size, void* reply_payload,
                           uint32_t reply_capacity, uint32_t* reply_size,
                           int32_t* status_out);
static int runtime_attach_existing_buffers(RinRuntimeGuiSurface* surface);
static int runtime_rebind_surfaces(void);
static int runtime_async_enqueue(uint32_t type, const void* payload,
                                 uint32_t payload_size,
                                 uint32_t second_type,
                                 const void* second_payload,
                                 uint32_t second_payload_size,
                                 RinRuntimeGuiHandle handle, uint64_t cookie,
                                 uint32_t result_kind);
static int runtime_async_pump(uint32_t timeout_ms);
static int runtime_async_drain(void);
static void runtime_async_abort_all(int32_t status);
static uint32_t runtime_async_dispatch_callbacks(uint32_t maximum);

static int runtime_send_icon_path(uint32_t surface_id, const char* path) {
    RinCompositorSetIconV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    size_t length = 0u;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_ICON_METADATA) == 0u ||
        !path) return -1;
    while (length < sizeof(request.executable_path) - 1u &&
           path[length] != '\0') {
        unsigned char value = (unsigned char)path[length];
        if (value < 0x20u || value == '\\') return -1;
        ++length;
    }
    if (path[length] != '\0') return -1;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface_id;
    memcpy(request.executable_path, path, length);
    if (runtime_request(RIN_COMPOSITOR_SET_ICON, &request, sizeof(request),
                        0, 0u, &reply_size, &status) != 0 || status != 0 ||
        reply_size != 0u) return -1;
    return 0;
}

static int runtime_store_icon_path(RinRuntimeGuiSurface* surface,
                                   const char* path) {
    size_t length = 0u;
    if (!surface || !path || runtime_send_icon_path(surface->id, path) != 0)
        return -1;
    while (length < sizeof(surface->icon_path) - 1u &&
           path[length] != '\0')
        ++length;
    if (path[length] != '\0') return -1;
    if (path != surface->icon_path) {
        memset(surface->icon_path, 0, sizeof(surface->icon_path));
        memcpy(surface->icon_path, path, length);
    }
    return 0;
}

static const char* runtime_process_icon_path(void) {
    const char* path;
    if (!rin_process_argv) return 0;
    path = rin_process_argv(0);
    return path && path[0] != '\0' ? path : 0;
}

static int runtime_role_has_application_icon(uint32_t role) {
    return role != RIN_COMPOSITOR_ROLE_DESKTOP &&
           role != RIN_COMPOSITOR_ROLE_PANEL &&
           role != RIN_COMPOSITOR_ROLE_CURSOR;
}

static void runtime_drop_input_ring(void) {
    if (g_input_ring_wake) {
        if (g_input_ring_wake_name[0] != '\0')
            (void)sem_unlink(g_input_ring_wake_name);
        (void)sem_close(g_input_ring_wake);
        g_input_ring_wake = 0;
    }
    if (g_input_ring_address) {
        (void)rin_shm_dt(g_input_ring_handle, g_input_ring_address);
        g_input_ring_address = 0;
    } else if (g_input_ring_handle >= 0) {
        (void)rin_shm_dt(g_input_ring_handle, 0);
    }
    g_input_ring_handle = -1;
    g_input_ring_bytes = 0u;
    g_input_ring_generation = 0u;
    g_input_ring_batch_count = 0u;
    g_input_ring_batch_index = 0u;
    g_input_ring_shm_name[0] = '\0';
    g_input_ring_wake_name[0] = '\0';
}

static void runtime_close_connection(void) {
    runtime_drop_input_ring();
    if (g_compositor_fd >= 0) {
        if (g_compositor_reconnect_count != UINT32_MAX)
            ++g_compositor_reconnect_count;
        close(g_compositor_fd);
    }
    g_compositor_fd = -1;
    g_compositor_protocol_version = RIN_COMPOSITOR_PROTOCOL_VERSION;
    runtime_async_abort_all(RIN_RESULT_IO);
}

/* The compositor service keeps its socket protocol private and reports
 * errno-shaped values.  Never let those private values cross the public
 * rinruntime ABI; translate the complete service-owned set here. */
static int runtime_compositor_status_known(int32_t status) {
    switch (status) {
    case 0:
    case -1:  /* EINVAL */
    case -4:  /* compositor capability/authority rejection */
    case -5:  /* capability service/lease release I/O */
    case -11: /* EAGAIN */
    case -13: /* EACCES */
    case -22: /* EINVAL */
    case -71: /* EPROTO */
    case -95: /* ENOTSUP */
        return 1;
    default:
        return 0;
    }
}

static int32_t runtime_public_result(int32_t status) {
    switch (status) {
    case 0:   return RIN_RESULT_OK;
    case -1:  /* EINVAL */
    case -22: /* EINVAL */
        return RIN_RESULT_INVALID_ARGUMENT;
    case -4:  /* compositor capability/authority rejection */
        return RIN_RESULT_ACCESS_DENIED;
    case -5:  /* capability service/lease release I/O */
        return RIN_RESULT_IO;
    case -11: /* EAGAIN */
        return RIN_RESULT_WOULD_BLOCK;
    case -13: /* EACCES */
        return RIN_RESULT_ACCESS_DENIED;
    case -71: /* EPROTO */
        return RIN_RESULT_VERSION_MISMATCH;
    case -95: /* ENOTSUP */
        return RIN_RESULT_NOT_SUPPORTED;
    default:
        return RIN_RESULT_CORRUPT_DATA;
    }
}

static int runtime_send_exact(const void* data, uint32_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        ssize_t count = send(g_compositor_fd, bytes + offset, size - offset,
                             MSG_NOSIGNAL);
        if (count > 0) {
            if ((uint32_t)count > size - offset) return -1;
            offset += (uint32_t)count;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RIN_RUNTIME_GUI_IO_INTERRUPTION_LIMIT)
                return -1;
            continue;
        }
        return -1;
    }
    return 0;
}

static int runtime_receive_exact(void* data, uint32_t size,
                                 uint64_t deadline_ms) {
    uint8_t* bytes = (uint8_t*)data;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        uint64_t now_ms;
        uint64_t remaining_ms;
        uint32_t timeout_ms;
        RinRuntimePollWaitResult ready;
        now_ms = rin_monotonic_ms();
        if (now_ms >= deadline_ms) return -1;
        remaining_ms = deadline_ms - now_ms;
        timeout_ms = remaining_ms > 1000u ? 1000u : (uint32_t)remaining_ms;
        if (timeout_ms == 0u) return -1;
        ready = rinruntime_poll_wait(
            g_compositor_fd, RINRUNTIME_POLL_WAIT_READABLE, timeout_ms);
        if (ready == RINRUNTIME_POLL_WAIT_TIMEOUT) continue;
        if (ready != RINRUNTIME_POLL_WAIT_READY) return -1;
        {
            ssize_t count = recv(g_compositor_fd, bytes + offset,
                                 size - offset, 0);
            if (count > 0) {
                if ((uint32_t)count > size - offset) return -1;
                offset += (uint32_t)count;
                interrupted = 0u;
                continue;
            }
            if (count < 0 && errno == EINTR) {
                if (++interrupted >= RIN_RUNTIME_GUI_IO_INTERRUPTION_LIMIT)
                    return -1;
                continue;
            }
            return -1;
        }
    }
    return 0;
}

static int runtime_deadline_after(uint64_t now_ms, uint64_t timeout_ms,
                                  uint64_t* deadline_out) {
    if (deadline_out == NULL || now_ms == 0u ||
        now_ms > UINT64_MAX - timeout_ms)
        return -1;
    *deadline_out = now_ms + timeout_ms;
    return 0;
}

/* Returns 0 for a valid transport exchange; status is a public result. */
static int runtime_request(uint32_t type, const void* payload,
                           uint32_t payload_size, void* reply_payload,
                           uint32_t reply_capacity, uint32_t* reply_size,
                           int32_t* status_out) {
    RinCompositorHeader request;
    RinCompositorHeader reply;
    uint8_t discard[RIN_RUNTIME_GUI_MAX_PAYLOAD];
    uint32_t request_id;
    uint64_t deadline_ms;
    uint64_t request_start_ms;
    uint64_t send_complete_ms = 0u;
    uint64_t reply_header_ms = 0u;
    uint64_t reply_payload_ms = 0u;
    char diagnostic[192];

    if (reply_size) *reply_size = 0u;
    if (status_out) *status_out = -1;
    if (g_compositor_fd < 0 && runtime_connect() != 0) return -1;
    if (payload_size > RIN_RUNTIME_GUI_MAX_PAYLOAD ||
        (payload_size != 0u && !payload)) return -1;
    if (g_async_requests.count != 0u) {
        errno = EAGAIN;
        return -1;
    }
    if (!runtime_request_id_valid(g_next_request_id)) g_next_request_id = 1u;
    request_id = g_next_request_id++;
    if (!runtime_request_id_valid(g_next_request_id)) g_next_request_id = 1u;
    request_start_ms = rin_monotonic_ms();
    if (runtime_deadline_after(
            request_start_ms,
            (type == RIN_COMPOSITOR_POLL_INPUT ||
             type == RIN_COMPOSITOR_POLL_INPUT_V2) ? 50u :
                RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS,
            &deadline_ms) != 0)
        return -1;
    memset(&request, 0, sizeof(request));
    request.magic = RIN_COMPOSITOR_MAGIC;
    request.version = g_compositor_protocol_version;
    request.type = type;
    request.payload_size = payload_size;
    request.request_id = request_id;
    if (runtime_send_exact(&request, sizeof(request)) != 0 ||
        (payload_size != 0u && runtime_send_exact(payload, payload_size) != 0)) {
        snprintf(diagnostic, sizeof(diagnostic),
                 "[rinruntime] compositor rpc type=%u request=%u "
                 "send_failed duration_ms=%llu\n", (unsigned)type,
                 (unsigned)request_id,
                 (unsigned long long)(rin_monotonic_ms() - request_start_ms));
        fputs(diagnostic, stderr);
        runtime_close_connection();
        return -1;
    }
    send_complete_ms = rin_monotonic_ms();
    if (runtime_receive_exact(&reply, sizeof(reply), deadline_ms) != 0) {
        snprintf(diagnostic, sizeof(diagnostic),
                 "[rinruntime] compositor rpc type=%u request=%u "
                 "reply_header_failed send_ms=%llu total_ms=%llu\n",
                 (unsigned)type, (unsigned)request_id,
                 (unsigned long long)(send_complete_ms - request_start_ms),
                 (unsigned long long)(rin_monotonic_ms() - request_start_ms));
        fputs(diagnostic, stderr);
        runtime_close_connection();
        return -1;
    }
    reply_header_ms = rin_monotonic_ms();
    if (reply.magic != RIN_COMPOSITOR_MAGIC ||
        ((type == RIN_COMPOSITOR_HELLO &&
          (reply.version < RIN_COMPOSITOR_MIN_PROTOCOL_VERSION ||
           reply.version > RIN_COMPOSITOR_PROTOCOL_VERSION)) ||
         (type != RIN_COMPOSITOR_HELLO &&
          reply.version != request.version)) ||
        reply.type != type || reply.request_id != request_id ||
        reply.payload_size > RIN_RUNTIME_GUI_MAX_PAYLOAD) {
        snprintf(diagnostic, sizeof(diagnostic),
                 "[rinruntime] compositor rpc type=%u request=%u "
                 "malformed_reply send_ms=%llu header_ms=%llu total_ms=%llu\n",
                 (unsigned)type, (unsigned)request_id,
                 (unsigned long long)(send_complete_ms - request_start_ms),
                 (unsigned long long)(reply_header_ms - request_start_ms),
                 (unsigned long long)(rin_monotonic_ms() - request_start_ms));
        fputs(diagnostic, stderr);
        runtime_close_connection();
        return -1;
    }
    if (reply.payload_size != 0u) {
        if (reply.payload_size > reply_capacity || !reply_payload) {
            if (reply.payload_size <= sizeof(discard))
                (void)runtime_receive_exact(discard, reply.payload_size,
                                            deadline_ms);
            snprintf(diagnostic, sizeof(diagnostic),
                     "[rinruntime] compositor rpc type=%u request=%u "
                     "reply_capacity_failed header_ms=%llu total_ms=%llu\n",
                     (unsigned)type, (unsigned)request_id,
                     (unsigned long long)(reply_header_ms - request_start_ms),
                     (unsigned long long)(rin_monotonic_ms() - request_start_ms));
            fputs(diagnostic, stderr);
            runtime_close_connection();
            return -1;
        }
        if (runtime_receive_exact(reply_payload, reply.payload_size,
                                  deadline_ms) != 0) {
            snprintf(diagnostic, sizeof(diagnostic),
                     "[rinruntime] compositor rpc type=%u request=%u "
                     "reply_payload_failed header_ms=%llu total_ms=%llu\n",
                     (unsigned)type, (unsigned)request_id,
                     (unsigned long long)(reply_header_ms - request_start_ms),
                     (unsigned long long)(rin_monotonic_ms() - request_start_ms));
            fputs(diagnostic, stderr);
            runtime_close_connection();
            return -1;
        }
    }
    reply_payload_ms = rin_monotonic_ms();
    {
        const int32_t private_status = (int32_t)reply.reserved;
        if (!runtime_compositor_status_known(private_status)) {
            if (reply_payload && reply.payload_size != 0u)
                memset(reply_payload, 0, reply.payload_size);
            if (reply_size) *reply_size = 0u;
            if (status_out) *status_out = RIN_RESULT_CORRUPT_DATA;
            runtime_close_connection();
            return 0;
        }
        if (reply_size) *reply_size = reply.payload_size;
        if (status_out) *status_out = runtime_public_result(private_status);
    }
    if (reply_payload_ms - request_start_ms >= 16u) {
        snprintf(diagnostic, sizeof(diagnostic),
                 "[rinruntime] compositor rpc type=%u request=%u "
                 "send_ms=%llu header_ms=%llu payload_ms=%llu total_ms=%llu "
                 "status=%d\n", (unsigned)type, (unsigned)request_id,
                 (unsigned long long)(send_complete_ms - request_start_ms),
                 (unsigned long long)(reply_header_ms - request_start_ms),
                 (unsigned long long)(reply_payload_ms - request_start_ms),
                 (unsigned long long)(reply_payload_ms - request_start_ms),
                 (int)runtime_public_result((int32_t)reply.reserved));
            fputs(diagnostic, stderr);
    }
    return 0;
}

static int runtime_negotiate(void) {
    RinCompositorHelloV1 hello;
    RinCompositorHelloV1 reply;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    memset(&hello, 0, sizeof(hello));
    hello.struct_size = sizeof(hello);
    hello.version = 1u;
    hello.min_protocol_version = RIN_COMPOSITOR_MIN_PROTOCOL_VERSION;
    hello.max_protocol_version = RIN_COMPOSITOR_PROTOCOL_VERSION;
    hello.features = RIN_COMPOSITOR_FEATURE_SHM_BUFFERS |
                     RIN_COMPOSITOR_FEATURE_INPUT_ROUTING |
                     RIN_COMPOSITOR_FEATURE_TEXT_INPUT |
                     RIN_COMPOSITOR_FEATURE_MULTI_OUTPUT |
                     RIN_COMPOSITOR_FEATURE_WINDOW_POLICY |
                     RIN_COMPOSITOR_FEATURE_RECONNECT |
                     RIN_COMPOSITOR_FEATURE_SEMANTIC_CURSOR |
                     RIN_COMPOSITOR_FEATURE_ICON_METADATA |
                     RIN_COMPOSITOR_FEATURE_INPUT_SHARED_QUEUE |
                     RIN_COMPOSITOR_FEATURE_INPUT_WAKE_HANDLE |
                     RIN_COMPOSITOR_FEATURE_FRAME_CALLBACK |
                     RIN_COMPOSITOR_FEATURE_PRESENT_FEEDBACK |
                     RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI;
    if (runtime_request(RIN_COMPOSITOR_HELLO, &hello, sizeof(hello), &reply,
                        sizeof(reply), &reply_size, &status) != 0 ||
        status != 0 || reply_size != sizeof(reply) ||
        !rin_compositor_hello_valid(&reply) ||
        reply.min_protocol_version != reply.max_protocol_version ||
        reply.min_protocol_version < RIN_COMPOSITOR_MIN_PROTOCOL_VERSION ||
        reply.max_protocol_version > RIN_COMPOSITOR_PROTOCOL_VERSION)
        return -1;
    g_compositor_protocol_version = reply.max_protocol_version;
    {
        uint64_t required = hello.features &
            ~(RIN_COMPOSITOR_FEATURE_SEMANTIC_CURSOR |
              RIN_COMPOSITOR_FEATURE_ICON_METADATA |
              RIN_COMPOSITOR_FEATURE_INPUT_SHARED_QUEUE |
              RIN_COMPOSITOR_FEATURE_INPUT_WAKE_HANDLE |
              RIN_COMPOSITOR_FEATURE_FRAME_CALLBACK |
              RIN_COMPOSITOR_FEATURE_PRESENT_FEEDBACK);
        if ((reply.features & required) != required) return -1;
    }
    g_compositor_features = reply.features;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_INPUT_SHARED_QUEUE) != 0u)
        (void)runtime_setup_input_ring();
    return 0;
}

static int runtime_setup_input_ring(void) {
    RinCompositorInputRingSetupV1 setup;
    RinCompositorInputRingHeaderV1* header;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    uint32_t bytes = rin_compositor_input_ring_bytes(
        RIN_COMPOSITOR_INPUT_RING_DEFAULT_CAPACITY);
    uint64_t generation = rin_monotonic_ms();
    if (bytes == 0u || generation == 0u ||
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_INPUT_WAKE_HANDLE) == 0u)
        return -1;
    snprintf(g_input_ring_shm_name, sizeof(g_input_ring_shm_name),
             "rin.input.%llu.%u", (unsigned long long)generation,
             (unsigned)g_next_name_id++);
    snprintf(g_input_ring_wake_name, sizeof(g_input_ring_wake_name),
             "/rin-input-%llu-%u", (unsigned long long)generation,
             (unsigned)g_next_name_id++);
    g_input_ring_handle = rin_shm_get(
        g_input_ring_shm_name, bytes,
        RIN_SHM_FLAG_CREAT | RIN_SHM_FLAG_EXCL | RIN_SHM_FLAG_UNLINK_ON_CLOSE);
    if (g_input_ring_handle < 0) return -1;
    g_input_ring_address = rin_shm_at(
        g_input_ring_handle, 0, RIN_SHM_PROT_READ | RIN_SHM_PROT_WRITE);
    if (!g_input_ring_address) {
        runtime_drop_input_ring();
        return -1;
    }
    g_input_ring_wake = sem_open(g_input_ring_wake_name, O_CREAT | O_EXCL,
                                 (mode_t)0600, 0u);
    if (!g_input_ring_wake || g_input_ring_wake == SEM_FAILED) {
        runtime_drop_input_ring();
        return -1;
    }
    memset(g_input_ring_address, 0, bytes);
    header = (RinCompositorInputRingHeaderV1*)g_input_ring_address;
    header->struct_size = sizeof(*header);
    header->version = RIN_COMPOSITOR_INPUT_RING_VERSION;
    header->capacity = RIN_COMPOSITOR_INPUT_RING_DEFAULT_CAPACITY;
    header->event_size = sizeof(RinCompositorInputRingEventV1);
    header->generation = generation;
    memset(&setup, 0, sizeof(setup));
    setup.struct_size = sizeof(setup);
    setup.version = RIN_COMPOSITOR_INPUT_RING_VERSION;
    setup.capacity = header->capacity;
    setup.event_size = header->event_size;
    setup.generation = generation;
    strncpy(setup.shm_name, g_input_ring_shm_name,
            sizeof(setup.shm_name) - 1u);
    strncpy(setup.wake_name, g_input_ring_wake_name,
            sizeof(setup.wake_name) - 1u);
    g_input_ring_bytes = bytes;
    g_input_ring_generation = generation;
    if (runtime_request(RIN_COMPOSITOR_SETUP_INPUT_RING, &setup,
                        sizeof(setup), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u) {
        runtime_drop_input_ring();
        return -1;
    }
    return 0;
}

static int runtime_connect(void) {
    struct sockaddr_un address;
    uint32_t attempt;

    if (g_compositor_fd >= 0) return 0;
    for (attempt = 0u; attempt < 40u; ++attempt) {
        int fd = rinruntime_create_private_unix_stream_socket();
        if (fd < 0) return -1;
        memset(&address, 0, sizeof(address));
        address.sun_family = AF_UNIX;
        strncpy(address.sun_path, RIN_COMPOSITOR_SOCKET_PATH,
                sizeof(address.sun_path) - 1u);
        if (connect(fd, (struct sockaddr*)&address, sizeof(address)) == 0) {
            g_compositor_fd = fd;
            if (runtime_negotiate() == 0 && runtime_rebind_surfaces() == 0)
                return 0;
            runtime_close_connection();
            return -1;
        }
        close(fd);
        rin_sleep(50u);
    }
    return -1;
}

static int runtime_handle_index(RinRuntimeGuiHandle handle,
                                uint32_t* index_out,
                                uint32_t* generation_out) {
    uint64_t value = (uint64_t)handle;
    uint32_t slot = (uint32_t)(value & (RIN_RUNTIME_GUI_MAX_SURFACES - 1u));
    uint64_t generation = value / RIN_RUNTIME_GUI_MAX_SURFACES;
    if (!index_out || !generation_out || slot == 0u ||
        slot > RIN_RUNTIME_GUI_MAX_SURFACES || generation == 0u ||
        generation > UINT32_MAX)
        return -1;
    *index_out = slot - 1u;
    *generation_out = (uint32_t)generation;
    return 0;
}

static RinRuntimeGuiSurface* runtime_surface(RinRuntimeGuiHandle handle) {
    uint32_t index;
    uint32_t generation;
    if (runtime_handle_index(handle, &index, &generation) != 0 ||
        !g_surfaces[index].active ||
        g_surfaces[index].handle_generation != generation) return 0;
    return &g_surfaces[index];
}

static int runtime_surface_id(RinRuntimeGuiHandle handle, uint32_t* id_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface || !id_out || surface->id == 0u) return -1;
    *id_out = surface->id;
    return 0;
}

static void runtime_release_buffers(RinRuntimeGuiSurface* surface) {
    uint32_t slot;
    if (!surface) return;
    surface->render_target_acquired = 0u;
    surface->render_target_slot = 0u;
    surface->acquired_generation = 0u;
    surface->acquired_pixels = 0;
    for (slot = 0u; slot < RIN_COMPOSITOR_MAX_BUFFERS; ++slot) {
        if (surface->shm_handles[slot] >= 0)
            (void)rin_shm_dt(surface->shm_handles[slot],
                              surface->pixels[slot]);
        surface->shm_handles[slot] = -1;
        surface->pixels[slot] = 0;
        surface->shm_names[slot][0] = '\0';
    }
}

static int runtime_attach_existing_buffers(RinRuntimeGuiSurface* surface);

static int runtime_render_target_generation_in_use(uint64_t generation) {
    uint32_t index;
    if (generation == 0u) return 1;
    for (index = 0u; index < RIN_RUNTIME_GUI_MAX_SURFACES; ++index) {
        if (g_surfaces[index].active != 0u &&
            g_surfaces[index].render_target_generation == generation)
            return 1;
    }
    return 0;
}

static int runtime_reserve_render_target_generation(
    RinRuntimeGuiSurface* surface) {
    uint64_t candidate;
    uint32_t probes;
    if (surface == NULL) return -1;
    candidate = g_next_render_target_generation;
    if (candidate == 0u) candidate = 1u;
    /* At most MAX_SURFACES generations can be live.  The extra probe either
     * finds the first free value after a contiguous run or proves that the
     * bounded live set has no available candidate. */
    for (probes = 0u; probes <= RIN_RUNTIME_GUI_MAX_SURFACES; ++probes) {
        if (!runtime_render_target_generation_in_use(candidate)) {
            surface->render_target_generation = candidate;
            g_next_render_target_generation = candidate == UINT64_MAX
                ? 1u : candidate + 1u;
            return 0;
        }
        candidate = candidate == UINT64_MAX ? 1u : candidate + 1u;
    }
    return -1;
}

static int runtime_allocate_buffers(RinRuntimeGuiSurface* surface) {
    uint32_t slot;

    if (!surface || surface->width == 0u || surface->height == 0u ||
        surface->width > UINT32_MAX / 4u)
        return -1;
    surface->pitch = surface->width * 4u;
    surface->bytes = (uint64_t)surface->pitch * (uint64_t)surface->height;
    if (surface->bytes == 0u || surface->bytes > UINT32_MAX ||
        surface->bytes > RIN_RUNTIME_GUI_MAX_BUFFER_BYTES)
        return -1;
    for (slot = 0u; slot < RIN_COMPOSITOR_MAX_BUFFERS; ++slot) {
        int handle;
        uint8_t* pixels;
        if (snprintf(surface->shm_names[slot], RIN_SHM_NAME_MAX,
                     "rin.gui.%u.%u.%u", (uint32_t)getpid(),
                     surface->id, g_next_name_id++) < 0)
            goto fail;
        surface->shm_names[slot][RIN_SHM_NAME_MAX - 1u] = '\0';
        handle = rin_shm_get(surface->shm_names[slot], (uint32_t)surface->bytes,
                             RIN_SHM_FLAG_CREAT | RIN_SHM_FLAG_EXCL |
                             RIN_SHM_FLAG_UNLINK_ON_CLOSE);
        if (handle < 0) goto fail;
        pixels = (uint8_t*)rin_shm_at(handle, 0,
                                      RIN_SHM_PROT_READ | RIN_SHM_PROT_WRITE);
        if (!pixels) {
            (void)rin_shm_dt(handle, 0);
            goto fail;
        }
        memset(pixels, 0, (size_t)surface->bytes);
        surface->shm_handles[slot] = handle;
        surface->pixels[slot] = pixels;
    }
    if (runtime_reserve_render_target_generation(surface) != 0) goto fail;
    return 0;
fail:
    runtime_release_buffers(surface);
    return -1;
}

static int runtime_make_buffers(RinRuntimeGuiSurface* surface) {
    if (runtime_allocate_buffers(surface) != 0) return -1;
    if (runtime_attach_existing_buffers(surface) != 0) {
        runtime_release_buffers(surface);
        return -1;
    }
    return 0;
}

static int runtime_build_attach_request(
    const RinRuntimeGuiSurface* surface,
    RinCompositorAttachBuffersV2* attach) {
    uint32_t slot;
    if (!surface || surface->id == 0u || surface->bytes == 0u ||
        surface->bytes > UINT32_MAX || !surface->pixels[0] ||
        !surface->pixels[1] || !attach) return -1;
    memset(attach, 0, sizeof(*attach));
    attach->surface_id = surface->id;
    attach->width = surface->width;
    attach->height = surface->height;
    attach->pitch = surface->pitch;
    attach->format = 0u;
    for (slot = 0u; slot < RIN_COMPOSITOR_MAX_BUFFERS; ++slot) {
        if (surface->shm_handles[slot] < 0 ||
            surface->shm_names[slot][0] == '\0') return -1;
        attach->bytes[slot] = surface->bytes;
        strncpy(attach->shm_name[slot], surface->shm_names[slot],
                RIN_SHM_NAME_MAX - 1u);
    }
    return 0;
}

static int runtime_attach_existing_buffers(RinRuntimeGuiSurface* surface) {
    RinCompositorAttachBuffersV2 attach;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (runtime_build_attach_request(surface, &attach) != 0 ||
        runtime_request(RIN_COMPOSITOR_ATTACH_BUFFERS_V2, &attach,
                        sizeof(attach), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u) return -1;
    memset(surface->slot_submitted_sequence, 0,
           sizeof(surface->slot_submitted_sequence));
    surface->compositor_surface_generation = 0u;
    return 0;
}

static void runtime_async_release_old_buffers(RinRuntimeGuiAsyncJob* job) {
    uint32_t slot;
    if (!job) return;
    for (slot = 0u; slot < RIN_COMPOSITOR_MAX_BUFFERS; ++slot) {
        if (job->old_shm_handles[slot] >= 0)
            (void)rin_shm_dt(job->old_shm_handles[slot],
                             job->old_pixels[slot]);
        job->old_shm_handles[slot] = -1;
        job->old_pixels[slot] = 0;
    }
}

static void runtime_async_queue_completion(
    const RinRuntimeGuiAsyncJob* job, int32_t status,
    const void* payload, uint32_t payload_size) {
    RinRuntimeGuiSurface* surface;
    uint32_t slot;
    RinRuntimeGuiCompletionDispatch* dispatch;
    if (!job) return;
    surface = runtime_surface(job->handle);
    if (job->result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_READBACK &&
        g_async_readback_completion_reservations != 0u)
        --g_async_readback_completion_reservations;
    if (!surface || !surface->completion_callback ||
        g_async_completion_count >= RIN_RUNTIME_GUI_COMPLETION_CAPACITY ||
        (job->result_kind != RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_READBACK &&
         g_async_completion_count +
                 g_async_readback_completion_reservations >=
             RIN_RUNTIME_GUI_COMPLETION_CAPACITY))
        return;
    slot = (g_async_completion_head + g_async_completion_count) %
           RIN_RUNTIME_GUI_COMPLETION_CAPACITY;
    dispatch = &g_async_completions[slot];
    memset(dispatch, 0, sizeof(*dispatch));
    dispatch->completion.struct_size = sizeof(dispatch->completion);
    dispatch->completion.version = 1u;
    dispatch->completion.request_type = job->type;
    dispatch->completion.status = status;
    dispatch->completion.handle = job->handle;
    dispatch->completion.cookie = job->cookie;
    if (payload_size > sizeof(dispatch->completion.payload))
        payload_size = sizeof(dispatch->completion.payload);
    if (payload_size != 0u && payload)
        memcpy(dispatch->completion.payload, payload, payload_size);
    dispatch->completion.payload_size = payload_size;
    ++g_async_completion_count;
}

static void runtime_async_apply_completion(RinRuntimeGuiAsyncJob* job,
                                           int32_t status,
                                           const void* payload,
                                           uint32_t payload_size) {
    RinRuntimeGuiSurface* surface;
    if (!job) return;
    surface = runtime_surface(job->handle);
    if (job->result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_INPUT) {
        if (surface) {
            surface->input_poll_pending = 0u;
            if (status == RIN_RESULT_WOULD_BLOCK && payload_size == 0u) {
                surface->input_error = 0;
            } else if (status != 0) {
                surface->input_error = status;
            } else if (!payload ||
                       payload_size != sizeof(RinCompositorInputEventV1)) {
                surface->input_error = RIN_RESULT_CORRUPT_DATA;
            } else {
                RinCompositorInputEventV1 routed;
                memcpy(&routed, payload, sizeof(routed));
                if (routed.struct_size != sizeof(routed) ||
                    routed.version != 1u || routed.flags != 0u ||
                    routed.surface_id != surface->id ||
                    routed.reserved[0] >= 4u || routed.reserved[1] != 0u ||
                    routed.event.struct_size != sizeof(routed.event) ||
                    routed.event.version != RIN_GUI_NATIVE_EVENT_VERSION) {
                    surface->input_error = RIN_RESULT_CORRUPT_DATA;
                } else {
                    surface->pending_input_event = routed.event;
                    surface->input_event_ready = 1u;
                    surface->input_error = 0;
                }
            }
        }
        return;
    } else if (job->result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_FRAME) {
        if (surface) {
            surface->frame_present_pending = 0u;
            if (status == 0 &&
                job->second_type == RIN_COMPOSITOR_COMMIT_V2 &&
                job->second_payload_size == sizeof(RinCompositorCommitV2)) {
                RinCompositorCommitV2 commit;
                memcpy(&commit, job->second_payload, sizeof(commit));
                if (commit.surface_id == surface->id &&
                    commit.buffer_slot < RIN_COMPOSITOR_MAX_BUFFERS) {
                    surface->slot_submitted_sequence[commit.buffer_slot] =
                        commit.frame_sequence;
                    const uint32_t next_slot = commit.buffer_slot ^ 1u;
                    if (next_slot < RIN_COMPOSITOR_MAX_BUFFERS &&
                        surface->pixels[commit.buffer_slot] &&
                        surface->pixels[next_slot]) {
                        surface->front_slot = commit.buffer_slot;
                        surface->draw_slot = next_slot;
                        surface->copy_front_before_draw = 1u;
                    }
                }
            }
        }
    } else if (job->result_kind ==
               RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_FRAME) {
        if (surface) {
            surface->frame_present_pending = 0u;
            if (status == 0 &&
                job->payload_size == sizeof(RinCompositorGpuPresentV1)) {
                RinCompositorGpuPresentV1 present;
                memcpy(&present, job->payload, sizeof(present));
                if (present.surface_id == surface->id &&
                    present.buffer_slot < RIN_COMPOSITOR_MAX_BUFFERS) {
                    surface->slot_submitted_sequence[present.buffer_slot] =
                        present.frame_sequence;
                    const uint32_t next_slot = present.buffer_slot ^ 1u;
                    if (next_slot < RIN_COMPOSITOR_MAX_BUFFERS &&
                        surface->pixels[present.buffer_slot] &&
                        surface->pixels[next_slot]) {
                        surface->front_slot = present.buffer_slot;
                        surface->draw_slot = next_slot;
                        surface->frame_sequence = present.frame_sequence;
                        surface->copy_front_before_draw = 1u;
                    }
                }
            }
        }
    } else if (job->result_kind ==
               RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_READBACK) {
        if (surface) {
            surface->frame_present_pending = 0u;
            surface->gpu_readback_pending = 0u;
            if (status == 0) {
                RinCompositorGpuReadbackLeaseResultV1 result;
                if (!payload || payload_size != sizeof(result)) {
                    status = RIN_RESULT_CORRUPT_DATA;
                } else {
                    memcpy(&result, payload, sizeof(result));
                    RinCompositorGpuReadbackLeasePresentV1 submitted;
                    memcpy(&submitted, job->payload, sizeof(submitted));
                    if (result.struct_size != sizeof(result) ||
                        result.version !=
                            RIN_COMPOSITOR_GPU_READBACK_LEASE_VERSION ||
                        result.surface_id != surface->id ||
                        result.buffer_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
                        result.surface_generation !=
                            submitted.expected_surface_generation ||
                        result.frame_sequence == 0u ||
                        result.frame_sequence != submitted.frame_sequence ||
                        result.frame_sequence <= surface->frame_sequence) {
                        status = RIN_RESULT_CORRUPT_DATA;
                    } else {
                        surface->slot_submitted_sequence[result.buffer_slot] =
                            result.frame_sequence;
                        surface->frame_sequence = result.frame_sequence;
                        const uint32_t next_slot = result.buffer_slot ^ 1u;
                        if (next_slot < RIN_COMPOSITOR_MAX_BUFFERS &&
                            surface->pixels[result.buffer_slot] &&
                            surface->pixels[next_slot]) {
                            surface->front_slot = result.buffer_slot;
                            surface->draw_slot = next_slot;
                            surface->copy_front_before_draw = 1u;
                        }
                    }
                }
            }
        }
    } else if (job->result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE) {
        runtime_async_release_old_buffers(job);
        if (surface) {
            if (status == 0)
                memset(surface->slot_submitted_sequence, 0,
                       sizeof(surface->slot_submitted_sequence));
            surface->resize_pending = 0u;
        }
    }
    runtime_async_queue_completion(job, status, payload, payload_size);
}

static int runtime_async_enqueue(uint32_t type, const void* payload,
                                 uint32_t payload_size,
                                 uint32_t second_type,
                                 const void* second_payload,
                                 uint32_t second_payload_size,
                                 RinRuntimeGuiHandle handle, uint64_t cookie,
                                 uint32_t result_kind) {
    RinRuntimeGuiAsyncJob* job;
    uint32_t slot;
    if (g_compositor_fd < 0) return RIN_RESULT_IO;
    if (payload_size > RIN_RUNTIME_GUI_MAX_PAYLOAD ||
        (payload_size != 0u && !payload) ||
        second_payload_size > RIN_RUNTIME_GUI_ASYNC_SECOND_PAYLOAD_MAX ||
        (second_payload_size != 0u && !second_payload) ||
        ((second_type == 0u) != (second_payload_size == 0u)))
        return RIN_RESULT_INVALID_ARGUMENT;
    if (g_async_requests.count >= RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY ||
        g_async_completion_count + g_async_requests.count >=
            RIN_RUNTIME_GUI_COMPLETION_CAPACITY)
        return RIN_RESULT_BUSY;
    slot = (g_async_requests.head + g_async_requests.count) %
           RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    job = &g_async_requests.jobs[slot];
    memset(job, 0, sizeof(*job));
    job->type = type;
    job->payload_size = payload_size;
    job->second_type = second_type;
    job->second_payload_size = second_payload_size;
    job->result_kind = result_kind;
    job->handle = handle;
    job->cookie = cookie;
    for (uint32_t index = 0u; index < RIN_COMPOSITOR_MAX_BUFFERS; ++index)
        job->old_shm_handles[index] = -1;
    if (payload_size != 0u) memcpy(job->payload, payload, payload_size);
    if (second_payload_size != 0u)
        memcpy(job->second_payload, second_payload, second_payload_size);
    ++g_async_requests.count;
    return RIN_RESULT_OK;
}

static int runtime_async_enqueue_query(
    uint32_t type, const void* payload, uint32_t payload_size,
    uint32_t reply_capacity, RinRuntimeGuiHandle handle, uint64_t cookie) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t slot;
    int result;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (!surface->completion_callback) return RIN_RESULT_INVALID_ARGUMENT;
    if (reply_capacity > RIN_RUNTIME_GUI_COMPLETION_PAYLOAD_MAX)
        return RIN_RESULT_LIMIT_EXCEEDED;
    result = runtime_async_enqueue(type, payload, payload_size, 0u, 0, 0u,
        handle, cookie, RIN_RUNTIME_GUI_ASYNC_RESULT_QUERY);
    if (result != RIN_RESULT_OK) return result;
    slot = (g_async_requests.head + g_async_requests.count - 1u) %
           RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    g_async_requests.jobs[slot].reply_capacity = reply_capacity;
    return RIN_RESULT_OK;
}

static int runtime_async_enqueue_input_poll(
    RinRuntimeGuiHandle handle, RinRuntimeGuiSurface* surface) {
    RinCompositorPollInputV2 request;
    uint32_t slot;
    int result;
    if (!surface || surface->input_poll_pending != 0u)
        return RIN_RESULT_BUSY;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    result = runtime_async_enqueue(RIN_COMPOSITOR_POLL_INPUT_V2, &request,
        sizeof(request), 0u, 0, 0u, handle, 0u,
        RIN_RUNTIME_GUI_ASYNC_RESULT_INPUT);
    if (result != RIN_RESULT_OK) return result;
    slot = (g_async_requests.head + g_async_requests.count - 1u) %
           RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    g_async_requests.jobs[slot].reply_capacity =
        sizeof(RinCompositorInputEventV1);
    surface->input_poll_pending = 1u;
    return RIN_RESULT_OK;
}

static int runtime_async_enqueue_resize(
    RinRuntimeGuiHandle handle, RinRuntimeGuiSurface* surface,
    uint32_t width, uint32_t height) {
    RinRuntimeGuiSurface candidate;
    RinCompositorSetSize resize;
    RinCompositorAttachBuffersV2 attach;
    RinRuntimeGuiAsyncJob* job;
    uint32_t job_slot;
    uint32_t index;
    int result;
    if (!surface || surface->resize_pending != 0u ||
        surface->render_target_acquired != 0u ||
        surface->gpu_readback_pending != 0u)
        return RIN_RESULT_BUSY;
    memset(&candidate, 0, sizeof(candidate));
    for (index = 0u; index < RIN_COMPOSITOR_MAX_BUFFERS; ++index)
        candidate.shm_handles[index] = -1;
    candidate.id = surface->id;
    candidate.width = width;
    candidate.height = height;
    if (runtime_allocate_buffers(&candidate) != 0) return RIN_RESULT_IO;
    if (runtime_build_attach_request(&candidate, &attach) != 0) {
        runtime_release_buffers(&candidate);
        return RIN_RESULT_CORRUPT_DATA;
    }
    memset(&resize, 0, sizeof(resize));
    resize.surface_id = surface->id;
    resize.width = width;
    resize.height = height;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_SIZE, &resize,
            sizeof(resize),
            RIN_COMPOSITOR_ATTACH_BUFFERS_V2, &attach, sizeof(attach),
            handle, 0u, RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE);
    if (result != RIN_RESULT_OK) {
        runtime_release_buffers(&candidate);
        return result;
    }
    job_slot = (g_async_requests.head + g_async_requests.count - 1u) %
               RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    job = &g_async_requests.jobs[job_slot];
    for (index = 0u; index < RIN_COMPOSITOR_MAX_BUFFERS; ++index) {
        job->old_shm_handles[index] = surface->shm_handles[index];
        job->old_pixels[index] = surface->pixels[index];
        surface->shm_handles[index] = candidate.shm_handles[index];
        surface->pixels[index] = candidate.pixels[index];
        memcpy(surface->shm_names[index], candidate.shm_names[index],
               sizeof(surface->shm_names[index]));
        candidate.shm_handles[index] = -1;
        candidate.pixels[index] = 0;
        candidate.shm_names[index][0] = '\0';
    }
    surface->width = candidate.width;
    surface->height = candidate.height;
    surface->pitch = candidate.pitch;
    surface->bytes = candidate.bytes;
    surface->render_target_generation = candidate.render_target_generation;
    surface->compositor_surface_generation = 0u;
    surface->draw_slot = 0u;
    surface->front_slot = 0u;
    surface->copy_front_before_draw = 0u;
    surface->render_target_acquired = 0u;
    surface->render_target_slot = 0u;
    surface->acquired_generation = 0u;
    surface->acquired_pixels = 0;
    surface->resize_pending = 1u;
    return RIN_RESULT_OK;
}

static uint32_t runtime_async_request_type(void) {
    const RinRuntimeGuiAsyncJob* job;
    if (g_async_requests.count == 0u) return 0u;
    job = &g_async_requests.jobs[g_async_requests.head];
    return g_async_requests.operation_index == 0u || job->second_type == 0u
        ? job->type : job->second_type;
}

static const void* runtime_async_request_payload(void) {
    const RinRuntimeGuiAsyncJob* job;
    if (g_async_requests.count == 0u) return 0;
    job = &g_async_requests.jobs[g_async_requests.head];
    return g_async_requests.operation_index == 0u || job->second_type == 0u
        ? job->payload : job->second_payload;
}

static uint32_t runtime_async_request_payload_size(void) {
    const RinRuntimeGuiAsyncJob* job;
    if (g_async_requests.count == 0u) return 0u;
    job = &g_async_requests.jobs[g_async_requests.head];
    return g_async_requests.operation_index == 0u || job->second_type == 0u
        ? job->payload_size : job->second_payload_size;
}

static void runtime_async_begin_operation(void) {
    memset(&g_async_requests.request, 0, sizeof(g_async_requests.request));
    memset(&g_async_requests.reply, 0, sizeof(g_async_requests.reply));
    g_async_requests.request.magic = RIN_COMPOSITOR_MAGIC;
    g_async_requests.request.version = g_compositor_protocol_version;
    g_async_requests.request.type = runtime_async_request_type();
    g_async_requests.request.payload_size =
        runtime_async_request_payload_size();
    if (!runtime_request_id_valid(g_next_request_id)) g_next_request_id = 1u;
    g_async_requests.request.request_id = g_next_request_id++;
    if (!runtime_request_id_valid(g_next_request_id)) g_next_request_id = 1u;
    g_async_requests.offset = 0u;
    g_async_requests.reply_offset = 0u;
    g_async_requests.stage = RIN_RUNTIME_GUI_ASYNC_SEND_HEADER;
    g_async_requests.started_ms = rin_monotonic_ms();
}

static void runtime_async_complete_head(int32_t status,
                                        const void* payload,
                                        uint32_t payload_size) {
    RinRuntimeGuiAsyncJob completed;
    uint32_t completed_slot;
    if (g_async_requests.count == 0u) return;
    completed_slot = g_async_requests.head;
    completed = g_async_requests.jobs[completed_slot];
    memset(&g_async_requests.jobs[completed_slot], 0,
           sizeof(g_async_requests.jobs[completed_slot]));
    g_async_requests.head = (g_async_requests.head + 1u) %
                            RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    --g_async_requests.count;
    g_async_requests.stage = RIN_RUNTIME_GUI_ASYNC_IDLE;
    g_async_requests.operation_index = 0u;
    g_async_requests.offset = 0u;
    g_async_requests.reply_offset = 0u;
    runtime_async_apply_completion(&completed, status, payload, payload_size);
    if (completed.result_kind != RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE)
        runtime_async_release_old_buffers(&completed);
}

static void runtime_async_abort_all(int32_t status) {
    while (g_async_requests.count != 0u) {
        RinRuntimeGuiAsyncJob aborted =
            g_async_requests.jobs[g_async_requests.head];
        memset(&g_async_requests.jobs[g_async_requests.head], 0,
               sizeof(g_async_requests.jobs[g_async_requests.head]));
        g_async_requests.head = (g_async_requests.head + 1u) %
                                RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
        --g_async_requests.count;
        runtime_async_apply_completion(&aborted, status, 0, 0u);
    }
    g_async_requests.stage = RIN_RUNTIME_GUI_ASYNC_IDLE;
    g_async_requests.operation_index = 0u;
    g_async_requests.offset = 0u;
    g_async_requests.reply_offset = 0u;
}

static int runtime_async_wait(uint32_t events, uint64_t deadline_ms) {
    while (true) {
        uint64_t now = rin_monotonic_ms();
        uint64_t remaining;
        uint32_t timeout_ms;
        RinRuntimePollWaitResult ready;
        if (now == 0u) return -1;
        if (now >= deadline_ms) return 0;
        remaining = deadline_ms - now;
        timeout_ms = remaining > 50u ? 50u : (uint32_t)remaining;
        ready = rinruntime_poll_wait(g_compositor_fd, events, timeout_ms);
        if (ready == RINRUNTIME_POLL_WAIT_TIMEOUT) continue;
        if (ready == RINRUNTIME_POLL_WAIT_FAILURE) return -1;
        return 1;
    }
}

static int runtime_async_pump(uint32_t timeout_ms) {
    uint32_t completed_count = 0u;
    int waited = 0;
    uint64_t wait_deadline;
    if (g_async_requests.count == 0u) return 0;
    if (runtime_deadline_after(rin_monotonic_ms(), timeout_ms,
                               &wait_deadline) != 0) {
        runtime_close_connection();
        return -1;
    }
    if (g_compositor_fd < 0) {
        runtime_async_abort_all(RIN_RESULT_IO);
        return -1;
    }
    while (completed_count < 4u && g_async_requests.count != 0u) {
        const uint32_t type = runtime_async_request_type();
        const uint32_t payload_size = runtime_async_request_payload_size();
        const void* payload = runtime_async_request_payload();
        RinRuntimeGuiAsyncJob* job =
            &g_async_requests.jobs[g_async_requests.head];
        if (g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_IDLE)
            runtime_async_begin_operation();
        {
            const uint64_t now_ms = rin_monotonic_ms();
            if (now_ms == 0u || g_async_requests.started_ms == 0u ||
                now_ms < g_async_requests.started_ms ||
                now_ms - g_async_requests.started_ms >=
                    RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS) {
                runtime_close_connection();
                return -1;
            }
        }
        if (g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_SEND_HEADER ||
            g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_SEND_PAYLOAD) {
            const uint8_t* bytes;
            uint32_t remaining;
            uint32_t expected;
            ssize_t sent;
            if (g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_SEND_HEADER) {
                bytes = (const uint8_t*)&g_async_requests.request;
                expected = (uint32_t)sizeof(g_async_requests.request);
            } else {
                bytes = (const uint8_t*)payload;
                expected = payload_size;
            }
            remaining = expected - g_async_requests.offset;
            sent = send(g_compositor_fd, bytes + g_async_requests.offset,
                        remaining, MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent < 0 && errno == EINTR)
                return (int)completed_count;
            if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int ready;
                if (timeout_ms == 0u || waited != 0)
                    return (int)completed_count;
                waited = 1;
                ready = runtime_async_wait(
                    RINRUNTIME_POLL_WAIT_WRITABLE, wait_deadline);
                if (ready > 0) continue;
                if (ready == 0) return (int)completed_count;
                runtime_close_connection();
                return -1;
            }
            if (sent <= 0 || (uint64_t)sent > remaining) {
                runtime_close_connection();
                return -1;
            }
            g_async_requests.offset += (uint32_t)sent;
            if (g_async_requests.offset < expected) continue;
            g_async_requests.offset = 0u;
            if (g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_SEND_HEADER &&
                payload_size != 0u) {
                g_async_requests.stage = RIN_RUNTIME_GUI_ASYNC_SEND_PAYLOAD;
                continue;
            }
            g_async_requests.stage = RIN_RUNTIME_GUI_ASYNC_RECEIVE_HEADER;
            continue;
        }
        if (g_async_requests.stage == RIN_RUNTIME_GUI_ASYNC_RECEIVE_HEADER) {
            uint8_t* bytes = (uint8_t*)&g_async_requests.reply;
            const uint32_t remaining = (uint32_t)sizeof(g_async_requests.reply) -
                                       g_async_requests.reply_offset;
            ssize_t received = recv(g_compositor_fd,
                bytes + g_async_requests.reply_offset, remaining, MSG_DONTWAIT);
            if (received < 0 && errno == EINTR)
                return (int)completed_count;
            if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int ready;
                if (timeout_ms == 0u || waited != 0)
                    return (int)completed_count;
                waited = 1;
                ready = runtime_async_wait(
                    RINRUNTIME_POLL_WAIT_READABLE, wait_deadline);
                if (ready > 0) continue;
                if (ready == 0) return (int)completed_count;
                runtime_close_connection();
                return -1;
            }
            if (received <= 0 || (uint64_t)received > remaining) {
                runtime_close_connection();
                return -1;
            }
            g_async_requests.reply_offset += (uint32_t)received;
            if (g_async_requests.reply_offset < sizeof(g_async_requests.reply))
                continue;
            if (g_async_requests.reply.magic != RIN_COMPOSITOR_MAGIC ||
                g_async_requests.reply.version != g_compositor_protocol_version ||
                g_async_requests.reply.type != type ||
                g_async_requests.reply.request_id !=
                    g_async_requests.request.request_id ||
                g_async_requests.reply.payload_size > job->reply_capacity ||
                g_async_requests.reply.payload_size >
                    sizeof(g_async_requests.reply_payload)) {
                runtime_close_connection();
                return -1;
            }
            {
                const int32_t private_status =
                    (int32_t)g_async_requests.reply.reserved;
                const int status_known =
                    runtime_compositor_status_known(private_status);
                const int32_t status = status_known
                    ? runtime_public_result(private_status)
                    : RIN_RESULT_CORRUPT_DATA;
                if (g_async_requests.reply.payload_size != 0u) {
                    g_async_requests.stage =
                        RIN_RUNTIME_GUI_ASYNC_RECEIVE_PAYLOAD;
                    g_async_requests.reply_offset = 0u;
                    continue;
                }
                if (g_async_requests.operation_index == 0u &&
                    job->second_type != 0u && status == 0) {
                    g_async_requests.operation_index = 1u;
                    runtime_async_begin_operation();
                    continue;
                }
                const uint32_t result_kind = job->result_kind;
                runtime_async_complete_head(status, 0, 0u);
                ++completed_count;
                if (!status_known) {
                    runtime_close_connection();
                    return -1;
                }
                if (result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE &&
                    status != 0) {
                    runtime_close_connection();
                    return -1;
                }
                if (result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_NONE &&
                    status != 0) {
                    runtime_close_connection();
                    return -1;
                }
            }
            continue;
        }
        if (g_async_requests.stage ==
            RIN_RUNTIME_GUI_ASYNC_RECEIVE_PAYLOAD) {
            const uint32_t remaining = g_async_requests.reply.payload_size -
                                       g_async_requests.reply_offset;
            ssize_t received = recv(g_compositor_fd,
                g_async_requests.reply_payload +
                    g_async_requests.reply_offset,
                remaining, MSG_DONTWAIT);
            if (received < 0 && errno == EINTR)
                return (int)completed_count;
            if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                int ready;
                if (timeout_ms == 0u || waited != 0)
                    return (int)completed_count;
                waited = 1;
                ready = runtime_async_wait(
                    RINRUNTIME_POLL_WAIT_READABLE, wait_deadline);
                if (ready > 0) continue;
                if (ready == 0) return (int)completed_count;
                runtime_close_connection();
                return -1;
            }
            if (received <= 0 || (uint64_t)received > remaining) {
                runtime_close_connection();
                return -1;
            }
            g_async_requests.reply_offset += (uint32_t)received;
            if (g_async_requests.reply_offset <
                g_async_requests.reply.payload_size) continue;
            {
                const int32_t private_status =
                    (int32_t)g_async_requests.reply.reserved;
                const int status_known =
                    runtime_compositor_status_known(private_status);
                const int32_t status = status_known
                    ? runtime_public_result(private_status)
                    : RIN_RESULT_CORRUPT_DATA;
                const uint32_t reply_size =
                    g_async_requests.reply.payload_size;
                const uint32_t result_kind = job->result_kind;
                if (g_async_requests.operation_index == 0u &&
                    job->second_type != 0u && status == 0) {
                    g_async_requests.operation_index = 1u;
                    runtime_async_begin_operation();
                    continue;
                }
                runtime_async_complete_head(status,
                    status_known ? g_async_requests.reply_payload : 0,
                    status_known ? reply_size : 0u);
                ++completed_count;
                if (!status_known) {
                    runtime_close_connection();
                    return -1;
                }
                if ((result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_RESIZE ||
                     result_kind == RIN_RUNTIME_GUI_ASYNC_RESULT_NONE) &&
                    status != 0) {
                    runtime_close_connection();
                    return -1;
                }
            }
            continue;
        }
        runtime_close_connection();
        return -1;
    }
    return (int)completed_count;
}

static int runtime_async_drain(void) {
    uint64_t deadline;
    if (runtime_deadline_after(rin_monotonic_ms(),
                               RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS,
                               &deadline) != 0) {
        runtime_close_connection();
        return -1;
    }
    while (g_async_requests.count != 0u) {
        const uint64_t now = rin_monotonic_ms();
        uint64_t remaining;
        uint32_t wait_ms;
        if (now == 0u) {
            runtime_close_connection();
            return -1;
        }
        if (now >= deadline) {
            runtime_close_connection();
            return -1;
        }
        remaining = deadline - now;
        wait_ms = remaining > 50u ? 50u : (uint32_t)remaining;
        if (runtime_async_pump(wait_ms) < 0) return -1;
    }
    return 0;
}

static uint32_t runtime_async_dispatch_callbacks(uint32_t maximum) {
    uint32_t dispatched = 0u;
    while (g_async_completion_count != 0u && dispatched < maximum) {
        RinRuntimeGuiCompletionDispatch completed =
            g_async_completions[g_async_completion_head];
        RinRuntimeGuiSurface* surface;
        memset(&g_async_completions[g_async_completion_head], 0,
               sizeof(g_async_completions[g_async_completion_head]));
        g_async_completion_head = (g_async_completion_head + 1u) %
                                  RIN_RUNTIME_GUI_COMPLETION_CAPACITY;
        --g_async_completion_count;
        surface = runtime_surface(completed.completion.handle);
        if (surface && surface->completion_callback) {
            surface->completion_callback(&completed.completion,
                                         surface->completion_context);
            ++dispatched;
        }
    }
    return dispatched;
}

static int runtime_rebind_surface(RinRuntimeGuiSurface* surface) {
    RinCompositorCreateSurface create;
    RinCompositorVisibility visibility;
    RinCompositorPosition position;
    RinCompositorSetTitleV1 title;
    RinCompositorWindowStateV1 state;
    RinCompositorSetCursorV1 cursor;
    RinCompositorInputPolicyV1 input_policy;
    RinCompositorFrameCallbackV1 frame_callback;
    RinCompositorTextInputState text_input;
    RinCompositorCommitV2 commit;
    uint32_t old_id;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !surface->active) return 0;
    if (surface->frame_sequence == UINT64_MAX) return -1;
    old_id = surface->id;
    memset(&create, 0, sizeof(create));
    create.width = surface->width;
    create.height = surface->height;
    create.format = 0u;
    create.x = surface->x;
    create.y = surface->y;
    create.flags = surface->surface_flags;
    uint32_t new_id = 0u;
    if (runtime_request(RIN_COMPOSITOR_CREATE_SURFACE, &create, sizeof(create),
                        &new_id, sizeof(new_id), &reply_size, &status) != 0 ||
        status != 0 || reply_size != sizeof(new_id) || new_id == 0u)
        return -1;
    surface->id = new_id;
    if ((surface->surface_flags & RIN_COMPOSITOR_SURFACE_FLAG_CURSOR) != 0u)
        surface->cursor_generation = 0u;
    surface->input_poll_pending = 0u;
    surface->input_event_ready = 0u;
    surface->input_error = 0;
    memset(&surface->pending_input_event, 0,
           sizeof(surface->pending_input_event));
    if (runtime_attach_existing_buffers(surface) != 0) {
        surface->id = old_id;
        return -1;
    }
    memset(&title, 0, sizeof(title));
    title.struct_size = sizeof(title);
    title.version = 1u;
    title.surface_id = new_id;
    strncpy(title.title, surface->title, sizeof(title.title) - 1u);
    if (runtime_request(RIN_COMPOSITOR_SET_TITLE, &title, sizeof(title),
                        0, 0u, &reply_size, &status) != 0 || status != 0 ||
        reply_size != 0u)
        return -1;
    if (surface->icon_path[0] != '\0' &&
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_ICON_METADATA) != 0u) {
        if (runtime_store_icon_path(surface, surface->icon_path) != 0) {
            return -1;
        }
    }
    memset(&position, 0, sizeof(position));
    position.surface_id = new_id;
    position.x = surface->x;
    position.y = surface->y;
    if (runtime_request(RIN_COMPOSITOR_SET_POSITION, &position,
                        sizeof(position), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u)
        return -1;
    memset(&state, 0, sizeof(state));
    state.struct_size = sizeof(state);
    state.version = 1u;
    state.surface_id = new_id;
    state.state = surface->window_state;
    state.workspace = surface->workspace;
    if (runtime_request(RIN_COMPOSITOR_SET_WINDOW_STATE, &state,
                        sizeof(state), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u)
        return -1;
    memset(&visibility, 0, sizeof(visibility));
    visibility.surface_id = new_id;
    visibility.visible = surface->visible;
    if (runtime_request(RIN_COMPOSITOR_SET_VISIBLE, &visibility,
                        sizeof(visibility), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u)
        return -1;
    if ((surface->surface_flags & RIN_COMPOSITOR_SURFACE_FLAG_CURSOR) == 0u) {
        if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_SEMANTIC_CURSOR) == 0u)
            goto cursor_rebind_done;
        memset(&cursor, 0, sizeof(cursor));
        cursor.struct_size = sizeof(cursor);
        cursor.version = 1u;
        cursor.surface_id = new_id;
        cursor.cursor_type = surface->cursor_type;
        if (runtime_request(RIN_COMPOSITOR_SET_CURSOR, &cursor, sizeof(cursor),
                            0, 0u, &reply_size, &status) != 0 || status != 0 ||
            reply_size != 0u)
            return -1;
    }
cursor_rebind_done:
    memset(&input_policy, 0, sizeof(input_policy));
    input_policy.struct_size = sizeof(input_policy);
    input_policy.version = 1u;
    input_policy.surface_id = new_id;
    if (surface->pointer_capture != 0u) {
        input_policy.enabled = surface->pointer_capture;
        if (runtime_request(RIN_COMPOSITOR_SET_POINTER_CAPTURE, &input_policy,
                            sizeof(input_policy), 0, 0u, &reply_size,
                            &status) != 0 || status != 0 || reply_size != 0u)
            return -1;
    }
    if (surface->keyboard_grab != 0u) {
        input_policy.enabled = surface->keyboard_grab;
        if (runtime_request(RIN_COMPOSITOR_SET_KEYBOARD_GRAB, &input_policy,
                            sizeof(input_policy), 0, 0u, &reply_size,
                            &status) != 0 || status != 0 || reply_size != 0u)
            return -1;
    }
    if (surface->modal != 0u) {
        input_policy.enabled = surface->modal;
        if (runtime_request(RIN_COMPOSITOR_SET_MODAL, &input_policy,
                            sizeof(input_policy), 0, 0u, &reply_size,
                            &status) != 0 || status != 0 || reply_size != 0u)
            return -1;
    }
    if (surface->frame_callback_enabled != 0u) {
        memset(&frame_callback, 0, sizeof(frame_callback));
        frame_callback.struct_size = sizeof(frame_callback);
        frame_callback.version = 1u;
        frame_callback.surface_id = new_id;
        frame_callback.enabled = 1u;
        frame_callback.max_inflight = surface->frame_callback_max_inflight;
        if (runtime_request(RIN_COMPOSITOR_SET_FRAME_CALLBACK, &frame_callback,
                            sizeof(frame_callback), 0, 0u, &reply_size,
                            &status) != 0 || status != 0 || reply_size != 0u)
            return -1;
    }
    if (surface->text_input.struct_size != 0u) {
        memset(&text_input, 0, sizeof(text_input));
        text_input.surface_id = new_id;
        text_input.state = surface->text_input;
        if (runtime_request(RIN_COMPOSITOR_SET_TEXT_INPUT_STATE,
                            &text_input, sizeof(text_input), 0, 0u,
                            &reply_size, &status) != 0 || status != 0 ||
            reply_size != 0u)
            return -1;
        if ((surface->text_composition.flags &
             RIN_TEXT_COMPOSITION_FLAG_ACTIVE) != 0u) {
            RinCompositorTextCompositionUpdateV1 composition;
            memset(&composition, 0, sizeof(composition));
            composition.struct_size = sizeof(composition);
            composition.version = 1u;
            composition.surface_id = new_id;
            composition.composition = surface->text_composition;
            if (runtime_request(RIN_COMPOSITOR_SET_TEXT_COMPOSITION,
                                &composition, sizeof(composition), 0, 0u,
                                &reply_size, &status) != 0 || status != 0 ||
                reply_size != 0u)
                return -1;
        }
    }
    memset(&commit, 0, sizeof(commit));
    commit.surface_id = new_id;
    commit.buffer_slot = surface->front_slot;
    commit.frame_sequence = ++surface->frame_sequence;
    if (runtime_request(RIN_COMPOSITOR_COMMIT_V2, &commit, sizeof(commit),
                        0, 0u, &reply_size, &status) != 0 || status != 0)
        return -1;
    surface->slot_submitted_sequence[commit.buffer_slot] =
        commit.frame_sequence;
    if ((surface->surface_flags & RIN_COMPOSITOR_SURFACE_FLAG_CURSOR) != 0u &&
        surface->cursor_surface_enabled != 0u) {
        RinCompositorUpdateCursorSurfaceV1 update;
        if (surface->cursor_surface_visible > 1u ||
            surface->cursor_hotspot_x < 0 ||
            surface->cursor_hotspot_y < 0 ||
            (uint32_t)surface->cursor_hotspot_x >= surface->width ||
            (uint32_t)surface->cursor_hotspot_y >= surface->height)
            return -1;
        memset(&update, 0, sizeof(update));
        update.struct_size = sizeof(update);
        update.version = RIN_COMPOSITOR_ABI_VERSION;
        update.surface_id = new_id;
        update.enabled = 1u;
        update.visible = surface->cursor_surface_visible;
        update.hotspot_x = surface->cursor_hotspot_x;
        update.hotspot_y = surface->cursor_hotspot_y;
        update.cursor_generation = 1u;
        if (runtime_request(RIN_COMPOSITOR_UPDATE_CURSOR_SURFACE, &update,
                            sizeof(update), 0, 0u, &reply_size, &status) != 0 ||
            status != 0 || reply_size != 0u)
            return -1;
        surface->cursor_generation = update.cursor_generation;
    }
    return 0;
}

static int runtime_rebind_surfaces(void) {
    uint32_t index;
    for (index = 0u; index < RIN_RUNTIME_GUI_MAX_SURFACES; ++index)
        if (runtime_rebind_surface(&g_surfaces[index]) != 0) {
            runtime_close_connection();
            return -1;
        }
    return 0;
}

static void runtime_destroy_local_surface(RinRuntimeGuiSurface* surface) {
    if (!surface) return;
    runtime_release_buffers(surface);
    memset(surface, 0, sizeof(*surface));
    surface->shm_handles[0] = -1;
    surface->shm_handles[1] = -1;
}

static RinRuntimeGuiSurface* runtime_new_surface(void) {
    uint32_t index;
    for (index = 0u; index < RIN_RUNTIME_GUI_MAX_SURFACES; ++index) {
        if (!g_surfaces[index].active) {
            if (g_handle_generations[index] == UINT32_MAX) continue;
            uint32_t generation = g_handle_generations[index] + 1u;
            g_handle_generations[index] = generation;
            memset(&g_surfaces[index], 0, sizeof(g_surfaces[index]));
            g_surfaces[index].shm_handles[0] = -1;
            g_surfaces[index].shm_handles[1] = -1;
            g_surfaces[index].handle_generation = generation;
            g_surfaces[index].handle_token =
                (RinRuntimeGuiHandle)(((uint64_t)generation *
                                       RIN_RUNTIME_GUI_MAX_SURFACES) +
                                      index + 1u);
            return &g_surfaces[index];
        }
    }
    return 0;
}

static uint32_t runtime_pack_legacy_event(const RinGuiNativeEventV1* event) {
    uint32_t data;
    if (!event) return 0u;
    switch (event->type) {
        case RIN_GUI_NATIVE_EVENT_POINTER_MOVE:
            return (event->type << 24u) |
                   ((uint32_t)event->screen_x & 0xfffu) |
                   (((uint32_t)event->screen_y & 0xfffu) << 12u);
        case RIN_GUI_NATIVE_EVENT_POINTER_BUTTON: {
            uint32_t button = event->data & RIN_GUI_NATIVE_POINTER_KNOWN_MASK;
            uint32_t action = event->data & RIN_GUI_NATIVE_POINTER_ACTION_MASK;
            uint32_t type = 0u;
            if (button == RIN_GUI_NATIVE_POINTER_LEFT)
                type = action == RIN_GUI_NATIVE_POINTER_ACTION_DOWN ? 3u : 4u;
            else if (button == RIN_GUI_NATIVE_POINTER_RIGHT &&
                     action == RIN_GUI_NATIVE_POINTER_ACTION_DOWN)
                type = 8u;
            if (type == 0u) return 0u;
            return (type << 24u) |
                   ((uint32_t)event->screen_x & 0xfffu) |
                   (((uint32_t)event->screen_y & 0xfffu) << 12u);
        }
        case RIN_GUI_NATIVE_EVENT_KEY_DOWN:
        case RIN_GUI_NATIVE_EVENT_KEY_UP:
            data = ((event->data & RIN_GUI_NATIVE_KEY_DATA_MASK) << 8u) |
                   (((uint32_t)event->key_modifiers &
                     RIN_GUI_NATIVE_KEYMOD_KNOWN_MASK) << 16u);
            if ((event->flags & RIN_GUI_NATIVE_EVENT_FLAG_KEY_REPEAT) != 0u)
                data |= (uint32_t)RIN_GUI_NATIVE_LEGACY_KEY_REPEAT << 16u;
            return (event->type << 24u) | data;
        case RIN_GUI_NATIVE_EVENT_MOUSE_WHEEL:
        case RIN_GUI_NATIVE_EVENT_MOUSE_HORIZONTAL_WHEEL:
            return (event->type << 24u) |
                   ((uint32_t)event->wheel_delta & 0xffu);
        default:
            return (event->type << 24u) | (event->data & 0x00ffffffu);
    }
}

RinRuntimeGuiHandle wnd_create(const char* title, int x, int y, int w, int h) {
    return wnd_create_role(title, x, y, w, h, RIN_COMPOSITOR_ROLE_NORMAL, 1);
}

RinRuntimeGuiHandle wnd_create_role(const char* title, int x, int y, int w,
                                    int h, uint32_t role, int opaque) {
    return wnd_create_flags(title, x, y, w, h, role,
                            opaque ? RIN_WINDOW_FLAG_OPAQUE : 0u);
}

RinRuntimeGuiHandle wnd_create_flags(const char* title, int x, int y, int w,
                                     int h, uint32_t role, uint32_t flags) {
    RinCompositorCreateSurface create;
    RinRuntimeGuiSurface* surface;
    uint32_t id = 0u;
    uint32_t reply_size;
    int32_t status;
    size_t title_length = 0u;
    if (w <= 0 || h <= 0 || !rin_compositor_surface_role_valid(role) ||
        (flags & ~RIN_WINDOW_FLAG_KNOWN_MASK) != 0u ||
        runtime_connect() != 0) return 0;
    if (runtime_async_drain() != 0) return 0;
    if (title) {
        while (title_length < 127u && title[title_length] != '\0')
            ++title_length;
        if (title[title_length] != '\0') return 0;
    }
    memset(&create, 0, sizeof(create));
    create.width = (uint32_t)w;
    create.height = (uint32_t)h;
    create.format = 0u;
    create.x = x;
    create.y = y;
    create.flags = ((role << RIN_COMPOSITOR_SURFACE_ROLE_SHIFT) &
                    RIN_COMPOSITOR_SURFACE_ROLE_MASK) | flags |
                   (role == RIN_COMPOSITOR_ROLE_CURSOR ?
                        RIN_COMPOSITOR_SURFACE_FLAG_CURSOR : 0u);
    if (runtime_request(RIN_COMPOSITOR_CREATE_SURFACE, &create,
                        sizeof(create), &id, sizeof(id), &reply_size,
                        &status) != 0 || status != 0 || reply_size != sizeof(id) ||
        id == 0u)
        return 0;
    surface = runtime_new_surface();
    if (!surface) goto fail_server_surface;
    surface->active = 1u;
    surface->id = id;
    surface->width = (uint32_t)w;
    surface->height = (uint32_t)h;
    surface->x = x;
    surface->y = y;
    surface->visible = 1u;
    surface->role = role;
    surface->surface_flags = create.flags;
    surface->cursor_type = RIN_CURSOR_DEFAULT;
    if (title) {
        memcpy(surface->title, title, title_length);
        surface->title[title_length] = '\0';
    }
    surface->draw_slot = 0u;
    surface->front_slot = 0u;
    if (runtime_make_buffers(surface) != 0) {
        runtime_destroy_local_surface(surface);
        goto fail_server_surface;
    }
    if (title) {
        RinCompositorSetTitleV1 title_request;
        memset(&title_request, 0, sizeof(title_request));
        title_request.struct_size = sizeof(title_request);
        title_request.version = 1u;
        title_request.surface_id = id;
        memcpy(title_request.title, title, title_length);
        if (runtime_request(RIN_COMPOSITOR_SET_TITLE, &title_request,
                            sizeof(title_request), 0, 0u, &reply_size,
                            &status) != 0 || status != 0 || reply_size != 0u) {
            runtime_destroy_local_surface(surface);
            goto fail_server_surface;
        }
    }
    if (runtime_role_has_application_icon(role) &&
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_ICON_METADATA) != 0u) {
        const char* icon_path = runtime_process_icon_path();
        if (icon_path && runtime_store_icon_path(surface, icon_path) != 0) {
            runtime_destroy_local_surface(surface);
            goto fail_server_surface;
        }
    }
    return (RinRuntimeGuiHandle)surface->handle_token;
fail_server_surface:
    (void)runtime_request(RIN_COMPOSITOR_DESTROY_SURFACE, &id, sizeof(id),
                          0, 0u, &reply_size, &status);
    return 0;
}

RinRuntimeGuiHandle wnd_create_frameless(const char* title, int x, int y,
                                         int w, int h) {
    /* Decoration is drawn by Rin::Window; compositor surfaces are always
     * content surfaces so kernel title bars cannot overwrite them. */
    return wnd_create_role(title, x, y, w, h, RIN_COMPOSITOR_ROLE_NORMAL, 1);
}

int wnd_close_async(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t id;
    int result;
    if (!surface || runtime_surface_id(handle, &id) != 0)
        return RIN_RESULT_INVALID_HANDLE;
    if (surface->gpu_readback_pending != 0u ||
        surface->render_target_acquired != 0u)
        return RIN_RESULT_BUSY;
    result = runtime_async_enqueue(RIN_COMPOSITOR_DESTROY_SURFACE, &id,
            sizeof(id),
            0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    runtime_destroy_local_surface(surface);
    return RIN_RESULT_OK;
}

void wnd_close(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface;
    const int close_result = wnd_close_async(handle);
    if (close_result == RIN_RESULT_BUSY) return;
    if (close_result != RIN_RESULT_OK) {
        surface = runtime_surface(handle);
        if (!surface) return;
        runtime_close_connection();
        runtime_destroy_local_surface(surface);
    }
}

int wnd_show_async(RinRuntimeGuiHandle handle, int visible) {
    RinCompositorVisibility request;
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    int result;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.visible = visible ? 1u : 0u;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_VISIBLE, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->visible = request.visible;
    if (surface->visible != 0u)
        surface->window_state &= ~RIN_COMPOSITOR_WINDOW_STATE_MINIMIZED;
    return RIN_RESULT_OK;
}

void wnd_show(RinRuntimeGuiHandle handle, int visible) {
    (void)wnd_show_async(handle, visible);
}

int wnd_title_async(RinRuntimeGuiHandle handle, const char* title) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorSetTitleV1 request;
    int result;
    size_t length = 0u;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (!title) return RIN_RESULT_INVALID_ARGUMENT;
    while (length < sizeof(surface->title) - 1u && title[length] != '\0')
        ++length;
    if (title[length] != '\0') return RIN_RESULT_LIMIT_EXCEEDED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    memcpy(request.title, title, length);
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_TITLE, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    memset(surface->title, 0, sizeof(surface->title));
    memcpy(surface->title, title, length);
    return RIN_RESULT_OK;
}

void wnd_title(RinRuntimeGuiHandle handle, const char* title) {
    (void)wnd_title_async(handle, title);
}

int wnd_set_icon_path(RinRuntimeGuiHandle handle, const char* path) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorSetIconV1 request;
    int result;
    size_t length = 0u;
    if (!surface || !path) return RIN_RESULT_INVALID_ARGUMENT;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_ICON_METADATA) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    while (length < sizeof(request.executable_path) - 1u &&
           path[length] != '\0') {
        const unsigned char value = (unsigned char)path[length];
        if (value < 0x20u || value == '\\')
            return RIN_RESULT_INVALID_ARGUMENT;
        ++length;
    }
    if (path[length] != '\0') return RIN_RESULT_LIMIT_EXCEEDED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    memcpy(request.executable_path, path, length);
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_ICON, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    memset(surface->icon_path, 0, sizeof(surface->icon_path));
    memcpy(surface->icon_path, path, length);
    return RIN_RESULT_OK;
}

int wnd_move_async(RinRuntimeGuiHandle handle, int x, int y) {
    RinCompositorPosition request;
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    int result;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.x = x;
    request.y = y;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_POSITION, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->x = x;
    surface->y = y;
    return RIN_RESULT_OK;
}

void wnd_move(RinRuntimeGuiHandle handle, int x, int y) {
    (void)wnd_move_async(handle, x, y);
}

int wnd_resize_async(RinRuntimeGuiHandle handle, int w, int h) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (w <= 0 || h <= 0 || (uint32_t)w > UINT32_MAX / 4u)
        return RIN_RESULT_INVALID_ARGUMENT;
    return runtime_async_enqueue_resize(handle, surface,
                                        (uint32_t)w, (uint32_t)h);
}

void wnd_resize(RinRuntimeGuiHandle handle, int w, int h) {
    (void)wnd_resize_async(handle, w, h);
}

static int runtime_ring_pop(RinCompositorInputRingEventV1* event) {
    int result;
    if (!event || !g_input_ring_address) return 0;
    for (;;) {
        while (g_input_ring_batch_index < g_input_ring_batch_count) {
            *event = g_input_ring_batch[g_input_ring_batch_index++];
            if (rin_compositor_input_ring_event_current(
                    (RinCompositorInputRingHeaderV1*)g_input_ring_address,
                    event)) {
                event->trace.t4_client_dequeue_ns = rin_monotonic_ms() *
                                                     UINT64_C(1000000);
                event->trace.t5_client_callback_ns =
                    event->trace.t4_client_dequeue_ns;
                return 1;
            }
        }
        g_input_ring_batch_count = 0u;
        g_input_ring_batch_index = 0u;
        result = rin_compositor_input_ring_pop_batch(
            (RinCompositorInputRingHeaderV1*)g_input_ring_address,
            g_input_ring_batch, RIN_RUNTIME_INPUT_BATCH_CAPACITY,
            g_input_ring_bytes, &g_input_ring_batch_count);
        if (result <= 0) return result;
    }
}

int wnd_poll_native(RinRuntimeGuiHandle handle, RinGuiNativeEventV1* event,
                    uint32_t* packed_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinGuiNativeEventV1 received;
    RinCompositorInputRingEventV1 ring_event;
    int poll_result;
    if (!surface || !event || !packed_out) return -1;
    (void)runtime_async_pump(0u);
    runtime_async_dispatch_callbacks(8u);
    memset(event, 0, sizeof(*event));
    *packed_out = 0u;
    memset(&ring_event, 0, sizeof(ring_event));
    if (g_input_ring_address) {
        int ring_result = runtime_ring_pop(&ring_event);
        if (ring_result > 0) {
            if (ring_event.surface_id != surface->id ||
                !rin_compositor_input_ring_event_valid(&ring_event)) {
                /* A client-visible ring record is untrusted input.  Drop the
                 * optional fast path and keep the authenticated socket
                 * fallback alive so one stale record cannot destroy all UI
                 * surfaces. */
                runtime_drop_input_ring();
            } else {
                received = ring_event.event;
                *event = received;
                if (received.type == RIN_GUI_NATIVE_EVENT_POINTER_MOVE ||
                    received.type == RIN_GUI_NATIVE_EVENT_POINTER_BUTTON ||
                    received.type == RIN_GUI_NATIVE_EVENT_MOUSE_WHEEL ||
                    received.type == RIN_GUI_NATIVE_EVENT_MOUSE_HORIZONTAL_WHEEL)
                    surface->focused = 1u;
                *packed_out = runtime_pack_legacy_event(&received);
                return 1;
            }
        }
        if (ring_result == 0) return 0;
        if (ring_result < 0) {
            /* A corrupt or stale ring is not allowed to poison the legacy
             * path; the socket remains available for control and fallback
             * input delivery. */
            runtime_drop_input_ring();
        }
    }
    if (surface->input_error != 0) return -1;
    if (surface->input_event_ready != 0u) {
        received = surface->pending_input_event;
        memset(&surface->pending_input_event, 0,
               sizeof(surface->pending_input_event));
        surface->input_event_ready = 0u;
        if (received.type == RIN_GUI_NATIVE_EVENT_POINTER_MOVE ||
            received.type == RIN_GUI_NATIVE_EVENT_POINTER_BUTTON ||
            received.type == RIN_GUI_NATIVE_EVENT_MOUSE_WHEEL ||
            received.type == RIN_GUI_NATIVE_EVENT_MOUSE_HORIZONTAL_WHEEL)
            surface->focused = 1u;
        *event = received;
        *packed_out = runtime_pack_legacy_event(&received);
        return 1;
    }
    if (g_compositor_fd < 0) return -1;
    poll_result = runtime_async_enqueue_input_poll(handle, surface);
    if (poll_result == RIN_RESULT_IO) return -1;
    if (poll_result != RIN_RESULT_OK && poll_result != RIN_RESULT_BUSY)
        return -1;
    return 0;
}

int wnd_poll(RinRuntimeGuiHandle handle, void* event) {
    RinGuiNativeEventV1 native_event;
    uint32_t packed;
    int result = wnd_poll_native(handle, &native_event, &packed);
    if (result <= 0) return result;
    if (event) *(RinGuiNativeEventV1*)event = native_event;
    return (int)packed;
}

int wnd_set_text_input_state(RinRuntimeGuiHandle handle,
                             const RinTextInputStateV1* state) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorTextInputState request;
    int result;
    if (!surface || !state) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.state = *state;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_TEXT_INPUT_STATE, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->text_input = *state;
    return RIN_RESULT_OK;
}

int wnd_get_text_composition(RinRuntimeGuiHandle handle,
                             RinTextCompositionV1* composition_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinTextCompositionV1 composition;
    uint32_t reply_size;
    int32_t status;
    if (!surface || !composition_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&composition, 0, sizeof(composition));
    if (runtime_request(RIN_COMPOSITOR_GET_TEXT_COMPOSITION, &surface->id,
                        sizeof(surface->id), &composition, sizeof(composition),
                        &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0 || reply_size != sizeof(composition)) {
        memset(composition_out, 0, sizeof(*composition_out));
        return status != 0 ? (int)status : RIN_RESULT_IO;
    }
    *composition_out = composition;
    return RIN_RESULT_OK;
}

int wnd_get_text_composition_async(RinRuntimeGuiHandle handle,
                                   uint64_t cookie) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    return runtime_async_enqueue_query(RIN_COMPOSITOR_GET_TEXT_COMPOSITION,
        &surface->id, sizeof(surface->id), sizeof(RinTextCompositionV1),
        handle, cookie);
}

int wnd_set_text_composition(RinRuntimeGuiHandle handle,
                             const RinTextCompositionV1* composition) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorTextCompositionUpdateV1 request;
    int result;
    if (!surface || !composition) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.composition = *composition;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_TEXT_COMPOSITION, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->text_composition = *composition;
    return RIN_RESULT_OK;
}

int wnd_set_window_state(RinRuntimeGuiHandle handle, uint32_t window_state,
                         uint32_t workspace) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorWindowStateV1 request;
    int result;
    if (!surface || (window_state & ~RIN_COMPOSITOR_WINDOW_STATE_KNOWN_MASK) != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.state = window_state;
    request.workspace = workspace;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_WINDOW_STATE, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->window_state = window_state;
    surface->workspace = workspace;
    surface->visible =
        (window_state & RIN_COMPOSITOR_WINDOW_STATE_MINIMIZED) == 0u;
    return RIN_RESULT_OK;
}

static int runtime_set_input_policy(RinRuntimeGuiHandle handle, uint32_t type,
                                    int enabled) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorInputPolicyV1 request;
    if (!surface || (enabled != 0 && enabled != 1))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.enabled = (uint32_t)enabled;
    {
        int result = runtime_async_enqueue(type, &request, sizeof(request),
            0u, 0, 0u, handle, 0u, RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
        if (result != RIN_RESULT_OK) return result;
        if (type == RIN_COMPOSITOR_SET_POINTER_CAPTURE)
            surface->pointer_capture = (uint32_t)enabled;
        else if (type == RIN_COMPOSITOR_SET_KEYBOARD_GRAB)
            surface->keyboard_grab = (uint32_t)enabled;
        else if (type == RIN_COMPOSITOR_SET_MODAL)
            surface->modal = (uint32_t)enabled;
        return RIN_RESULT_OK;
    }
}

int wnd_set_pointer_capture(RinRuntimeGuiHandle handle, int enabled) {
    return runtime_set_input_policy(handle,
                                    RIN_COMPOSITOR_SET_POINTER_CAPTURE,
                                    enabled);
}

int wnd_set_keyboard_grab(RinRuntimeGuiHandle handle, int enabled) {
    return runtime_set_input_policy(handle,
                                    RIN_COMPOSITOR_SET_KEYBOARD_GRAB,
                                    enabled);
}

int wnd_set_modal(RinRuntimeGuiHandle handle, int enabled) {
    return runtime_set_input_policy(handle, RIN_COMPOSITOR_SET_MODAL, enabled);
}

int wnd_set_cursor(RinRuntimeGuiHandle handle, uint32_t cursor_type) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorSetCursorV1 request;
    int result;
    if (!surface || cursor_type >= RIN_CURSOR_TYPE_COUNT ||
        (surface->surface_flags & RIN_COMPOSITOR_SURFACE_FLAG_CURSOR) != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_SEMANTIC_CURSOR) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    /* Cursor updates are commonly emitted by pointer-move handlers.  Avoid
     * serializing a synchronous compositor RPC when the surface already has
     * the requested cursor; the server state is restored by rebind before a
     * connection is exposed after reconnect. */
    if (surface->cursor_type == cursor_type) return RIN_RESULT_OK;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.cursor_type = cursor_type;
    result = runtime_async_enqueue(RIN_COMPOSITOR_SET_CURSOR, &request,
            sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
    if (result != RIN_RESULT_OK) return result;
    surface->cursor_type = cursor_type;
    return RIN_RESULT_OK;
}

int wnd_update_cursor_surface(RinRuntimeGuiHandle handle,
                              int32_t hotspot_x, int32_t hotspot_y,
                              int visible, int enabled) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorUpdateCursorSurfaceV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    uint64_t generation;
    if (!surface ||
        (surface->surface_flags & RIN_COMPOSITOR_SURFACE_FLAG_CURSOR) == 0u ||
        surface->role != RIN_COMPOSITOR_ROLE_CURSOR)
        return RIN_RESULT_INVALID_HANDLE;
    if (visible < 0 || visible > 1 || enabled < 0 || enabled > 1 ||
        hotspot_x < 0 || hotspot_y < 0 ||
        (uint32_t)hotspot_x >= surface->width ||
        (uint32_t)hotspot_y >= surface->height)
        return RIN_RESULT_INVALID_ARGUMENT;
    if (surface->cursor_generation == UINT64_MAX)
        return RIN_RESULT_LIMIT_EXCEEDED;
    if (runtime_async_drain() != 0) return RIN_RESULT_IO;

    generation = surface->cursor_generation + 1u;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_COMPOSITOR_ABI_VERSION;
    request.surface_id = surface->id;
    request.enabled = (uint32_t)enabled;
    request.visible = (uint32_t)visible;
    request.hotspot_x = hotspot_x;
    request.hotspot_y = hotspot_y;
    request.cursor_generation = generation;
    if (runtime_request(RIN_COMPOSITOR_UPDATE_CURSOR_SURFACE, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0 || reply_size != 0u)
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    surface->cursor_generation = generation;
    surface->cursor_surface_enabled = (uint32_t)enabled;
    surface->cursor_surface_visible = (uint32_t)visible;
    surface->cursor_hotspot_x = hotspot_x;
    surface->cursor_hotspot_y = hotspot_y;
    return RIN_RESULT_OK;
}

int wnd_get_frame_info(RinRuntimeGuiHandle handle,
                       RinCompositorFrameInfoV1* info) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !info) return RIN_RESULT_INVALID_ARGUMENT;
    memset(info, 0, sizeof(*info));
    if (runtime_request(RIN_COMPOSITOR_GET_FRAME_INFO, 0, 0u, info,
                        sizeof(*info), &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0 || reply_size != sizeof(*info)) {
        memset(info, 0, sizeof(*info));
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    }
    return RIN_RESULT_OK;
}

int wnd_get_frame_info_async(RinRuntimeGuiHandle handle, uint64_t cookie) {
    if (!runtime_surface(handle)) return RIN_RESULT_INVALID_HANDLE;
    if ((g_compositor_features &
         RIN_COMPOSITOR_FEATURE_PRESENT_FEEDBACK) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    return runtime_async_enqueue_query(RIN_COMPOSITOR_GET_FRAME_INFO, 0, 0u,
        sizeof(RinCompositorFrameInfoV1), handle, cookie);
}

int wnd_set_frame_callback(RinRuntimeGuiHandle handle, int enabled,
                           uint32_t max_inflight) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorFrameCallbackV1 request;
    if (!surface || (enabled != 0 && enabled != 1) ||
        (enabled != 0 && (max_inflight == 0u || max_inflight > 4u)))
        return RIN_RESULT_INVALID_ARGUMENT;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_FRAME_CALLBACK) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.enabled = enabled != 0 ? 1u : 0u;
    request.max_inflight = enabled != 0 ? max_inflight : 1u;
    {
        int result = runtime_async_enqueue(RIN_COMPOSITOR_SET_FRAME_CALLBACK,
            &request, sizeof(request), 0u, 0, 0u, handle, 0u,
            RIN_RUNTIME_GUI_ASYNC_RESULT_NONE);
        if (result != RIN_RESULT_OK) return result;
        surface->frame_callback_enabled = enabled != 0 ? 1u : 0u;
        surface->frame_callback_max_inflight = enabled != 0 ? max_inflight : 0u;
        return RIN_RESULT_OK;
    }
}

int wnd_ack_frame(RinRuntimeGuiHandle handle, uint64_t frame_sequence,
                  RinCompositorFrameInfoV1* next_frame_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorFrameAckV1 request;
    RinCompositorFrameInfoV1 info;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface) return RIN_RESULT_INVALID_ARGUMENT;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_FRAME_CALLBACK) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.frame_sequence = frame_sequence;
    memset(&info, 0, sizeof(info));
    if (runtime_request(RIN_COMPOSITOR_FRAME_ACK, &request, sizeof(request),
                        &info, sizeof(info), &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0) return status;
    if (reply_size != sizeof(info) || info.struct_size != sizeof(info) ||
        info.version != 1u) return RIN_RESULT_CORRUPT_DATA;
    if (next_frame_out) *next_frame_out = info;
    return RIN_RESULT_OK;
}

int wnd_ack_frame_async(RinRuntimeGuiHandle handle, uint64_t frame_sequence,
                        uint64_t cookie) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorFrameAckV1 request;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_FRAME_CALLBACK) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.frame_sequence = frame_sequence;
    return runtime_async_enqueue_query(RIN_COMPOSITOR_FRAME_ACK, &request,
        sizeof(request), sizeof(RinCompositorFrameInfoV1), handle, cookie);
}

int rinruntime_gui_get_outputs(RinCompositorOutputListV1* outputs) {
    uint32_t reply_size = 0u;
    int32_t status = -1;
    uint32_t index;
    if (!outputs) return RIN_RESULT_INVALID_ARGUMENT;
    memset(outputs, 0, sizeof(*outputs));
    if (runtime_request(RIN_COMPOSITOR_ENUMERATE_OUTPUTS, 0, 0u, outputs,
                        sizeof(*outputs), &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0 || reply_size != sizeof(*outputs) ||
        outputs->struct_size != sizeof(*outputs) || outputs->version != 1u ||
        outputs->flags != 0u || outputs->reserved != 0u ||
        outputs->count == 0u || outputs->count > RIN_COMPOSITOR_MAX_OUTPUTS) {
        memset(outputs, 0, sizeof(*outputs));
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    }
    for (index = 0u; index < outputs->count; ++index) {
        const RinCompositorOutputDescriptorV1* output = &outputs->outputs[index];
        if (output->struct_size != sizeof(*output) || output->version != 1u ||
            output->flags != 0u || output->width == 0u ||
            output->height == 0u || output->pitch < output->width * 4u ||
            output->scale_numerator == 0u || output->scale_denominator == 0u ||
            output->reserved[0] != 0u || output->reserved[1] != 0u) {
            memset(outputs, 0, sizeof(*outputs));
            return RIN_RESULT_CORRUPT_DATA;
        }
    }
    return RIN_RESULT_OK;
}

int rinruntime_gui_get_outputs_async(RinRuntimeGuiHandle completion_handle,
                                     uint64_t cookie) {
    if (!runtime_surface(completion_handle)) return RIN_RESULT_INVALID_HANDLE;
    return runtime_async_enqueue_query(RIN_COMPOSITOR_ENUMERATE_OUTPUTS, 0,
        0u, sizeof(RinCompositorOutputListV1), completion_handle, cookie);
}

int wnd_present(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorDamage damage;
    RinCompositorCommitV2 commit;
    uint32_t next_slot;
    int result;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u ||
        surface->resize_pending != 0u ||
        surface->copy_front_before_draw != 0u ||
        surface->draw_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        !surface->pixels[surface->draw_slot])
        return RIN_RESULT_BUSY;
    next_slot = surface->draw_slot ^ 1u;
    if (next_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        !surface->pixels[next_slot])
        return RIN_RESULT_CORRUPT_DATA;
    memset(&damage, 0, sizeof(damage));
    damage.surface_id = surface->id;
    damage.x = surface->x;
    damage.y = surface->y;
    damage.w = surface->width;
    damage.h = surface->height;
    memset(&commit, 0, sizeof(commit));
    commit.surface_id = surface->id;
    commit.buffer_slot = surface->draw_slot;
    if (surface->frame_sequence == UINT64_MAX)
        return RIN_RESULT_LIMIT_EXCEEDED;
    commit.frame_sequence = surface->frame_sequence + 1u;
    result = runtime_async_enqueue(RIN_COMPOSITOR_DAMAGE, &damage,
            sizeof(damage),
            RIN_COMPOSITOR_COMMIT_V2, &commit, sizeof(commit), handle,
            commit.frame_sequence,
            RIN_RUNTIME_GUI_ASYNC_RESULT_FRAME);
    if (result != RIN_RESULT_OK) return result;
    surface->frame_present_pending = 1u;
    surface->frame_sequence = commit.frame_sequence;
    return RIN_RESULT_OK;
}

static int runtime_draw_slot_available(RinRuntimeGuiSurface* surface,
                                       uint32_t slot) {
    RinCompositorGpuImageV1 image;
    int result;
    if (!surface || slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        slot != surface->draw_slot)
        return RIN_RESULT_INVALID_ARGUMENT;
    result = wnd_export_gpu_image(surface->handle_token, &image);
    if (result != RIN_RESULT_OK) return result;
    if (image.buffer_slot != slot || image.surface_id != surface->id)
        return RIN_RESULT_CORRUPT_DATA;
    return rinruntime_compositor_gpu_slot_reuse_status_v1(
        surface->slot_submitted_sequence[slot], image.acquire_fence);
}

int rinruntime_compositor_gpu_import_frame_v1(
    RinRuntimeGuiHandle handle, uint64_t expected_generation,
    const RinRuntimeCompositorGpuFrameV1* frame) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    int result;
    if (!surface || !frame ||
        frame->struct_size != sizeof(*frame) ||
        frame->version != RIN_RUNTIME_COMPOSITOR_GPU_FRAME_V1_VERSION ||
        expected_generation == 0u ||
        surface->render_target_generation != expected_generation ||
        frame->width != surface->width || frame->height != surface->height)
        return RIN_RESULT_INVALID_ARGUMENT;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u || surface->resize_pending != 0u ||
        surface->draw_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        !surface->pixels[surface->draw_slot])
        return RIN_RESULT_BUSY;
    result = runtime_draw_slot_available(surface, surface->draw_slot);
    if (result != RIN_RESULT_OK) return result;
    result = rinruntime_compositor_gpu_copy_frame_v1(
        surface->pixels[surface->draw_slot], surface->bytes, surface->pitch,
        RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8, frame);
    if (result != RIN_RESULT_OK) return result;
    surface->copy_front_before_draw = 0u;
    /* wnd_present queues the established Compositor damage+commit path. The
     * source GPU allocation is no longer needed: pixels have been copied to
     * the window owner's SHM buffer before this point. */
    return wnd_present(handle);
}

int wnd_get_gpu_frame_generation_v1(RinRuntimeGuiHandle handle,
                                    uint64_t* generation_out) {
    RinRuntimeGuiSurface* surface;
    if (!generation_out) return RIN_RESULT_INVALID_ARGUMENT;
    *generation_out = 0u;
    surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->resize_pending != 0u) return RIN_RESULT_BUSY;
    if (surface->render_target_generation == 0u)
        return RIN_RESULT_CORRUPT_DATA;
    *generation_out = surface->render_target_generation;
    return RIN_RESULT_OK;
}

int wnd_get_gpu_surface_v1(
    RinRuntimeGuiHandle handle,
    RinRuntimeCompositorGpuSurfaceV1* surface_out) {
    RinRuntimeGuiSurface* surface;
    if (!surface_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(surface_out, 0, sizeof(*surface_out));
    surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->resize_pending != 0u) return RIN_RESULT_BUSY;
    if (surface->width == 0u || surface->height == 0u ||
        surface->width > UINT32_MAX / 4u ||
        surface->pitch < surface->width * 4u ||
        surface->bytes < (uint64_t)surface->pitch * surface->height ||
        surface->bytes > RIN_RUNTIME_GUI_MAX_BUFFER_BYTES ||
        surface->render_target_generation == 0u)
        return RIN_RESULT_CORRUPT_DATA;

    surface_out->struct_size = sizeof(*surface_out);
    surface_out->version = RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_V1_VERSION;
    surface_out->width = surface->width;
    surface_out->height = surface->height;
    surface_out->supported_frame_formats =
        RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_FORMAT_BGRA8_BIT |
        RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_FORMAT_RGBA8_BIT;
    surface_out->surface_generation = surface->render_target_generation;
    return RIN_RESULT_OK;
}

int wnd_import_gpu_readback_frame_v1(
    RinRuntimeGuiHandle handle, uint64_t expected_generation,
    const RinRuntimeCompositorGpuFrameV1* frame) {
    return rinruntime_compositor_gpu_import_frame_v1(
        handle, expected_generation, frame);
}

static int runtime_gpu_surface_query_callback_v1(
    void* context, RinRuntimeGuiHandle handle,
    RinRuntimeCompositorGpuSurfaceV1* surface_out) {
    if (context != NULL) return RIN_RESULT_INVALID_ARGUMENT;
    return wnd_get_gpu_surface_v1(handle, surface_out);
}

static int runtime_gpu_frame_import_callback_v1(
    void* context, RinRuntimeGuiHandle handle, uint64_t surface_generation,
    const RinRuntimeCompositorGpuFrameV1* frame) {
    if (context != NULL) return RIN_RESULT_INVALID_ARGUMENT;
    return wnd_import_gpu_readback_frame_v1(handle, surface_generation, frame);
}

int wnd_get_gpu_surface_ops_v1(
    RinRuntimeCompositorGpuSurfaceOpsV1* ops_out) {
    if (!ops_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(ops_out, 0, sizeof(*ops_out));
    ops_out->struct_size = sizeof(*ops_out);
    ops_out->version = RIN_RUNTIME_COMPOSITOR_GPU_SURFACE_OPS_V1_VERSION;
    ops_out->query = runtime_gpu_surface_query_callback_v1;
    ops_out->import_frame = runtime_gpu_frame_import_callback_v1;
    return RIN_RESULT_OK;
}

int wnd_present_gpu_readback_lease_v1(
    RinRuntimeGuiHandle handle,
    const RinRuntimeGpuReadbackLeaseV1* readback, uint64_t cookie) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuReadbackLeasePresentV1 request;
    uint32_t job_slot;
    int result;
    if (!surface || !readback) return RIN_RESULT_INVALID_ARGUMENT;
    if ((g_compositor_features &
         (RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI |
          RIN_COMPOSITOR_FEATURE_GPU_READBACK_LEASE)) !=
        (RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI |
         RIN_COMPOSITOR_FEATURE_GPU_READBACK_LEASE))
        return RIN_RESULT_NOT_SUPPORTED;
    if (!surface->completion_callback ||
        readback->struct_size != sizeof(*readback) ||
        readback->version != RIN_RUNTIME_GPU_READBACK_LEASE_V1_VERSION ||
        (readback->format != RIN_COMPOSITOR_GPU_READBACK_FORMAT_BGRA8 &&
         readback->format != RIN_COMPOSITOR_GPU_READBACK_FORMAT_RGBA8) ||
        readback->width != surface->width ||
        readback->height != surface->height ||
        readback->width > UINT32_MAX / 4u ||
        readback->row_pitch < readback->width * 4u ||
        readback->bytes == 0u ||
        readback->allocation_offset > UINT64_MAX - readback->bytes ||
        readback->expected_surface_generation == 0u ||
        readback->capability.struct_size !=
            sizeof(readback->capability) ||
        readback->capability.version !=
            RIN_GPU_CROSS_PROCESS_CAPABILITY_V2_VERSION ||
        readback->capability.token == 0u ||
        readback->capability.device_generation == 0u ||
        (readback->capability.rights &
         RIN_GPU_CROSS_PROCESS_RIGHT_READ) == 0u ||
        (readback->capability.rights &
         ~RIN_GPU_CROSS_PROCESS_RIGHT_MASK) != 0u ||
        readback->capability.reserved[0] != 0u ||
        readback->capability.reserved[1] != 0u ||
        readback->capability.reserved[2] != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    {
        const uint64_t last_row_offset =
            (uint64_t)(readback->height - 1u) * readback->row_pitch;
        const uint64_t row_bytes = (uint64_t)readback->width * 4u;
        if (last_row_offset > UINT64_MAX - row_bytes ||
            readback->bytes < last_row_offset + row_bytes)
            return RIN_RESULT_INVALID_ARGUMENT;
    }
    if (readback->expected_surface_generation !=
        surface->compositor_surface_generation)
        return RIN_RESULT_BUSY;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u || surface->resize_pending != 0u)
        return RIN_RESULT_BUSY;
    if (surface->frame_sequence == UINT64_MAX)
        return RIN_RESULT_LIMIT_EXCEEDED;
    if (g_async_completion_count +
            g_async_readback_completion_reservations >=
        RIN_RUNTIME_GUI_COMPLETION_CAPACITY)
        return RIN_RESULT_BUSY;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_COMPOSITOR_GPU_READBACK_LEASE_VERSION;
    request.surface_id = surface->id;
    request.format = readback->format;
    request.expected_surface_generation =
        readback->expected_surface_generation;
    request.frame_sequence = surface->frame_sequence + 1u;
    request.allocation_offset = readback->allocation_offset;
    request.bytes = readback->bytes;
    request.capability = readback->capability;
    request.width = readback->width;
    request.height = readback->height;
    request.row_pitch = readback->row_pitch;
    result = runtime_async_enqueue(
        RIN_COMPOSITOR_PRESENT_GPU_READBACK_LEASE, &request,
        sizeof(request), 0u, 0, 0u, handle, cookie,
        RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_READBACK);
    if (result != RIN_RESULT_OK) return result;
    job_slot = (g_async_requests.head + g_async_requests.count - 1u) %
               RIN_RUNTIME_GUI_ASYNC_QUEUE_CAPACITY;
    g_async_requests.jobs[job_slot].reply_capacity =
        sizeof(RinCompositorGpuReadbackLeaseResultV1);
    ++g_async_readback_completion_reservations;
    surface->frame_present_pending = 1u;
    surface->gpu_readback_pending = 1u;
    return RIN_RESULT_OK;
}

int wnd_present_gpu_readback_lease_sync_v1(
    RinRuntimeGuiHandle handle,
    const RinRuntimeGpuReadbackLeaseV1* readback) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuReadbackLeasePresentV1 request;
    RinCompositorGpuReadbackLeaseResultV1 response;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    int result;
    if (!surface || !readback) return RIN_RESULT_INVALID_ARGUMENT;
    if (!surface->pixels[0] || !surface->pixels[1])
        return RIN_RESULT_NOT_SUPPORTED;
    if ((g_compositor_features &
         (RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI |
          RIN_COMPOSITOR_FEATURE_GPU_READBACK_LEASE)) !=
        (RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI |
         RIN_COMPOSITOR_FEATURE_GPU_READBACK_LEASE))
        return RIN_RESULT_NOT_SUPPORTED;
    if (readback->struct_size != sizeof(*readback) ||
        readback->version != RIN_RUNTIME_GPU_READBACK_LEASE_V1_VERSION ||
        (readback->format != RIN_COMPOSITOR_GPU_READBACK_FORMAT_BGRA8 &&
         readback->format != RIN_COMPOSITOR_GPU_READBACK_FORMAT_RGBA8) ||
        readback->width != surface->width ||
        readback->height != surface->height ||
        readback->width > UINT32_MAX / 4u ||
        readback->row_pitch < readback->width * 4u ||
        readback->bytes == 0u ||
        readback->allocation_offset > UINT64_MAX - readback->bytes ||
        readback->expected_surface_generation == 0u ||
        readback->capability.struct_size !=
            sizeof(readback->capability) ||
        readback->capability.version !=
            RIN_GPU_CROSS_PROCESS_CAPABILITY_V2_VERSION ||
        readback->capability.token == 0u ||
        readback->capability.device_generation == 0u ||
        readback->capability.rights != RIN_GPU_CROSS_PROCESS_RIGHT_READ ||
        readback->capability.reserved[0] != 0u ||
        readback->capability.reserved[1] != 0u ||
        readback->capability.reserved[2] != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    {
        const uint64_t last_row_offset =
            (uint64_t)(readback->height - 1u) * readback->row_pitch;
        const uint64_t row_bytes = (uint64_t)readback->width * 4u;
        if (last_row_offset > UINT64_MAX - row_bytes ||
            readback->bytes < last_row_offset + row_bytes)
            return RIN_RESULT_INVALID_ARGUMENT;
    }
    if (readback->expected_surface_generation !=
        surface->compositor_surface_generation)
        return RIN_RESULT_BUSY;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u || surface->resize_pending != 0u)
        return RIN_RESULT_BUSY;
    if (surface->frame_sequence == UINT64_MAX) return RIN_RESULT_LIMIT_EXCEEDED;
    if (g_async_requests.count != 0u) return RIN_RESULT_BUSY;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_COMPOSITOR_GPU_READBACK_LEASE_VERSION;
    request.surface_id = surface->id;
    request.format = readback->format;
    request.expected_surface_generation =
        readback->expected_surface_generation;
    request.frame_sequence = surface->frame_sequence + 1u;
    request.allocation_offset = readback->allocation_offset;
    request.bytes = readback->bytes;
    request.capability = readback->capability;
    request.width = readback->width;
    request.height = readback->height;
    request.row_pitch = readback->row_pitch;

    surface->frame_present_pending = 1u;
    surface->gpu_readback_pending = 1u;
    result = runtime_request(RIN_COMPOSITOR_PRESENT_GPU_READBACK_LEASE,
                             &request, sizeof(request), &response,
                             sizeof(response), &reply_size, &status);
    surface->frame_present_pending = 0u;
    surface->gpu_readback_pending = 0u;
    if (result != 0) return RIN_RESULT_IO;
    if (status != 0) return status;
    if (reply_size != sizeof(response) ||
        response.struct_size != sizeof(response) ||
        response.version != RIN_COMPOSITOR_GPU_READBACK_LEASE_VERSION ||
        response.surface_id != surface->id ||
        response.buffer_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        response.surface_generation !=
            request.expected_surface_generation ||
        response.frame_sequence != request.frame_sequence ||
        response.frame_sequence <= surface->frame_sequence)
        return RIN_RESULT_CORRUPT_DATA;

    surface->slot_submitted_sequence[response.buffer_slot] =
        response.frame_sequence;
    surface->frame_sequence = response.frame_sequence;
    surface->front_slot = response.buffer_slot;
    surface->draw_slot = response.buffer_slot ^ 1u;
    surface->copy_front_before_draw = 1u;
    return RIN_RESULT_OK;
}

static int runtime_query_compositor_peer_identity(
    void* context, rin_unix_peer_identity_v1* peer_out,
    uint32_t* peer_size_out) {
    const int* descriptor = (const int*)context;
    socklen_t size = sizeof(*peer_out);
    if (!descriptor || *descriptor < 0 || !peer_out || !peer_size_out)
        return RIN_RESULT_INVALID_ARGUMENT;
    *peer_size_out = 0u;
    if (getsockopt(*descriptor, SOL_SOCKET, SO_RIN_UNIX_PEER_IDENTITY,
                   peer_out, &size) != 0)
        return errno == ENOPROTOOPT ? RIN_RESULT_NOT_SUPPORTED
                                    : RIN_RESULT_IO;
    if (size > UINT32_MAX) return RIN_RESULT_CORRUPT_DATA;
    *peer_size_out = (uint32_t)size;
    return RIN_RESULT_OK;
}

int wnd_get_compositor_peer_identity_v1(
    RinIpcPeerIdentityV1* identity_out) {
    int descriptor;
    if (!identity_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(identity_out, 0, sizeof(*identity_out));
    if (g_compositor_fd < 0 && runtime_connect() != 0)
        return RIN_RESULT_IO;
    descriptor = g_compositor_fd;
    return rinruntime_compositor_peer_identity_query_v1(
        runtime_query_compositor_peer_identity, &descriptor, identity_out);
}

int wnd_export_gpu_image(RinRuntimeGuiHandle handle,
                         RinCompositorGpuImageV1* image_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuExportImageV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !image_out ||
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION;
    request.surface_id = surface->id;
    request.buffer_slot = surface->draw_slot;
    request.expected_surface_generation =
        surface->compositor_surface_generation;
    if (runtime_request(RIN_COMPOSITOR_EXPORT_GPU_IMAGE, &request,
                        sizeof(request), image_out, sizeof(*image_out),
                        &reply_size, &status) != 0 || status != 0 ||
        reply_size != sizeof(*image_out) ||
        rinruntime_compositor_shm_export_validate_v1(
            image_out, surface->id, surface->draw_slot,
            surface->compositor_surface_generation, surface->width,
            surface->height, surface->pitch, 0u, surface->bytes) !=
            RIN_RESULT_OK)
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    surface->compositor_surface_generation = image_out->surface_generation;
    return RIN_RESULT_OK;
}

int wnd_export_gpu_image_async(RinRuntimeGuiHandle handle, uint64_t cookie) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuExportImageV1 request;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if ((g_compositor_features & RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION;
    request.surface_id = surface->id;
    request.buffer_slot = surface->draw_slot;
    return runtime_async_enqueue_query(RIN_COMPOSITOR_EXPORT_GPU_IMAGE,
        &request, sizeof(request), sizeof(RinCompositorGpuImageV1), handle,
        cookie);
}

int wnd_present_gpu(RinRuntimeGuiHandle handle,
                    const RinCompositorGpuPresentV1* present) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuPresentV1 request;
    int result;
    if (!surface || !present ||
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u ||
        surface->resize_pending != 0u ||
        present->struct_size != sizeof(*present) ||
        present->version != RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION ||
        present->reserved != 0u || present->reserved2 != 0u ||
        present->buffer_slot != surface->draw_slot ||
        present->frame_sequence == 0u ||
        present->release_fence != present->frame_sequence)
        return RIN_RESULT_INVALID_ARGUMENT;
    request = *present;
    request.surface_id = surface->id;
    result = runtime_async_enqueue(RIN_COMPOSITOR_PRESENT_GPU_IMAGE, &request,
            sizeof(request), 0u, 0, 0u, handle, request.frame_sequence,
            RIN_RUNTIME_GUI_ASYNC_RESULT_GPU_FRAME);
    if (result != RIN_RESULT_OK) return result;
    surface->frame_present_pending = 1u;
    return RIN_RESULT_OK;
}

int wnd_acquire_render_target(RinRuntimeGuiHandle handle,
                              RinRenderTarget* out_target) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t slot;
    if (!out_target) return RIN_RESULT_INVALID_ARGUMENT;
    memset(out_target, 0, sizeof(*out_target));
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->render_target_acquired != 0u ||
        surface->frame_present_pending != 0u ||
        surface->resize_pending != 0u) return RIN_RESULT_BUSY;
    slot = surface->draw_slot;
    if (slot >= RIN_COMPOSITOR_MAX_BUFFERS || !surface->pixels[slot] ||
        surface->render_target_generation == 0u)
        return RIN_RESULT_CORRUPT_DATA;
    {
        int result = runtime_draw_slot_available(surface, slot);
        if (result != RIN_RESULT_OK) return result;
    }
    if (surface->copy_front_before_draw != 0u) {
        if (surface->front_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
            !surface->pixels[surface->front_slot])
            return RIN_RESULT_CORRUPT_DATA;
        if (slot != surface->front_slot)
            memcpy(surface->pixels[slot],
                   surface->pixels[surface->front_slot],
                   (size_t)surface->bytes);
        surface->copy_front_before_draw = 0u;
    }
    out_target->struct_size = sizeof(*out_target);
    out_target->version = RIN_RENDER_TARGET_VERSION;
    out_target->pixels = surface->pixels[slot];
    out_target->width = surface->width;
    out_target->height = surface->height;
    out_target->pitch = surface->pitch;
    out_target->format = RIN_RENDER_TARGET_FORMAT_BGRA32;
    out_target->generation = surface->render_target_generation;
    out_target->buffer_slot = slot;
    out_target->flags = RIN_RENDER_TARGET_FLAG_WRITABLE |
                        RIN_RENDER_TARGET_FLAG_EXTERNAL;
    surface->render_target_acquired = 1u;
    surface->render_target_slot = slot;
    surface->acquired_generation = out_target->generation;
    surface->acquired_pixels = (uint8_t*)out_target->pixels;
    return RIN_RESULT_OK;
}

int wnd_release_render_target(RinRuntimeGuiHandle handle,
                              const RinRenderTarget* target) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface || !target) return RIN_RESULT_INVALID_ARGUMENT;
    if (surface->render_target_acquired == 0u) return RIN_RESULT_BUSY;
    if (target->struct_size != sizeof(*target) ||
        target->version != RIN_RENDER_TARGET_VERSION ||
        target->reserved0 != 0u || target->pixels != surface->acquired_pixels ||
        target->generation != surface->acquired_generation ||
        target->buffer_slot != surface->render_target_slot ||
        target->width != surface->width || target->height != surface->height ||
        target->pitch != surface->pitch ||
        target->format != RIN_RENDER_TARGET_FORMAT_BGRA32 ||
        target->flags != (RIN_RENDER_TARGET_FLAG_WRITABLE |
                          RIN_RENDER_TARGET_FLAG_EXTERNAL))
        return RIN_RESULT_INVALID_ARGUMENT;
    surface->render_target_acquired = 0u;
    surface->render_target_slot = 0u;
    surface->acquired_generation = 0u;
    surface->acquired_pixels = 0;
    return RIN_RESULT_OK;
}

int wnd_get_position(RinRuntimeGuiHandle handle, int* x, int* y) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (x) *x = surface->x;
    if (y) *y = surface->y;
    return RIN_RESULT_OK;
}

int rinruntime_gui_get_size(RinRuntimeGuiHandle handle, int* width,
                            int* height) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface) return -1;
    if (width) *width = (int)surface->width;
    if (height) *height = (int)surface->height;
    return 0;
}

int wnd_get_size(RinRuntimeGuiHandle handle, int* width, int* height) {
    return rinruntime_gui_get_size(handle, width, height);
}

int wnd_get_geometry(RinRuntimeGuiHandle handle, RinWindowGeometryV1* geometry) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface || !geometry) return RIN_RESULT_INVALID_ARGUMENT;
    memset(geometry, 0, sizeof(*geometry));
    geometry->struct_size = sizeof(*geometry);
    geometry->version = RIN_WINDOW_ABI_VERSION;
    geometry->x = surface->x;
    geometry->y = surface->y;
    geometry->width = surface->width;
    geometry->height = surface->height;
    geometry->scale_numerator = 1u;
    geometry->scale_denominator = 1u;
    return RIN_RESULT_OK;
}

int rinruntime_gui_is_focused(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    return surface ? (surface->focused != 0u) : 0;
}

int wnd_is_focused(RinRuntimeGuiHandle handle) {
    return rinruntime_gui_is_focused(handle);
}

int wnd_set_compositor_completion_callback(
    RinRuntimeGuiHandle handle, RinRuntimeGuiCompletionCallback callback,
    void* context) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (!callback && surface->gpu_readback_pending != 0u)
        return RIN_RESULT_BUSY;
    surface->completion_callback = callback;
    surface->completion_context = context;
    return RIN_RESULT_OK;
}

int wnd_dispatch_compositor(uint32_t timeout_ms, uint32_t max_completions) {
    uint32_t dispatched;
    int pump_result;
    if (max_completions == 0u) return RIN_RESULT_INVALID_ARGUMENT;
    if (max_completions > RIN_RUNTIME_GUI_COMPLETION_CAPACITY)
        max_completions = RIN_RUNTIME_GUI_COMPLETION_CAPACITY;
    if (timeout_ms > 50u) timeout_ms = 50u;
    pump_result = runtime_async_pump(timeout_ms);
    dispatched = runtime_async_dispatch_callbacks(max_completions);
    if (pump_result < 0) return RIN_RESULT_IO;
    return (int)dispatched;
}

int wnd_reconnect_compositor(void) {
    if (g_async_requests.count != 0u) return RIN_RESULT_BUSY;
    return runtime_connect() == 0 ? RIN_RESULT_OK : RIN_RESULT_IO;
}

static int runtime_drag_drop_actions_valid(uint32_t actions) {
    return actions != 0u && (actions & ~UINT32_C(7)) == 0u;
}

static int runtime_drag_drop_action_valid(uint32_t action) {
    return runtime_drag_drop_actions_valid(action) &&
           (action & (action - 1u)) == 0u;
}

static int runtime_drag_drop_payload_valid(
    const RinRuntimeDragDropPayloadV1* payload) {
    uint32_t index;
    if (payload == NULL || payload->mime_size == 0u ||
        payload->mime_size > RINRUNTIME_DRAG_DROP_MAX_MIME_BYTES ||
        payload->label_size > RINRUNTIME_DRAG_DROP_MAX_LABEL_BYTES ||
        payload->payload_size > RIN_RUNTIME_DRAG_DROP_MAX_PAYLOAD_BYTES ||
        payload->reserved0 != 0u || payload->payload_capability == 0u ||
        payload->mime[payload->mime_size] != '\0' ||
        payload->label[payload->label_size] != '\0' ||
        memchr(payload->mime, '\0', payload->mime_size) != NULL ||
        memchr(payload->label, '\0', payload->label_size) != NULL)
        return 0;
    for (index = payload->mime_size + 1u;
         index < sizeof(payload->mime); ++index)
        if (payload->mime[index] != '\0') return 0;
    for (index = payload->label_size + 1u;
         index < sizeof(payload->label); ++index)
        if (payload->label[index] != '\0') return 0;
    return 1;
}

static int runtime_drag_drop_request(uint32_t type, const void* request,
                                     uint32_t request_size, void* response,
                                     uint32_t response_capacity,
                                     uint32_t expected_response_size) {
    uint32_t response_size = 0u;
    int32_t status = -1;
    if (runtime_request(type, request, request_size, response,
                        response_capacity, &response_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != RIN_RESULT_OK) return status;
    if (response_size != expected_response_size)
        return RIN_RESULT_CORRUPT_DATA;
    return RIN_RESULT_OK;
}

static int runtime_drag_drop_owner_bind_offer_v1(
    uint64_t offer_token, uint64_t generation, uint32_t actions,
    const RinRuntimeDragDropPayloadV1* payloads, uint32_t payload_count);

int rinruntime_drag_drop_begin_v1(
    RinRuntimeGuiHandle source, uint64_t session_id, uint64_t generation,
    uint32_t actions, const RinRuntimeDragDropPayloadV1* payloads,
    uint32_t payload_count, uint64_t* offer_token_out) {
    RinRuntimeDragDropWireBeginV1 request;
    RinRuntimeGuiSurface* surface = runtime_surface(source);
    uint32_t response_size = 0u;
    uint64_t offer_token = 0u;
    int32_t status = -1;
    int result;
    uint32_t index;
    if (offer_token_out != NULL) *offer_token_out = 0u;
    if (surface == NULL || offer_token_out == NULL || session_id == 0u ||
        session_id == UINT64_MAX || generation == 0u ||
        generation == UINT64_MAX || !runtime_drag_drop_actions_valid(actions) ||
        payloads == NULL || payload_count == 0u ||
        payload_count > RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS)
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
    request.session_id = session_id;
    request.generation = generation;
    request.actions = actions;
    request.payload_count = payload_count;
    for (index = 0u; index < payload_count; ++index) {
        if (!runtime_drag_drop_payload_valid(&payloads[index]))
            return RIN_RESULT_INVALID_ARGUMENT;
        request.payloads[index] = payloads[index];
    }
    if (runtime_request(RIN_RUNTIME_DRAG_DROP_BEGIN, &request,
                        sizeof(request), &offer_token, sizeof(offer_token),
                        &response_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != RIN_RESULT_OK) return status;
    if (response_size != sizeof(offer_token) || offer_token == 0u)
        return RIN_RESULT_CORRUPT_DATA;
    result = runtime_drag_drop_owner_bind_offer_v1(
        offer_token, generation, actions, payloads, payload_count);
    if (result != RIN_RESULT_OK) {
        RinRuntimeDragDropWireLeaseV1 cancel;
        uint32_t cancel_response_size = 0u;
        int32_t cancel_status = -1;
        memset(&cancel, 0, sizeof(cancel));
        cancel.struct_size = sizeof(cancel);
        cancel.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
        cancel.offer_token = offer_token;
        cancel.generation = generation;
        (void)runtime_request(RIN_RUNTIME_DRAG_DROP_CANCEL, &cancel,
                              sizeof(cancel), NULL, 0u,
                              &cancel_response_size, &cancel_status);
        return result;
    }
    *offer_token_out = offer_token;
    return RIN_RESULT_OK;
}

int rinruntime_drag_drop_update_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation,
    uint32_t action, uint64_t* target_handle_out, uint32_t* state_out) {
    RinRuntimeDragDropWireUpdateV1 request;
    RinRuntimeDragDropWireUpdateResultV1 response;
    RinRuntimeGuiSurface* surface = runtime_surface(source);
    int result;
    if (target_handle_out != NULL) *target_handle_out = 0u;
    if (state_out != NULL) *state_out = RINRUNTIME_DRAG_DROP_STATE_NONE;
    if (surface == NULL || offer_token == 0u || generation == 0u ||
        generation == UINT64_MAX || target_handle_out == NULL ||
        state_out == NULL || !runtime_drag_drop_action_valid(action))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
    request.offer_token = offer_token;
    request.generation = generation;
    request.action = action;
    memset(&response, 0, sizeof(response));
    result = runtime_drag_drop_request(
        RIN_RUNTIME_DRAG_DROP_UPDATE, &request, sizeof(request), &response,
        sizeof(response), sizeof(response));
    if (result != RIN_RESULT_OK) return result;
    if (response.struct_size != sizeof(response) ||
        response.version != RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION ||
        response.flags != 0u || response.reserved[0] != 0u ||
        response.reserved[1] != 0u ||
        response.state > RINRUNTIME_DRAG_DROP_STATE_ACCEPTED ||
        (response.target_handle == 0u) !=
            (response.state == RINRUNTIME_DRAG_DROP_STATE_NONE) ||
        (response.target_handle != 0u &&
         !runtime_drag_drop_action_valid(response.action)))
        return RIN_RESULT_CORRUPT_DATA;
    *target_handle_out = response.target_handle;
    *state_out = response.state;
    return RIN_RESULT_OK;
}

int rinruntime_drag_drop_accept_v1(
    RinRuntimeGuiHandle target, uint64_t offer_token, uint64_t generation,
    uint32_t action) {
    RinRuntimeDragDropWireAcceptV1 request;
    RinRuntimeGuiSurface* surface = runtime_surface(target);
    if (surface == NULL || offer_token == 0u || generation == 0u ||
        generation == UINT64_MAX || !runtime_drag_drop_action_valid(action))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
    request.offer_token = offer_token;
    request.generation = generation;
    request.target_handle = surface->id;
    request.action = action;
    return runtime_drag_drop_request(RIN_RUNTIME_DRAG_DROP_ACCEPT, &request,
                                     sizeof(request), NULL, 0u, 0u);
}

static int runtime_drag_drop_finish_v1(RinRuntimeGuiHandle source,
                                      uint32_t type, uint64_t offer_token,
                                      uint64_t generation) {
    RinRuntimeDragDropWireLeaseV1 request;
    if (runtime_surface(source) == NULL || offer_token == 0u ||
        generation == 0u || generation == UINT64_MAX ||
        (type != RIN_RUNTIME_DRAG_DROP &&
         type != RIN_RUNTIME_DRAG_DROP_CANCEL))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
    request.offer_token = offer_token;
    request.generation = generation;
    return runtime_drag_drop_request(type, &request, sizeof(request), NULL,
                                     0u, 0u);
}

int rinruntime_drag_drop_drop_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation) {
    return runtime_drag_drop_finish_v1(source, RIN_RUNTIME_DRAG_DROP,
                                       offer_token, generation);
}

int rinruntime_drag_drop_cancel_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation) {
    return runtime_drag_drop_finish_v1(source, RIN_RUNTIME_DRAG_DROP_CANCEL,
                                       offer_token, generation);
}

int rinruntime_drag_drop_poll_v1(
    RinRuntimeGuiHandle target, RinRuntimeDragDropOfferV1* offer_out) {
    RinRuntimeDragDropWirePollV1 request;
    RinRuntimeDragDropWirePublicationV1 publication;
    RinRuntimeGuiSurface* surface = runtime_surface(target);
    uint32_t index;
    int result;
    if (offer_out != NULL) memset(offer_out, 0, sizeof(*offer_out));
    if (surface == NULL || offer_out == NULL)
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION;
    request.surface_id = surface->id;
    memset(&publication, 0, sizeof(publication));
    result = runtime_drag_drop_request(
        RIN_RUNTIME_DRAG_DROP_POLL, &request, sizeof(request), &publication,
        sizeof(publication), sizeof(publication));
    if (result != RIN_RESULT_OK) return result;
    offer_out->struct_size = sizeof(*offer_out);
    offer_out->version = RIN_RUNTIME_DRAG_DROP_VERSION;
    if (publication.struct_size != sizeof(publication) ||
        publication.version != RIN_RUNTIME_DRAG_DROP_PROTOCOL_VERSION ||
        publication.flags != 0u || publication.has_publication > 1u)
        return RIN_RESULT_CORRUPT_DATA;
    if (publication.has_publication == 0u) {
        if (publication.payload_count != 0u || publication.offer_token != 0u ||
            publication.generation != 0u || publication.origin_peer != 0u ||
            publication.target_handle != 0u || publication.action != 0u ||
            publication.state != RINRUNTIME_DRAG_DROP_STATE_NONE)
            return RIN_RESULT_CORRUPT_DATA;
        for (index = 0u; index < RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS; ++index)
            if (memcmp(&publication.payloads[index],
                       &(RinRuntimeDragDropPayloadV1){0},
                       sizeof(publication.payloads[index])) != 0)
                return RIN_RESULT_CORRUPT_DATA;
        return RIN_RESULT_OK;
    }
    if (publication.offer_token == 0u || publication.generation == 0u ||
        publication.origin_peer == 0u ||
        publication.target_handle != surface->id ||
        publication.payload_count == 0u ||
        publication.payload_count > RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS ||
        !runtime_drag_drop_action_valid(publication.action) ||
        (publication.state != RINRUNTIME_DRAG_DROP_STATE_OFFERED &&
         publication.state != RINRUNTIME_DRAG_DROP_STATE_ACCEPTED &&
         publication.state != RINRUNTIME_DRAG_DROP_STATE_DROPPED))
        return RIN_RESULT_CORRUPT_DATA;
    offer_out->offer_token = publication.offer_token;
    offer_out->generation = publication.generation;
    offer_out->origin_peer = publication.origin_peer;
    offer_out->target_handle = publication.target_handle;
    offer_out->action = publication.action;
    offer_out->state = publication.state;
    offer_out->payload_count = publication.payload_count;
    for (index = 0u; index < publication.payload_count; ++index) {
        if (!runtime_drag_drop_payload_valid(&publication.payloads[index])) {
            memset(offer_out, 0, sizeof(*offer_out));
            return RIN_RESULT_CORRUPT_DATA;
        }
        offer_out->payloads[index] = publication.payloads[index];
    }
    for (; index < RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS; ++index) {
        if (memcmp(&publication.payloads[index],
                   &(RinRuntimeDragDropPayloadV1){0},
                   sizeof(publication.payloads[index])) != 0) {
            memset(offer_out, 0, sizeof(*offer_out));
            return RIN_RESULT_CORRUPT_DATA;
        }
    }
    return RIN_RESULT_OK;
}

static int runtime_drag_drop_owner_connect(int* descriptor_out) {
    struct sockaddr_un address;
    rin_unix_peer_service_identity_v1 service;
    socklen_t service_size = (socklen_t)sizeof(service);
    char path[sizeof(address.sun_path)];
    const uid_t uid = getuid();
    int descriptor;
    int written;
    if (descriptor_out != NULL) *descriptor_out = -1;
    if (descriptor_out == NULL || uid == 0u) return RIN_RESULT_ACCESS_DENIED;
    written = snprintf(path, sizeof(path),
                       "/run/rin/desktopd-drag-drop-%u.sock",
                       (unsigned)uid);
    if (written <= 0 || (size_t)written >= sizeof(path))
        return RIN_RESULT_INVALID_ARGUMENT;
    descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (descriptor < 0) return RIN_RESULT_IO;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, (size_t)written + 1u);
    if (connect(descriptor, (struct sockaddr*)&address, sizeof(address)) != 0 ||
        getsockopt(descriptor, SOL_SOCKET, SO_RIN_UNIX_PEER_SERVICE_IDENTITY,
                   &service, &service_size) != 0 ||
        service_size != (socklen_t)sizeof(service) ||
        !rin_unix_peer_service_identity_valid(&service) ||
        service.scope != RIN_UNIX_SCOPE_USER || service.owner_uid != uid ||
        strncmp(service.service_id, "desktopd",
                sizeof(service.service_id)) != 0) {
        close(descriptor);
        return RIN_RESULT_ACCESS_DENIED;
    }
    *descriptor_out = descriptor;
    return RIN_RESULT_OK;
}

static int runtime_drag_drop_owner_rpc(
    const RinRuntimeDragDropOwnerRequestV1* request, const void* body,
    uint32_t body_size, RinRuntimeDragDropOwnerResponseV1* response_out,
    void* response_body, uint32_t response_body_capacity) {
    uint8_t* packet = NULL;
    uint8_t* reply = NULL;
    int descriptor = -1;
    int result;
    ssize_t transferred;
    const uint32_t max_body = RINRUNTIME_DRAG_DROP_OWNER_MAX_TEXT_BYTES +
        RINRUNTIME_DRAG_DROP_OWNER_MAX_MIME_BYTES +
        RINRUNTIME_DRAG_DROP_OWNER_MAX_LABEL_BYTES;
    if (response_out != NULL) memset(response_out, 0, sizeof(*response_out));
    if (request == NULL || response_out == NULL ||
        request->body_size != body_size || body_size > max_body ||
        (body == NULL && body_size != 0u) ||
        (response_body == NULL && response_body_capacity != 0u))
        return RIN_RESULT_INVALID_ARGUMENT;
    result = runtime_drag_drop_owner_connect(&descriptor);
    if (result != RIN_RESULT_OK) return result;
    packet = (uint8_t*)malloc(sizeof(*request) + body_size);
    reply = (uint8_t*)malloc(sizeof(*response_out) + max_body);
    if (packet == NULL || reply == NULL) {
        result = RIN_RESULT_NO_MEMORY;
        goto done;
    }
    memcpy(packet, request, sizeof(*request));
    if (body_size != 0u)
        memcpy(packet + sizeof(*request), body, body_size);
    transferred = send(descriptor, packet, sizeof(*request) + body_size,
                       MSG_NOSIGNAL);
    if (transferred != (ssize_t)(sizeof(*request) + body_size)) {
        result = RIN_RESULT_IO;
        goto done;
    }
    transferred = recv(descriptor, reply, sizeof(*response_out) + max_body,
                       MSG_TRUNC);
    if (transferred < (ssize_t)sizeof(*response_out) ||
        (size_t)transferred > sizeof(*response_out) + max_body) {
        result = RIN_RESULT_IO;
        goto done;
    }
    memcpy(response_out, reply, sizeof(*response_out));
    if (response_out->magic != RINRUNTIME_DRAG_DROP_OWNER_MAGIC ||
        response_out->version != RINRUNTIME_DRAG_DROP_OWNER_VERSION ||
        response_out->operation != request->operation ||
        response_out->struct_size != sizeof(*response_out) ||
        response_out->reserved0 != 0u ||
        response_out->body_size > max_body ||
        (size_t)transferred != sizeof(*response_out) +
                                   response_out->body_size ||
        response_out->body_size > response_body_capacity) {
        result = response_out->body_size > response_body_capacity
            ? RIN_RESULT_BUFFER_TOO_SMALL : RIN_RESULT_CORRUPT_DATA;
        goto done;
    }
    if (response_out->body_size != 0u) {
        if (response_body == NULL) {
            result = RIN_RESULT_CORRUPT_DATA;
            goto done;
        }
        memcpy(response_body, reply + sizeof(*response_out),
               response_out->body_size);
    }
    result = response_out->result;
done:
    if (descriptor >= 0) close(descriptor);
    if (packet != NULL) {
        memset(packet, 0, sizeof(*request) + body_size);
        free(packet);
    }
    if (reply != NULL) {
        memset(reply, 0, sizeof(*response_out) + max_body);
        free(reply);
    }
    return result;
}

static void runtime_drag_drop_owner_request_init(
    RinRuntimeDragDropOwnerRequestV1* request, uint16_t operation) {
    memset(request, 0, sizeof(*request));
    request->magic = RINRUNTIME_DRAG_DROP_OWNER_MAGIC;
    request->version = RINRUNTIME_DRAG_DROP_OWNER_VERSION;
    request->operation = operation;
    request->struct_size = sizeof(*request);
}

static int runtime_drag_drop_owner_string_size(const char* value,
                                               uint32_t maximum,
                                               uint32_t* size_out) {
    size_t size;
    if (size_out != NULL) *size_out = 0u;
    if (value == NULL || size_out == NULL) return 0;
    size = strlen(value);
    if (size == 0u || size > maximum) return 0;
    *size_out = (uint32_t)size;
    return 1;
}

int rinruntime_drag_drop_payload_register_text_v1(
    const char* mime, const char* label, const void* bytes,
    uint32_t byte_count, uint64_t* payload_capability_out) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    uint32_t mime_size = 0u;
    uint32_t label_size = 0u;
    uint32_t body_size;
    uint8_t* body;
    int result;
    if (payload_capability_out != NULL) *payload_capability_out = 0u;
    if (payload_capability_out == NULL || bytes == NULL || byte_count == 0u ||
        byte_count > RINRUNTIME_DRAG_DROP_OWNER_MAX_TEXT_BYTES ||
        !runtime_drag_drop_owner_string_size(
            mime, RINRUNTIME_DRAG_DROP_OWNER_MAX_MIME_BYTES, &mime_size) ||
        !runtime_drag_drop_owner_string_size(
            label, RINRUNTIME_DRAG_DROP_OWNER_MAX_LABEL_BYTES, &label_size) ||
        byte_count > UINT32_MAX - mime_size - label_size)
        return RIN_RESULT_INVALID_ARGUMENT;
    body_size = mime_size + label_size + byte_count;
    body = (uint8_t*)malloc(body_size);
    if (body == NULL) return RIN_RESULT_NO_MEMORY;
    memcpy(body, mime, mime_size);
    memcpy(body + mime_size, label, label_size);
    memcpy(body + mime_size + label_size, bytes, byte_count);
    runtime_drag_drop_owner_request_init(
        &request, RINRUNTIME_DRAG_DROP_OWNER_REGISTER_TEXT);
    request.body_size = body_size;
    request.mime_size = mime_size;
    request.label_size = label_size;
    memset(&response, 0, sizeof(response));
    result = runtime_drag_drop_owner_rpc(&request, body, body_size,
                                         &response, NULL, 0u);
    if (result == RIN_RESULT_OK &&
        (response.payload_type != RINRUNTIME_DRAG_DROP_PAYLOAD_TEXT ||
         response.capability == 0u || response.body_size != 0u))
        result = RIN_RESULT_CORRUPT_DATA;
    if (result == RIN_RESULT_OK)
        *payload_capability_out = response.capability;
    memset(body, 0, body_size);
    free(body);
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    return result;
}

static void runtime_drag_drop_revoke_file_object(uint64_t object_id) {
    RinFilePortalCallV1 revoke;
    if (object_id == 0u) return;
    memset(&revoke, 0, sizeof(revoke));
    revoke.struct_size = sizeof(revoke);
    revoke.version = RIN_FILE_PORTAL_CALL_VERSION;
    revoke.operation = RIN_FILE_PORTAL_OPERATION_REVOKE;
    revoke.descriptor = -1;
    revoke.process_fd = -1;
    revoke.file_object_id = object_id;
    (void)rin_file_portal_call(&revoke);
    memset(&revoke, 0, sizeof(revoke));
}

int rinruntime_drag_drop_payload_register_file_v1(
    int32_t source_fd, const char* mime, const char* label,
    uint64_t* payload_capability_out) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    rin_unix_peer_service_identity_v1 service;
    RinFilePortalCallV1 issue;
    uint32_t mime_size = 0u;
    uint32_t label_size = 0u;
    uint8_t* body = NULL;
    int owner_fd = -1;
    int pidfd = -1;
    int result;
    uint64_t issued_object = 0u;
    if (payload_capability_out != NULL) *payload_capability_out = 0u;
    if (source_fd < 0 || payload_capability_out == NULL ||
        !runtime_drag_drop_owner_string_size(
            mime, RINRUNTIME_DRAG_DROP_OWNER_MAX_MIME_BYTES, &mime_size) ||
        !runtime_drag_drop_owner_string_size(
            label, RINRUNTIME_DRAG_DROP_OWNER_MAX_LABEL_BYTES, &label_size))
        return RIN_RESULT_INVALID_ARGUMENT;
    result = runtime_drag_drop_owner_connect(&owner_fd);
    if (result != RIN_RESULT_OK) return result;
    socklen_t service_size = (socklen_t)sizeof(service);
    memset(&service, 0, sizeof(service));
    if (getsockopt(owner_fd, SOL_SOCKET, SO_RIN_UNIX_PEER_SERVICE_IDENTITY,
                   &service, &service_size) != 0 ||
        service_size != (socklen_t)sizeof(service) ||
        !rin_unix_peer_service_identity_valid(&service) ||
        service.process_id > INT_MAX) {
        result = RIN_RESULT_ACCESS_DENIED;
        goto done;
    }
    pidfd = pidfd_open((pid_t)service.process_id, 0u);
    if (pidfd < 0) {
        result = RIN_RESULT_ACCESS_DENIED;
        goto done;
    }
    memset(&issue, 0, sizeof(issue));
    issue.struct_size = sizeof(issue);
    issue.version = RIN_FILE_PORTAL_CALL_VERSION;
    issue.operation = RIN_FILE_PORTAL_OPERATION_ISSUE;
    issue.descriptor = source_fd;
    issue.requested_rights = RIN_FILE_PORTAL_RIGHT_READ |
                             RIN_FILE_PORTAL_RIGHT_METADATA;
    issue.target_process_id = (uint32_t)service.process_id;
    issue.target_process_cookie = service.process_instance_cookie;
    issue.process_fd = pidfd;
    result = rin_file_portal_call(&issue);
    issued_object = issue.file_object_id;
    (void)close(pidfd);
    pidfd = -1;
    if (result != RIN_RESULT_OK ||
        issue.granted_rights != (RIN_FILE_PORTAL_RIGHT_READ |
                                 RIN_FILE_PORTAL_RIGHT_METADATA) ||
        issue.process_fd != -1 || issue.file_object_id == 0u ||
        issue.expires_at_epoch == 0u ||
        issue.token.magic != RIN_FILE_PORTAL_TOKEN_MAGIC ||
        issue.token.rights != (RIN_FILE_PORTAL_RIGHT_READ |
                               RIN_FILE_PORTAL_RIGHT_METADATA)) {
        if (result == RIN_RESULT_OK) result = RIN_RESULT_CORRUPT_DATA;
        goto done;
    }
    body = (uint8_t*)malloc(mime_size + label_size);
    if (body == NULL) {
        result = RIN_RESULT_NO_MEMORY;
        goto done;
    }
    memcpy(body, mime, mime_size);
    memcpy(body + mime_size, label, label_size);
    runtime_drag_drop_owner_request_init(
        &request, RINRUNTIME_DRAG_DROP_OWNER_REGISTER_FILE);
    request.body_size = mime_size + label_size;
    request.mime_size = mime_size;
    request.label_size = label_size;
    request.file_token = issue.token;
    memset(&response, 0, sizeof(response));
    close(owner_fd);
    owner_fd = -1;
    result = runtime_drag_drop_owner_rpc(&request, body,
                                         request.body_size, &response, NULL,
                                         0u);
    if (result == RIN_RESULT_OK &&
        (response.payload_type != RINRUNTIME_DRAG_DROP_PAYLOAD_FILE ||
         response.capability == 0u || response.body_size != 0u))
        result = RIN_RESULT_CORRUPT_DATA;
    if (result == RIN_RESULT_OK) {
        *payload_capability_out = response.capability;
        issued_object = 0u;
    }
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
done:
    if (pidfd >= 0) close(pidfd);
    if (owner_fd >= 0) close(owner_fd);
    if (body != NULL) {
        memset(body, 0, mime_size + label_size);
        free(body);
    }
    memset(&issue, 0, sizeof(issue));
    runtime_drag_drop_revoke_file_object(issued_object);
    return result;
}

static int runtime_drag_drop_owner_bind_offer_v1(
    uint64_t offer_token, uint64_t generation, uint32_t actions,
    const RinRuntimeDragDropPayloadV1* payloads, uint32_t payload_count) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    uint64_t capabilities[RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS] = {0u};
    uint32_t index;
    if (offer_token == 0u || generation == 0u ||
        !runtime_drag_drop_actions_valid(actions) || payloads == NULL ||
        payload_count == 0u ||
        payload_count > RIN_RUNTIME_DRAG_DROP_MAX_PAYLOADS)
        return RIN_RESULT_INVALID_ARGUMENT;
    for (index = 0u; index < payload_count; ++index)
        capabilities[index] = payloads[index].payload_capability;
    runtime_drag_drop_owner_request_init(
        &request, RINRUNTIME_DRAG_DROP_OWNER_BIND_OFFER);
    request.offer_token = offer_token;
    request.generation = generation;
    request.action = actions;
    request.body_size = payload_count * (uint32_t)sizeof(uint64_t);
    memset(&response, 0, sizeof(response));
    const int result = runtime_drag_drop_owner_rpc(
        &request, capabilities, request.body_size, &response, NULL, 0u);
    memset(capabilities, 0, sizeof(capabilities));
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    return result;
}

int rinruntime_drag_drop_receive_v1(
    uint64_t offer_token, uint64_t generation, uint64_t payload_capability,
    void* text_bytes, uint32_t text_capacity, uint32_t* text_size_out,
    RinFilePortalTokenV1* file_token_out, uint32_t* payload_type_out) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    uint32_t body_capacity = text_capacity;
    if (text_size_out != NULL) *text_size_out = 0u;
    if (payload_type_out != NULL) *payload_type_out = 0u;
    if (file_token_out != NULL) memset(file_token_out, 0, sizeof(*file_token_out));
    if (offer_token == 0u || generation == 0u || payload_capability == 0u ||
        text_size_out == NULL || payload_type_out == NULL ||
        (text_bytes == NULL && text_capacity != 0u) ||
        text_capacity > RINRUNTIME_DRAG_DROP_OWNER_MAX_TEXT_BYTES)
        return RIN_RESULT_INVALID_ARGUMENT;
    runtime_drag_drop_owner_request_init(
        &request, RINRUNTIME_DRAG_DROP_OWNER_RECEIVE);
    request.offer_token = offer_token;
    request.generation = generation;
    request.capability = payload_capability;
    memset(&response, 0, sizeof(response));
    const int result = runtime_drag_drop_owner_rpc(
        &request, NULL, 0u, &response, text_bytes, body_capacity);
    if (result == RIN_RESULT_BUFFER_TOO_SMALL &&
        response.payload_type == RINRUNTIME_DRAG_DROP_PAYLOAD_TEXT) {
        *text_size_out = response.body_size;
        return result;
    }
    if (result != RIN_RESULT_OK) return result;
    if (response.payload_type == RINRUNTIME_DRAG_DROP_PAYLOAD_TEXT) {
        if (response.body_size == 0u || file_token_out != NULL &&
                response.file_token.magic != 0u) {
            memset(text_bytes, 0, response.body_size <= text_capacity
                                      ? response.body_size : text_capacity);
            return RIN_RESULT_CORRUPT_DATA;
        }
        *text_size_out = response.body_size;
    } else if (response.payload_type ==
               RINRUNTIME_DRAG_DROP_PAYLOAD_FILE) {
        const RinFilePortalTokenV1* token = &response.file_token;
        if (response.body_size != 0u || file_token_out == NULL ||
            token->magic != RIN_FILE_PORTAL_TOKEN_MAGIC ||
            token->version != RIN_FILE_PORTAL_TOKEN_VERSION ||
            token->token_size != RIN_FILE_PORTAL_TOKEN_SIZE ||
            token->rights != (RIN_FILE_PORTAL_RIGHT_READ |
                              RIN_FILE_PORTAL_RIGHT_METADATA) ||
            token->file_object_id == 0u || token->expires_at_epoch == 0u) {
            return RIN_RESULT_CORRUPT_DATA;
        }
        *file_token_out = *token;
    } else {
        return RIN_RESULT_CORRUPT_DATA;
    }
    *payload_type_out = response.payload_type;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    return RIN_RESULT_OK;
}

static int runtime_drag_drop_owner_simple_request(
    uint16_t operation, uint64_t offer_token, uint64_t generation,
    uint32_t value, uint32_t* value_out) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    if (offer_token == 0u || generation == 0u || generation == UINT64_MAX)
        return RIN_RESULT_INVALID_ARGUMENT;
    runtime_drag_drop_owner_request_init(&request, operation);
    request.offer_token = offer_token;
    request.generation = generation;
    request.result = value;
    memset(&response, 0, sizeof(response));
    const int result = runtime_drag_drop_owner_rpc(&request, NULL, 0u,
                                                   &response, NULL, 0u);
    if (result == RIN_RESULT_OK && value_out != NULL)
        *value_out = response.completion;
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    return result;
}

int rinruntime_drag_drop_complete_v1(uint64_t offer_token,
                                     uint64_t generation,
                                     uint32_t result) {
    if (result != RINRUNTIME_DRAG_DROP_OWNER_RESULT_SUCCEEDED &&
        result != RINRUNTIME_DRAG_DROP_OWNER_RESULT_FAILED)
        return RIN_RESULT_INVALID_ARGUMENT;
    return runtime_drag_drop_owner_simple_request(
        RINRUNTIME_DRAG_DROP_OWNER_COMPLETE, offer_token, generation,
        result, NULL);
}

int rinruntime_drag_drop_source_result_v1(uint64_t offer_token,
                                         uint64_t generation,
                                         uint32_t* result_out) {
    if (result_out != NULL)
        *result_out = RINRUNTIME_DRAG_DROP_OWNER_RESULT_PENDING;
    if (result_out == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    return runtime_drag_drop_owner_simple_request(
        RINRUNTIME_DRAG_DROP_OWNER_SOURCE_RESULT, offer_token, generation,
        0u, result_out);
}

int rinruntime_drag_drop_release_v1(uint64_t offer_token,
                                    uint64_t generation) {
    return runtime_drag_drop_owner_simple_request(
        RINRUNTIME_DRAG_DROP_OWNER_RELEASE, offer_token, generation,
        0u, NULL);
}

int rinruntime_drag_drop_payload_release_v1(uint64_t payload_capability) {
    RinRuntimeDragDropOwnerRequestV1 request;
    RinRuntimeDragDropOwnerResponseV1 response;
    if (payload_capability == 0u) return RIN_RESULT_INVALID_ARGUMENT;
    runtime_drag_drop_owner_request_init(
        &request, RINRUNTIME_DRAG_DROP_OWNER_RELEASE_PAYLOAD);
    request.capability = payload_capability;
    memset(&response, 0, sizeof(response));
    const int result = runtime_drag_drop_owner_rpc(
        &request, NULL, 0u, &response, NULL, 0u);
    memset(&request, 0, sizeof(request));
    memset(&response, 0, sizeof(response));
    return result;
}
