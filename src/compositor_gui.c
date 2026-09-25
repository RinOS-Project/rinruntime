/* SPDX-License-Identifier: MIT */
/*
 * Native GUI runtime backend.
 *
 * Applications acquire a private compositor buffer as RinRenderTarget and
 * draw into it through Aquamarine.  This runtime owns only lifecycle, input,
 * buffer acquisition and presentation; it never owns drawing primitives.
 */
#include <rinruntime/window.h>
#include "platform.h"
#include <rin/contract_abi.h>
#include <rin/ipc/shm_abi.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <semaphore.h>

#define RIN_RUNTIME_GUI_MAX_SURFACES 32u
#define RIN_RUNTIME_GUI_MAX_PAYLOAD 8192u
#define RIN_RUNTIME_GUI_MAX_BUFFER_BYTES (64u * 1024u * 1024u)
#define RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS 8000u

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
    uint32_t window_state;
    uint32_t workspace;
    uint32_t draw_slot;
    uint32_t front_slot;
    uint64_t frame_sequence;
    uint64_t render_target_generation;
    uint32_t render_target_acquired;
    uint32_t render_target_slot;
    uint64_t acquired_generation;
    uint8_t* acquired_pixels;
    int shm_handles[RIN_COMPOSITOR_MAX_BUFFERS];
    uint8_t* pixels[RIN_COMPOSITOR_MAX_BUFFERS];
    RinTextInputStateV1 text_input;
    RinTextCompositionV1 text_composition;
    char title[128];
    char icon_path[256];
    char shm_names[RIN_COMPOSITOR_MAX_BUFFERS][RIN_SHM_NAME_MAX];
} RinRuntimeGuiSurface;

static int g_compositor_fd = -1;
static uint32_t g_compositor_protocol_version =
    RIN_COMPOSITOR_PROTOCOL_VERSION;
static uint64_t g_compositor_features = 0u;
static uint32_t g_next_request_id = 1u;
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

static int runtime_connect(void);
static int runtime_setup_input_ring(void);
static int runtime_request(uint32_t type, const void* payload,
                           uint32_t payload_size, void* reply_payload,
                           uint32_t reply_capacity, uint32_t* reply_size,
                           int32_t* status_out);
static int runtime_attach_existing_buffers(RinRuntimeGuiSurface* surface);
static int runtime_rebind_surfaces(void);

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
}

static int runtime_send_exact(const void* data, uint32_t size) {
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t offset = 0u;
    while (offset < size) {
        ssize_t count = send(g_compositor_fd, bytes + offset, size - offset,
                             MSG_NOSIGNAL);
        if (count > 0) {
            if ((uint32_t)count > size - offset) return -1;
            offset += (uint32_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static int runtime_receive_exact(void* data, uint32_t size,
                                 uint64_t deadline_ms) {
    uint8_t* bytes = (uint8_t*)data;
    uint32_t offset = 0u;
    while (offset < size) {
        struct pollfd descriptor;
        uint64_t now_ms;
        uint64_t remaining_ms;
        int timeout_ms;
        int ready;
        now_ms = rin_monotonic_ms();
        if (now_ms >= deadline_ms) return -1;
        remaining_ms = deadline_ms - now_ms;
        timeout_ms = remaining_ms > 1000u ? 1000 : (int)remaining_ms;
        if (timeout_ms <= 0) return -1;
        descriptor.fd = g_compositor_fd;
        descriptor.events = POLLIN;
        descriptor.revents = 0;
        ready = poll(&descriptor, 1u, timeout_ms);
        if (ready == 0) continue;
        if (ready < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0 ||
            (descriptor.revents & POLLIN) == 0)
            return -1;
        {
            ssize_t count = recv(g_compositor_fd, bytes + offset,
                                 size - offset, 0);
            if (count > 0) {
                if ((uint32_t)count > size - offset) return -1;
                offset += (uint32_t)count;
                continue;
            }
            if (count < 0 && errno == EINTR) continue;
            return -1;
        }
    }
    return 0;
}

/* Returns 0 for a valid transport exchange; status is the compositor status. */
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
    request_id = g_next_request_id++;
    if (g_next_request_id == 0u) g_next_request_id = 1u;
    request_start_ms = rin_monotonic_ms();
    memset(&request, 0, sizeof(request));
    request.magic = RIN_COMPOSITOR_MAGIC;
    request.version = g_compositor_protocol_version;
    request.type = type;
    request.payload_size = payload_size;
    request.request_id = request_id;
    deadline_ms = rin_monotonic_ms() +
        ((type == RIN_COMPOSITOR_POLL_INPUT ||
          type == RIN_COMPOSITOR_POLL_INPUT_V2) ? 50u :
         RIN_RUNTIME_GUI_REQUEST_TIMEOUT_MS);
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
    if (reply_size) *reply_size = reply.payload_size;
    if (status_out) *status_out = (int32_t)reply.reserved;
    if (reply_payload_ms - request_start_ms >= 16u) {
        snprintf(diagnostic, sizeof(diagnostic),
                 "[rinruntime] compositor rpc type=%u request=%u "
                 "send_ms=%llu header_ms=%llu payload_ms=%llu total_ms=%llu "
                 "status=%d\n", (unsigned)type, (unsigned)request_id,
                 (unsigned long long)(send_complete_ms - request_start_ms),
                 (unsigned long long)(reply_header_ms - request_start_ms),
                 (unsigned long long)(reply_payload_ms - request_start_ms),
                 (unsigned long long)(reply_payload_ms - request_start_ms),
                 (int)reply.reserved);
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
                                 0, 0u);
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
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
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
        (void)poll(0, 0u, 50);
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

static int runtime_make_buffers(RinRuntimeGuiSurface* surface) {
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
    if (runtime_attach_existing_buffers(surface) != 0) goto fail;
    if (g_next_render_target_generation == 0u)
        g_next_render_target_generation = 1u;
    surface->render_target_generation = g_next_render_target_generation++;
    if (g_next_render_target_generation == 0u)
        g_next_render_target_generation = 1u;
    return 0;
fail:
    runtime_release_buffers(surface);
    return -1;
}

static int runtime_attach_existing_buffers(RinRuntimeGuiSurface* surface) {
    RinCompositorAttachBuffersV2 attach;
    uint32_t slot;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || surface->id == 0u || surface->bytes == 0u ||
        surface->bytes > UINT32_MAX || !surface->pixels[0] ||
        !surface->pixels[1]) return -1;
    memset(&attach, 0, sizeof(attach));
    attach.surface_id = surface->id;
    attach.width = surface->width;
    attach.height = surface->height;
    attach.pitch = surface->pitch;
    attach.format = 0u;
    for (slot = 0u; slot < RIN_COMPOSITOR_MAX_BUFFERS; ++slot) {
        if (surface->shm_handles[slot] < 0 ||
            surface->shm_names[slot][0] == '\0') return -1;
        attach.bytes[slot] = surface->bytes;
        strncpy(attach.shm_name[slot], surface->shm_names[slot],
                RIN_SHM_NAME_MAX - 1u);
    }
    if (runtime_request(RIN_COMPOSITOR_ATTACH_BUFFERS_V2, &attach,
                        sizeof(attach), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u) return -1;
    return 0;
}

static int runtime_rebind_surface(RinRuntimeGuiSurface* surface) {
    RinCompositorCreateSurface create;
    RinCompositorVisibility visibility;
    RinCompositorPosition position;
    RinCompositorSetTitleV1 title;
    RinCompositorWindowStateV1 state;
    RinCompositorSetCursorV1 cursor;
    RinCompositorTextInputState text_input;
    RinCompositorCommitV2 commit;
    uint32_t old_id;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !surface->active) return 0;
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
            uint32_t generation = g_handle_generations[index] + 1u;
            if (generation == 0u) generation = 1u;
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

void wnd_close(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t id;
    uint32_t reply_size;
    int32_t status;
    if (!surface || runtime_surface_id(handle, &id) != 0) return;
    (void)runtime_request(RIN_COMPOSITOR_DESTROY_SURFACE, &id, sizeof(id),
                          0, 0u, &reply_size, &status);
    runtime_destroy_local_surface(surface);
}

void wnd_show(RinRuntimeGuiHandle handle, int visible) {
    RinCompositorVisibility request;
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t reply_size;
    int32_t status;
    if (!surface) return;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.visible = visible ? 1u : 0u;
    if (runtime_request(RIN_COMPOSITOR_SET_VISIBLE, &request, sizeof(request),
                        0, 0u, &reply_size, &status) == 0 && status == 0)
    {
        surface->visible = request.visible;
        if (surface->visible != 0u)
            surface->window_state &= ~RIN_COMPOSITOR_WINDOW_STATE_MINIMIZED;
    }
}

void wnd_title(RinRuntimeGuiHandle handle, const char* title) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorSetTitleV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    size_t length = 0u;
    if (!surface || !title) return;
    while (length < sizeof(surface->title) - 1u && title[length] != '\0')
        ++length;
    if (title[length] != '\0') return;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    memcpy(request.title, title, length);
    if (runtime_request(RIN_COMPOSITOR_SET_TITLE, &request, sizeof(request),
                        0, 0u, &reply_size, &status) == 0 && status == 0) {
        memset(surface->title, 0, sizeof(surface->title));
        memcpy(surface->title, title, length);
    }
}

int wnd_set_icon_path(RinRuntimeGuiHandle handle, const char* path) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    return runtime_store_icon_path(surface, path);
}

void wnd_move(RinRuntimeGuiHandle handle, int x, int y) {
    RinCompositorPosition request;
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t reply_size;
    int32_t status;
    if (!surface) return;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.x = x;
    request.y = y;
    if (runtime_request(RIN_COMPOSITOR_SET_POSITION, &request, sizeof(request),
                        0, 0u, &reply_size, &status) == 0 && status == 0) {
        surface->x = x;
        surface->y = y;
    }
}

void wnd_resize(RinRuntimeGuiHandle handle, int w, int h) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorSetSize request;
    uint32_t reply_size;
    int32_t status;
    if (!surface || w <= 0 || h <= 0 || (uint32_t)w > UINT32_MAX / 4u)
        return;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.width = (uint32_t)w;
    request.height = (uint32_t)h;
    if (runtime_request(RIN_COMPOSITOR_SET_SIZE, &request, sizeof(request),
                        0, 0u, &reply_size, &status) != 0 || status != 0)
        return;
    runtime_release_buffers(surface);
    surface->width = (uint32_t)w;
    surface->height = (uint32_t)h;
    surface->draw_slot = 0u;
    surface->front_slot = 0u;
    if (runtime_make_buffers(surface) != 0) {
        /* The compositor has already rejected the old geometry.  Keep the
         * handle valid but invisible until the caller retries a valid size. */
        surface->visible = 0u;
    }
}

static int runtime_ring_pop(RinCompositorInputRingEventV1* event) {
    int result;
    if (!event || !g_input_ring_address) return 0;
    if (g_input_ring_batch_index >= g_input_ring_batch_count) {
        g_input_ring_batch_count = 0u;
        g_input_ring_batch_index = 0u;
        result = rin_compositor_input_ring_pop_batch(
            (RinCompositorInputRingHeaderV1*)g_input_ring_address,
            g_input_ring_batch, RIN_RUNTIME_INPUT_BATCH_CAPACITY,
            g_input_ring_bytes, &g_input_ring_batch_count);
        if (result <= 0) return result;
    }
    *event = g_input_ring_batch[g_input_ring_batch_index++];
    event->trace.t4_client_dequeue_ns = rin_monotonic_ms() *
                                         UINT64_C(1000000);
    event->trace.t5_client_callback_ns = event->trace.t4_client_dequeue_ns;
    return 1;
}

int wnd_poll_native(RinRuntimeGuiHandle handle, RinGuiNativeEventV1* event,
                    uint32_t* packed_out) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinGuiNativeEventV1 received;
    RinCompositorPollInputV2 poll_request;
    RinCompositorInputEventV1 routed;
    RinCompositorInputRingEventV1 ring_event;
    uint32_t reply_size;
    int32_t status;
    if (!surface || !event || !packed_out) return -1;
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
    memset(&poll_request, 0, sizeof(poll_request));
    poll_request.struct_size = sizeof(poll_request);
    poll_request.version = 1u;
    poll_request.surface_id = surface->id;
    memset(&routed, 0, sizeof(routed));
    if (runtime_request(RIN_COMPOSITOR_POLL_INPUT_V2, &poll_request,
                        sizeof(poll_request), &routed, sizeof(routed),
                        &reply_size, &status) != 0)
        return -1;
    if (status == -11) return 0;
    if (status != 0 || reply_size != sizeof(routed) ||
        routed.struct_size != sizeof(routed) || routed.version != 1u ||
        routed.flags != 0u || routed.surface_id != surface->id ||
        routed.reserved[0] >= 4u || routed.reserved[1] != 0u ||
        routed.event.struct_size != sizeof(routed.event) ||
        routed.event.version != RIN_GUI_NATIVE_EVENT_VERSION)
        return -1;
    received = routed.event;
    *event = received;
    if (received.type == RIN_GUI_NATIVE_EVENT_POINTER_MOVE ||
        received.type == RIN_GUI_NATIVE_EVENT_POINTER_BUTTON ||
        received.type == RIN_GUI_NATIVE_EVENT_MOUSE_WHEEL ||
        received.type == RIN_GUI_NATIVE_EVENT_MOUSE_HORIZONTAL_WHEEL)
        surface->focused = 1u;
    *packed_out = runtime_pack_legacy_event(&received);
    return 1;
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
    uint32_t reply_size;
    int32_t status;
    if (!surface || !state) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.surface_id = surface->id;
    request.state = *state;
    if (runtime_request(RIN_COMPOSITOR_SET_TEXT_INPUT_STATE, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0) return (int)status;
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

int wnd_set_text_composition(RinRuntimeGuiHandle handle,
                             const RinTextCompositionV1* composition) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorTextCompositionUpdateV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !composition) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.composition = *composition;
    if (runtime_request(RIN_COMPOSITOR_SET_TEXT_COMPOSITION, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0) return status;
    surface->text_composition = *composition;
    return RIN_RESULT_OK;
}

int wnd_set_window_state(RinRuntimeGuiHandle handle, uint32_t window_state,
                         uint32_t workspace) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorWindowStateV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || (window_state & ~RIN_COMPOSITOR_WINDOW_STATE_KNOWN_MASK) != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.state = window_state;
    request.workspace = workspace;
    if (runtime_request(RIN_COMPOSITOR_SET_WINDOW_STATE, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0) return status;
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
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || (enabled != 0 && enabled != 1))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = 1u;
    request.surface_id = surface->id;
    request.enabled = (uint32_t)enabled;
    if (runtime_request(type, &request, sizeof(request), 0, 0u,
                        &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    return status == 0 ? RIN_RESULT_OK : status;
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
    uint32_t reply_size = 0u;
    int32_t status = -1;
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
    if (runtime_request(RIN_COMPOSITOR_SET_CURSOR, &request, sizeof(request),
                        0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    if (status != 0 || reply_size != 0u)
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    surface->cursor_type = cursor_type;
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

int wnd_set_frame_callback(RinRuntimeGuiHandle handle, int enabled,
                           uint32_t max_inflight) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorFrameCallbackV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
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
    if (runtime_request(RIN_COMPOSITOR_SET_FRAME_CALLBACK, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0)
        return RIN_RESULT_IO;
    return status != 0 ? status : RIN_RESULT_OK;
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

int wnd_present(RinRuntimeGuiHandle handle) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorDamage damage;
    RinCompositorCommitV2 commit;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    uint32_t next_slot;
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->render_target_acquired != 0u ||
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
    if (runtime_request(RIN_COMPOSITOR_DAMAGE, &damage, sizeof(damage), 0,
                        0u, &reply_size, &status) != 0 || status != 0)
        return status != 0 ? status : RIN_RESULT_IO;
    memset(&commit, 0, sizeof(commit));
    commit.surface_id = surface->id;
    commit.buffer_slot = surface->draw_slot;
    commit.frame_sequence = ++surface->frame_sequence;
    if (runtime_request(RIN_COMPOSITOR_COMMIT_V2, &commit, sizeof(commit), 0,
                        0u, &reply_size, &status) != 0 || status != 0)
        return status != 0 ? status : RIN_RESULT_IO;
    surface->front_slot = surface->draw_slot;
    memcpy(surface->pixels[next_slot], surface->pixels[surface->front_slot],
           (size_t)surface->bytes);
    surface->draw_slot = next_slot;
    return RIN_RESULT_OK;
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
    if (runtime_request(RIN_COMPOSITOR_EXPORT_GPU_IMAGE, &request,
                        sizeof(request), image_out, sizeof(*image_out),
                        &reply_size, &status) != 0 || status != 0 ||
        reply_size != sizeof(*image_out) ||
        image_out->struct_size != sizeof(*image_out) ||
        image_out->version != RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION ||
        image_out->surface_id != surface->id ||
        image_out->buffer_slot != surface->draw_slot ||
        image_out->image_handle == 0u || image_out->surface_generation == 0u)
        return status != 0 ? status : RIN_RESULT_CORRUPT_DATA;
    return RIN_RESULT_OK;
}

int wnd_present_gpu(RinRuntimeGuiHandle handle,
                    const RinCompositorGpuPresentV1* present) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    RinCompositorGpuPresentV1 request;
    uint32_t reply_size = 0u;
    int32_t status = -1;
    if (!surface || !present ||
        (g_compositor_features & RIN_COMPOSITOR_FEATURE_GPU_SURFACE_ABI) == 0u)
        return RIN_RESULT_NOT_SUPPORTED;
    if (surface->render_target_acquired != 0u ||
        present->struct_size != sizeof(*present) ||
        present->version != RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION ||
        present->reserved != 0u || present->reserved2 != 0u ||
        present->buffer_slot != surface->draw_slot ||
        present->frame_sequence == 0u ||
        present->release_fence != present->frame_sequence)
        return RIN_RESULT_INVALID_ARGUMENT;
    request = *present;
    request.surface_id = surface->id;
    if (runtime_request(RIN_COMPOSITOR_PRESENT_GPU_IMAGE, &request,
                        sizeof(request), 0, 0u, &reply_size, &status) != 0 ||
        status != 0 || reply_size != 0u)
        return status != 0 ? status : RIN_RESULT_IO;
    surface->front_slot = request.buffer_slot;
    surface->draw_slot = request.buffer_slot ^ 1u;
    surface->frame_sequence = request.frame_sequence;
    if (surface->draw_slot >= RIN_COMPOSITOR_MAX_BUFFERS ||
        !surface->pixels[surface->draw_slot])
        return RIN_RESULT_CORRUPT_DATA;
    memcpy(surface->pixels[surface->draw_slot],
           surface->pixels[surface->front_slot], (size_t)surface->bytes);
    return RIN_RESULT_OK;
}

int wnd_acquire_render_target(RinRuntimeGuiHandle handle,
                              RinRenderTarget* out_target) {
    RinRuntimeGuiSurface* surface = runtime_surface(handle);
    uint32_t slot;
    if (!out_target) return RIN_RESULT_INVALID_ARGUMENT;
    memset(out_target, 0, sizeof(*out_target));
    if (!surface) return RIN_RESULT_INVALID_HANDLE;
    if (surface->render_target_acquired != 0u) return RIN_RESULT_BUSY;
    slot = surface->draw_slot;
    if (slot >= RIN_COMPOSITOR_MAX_BUFFERS || !surface->pixels[slot] ||
        surface->render_target_generation == 0u)
        return RIN_RESULT_CORRUPT_DATA;
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
