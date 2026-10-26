/* SPDX-License-Identifier: MIT */
/* SDK GUI v1 adapters owned by the authenticated RinRuntime compositor client. */
#include <rin/gui.h>
#include <rin/gui/surface_abi.h>
#include <rin/gui/window_abi.h>
#include <rin/runtime.h>
#include <rinruntime/window.h>
#include <aquamarine.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RIN_RUNTIME_SDK_GUI_SURFACES 32u
#define RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_BITS 8u
#define RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_MASK UINT64_C(0xff)
#define RIN_RUNTIME_SDK_GUI_DIALOG_WIDTH 560
#define RIN_RUNTIME_SDK_GUI_DIALOG_HEIGHT 260
#define RIN_RUNTIME_SDK_GUI_DIALOG_MESSAGE_WIDTH 512
#define RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES 8u

typedef struct RinRuntimeSdkGuiSurface {
    uint8_t* pixels;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    uint64_t generation;
    uint8_t active;
    uint8_t mapped;
    uint8_t busy;
    uint8_t reserved;
} RinRuntimeSdkGuiSurface;

static RinRuntimeSdkGuiSurface
    g_sdk_gui_surfaces[RIN_RUNTIME_SDK_GUI_SURFACES];
static volatile uint32_t g_sdk_gui_surface_lock;

static void sdk_gui_lock(void) {
    while (__sync_lock_test_and_set(&g_sdk_gui_surface_lock, 1u) != 0u) {
        while (__atomic_load_n(&g_sdk_gui_surface_lock, __ATOMIC_RELAXED) != 0u)
            ;
    }
}

static void sdk_gui_unlock(void) {
    __sync_lock_release(&g_sdk_gui_surface_lock);
}

static RinResult sdk_gui_result(int32_t result) {
    switch (result) {
        case RIN_RESULT_OK: return RIN_SUCCESS;
        case RIN_RESULT_INVALID_ARGUMENT: return RIN_ERROR_INVALID_ARGUMENT;
        case RIN_RESULT_NOT_FOUND: return RIN_ERROR_NOT_FOUND;
        case RIN_RESULT_IO: return RIN_ERROR_IO;
        case RIN_RESULT_ACCESS_DENIED: return RIN_ERROR_ACCESS_DENIED;
        case RIN_RESULT_NO_MEMORY: return RIN_ERROR_NO_MEMORY;
        case RIN_RESULT_BUSY: return RIN_ERROR_BUSY;
        case RIN_RESULT_TIMED_OUT: return RIN_ERROR_TIMEOUT;
        case RIN_RESULT_NOT_SUPPORTED: return RIN_ERROR_NOT_SUPPORTED;
        case RIN_RESULT_INVALID_HANDLE: return RIN_ERROR_STALE_HANDLE;
        case RIN_RESULT_TABLE_FULL: return RIN_ERROR_TABLE_FULL;
        case RIN_RESULT_WOULD_BLOCK: return RIN_ERROR_WOULD_BLOCK;
        case RIN_RESULT_BUFFER_TOO_SMALL: return RIN_ERROR_BUFFER_TOO_SMALL;
        case RIN_RESULT_CORRUPT_DATA: return RIN_ERROR_INTEGRITY;
        case RIN_RESULT_LIMIT_EXCEEDED: return RIN_ERROR_LIMIT_EXCEEDED;
        case RIN_RESULT_DEVICE_LOST: return RIN_ERROR_IO;
        default: return RIN_ERROR_IO;
    }
}

static int sdk_gui_versioned(const void* value, uint32_t size) {
    const RinVersionedV1* header = (const RinVersionedV1*)value;
    return header != NULL && header->struct_size >= size &&
           header->version == RIN_SDK_STRUCT_VERSION_1;
}

static int sdk_gui_pointer_span(uint64_t address, uint64_t size) {
    return size == 0u ||
           (address != 0u && address <= (uint64_t)UINTPTR_MAX &&
            size <= (uint64_t)UINTPTR_MAX - address);
}

static int sdk_gui_utf8_valid(const uint8_t* bytes, uint64_t size) {
    uint64_t offset = 0u;
    if (size != 0u && bytes == NULL) return 0;
    while (offset < size) {
        const uint8_t lead = bytes[offset++];
        uint32_t continuation_count;
        uint32_t codepoint;
        uint8_t second;
        if (lead == 0u) return 0;
        if (lead < 0x80u) continue;
        if (lead >= 0xc2u && lead <= 0xdfu) {
            continuation_count = 1u;
            codepoint = (uint32_t)(lead & 0x1fu);
        } else if (lead >= 0xe0u && lead <= 0xefu) {
            continuation_count = 2u;
            codepoint = (uint32_t)(lead & 0x0fu);
        } else if (lead >= 0xf0u && lead <= 0xf4u) {
            continuation_count = 3u;
            codepoint = (uint32_t)(lead & 0x07u);
        } else {
            return 0;
        }
        if (continuation_count > size - offset) return 0;
        second = bytes[offset];
        if ((second & 0xc0u) != 0x80u ||
            (lead == 0xe0u && second < 0xa0u) ||
            (lead == 0xedu && second >= 0xa0u) ||
            (lead == 0xf0u && second < 0x90u) ||
            (lead == 0xf4u && second > 0x8fu))
            return 0;
        for (uint32_t index = 0u; index < continuation_count; ++index) {
            const uint8_t next = bytes[offset++];
            if ((next & 0xc0u) != 0x80u) return 0;
            codepoint = (codepoint << 6u) | (uint32_t)(next & 0x3fu);
        }
        if (codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu))
            return 0;
    }
    return 1;
}

static int sdk_gui_text_snapshot(RinStringV1 input, uint64_t maximum,
                                 char* output) {
    if (output == NULL || input.size > maximum ||
        !sdk_gui_pointer_span(input.address, input.size))
        return 0;
    if (input.size != 0u) {
        memcpy(output, (const void*)(uintptr_t)input.address,
               (size_t)input.size);
        if (!sdk_gui_utf8_valid((const uint8_t*)output, input.size))
            return 0;
    }
    output[input.size] = '\0';
    return 1;
}

static int sdk_gui_surface_handle(uint64_t handle, uint32_t* index_out,
                                  uint64_t* generation_out) {
    const uint64_t encoded_index = handle &
                                   RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_MASK;
    const uint64_t generation = handle >>
                                RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_BITS;
    if (handle == RIN_HANDLE_INVALID || encoded_index == 0u ||
        encoded_index > RIN_RUNTIME_SDK_GUI_SURFACES || generation == 0u)
        return 0;
    if (index_out != NULL) *index_out = (uint32_t)(encoded_index - 1u);
    if (generation_out != NULL) *generation_out = generation;
    return 1;
}

static RinRuntimeSdkGuiSurface* sdk_gui_find_surface(uint64_t handle,
                                                      uint32_t* index_out) {
    uint32_t index;
    uint64_t generation;
    if (!sdk_gui_surface_handle(handle, &index, &generation)) return NULL;
    if (!g_sdk_gui_surfaces[index].active ||
        g_sdk_gui_surfaces[index].generation != generation)
        return NULL;
    if (index_out != NULL) *index_out = index;
    return &g_sdk_gui_surfaces[index];
}

static int sdk_gui_target_valid(const RinRenderTarget* target) {
    uint64_t row_bytes;
    uint64_t target_bytes;
    if (target == NULL || !rin_surface_descriptor_valid(target) ||
        target->pixels == NULL ||
        (target->format != RIN_RENDER_TARGET_FORMAT_BGRA32 &&
         target->format != RIN_RENDER_TARGET_FORMAT_RGBA32))
        return 0;
    row_bytes = (uint64_t)target->width * 4u;
    target_bytes = (uint64_t)target->pitch * target->height;
    return (uint64_t)target->pitch >= row_bytes &&
           target_bytes <= RIN_GUI_SURFACE_MAX_BYTES;
}

RinResult rin_window_create_v1(const RinWindowCreateV1* request,
                               RinWindow* window) {
    RinWindowCreateV1 snapshot;
    char title[RIN_GUI_WINDOW_TITLE_MAX_BYTES + 1u];
    uint64_t pixel_count;
    int64_t right;
    int64_t bottom;
    RinRuntimeGuiHandle runtime_handle;
    if (window == NULL) return RIN_ERROR_INVALID_ARGUMENT;
    *window = RIN_HANDLE_INVALID;
    if (!sdk_gui_versioned(request, sizeof(snapshot)))
        return RIN_ERROR_ABI_MISMATCH;
    memcpy(&snapshot, request, sizeof(snapshot));
    if (!sdk_gui_versioned(&snapshot, sizeof(snapshot)))
        return RIN_ERROR_ABI_MISMATCH;
    if (snapshot.flags != 0u ||
        snapshot.pixel_format > RIN_GUI_PIXEL_FORMAT_RGBA32 ||
        snapshot.bounds.width == 0u || snapshot.bounds.height == 0u)
        return RIN_ERROR_INVALID_ARGUMENT;
    pixel_count = (uint64_t)snapshot.bounds.width *
                  (uint64_t)snapshot.bounds.height;
    if (pixel_count > RIN_GUI_SURFACE_MAX_BYTES / 4u ||
        snapshot.bounds.width > (uint32_t)INT_MAX ||
        snapshot.bounds.height > (uint32_t)INT_MAX)
        return RIN_ERROR_LIMIT_EXCEEDED;
    right = (int64_t)snapshot.bounds.x + snapshot.bounds.width;
    bottom = (int64_t)snapshot.bounds.y + snapshot.bounds.height;
    if (right > INT32_MAX || bottom > INT32_MAX)
        return RIN_ERROR_INVALID_ARGUMENT;
    for (uint32_t index = 0u; index < 4u; ++index)
        if (snapshot.reserved[index] != 0u)
            return RIN_ERROR_INVALID_ARGUMENT;
    if (!sdk_gui_text_snapshot(snapshot.title,
                               RIN_GUI_WINDOW_TITLE_MAX_BYTES, title))
        return RIN_ERROR_INVALID_ARGUMENT;
    runtime_handle = wnd_create_flags(
        title, snapshot.bounds.x, snapshot.bounds.y,
        (int)snapshot.bounds.width, (int)snapshot.bounds.height,
        RIN_WINDOW_ROLE_NORMAL, RIN_WINDOW_FLAG_OPAQUE);
    if (runtime_handle == RIN_WINDOW_HANDLE_INVALID) return RIN_ERROR_IO;
    *window = (RinWindow)runtime_handle;
    return RIN_SUCCESS;
}

RinResult rin_window_close_v1(RinWindow window) {
    if (window == RIN_HANDLE_INVALID) return RIN_ERROR_INVALID_ARGUMENT;
    return sdk_gui_result(wnd_close_async((RinRuntimeGuiHandle)window));
}

RinResult rin_window_next_event_v1(RinWindow window, uint64_t timeout_ns,
                                   RinGuiEventV1* event) {
    RinWindowGeometryV1 geometry;
    uint64_t start_ms;
    uint64_t timeout_ms;
    int first_poll = 1;
    if (event == NULL || !sdk_gui_versioned(event, sizeof(*event)))
        return RIN_ERROR_ABI_MISMATCH;
    memset(event, 0, sizeof(*event));
    event->struct_size = sizeof(*event);
    event->version = RIN_SDK_STRUCT_VERSION_1;
    if (window == RIN_HANDLE_INVALID) return RIN_ERROR_INVALID_ARGUMENT;
    memset(&geometry, 0, sizeof(geometry));
    geometry.struct_size = sizeof(geometry);
    geometry.version = RIN_WINDOW_ABI_VERSION;
    {
        const int geometry_result =
            wnd_get_geometry((RinRuntimeGuiHandle)window, &geometry);
        if (geometry_result != RIN_RESULT_OK)
            return sdk_gui_result(geometry_result);
    }
    start_ms = rin_monotonic_ms();
    timeout_ms = timeout_ns == RIN_SDK_INFINITE
        ? UINT64_MAX
        : timeout_ns / UINT64_C(1000000) +
              ((timeout_ns % UINT64_C(1000000)) != 0u ? 1u : 0u);
    for (;;) {
        RinGuiNativeEventV1 native_event;
        uint32_t packed_event = 0u;
        const int poll_result = wnd_poll_native(
            (RinRuntimeGuiHandle)window, &native_event, &packed_event);
        (void)packed_event;
        if (poll_result < 0) return RIN_ERROR_IO;
        if (poll_result > 0) {
            if (native_event.struct_size != sizeof(native_event) ||
                native_event.version != RIN_GUI_NATIVE_EVENT_VERSION ||
                native_event.reserved[0] != 0u ||
                native_event.reserved[1] != 0u)
                return RIN_ERROR_ABI_MISMATCH;
            event->type = native_event.type;
            event->flags = native_event.flags;
            event->timestamp_ns = rin_monotonic_ms() * UINT64_C(1000000);
            event->window = window;
            event->data[0] = (int64_t)native_event.data;
            {
                const uint64_t packed_coordinates =
                    ((uint64_t)(uint32_t)native_event.screen_x << 32u) |
                    (uint64_t)(uint32_t)native_event.screen_y;
                memcpy(&event->data[1], &packed_coordinates,
                       sizeof(packed_coordinates));
            }
            event->data[2] =
                ((int64_t)native_event.key_modifiers << 32u) |
                (int64_t)native_event.pointer_buttons;
            event->data[3] = native_event.wheel_delta;
            return RIN_SUCCESS;
        }
        if (timeout_ns == 0u) return RIN_ERROR_TIMEOUT;
        if (timeout_ms != UINT64_MAX) {
            const uint64_t now_ms = rin_monotonic_ms();
            const uint64_t elapsed_ms = now_ms >= start_ms
                                            ? now_ms - start_ms : 0u;
            if (!first_poll && elapsed_ms >= timeout_ms)
                return RIN_ERROR_TIMEOUT;
        }
        first_poll = 0;
        rin_sleep(1u);
    }
}

RinResult rin_surface_create_v1(uint32_t width, uint32_t height,
                                uint32_t format, RinSurface* surface) {
    uint64_t bytes;
    uint8_t* pixels;
    if (surface == NULL) return RIN_ERROR_INVALID_ARGUMENT;
    *surface = RIN_HANDLE_INVALID;
    if (width == 0u || height == 0u ||
        format > RIN_GUI_PIXEL_FORMAT_RGBA32)
        return RIN_ERROR_INVALID_ARGUMENT;
    if ((uint64_t)width >
        (uint64_t)RIN_GUI_SURFACE_MAX_BYTES / 4u / (uint64_t)height)
        return RIN_ERROR_LIMIT_EXCEEDED;
    bytes = (uint64_t)width * (uint64_t)height * 4u;
    if (bytes > SIZE_MAX) return RIN_ERROR_LIMIT_EXCEEDED;
    pixels = (uint8_t*)calloc((size_t)bytes, 1u);
    if (pixels == NULL) return RIN_ERROR_NO_MEMORY;
    sdk_gui_lock();
    for (uint32_t index = 0u; index < RIN_RUNTIME_SDK_GUI_SURFACES; ++index) {
        RinRuntimeSdkGuiSurface* entry = &g_sdk_gui_surfaces[index];
        if (!entry->active && entry->generation != UINT64_MAX &&
            (entry->generation >>
             (64u - RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_BITS)) == 0u) {
            if (entry->generation == 0u) entry->generation = 1u;
            entry->pixels = pixels;
            entry->width = width;
            entry->height = height;
            entry->format = format;
            entry->active = 1u;
            entry->mapped = 0u;
            entry->busy = 0u;
            entry->reserved = 0u;
            *surface = (RinSurface)((entry->generation <<
                                     RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_BITS) |
                                    (uint64_t)(index + 1u));
            sdk_gui_unlock();
            return RIN_SUCCESS;
        }
    }
    sdk_gui_unlock();
    free(pixels);
    return RIN_ERROR_TABLE_FULL;
}

RinResult rin_surface_map_v1(RinSurface surface,
                             RinGuiSurfaceMapV1* mapping) {
    RinRuntimeSdkGuiSurface* entry;
    if (mapping == NULL || !sdk_gui_versioned(mapping, sizeof(*mapping)))
        return RIN_ERROR_ABI_MISMATCH;
    memset(mapping, 0, sizeof(*mapping));
    mapping->struct_size = sizeof(*mapping);
    mapping->version = RIN_SDK_STRUCT_VERSION_1;
    sdk_gui_lock();
    entry = sdk_gui_find_surface(surface, NULL);
    if (entry == NULL) {
        sdk_gui_unlock();
        return RIN_ERROR_STALE_HANDLE;
    }
    if (entry->mapped || entry->busy) {
        sdk_gui_unlock();
        return RIN_ERROR_BUSY;
    }
    entry->mapped = 1u;
    mapping->address = (uint64_t)(uintptr_t)entry->pixels;
    mapping->width = entry->width;
    mapping->height = entry->height;
    mapping->stride_bytes = entry->width * 4u;
    mapping->format = entry->format;
    mapping->generation = entry->generation;
    sdk_gui_unlock();
    return RIN_SUCCESS;
}

RinResult rin_surface_unmap_v1(RinSurface surface,
                               const RinGuiSurfaceMapV1* mapping) {
    RinGuiSurfaceMapV1 snapshot;
    RinRuntimeSdkGuiSurface* entry;
    if (mapping == NULL || !sdk_gui_versioned(mapping, sizeof(snapshot)))
        return RIN_ERROR_ABI_MISMATCH;
    memcpy(&snapshot, mapping, sizeof(snapshot));
    if (snapshot.struct_size != sizeof(snapshot) ||
        snapshot.version != RIN_SDK_STRUCT_VERSION_1 ||
        snapshot.reserved[0] != 0u || snapshot.reserved[1] != 0u ||
        snapshot.address == 0u ||
        snapshot.address > (uint64_t)UINTPTR_MAX)
        return RIN_ERROR_INVALID_ARGUMENT;
    sdk_gui_lock();
    entry = sdk_gui_find_surface(surface, NULL);
    if (entry == NULL) {
        sdk_gui_unlock();
        return RIN_ERROR_STALE_HANDLE;
    }
    if (!entry->mapped || entry->busy ||
        snapshot.address != (uint64_t)(uintptr_t)entry->pixels ||
        snapshot.width != entry->width || snapshot.height != entry->height ||
        snapshot.stride_bytes != entry->width * 4u ||
        snapshot.format != entry->format ||
        snapshot.generation != entry->generation) {
        sdk_gui_unlock();
        return RIN_ERROR_INVALID_ARGUMENT;
    }
    entry->mapped = 0u;
    sdk_gui_unlock();
    return RIN_SUCCESS;
}

RinResult rin_surface_destroy_v1(RinSurface surface) {
    RinRuntimeSdkGuiSurface* entry;
    uint8_t* pixels;
    sdk_gui_lock();
    entry = sdk_gui_find_surface(surface, NULL);
    if (entry == NULL) {
        sdk_gui_unlock();
        return RIN_ERROR_STALE_HANDLE;
    }
    if (entry->mapped || entry->busy) {
        sdk_gui_unlock();
        return RIN_ERROR_BUSY;
    }
    pixels = entry->pixels;
    entry->pixels = NULL;
    entry->width = 0u;
    entry->height = 0u;
    entry->format = 0u;
    entry->active = 0u;
    if (entry->generation == (UINT64_MAX >>
                              RIN_RUNTIME_SDK_GUI_HANDLE_INDEX_BITS))
        entry->generation = UINT64_MAX;
    else
        ++entry->generation;
    sdk_gui_unlock();
    free(pixels);
    return RIN_SUCCESS;
}

RinResult rin_window_present_v1(RinWindow window, RinSurface surface,
                                RinSliceV1 damage) {
    RinRectV1 damage_snapshot[RIN_GUI_DAMAGE_MAX_RECTS];
    const uint64_t damage_bytes = sizeof(damage_snapshot);
    uint64_t damage_count;
    RinRuntimeSdkGuiSurface* entry;
    uint8_t* source_pixels;
    uint32_t source_width;
    uint32_t source_height;
    uint32_t source_format;
    RinRenderTarget target;
    RinResult result = RIN_SUCCESS;
    int acquired = 0;
    if (window == RIN_HANDLE_INVALID || surface == RIN_HANDLE_INVALID ||
        damage.size > damage_bytes || damage.size % sizeof(RinRectV1) != 0u ||
        !sdk_gui_pointer_span(damage.address, damage.size))
        return RIN_ERROR_INVALID_ARGUMENT;
    damage_count = damage.size / sizeof(RinRectV1);
    if (damage_count != 0u)
        memcpy(damage_snapshot, (const void*)(uintptr_t)damage.address,
               (size_t)damage.size);
    sdk_gui_lock();
    entry = sdk_gui_find_surface(surface, NULL);
    if (entry == NULL) {
        sdk_gui_unlock();
        return RIN_ERROR_STALE_HANDLE;
    }
    if (entry->mapped || entry->busy) {
        sdk_gui_unlock();
        return RIN_ERROR_BUSY;
    }
    for (uint64_t index = 0u; index < damage_count; ++index) {
        const RinRectV1* rect = &damage_snapshot[index];
        if (rect->x < 0 || rect->y < 0 || rect->width == 0u ||
            rect->height == 0u ||
            (uint64_t)(uint32_t)rect->x + rect->width > entry->width ||
            (uint64_t)(uint32_t)rect->y + rect->height > entry->height) {
            sdk_gui_unlock();
            return RIN_ERROR_INVALID_ARGUMENT;
        }
    }
    entry->busy = 1u;
    source_pixels = entry->pixels;
    source_width = entry->width;
    source_height = entry->height;
    source_format = entry->format;
    sdk_gui_unlock();

    memset(&target, 0, sizeof(target));
    result = sdk_gui_result(wnd_acquire_render_target(
        (RinRuntimeGuiHandle)window, &target));
    if (result == RIN_SUCCESS) {
        acquired = 1;
        if (!sdk_gui_target_valid(&target) || target.width != source_width ||
            target.height != source_height) {
            result = RIN_ERROR_INVALID_ARGUMENT;
        } else {
            const uint64_t row_bytes = (uint64_t)source_width * 4u;
            for (uint32_t y = 0u; y < source_height; ++y) {
                const uint8_t* source_row = source_pixels +
                                            (size_t)y * (size_t)row_bytes;
                uint8_t* target_row = (uint8_t*)target.pixels +
                                      (size_t)y * target.pitch;
                if (source_format == target.format) {
                    memcpy(target_row, source_row, (size_t)row_bytes);
                } else {
                    for (uint32_t x = 0u; x < source_width; ++x) {
                        const size_t offset = (size_t)x * 4u;
                        target_row[offset] = source_row[offset + 2u];
                        target_row[offset + 1u] = source_row[offset + 1u];
                        target_row[offset + 2u] = source_row[offset];
                        target_row[offset + 3u] = source_row[offset + 3u];
                    }
                }
            }
        }
        {
            const RinResult release_result = sdk_gui_result(
                wnd_release_render_target((RinRuntimeGuiHandle)window,
                                          &target));
            if (release_result != RIN_SUCCESS) result = release_result;
            else if (result == RIN_SUCCESS)
                result = sdk_gui_result(
                    wnd_present((RinRuntimeGuiHandle)window));
        }
    }
    (void)acquired;
    sdk_gui_lock();
    entry = sdk_gui_find_surface(surface, NULL);
    if (entry != NULL) entry->busy = 0u;
    sdk_gui_unlock();
    return result;
}

static int sdk_gui_dialog_wrap(const char* input, char* output,
                              size_t output_capacity, const AqFont* font) {
    const char* cursor = input;
    size_t output_size = 0u;
    int32_t line_width = 0;
    while (*cursor != '\0') {
        const char* start = cursor;
        const uint32_t codepoint = aq_text_decode_utf8(&cursor);
        const size_t bytes = (size_t)(cursor - start);
        int32_t advance;
        if (bytes == 0u || bytes > output_capacity - output_size - 1u)
            return 0;
        if (codepoint == '\n') {
            output[output_size++] = '\n';
            line_width = 0;
            continue;
        }
        advance = aq_text_codepoint_advance(font, codepoint);
        if (advance < 0) advance = 0;
        if (line_width != 0 &&
            (int64_t)line_width + advance >
                RIN_RUNTIME_SDK_GUI_DIALOG_MESSAGE_WIDTH) {
            if (output_size + bytes + 1u >= output_capacity) return 0;
            output[output_size++] = '\n';
            line_width = 0;
        }
        memcpy(output + output_size, start, bytes);
        output_size += bytes;
        line_width += advance;
    }
    output[output_size] = '\0';
    return 1;
}

static size_t sdk_gui_dialog_line_count(const char* text) {
    size_t lines = 1u;
    for (const char* cursor = text; *cursor != '\0'; ++cursor)
        if (*cursor == '\n') ++lines;
    return lines;
}

static size_t sdk_gui_dialog_page(const char* wrapped, size_t first_line,
                                  char* output, size_t output_capacity) {
    const char* cursor = wrapped;
    size_t line = 0u;
    size_t output_size = 0u;
    size_t visible_lines = 1u;
    while (line < first_line && *cursor != '\0') {
        if (*cursor++ == '\n') ++line;
    }
    while (*cursor != '\0' && output_size + 1u < output_capacity) {
        const char value = *cursor++;
        if (value == '\n' &&
            visible_lines >= RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES)
            break;
        output[output_size++] = value;
        if (value == '\n') ++visible_lines;
    }
    output[output_size] = '\0';
    return visible_lines;
}

static RinResult sdk_gui_dialog_paint(RinRuntimeGuiHandle window,
                                     const char* message,
                                     size_t requested_first_line,
                                     size_t* line_count_out) {
    RinRenderTarget target;
    AqSurface surface;
    const AqFont* font = aq_font_default();
    char wrapped[RIN_GUI_DIALOG_TEXT_MAX_BYTES * 2u + 1u];
    char page[RIN_GUI_DIALOG_TEXT_MAX_BYTES * 2u + 1u];
    size_t line_count;
    size_t maximum_first_line;
    int status;
    if (!sdk_gui_dialog_wrap(message, wrapped, sizeof(wrapped), font))
        return RIN_ERROR_LIMIT_EXCEEDED;
    line_count = sdk_gui_dialog_line_count(wrapped);
    maximum_first_line = line_count > RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES
        ? line_count - RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES : 0u;
    if (requested_first_line > maximum_first_line)
        requested_first_line = maximum_first_line;
    (void)sdk_gui_dialog_page(wrapped, requested_first_line, page,
                              sizeof(page));
    if (line_count_out != NULL) *line_count_out = line_count;
    memset(&target, 0, sizeof(target));
    status = wnd_acquire_render_target(window, &target);
    if (status != RIN_RESULT_OK) return sdk_gui_result(status);
    if (!sdk_gui_target_valid(&target) ||
        target.width != RIN_RUNTIME_SDK_GUI_DIALOG_WIDTH ||
        target.height != RIN_RUNTIME_SDK_GUI_DIALOG_HEIGHT ||
        aq_surface_init_from_rin_render_target(&surface, &target) != 0) {
        const int release_status = wnd_release_render_target(window, &target);
        return release_status == RIN_RESULT_OK
                   ? RIN_ERROR_ABI_MISMATCH
                   : sdk_gui_result(release_status);
    }
    aq_surface_clear(&surface, AQ_RGB(246, 247, 250));
    aq_fill_rect(&surface, 0, 0, RIN_RUNTIME_SDK_GUI_DIALOG_WIDTH, 2,
                 AQ_RGB(50, 100, 170));
    aq_surface_set_clip(&surface, AQ_RECT(24, 48, 512, 140));
    aq_draw_string(&surface, 24, 52, page, AQ_RGB(30, 34, 40), font);
    aq_surface_reset_clip(&surface);
    aq_fill_rect(&surface, 360, 208, 80, 32, AQ_RGB(30, 100, 190));
    aq_fill_rect(&surface, 452, 208, 80, 32, AQ_RGB(225, 228, 234));
    aq_draw_string_centered(&surface, AQ_RECT(360, 208, 80, 32), "OK",
                            AQ_WHITE, font);
    aq_draw_string_centered(&surface, AQ_RECT(452, 208, 80, 32), "Cancel",
                            AQ_RGB(30, 34, 40), font);
    status = wnd_release_render_target(window, &target);
    if (status != RIN_RESULT_OK) return sdk_gui_result(status);
    return sdk_gui_result(wnd_present(window));
}

RinResult rin_dialog_show_v1(RinStringV1 title, RinStringV1 message,
                             uint32_t flags, uint32_t* result_out) {
    char title_snapshot[RIN_GUI_WINDOW_TITLE_MAX_BYTES + 1u];
    char message_snapshot[RIN_GUI_DIALOG_TEXT_MAX_BYTES + 1u];
    RinRuntimeGuiHandle window = RIN_WINDOW_HANDLE_INVALID;
    RinResult result = RIN_SUCCESS;
    uint32_t dialog_result = 0u;
    int modal = 0;
    int keyboard_grab = 0;
    int x = 0;
    int y = 0;
    size_t first_line = 0u;
    size_t line_count = 1u;
    if (result_out != NULL) *result_out = 0u;
    if (result_out == NULL || flags != 0u ||
        !sdk_gui_text_snapshot(title, RIN_GUI_WINDOW_TITLE_MAX_BYTES,
                               title_snapshot) ||
        !sdk_gui_text_snapshot(message, RIN_GUI_DIALOG_TEXT_MAX_BYTES,
                               message_snapshot))
        return RIN_ERROR_INVALID_ARGUMENT;
    window = wnd_create_flags(
        title_snapshot, 80, 80, RIN_RUNTIME_SDK_GUI_DIALOG_WIDTH,
        RIN_RUNTIME_SDK_GUI_DIALOG_HEIGHT, RIN_WINDOW_ROLE_DIALOG,
        RIN_WINDOW_FLAG_OPAQUE);
    if (window == RIN_WINDOW_HANDLE_INVALID) return RIN_ERROR_IO;
    result = sdk_gui_result(wnd_set_modal(window, 1));
    if (result != RIN_SUCCESS) goto cleanup;
    modal = 1;
    result = sdk_gui_result(wnd_set_keyboard_grab(window, 1));
    if (result != RIN_SUCCESS) goto cleanup;
    keyboard_grab = 1;
    result = sdk_gui_dialog_paint(window, message_snapshot, first_line,
                                  &line_count);
    if (result != RIN_SUCCESS) goto cleanup;
    (void)wnd_get_position(window, &x, &y);
    for (;;) {
        RinGuiNativeEventV1 event;
        uint32_t packed = 0u;
        const int poll_result = wnd_poll_native(window, &event, &packed);
        (void)packed;
        if (poll_result < 0) {
            result = RIN_ERROR_IO;
            break;
        }
        if (poll_result > 0) {
            if (event.struct_size != sizeof(event) ||
                event.version != RIN_GUI_NATIVE_EVENT_VERSION ||
                event.reserved[0] != 0u || event.reserved[1] != 0u) {
                result = RIN_ERROR_ABI_MISMATCH;
                break;
            }
            if (event.type == 2u) {
                dialog_result = 0u;
                break;
            }
            if (event.type == RIN_GUI_NATIVE_EVENT_KEY_DOWN) {
                const uint8_t scancode =
                    (uint8_t)(event.data & RIN_GUI_NATIVE_KEY_SCANCODE_MASK);
                if (scancode == 0x1cu) {
                    dialog_result = 1u;
                    break;
                }
                if (scancode == 0x01u) {
                    dialog_result = 0u;
                    break;
                }
                if (scancode == 0x48u && first_line != 0u) {
                    --first_line;
                    result = sdk_gui_dialog_paint(window, message_snapshot,
                                                  first_line, &line_count);
                    if (result != RIN_SUCCESS) break;
                } else if (scancode == 0x50u &&
                           first_line + RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES <
                               line_count) {
                    ++first_line;
                    result = sdk_gui_dialog_paint(window, message_snapshot,
                                                  first_line, &line_count);
                    if (result != RIN_SUCCESS) break;
                }
            }
            if (event.type == RIN_GUI_NATIVE_EVENT_MOUSE_WHEEL &&
                event.wheel_delta != 0) {
                const size_t maximum_first_line =
                    line_count > RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES
                        ? line_count -
                              RIN_RUNTIME_SDK_GUI_DIALOG_VISIBLE_LINES : 0u;
                if (event.wheel_delta > 0) {
                    first_line = first_line > 3u ? first_line - 3u : 0u;
                } else if (first_line < maximum_first_line) {
                    first_line += 3u;
                    if (first_line > maximum_first_line)
                        first_line = maximum_first_line;
                }
                result = sdk_gui_dialog_paint(window, message_snapshot,
                                              first_line, &line_count);
                if (result != RIN_SUCCESS) break;
            }
            if (event.type == RIN_GUI_NATIVE_EVENT_POINTER_BUTTON &&
                (event.data & RIN_GUI_NATIVE_POINTER_ACTION_MASK) ==
                    RIN_GUI_NATIVE_POINTER_ACTION_DOWN &&
                (event.data & RIN_GUI_NATIVE_POINTER_LEFT) != 0u) {
                const int64_t local_x = (int64_t)event.screen_x - x;
                const int64_t local_y = (int64_t)event.screen_y - y;
                if (local_y >= 208 && local_y < 240 &&
                    local_x >= 360 && local_x < 440) {
                    dialog_result = 1u;
                    break;
                }
                if (local_y >= 208 && local_y < 240 &&
                    local_x >= 452 && local_x < 532) {
                    dialog_result = 0u;
                    break;
                }
            }
        }
        rin_sleep(1u);
    }

cleanup:
    if (keyboard_grab) {
        const RinResult release_result =
            sdk_gui_result(wnd_set_keyboard_grab(window, 0));
        if (result == RIN_SUCCESS && release_result != RIN_SUCCESS)
            result = release_result;
    }
    if (modal) {
        const RinResult release_result =
            sdk_gui_result(wnd_set_modal(window, 0));
        if (result == RIN_SUCCESS && release_result != RIN_SUCCESS)
            result = release_result;
    }
    {
        const RinResult close_result = sdk_gui_result(wnd_close_async(window));
        if (result == RIN_SUCCESS && close_result != RIN_SUCCESS)
            result = close_result;
    }
    if (result == RIN_SUCCESS) *result_out = dialog_result;
    return result;
}
