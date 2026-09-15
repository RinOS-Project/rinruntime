/* SPDX-License-Identifier: MIT */
/* Backend-independent caller-owned cursor frame model. */

#ifndef RINRUNTIME_CURSOR_H
#define RINRUNTIME_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_RUNTIME_CURSOR_VERSION 1u
#define RIN_RUNTIME_CURSOR_MAX_FRAMES 32u
#define RIN_RUNTIME_CURSOR_MAX_DIMENSION 256u
#define RIN_RUNTIME_CURSOR_MAX_STRIDE_BYTES \
    (RIN_RUNTIME_CURSOR_MAX_DIMENSION * sizeof(uint32_t))
#define RIN_RUNTIME_CURSOR_MAX_STORAGE_BYTES (1024u * 1024u)
#define RIN_RUNTIME_CURSOR_MAX_DURATION_MS 60000u

typedef enum RinRuntimeCursorStatus {
    RIN_RUNTIME_CURSOR_OK = 0,
    RIN_RUNTIME_CURSOR_INVALID_ARGUMENT = -1,
    RIN_RUNTIME_CURSOR_LIMIT = -2
} RinRuntimeCursorStatus;

/* The pixel memory and frame array remain caller-owned.  The public model
 * intentionally carries no path, file-format, theme-root, or compositor
 * handle.  duration_ms==0 denotes a non-animated/static frame. */
typedef struct RinRuntimeCursorFrameV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint32_t width;
    uint32_t height;
    uint32_t stride_bytes;
    int32_t hotspot_x;
    int32_t hotspot_y;
    uint32_t duration_ms;
    const uint32_t* pixels;
} RinRuntimeCursorFrameV1;

typedef struct RinRuntimeCursorImageV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint32_t frame_count;
    const RinRuntimeCursorFrameV1* frames;
} RinRuntimeCursorImageV1;

static inline RinRuntimeCursorStatus
rinruntime_cursor_frame_validate(const RinRuntimeCursorFrameV1* frame)
{
    uint64_t storage_bytes;
    if (frame == NULL || frame->struct_size < sizeof(*frame) ||
        frame->version != RIN_RUNTIME_CURSOR_VERSION ||
        frame->reserved0 != 0u || frame->width == 0u || frame->height == 0u ||
        frame->width > RIN_RUNTIME_CURSOR_MAX_DIMENSION ||
        frame->height > RIN_RUNTIME_CURSOR_MAX_DIMENSION ||
        frame->stride_bytes < frame->width * sizeof(uint32_t) ||
        frame->stride_bytes > RIN_RUNTIME_CURSOR_MAX_STRIDE_BYTES ||
        (frame->stride_bytes % sizeof(uint32_t)) != 0u ||
        frame->hotspot_x < 0 || frame->hotspot_y < 0 ||
        (uint32_t)frame->hotspot_x >= frame->width ||
        (uint32_t)frame->hotspot_y >= frame->height ||
        frame->duration_ms > RIN_RUNTIME_CURSOR_MAX_DURATION_MS ||
        frame->pixels == NULL)
        return RIN_RUNTIME_CURSOR_INVALID_ARGUMENT;
    storage_bytes = (uint64_t)(frame->height - 1u) * frame->stride_bytes +
                    (uint64_t)frame->width * sizeof(uint32_t);
    if (storage_bytes > RIN_RUNTIME_CURSOR_MAX_STORAGE_BYTES)
        return RIN_RUNTIME_CURSOR_LIMIT;
    return RIN_RUNTIME_CURSOR_OK;
}

static inline RinRuntimeCursorStatus
rinruntime_cursor_image_validate(const RinRuntimeCursorImageV1* image)
{
    uint32_t index;
    if (image == NULL || image->struct_size < sizeof(*image) ||
        image->version != RIN_RUNTIME_CURSOR_VERSION ||
        image->reserved0 != 0u || image->frame_count == 0u ||
        image->frame_count > RIN_RUNTIME_CURSOR_MAX_FRAMES ||
        image->frames == NULL)
        return RIN_RUNTIME_CURSOR_INVALID_ARGUMENT;
    for (index = 0u; index < image->frame_count; ++index) {
        RinRuntimeCursorStatus status =
            rinruntime_cursor_frame_validate(&image->frames[index]);
        if (status != RIN_RUNTIME_CURSOR_OK) return status;
    }
    return RIN_RUNTIME_CURSOR_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CURSOR_H */
