/* SPDX-License-Identifier: MIT */
/* Explicit CPU-readable image copy for the native-window Compositor route. */
#include "compositor_gpu_bridge.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static int compositor_gpu_frame_reserved_zero(
    const RinRuntimeCompositorGpuFrameV1* frame) {
    return frame->reserved[0] == 0u && frame->reserved[1] == 0u;
}

static int compositor_gpu_span(uint32_t pitch, uint32_t height,
                                uint32_t row_bytes, uint64_t* span_out) {
    uint64_t preceding_rows;
    if (!span_out || height == 0u || row_bytes == 0u || pitch < row_bytes)
        return 0;
    preceding_rows = (uint64_t)(height - 1u) * pitch;
    if (preceding_rows > UINT64_MAX - row_bytes) return 0;
    *span_out = preceding_rows + row_bytes;
    return 1;
}

static int compositor_gpu_ranges_overlap(uintptr_t left, uint64_t left_size,
                                         uintptr_t right,
                                         uint64_t right_size) {
    uintptr_t left_end;
    uintptr_t right_end;
    if (left_size > UINTPTR_MAX - left || right_size > UINTPTR_MAX - right)
        return -1;
    left_end = left + (uintptr_t)left_size;
    right_end = right + (uintptr_t)right_size;
    return left < right_end && right < left_end;
}

int rinruntime_compositor_gpu_copy_frame_v1(
    void* destination, uint64_t destination_bytes,
    uint32_t destination_pitch, uint32_t destination_format,
    const RinRuntimeCompositorGpuFrameV1* frame) {
    const uint32_t row_bytes = frame && frame->width <= UINT32_MAX / 4u
                                   ? frame->width * 4u : 0u;
    uint64_t source_span;
    uint64_t destination_span;
    int overlap;

    if (!destination || !frame || frame->struct_size != sizeof(*frame) ||
        frame->version != RIN_RUNTIME_COMPOSITOR_GPU_FRAME_V1_VERSION ||
        !frame->pixels || frame->width == 0u || frame->height == 0u ||
        row_bytes == 0u || frame->bytes == 0u ||
        !compositor_gpu_frame_reserved_zero(frame) ||
        (frame->format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 &&
         frame->format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8) ||
        (destination_format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 &&
         destination_format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8))
        return RIN_RESULT_INVALID_ARGUMENT;
    if (!compositor_gpu_span(frame->row_pitch, frame->height, row_bytes,
                             &source_span) ||
        !compositor_gpu_span(destination_pitch, frame->height, row_bytes,
                             &destination_span) ||
        frame->bytes < source_span || destination_bytes < destination_span)
        return RIN_RESULT_BUFFER_TOO_SMALL;

    overlap = compositor_gpu_ranges_overlap(
        (uintptr_t)frame->pixels, source_span,
        (uintptr_t)destination, destination_span);
    if (overlap != 0) return RIN_RESULT_INVALID_ARGUMENT;

    for (uint32_t y = 0u; y < frame->height; ++y) {
        const uint8_t* source = (const uint8_t*)frame->pixels +
                                (size_t)y * frame->row_pitch;
        uint8_t* target = (uint8_t*)destination +
                          (size_t)y * destination_pitch;
        if (frame->format == destination_format) {
            memcpy(target, source, row_bytes);
        } else {
            for (uint32_t x = 0u; x < frame->width; ++x) {
                const uint32_t offset = x * 4u;
                target[offset] = source[offset + 2u];
                target[offset + 1u] = source[offset + 1u];
                target[offset + 2u] = source[offset];
                target[offset + 3u] = source[offset + 3u];
            }
        }
        if (destination_pitch > row_bytes && y + 1u < frame->height)
            memset(target + row_bytes, 0, destination_pitch - row_bytes);
    }
    return RIN_RESULT_OK;
}
