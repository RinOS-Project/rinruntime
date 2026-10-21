/* SPDX-License-Identifier: MIT */
#include <rinruntime/frame_copy.h>

#include <limits.h>
#include <string.h>

static int frame_copy_span(uint32_t pitch, uint32_t height,
                           uint32_t row_bytes, uint64_t* span_out) {
    uint64_t preceding_rows;
    if (!span_out || height == 0u || row_bytes == 0u || pitch < row_bytes)
        return 0;
    preceding_rows = (uint64_t)(height - 1u) * pitch;
    if (preceding_rows > UINT64_MAX - row_bytes) return 0;
    *span_out = preceding_rows + row_bytes;
    return 1;
}

static int frame_copy_ranges_overlap(uintptr_t left, uint64_t left_size,
                                     uintptr_t right, uint64_t right_size) {
    uintptr_t left_end;
    uintptr_t right_end;
    if (left_size > UINTPTR_MAX - left || right_size > UINTPTR_MAX - right)
        return -1;
    left_end = left + (uintptr_t)left_size;
    right_end = right + (uintptr_t)right_size;
    return left < right_end && right < left_end;
}

RinResultCode rinruntime_frame_copy_v1(
    const RinRuntimeFrameCopyV1* request) {
    RinRuntimeFrameCopyV1 copy;
    const uint8_t* source;
    uint8_t* destination;
    uint32_t row_bytes;
    uint64_t source_span;
    uint64_t destination_span;
    uintptr_t request_address;
    uintptr_t source_address;
    uintptr_t destination_address;
    int overlap;

    if (!request) return RIN_RESULT_INVALID_ARGUMENT;
    memcpy(&copy, request, sizeof(copy));
    if (copy.struct_size != sizeof(copy) ||
        copy.version != RINRUNTIME_FRAME_COPY_V1_VERSION)
        return RIN_RESULT_VERSION_MISMATCH;
    if (copy.reserved[0] != 0u || copy.reserved[1] != 0u ||
        copy.width == 0u || copy.height == 0u ||
        copy.width > UINT32_MAX / 4u || copy.source.address == 0u ||
        copy.destination.address == 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    if ((copy.source_format != RINRUNTIME_FRAME_PIXEL_BGRA8 &&
         copy.source_format != RINRUNTIME_FRAME_PIXEL_RGBA8) ||
        (copy.destination_format != RINRUNTIME_FRAME_PIXEL_BGRA8 &&
         copy.destination_format != RINRUNTIME_FRAME_PIXEL_RGBA8))
        return RIN_RESULT_NOT_SUPPORTED;
#if UINTPTR_MAX < UINT64_MAX
    if (copy.source.address > UINTPTR_MAX ||
        copy.destination.address > UINTPTR_MAX)
        return RIN_RESULT_LIMIT_EXCEEDED;
#endif

    row_bytes = copy.width * 4u;
    if (copy.source_pitch < row_bytes ||
        copy.destination_pitch < row_bytes)
        return RIN_RESULT_BUFFER_TOO_SMALL;
    if (!frame_copy_span(copy.source_pitch, copy.height, row_bytes,
                         &source_span) ||
        !frame_copy_span(copy.destination_pitch, copy.height, row_bytes,
                         &destination_span))
        return RIN_RESULT_INVALID_ARGUMENT;
    if (copy.source.size < source_span ||
        copy.destination.size < destination_span)
        return RIN_RESULT_BUFFER_TOO_SMALL;

    request_address = (uintptr_t)request;
    source_address = (uintptr_t)copy.source.address;
    destination_address = (uintptr_t)copy.destination.address;
    overlap = frame_copy_ranges_overlap(source_address, source_span,
                                        destination_address,
                                        destination_span);
    if (overlap != 0) return RIN_RESULT_INVALID_ARGUMENT;
    overlap = frame_copy_ranges_overlap(destination_address,
                                        destination_span,
                                        request_address, sizeof(copy));
    if (overlap != 0) return RIN_RESULT_INVALID_ARGUMENT;

    source = (const uint8_t*)source_address;
    destination = (uint8_t*)destination_address;
    for (uint32_t y = 0u; y < copy.height; ++y) {
        const uint64_t source_offset = (uint64_t)y * copy.source_pitch;
        const uint64_t destination_offset =
            (uint64_t)y * copy.destination_pitch;
        const uint8_t* source_row = source + (size_t)source_offset;
        uint8_t* destination_row = destination + (size_t)destination_offset;
        if (copy.source_format == copy.destination_format) {
            memcpy(destination_row, source_row, row_bytes);
        } else {
            for (uint32_t x = 0u; x < copy.width; ++x) {
                const uint32_t offset = x * 4u;
                destination_row[offset] = source_row[offset + 2u];
                destination_row[offset + 1u] = source_row[offset + 1u];
                destination_row[offset + 2u] = source_row[offset];
                destination_row[offset + 3u] = source_row[offset + 3u];
            }
        }
        if (copy.destination_pitch > row_bytes && y + 1u < copy.height) {
            memset(destination_row + row_bytes, 0,
                   copy.destination_pitch - row_bytes);
        }
    }
    return RIN_RESULT_OK;
}
