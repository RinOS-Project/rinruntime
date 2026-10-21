/* SPDX-License-Identifier: MIT */
/* Stable CPU pixel conversion helpers; no GPU, IPC, or compositor contract. */
#ifndef RINRUNTIME_FRAME_COPY_H
#define RINRUNTIME_FRAME_COPY_H

#include <stdint.h>
#include <rin/abi.h>
#include <rin/contract_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_FRAME_COPY_V1_VERSION UINT32_C(1)

typedef enum RinRuntimeFramePixelFormatV1 {
    RINRUNTIME_FRAME_PIXEL_BGRA8 = 0,
    RINRUNTIME_FRAME_PIXEL_RGBA8 = 1
} RinRuntimeFramePixelFormatV1;

/* `source` and `destination` are byte slices. Each active pixel is four
 * bytes. Copying between formats swaps the red and blue bytes and preserves
 * green and alpha exactly; no premultiplication, blending, or color-space
 * conversion is performed. Destination inter-row padding is zeroed when
 * present; bytes after the final active pixel are left untouched. */
typedef struct RinRuntimeFrameCopyV1 {
    uint32_t struct_size;
    uint32_t version;
    RinSliceV1 source;
    RinSliceV1 destination;
    uint32_t width;
    uint32_t height;
    uint32_t source_pitch;
    uint32_t destination_pitch;
    uint32_t source_format;
    uint32_t destination_format;
    uint64_t reserved[2];
} RinRuntimeFrameCopyV1;

#if defined(__cplusplus)
static_assert(sizeof(RinRuntimeFrameCopyV1) == 80,
              "RinRuntimeFrameCopyV1 ABI drift");
#else
_Static_assert(sizeof(RinRuntimeFrameCopyV1) == 80,
               "RinRuntimeFrameCopyV1 ABI drift");
#endif

/* Copies a bounded frame synchronously. On failure, destination bytes are
 * unchanged. Overlapping active source and destination ranges are rejected.
 * Returns the public Rin result code, including BUFFER_TOO_SMALL for short
 * slices and NOT_SUPPORTED for unknown pixel formats. */
RinResultCode rinruntime_frame_copy_v1(
    const RinRuntimeFrameCopyV1* request);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FRAME_COPY_H */
