/* SPDX-License-Identifier: MIT */
/* Private GPU-to-native-window frame handoff; not a drawing API. */
#ifndef RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H
#define RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#include <rin/contract_abi.h>
#include <rinruntime/window.h>

#define RIN_RUNTIME_COMPOSITOR_GPU_FRAME_V1_VERSION UINT32_C(1)

typedef enum RinRuntimeCompositorGpuPixelFormatV1 {
    RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 = 0,
    RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8 = 1
} RinRuntimeCompositorGpuPixelFormatV1;

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

/* Copy a completed, CPU-readable GPU image into the active native-window
 * SHM backbuffer, then enqueue the existing damage+commit transaction.
 * expected_generation binds the copy to the current window buffer set. The
 * source may be released as soon as this function returns because the copy
 * is synchronous; the Compositor owns the SHM buffer through its commit path. */
int rinruntime_compositor_gpu_import_frame_v1(
    RinRuntimeGuiHandle handle, uint64_t expected_generation,
    const RinRuntimeCompositorGpuFrameV1* frame);

/* API-independent checked pixel copy used by the window handoff and host
 * tests. Formats use the native Compositor protocol's BGRA32/RGBA32 values. */
int rinruntime_compositor_gpu_copy_frame_v1(
    void* destination, uint64_t destination_bytes,
    uint32_t destination_pitch, uint32_t destination_format,
    const RinRuntimeCompositorGpuFrameV1* frame);

#endif /* RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H */
