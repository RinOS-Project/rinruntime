/* SPDX-License-Identifier: MIT */
/* Private GPU-to-native-window frame handoff; not a drawing API. */
#ifndef RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H
#define RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#include <rin/contract_abi.h>
#include <rin/ipc.h>
#include <rin/net/socket_abi.h>
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

/* Copy a completed, CPU-readable GPU image into an available native-window
 * SHM backbuffer, then enqueue the existing damage+commit transaction.
 * expected_generation binds the copy to the current window buffer set. On
 * success the source may be released when this function returns because the
 * copy is synchronous. BUSY means no copy occurred and the source remains
 * caller-owned; the Compositor owns an accepted SHM slot until render release. */
int rinruntime_compositor_gpu_import_frame_v1(
    RinRuntimeGuiHandle handle, uint64_t expected_generation,
    const RinRuntimeCompositorGpuFrameV1* frame);

/* Compare one producer slot's last accepted submission with the Compositor's
 * completed-read sequence. BUSY means the producer must keep the slot
 * unchanged and retry; a future completion sequence is protocol corruption. */
int rinruntime_compositor_gpu_slot_reuse_status_v1(
    uint64_t submitted_sequence, uint64_t released_sequence);

/* Project only the recipient process identity from the kernel-owned Unix
 * peer record. Callers must obtain that record from the connected Compositor
 * socket with SO_RIN_UNIX_PEER_IDENTITY. */
int rinruntime_compositor_peer_identity_project_v1(
    const rin_unix_peer_identity_v1* peer,
    RinIpcPeerIdentityV1* identity_out);
typedef int (*RinRuntimeCompositorPeerQueryV1Fn)(
    void* context, rin_unix_peer_identity_v1* peer_out,
    uint32_t* peer_size_out);
int rinruntime_compositor_peer_identity_query_v1(
    RinRuntimeCompositorPeerQueryV1Fn query, void* context,
    RinIpcPeerIdentityV1* identity_out);

/* Validate the Compositor's explicitly software-SHM export against the
 * caller-owned native-window buffer set. expected_surface_generation may be
 * zero only before the first export of a buffer generation. */
int rinruntime_compositor_shm_export_validate_v1(
    const RinCompositorGpuImageV1* image, uint32_t surface_id,
    uint32_t buffer_slot, uint64_t expected_surface_generation,
    uint32_t width, uint32_t height, uint32_t pitch, uint32_t format,
    uint64_t bytes);

/* API-independent checked pixel copy used by the window handoff and host
 * tests. Formats use the native Compositor protocol's BGRA32/RGBA32 values. */
int rinruntime_compositor_gpu_copy_frame_v1(
    void* destination, uint64_t destination_bytes,
    uint32_t destination_pitch, uint32_t destination_format,
    const RinRuntimeCompositorGpuFrameV1* frame);

#endif /* RINRUNTIME_PRIVATE_COMPOSITOR_GPU_BRIDGE_H */
