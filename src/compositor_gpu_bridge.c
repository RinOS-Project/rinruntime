/* SPDX-License-Identifier: MIT */
/* Explicit CPU-readable image copy for the native-window Compositor route. */
#include "compositor_gpu_bridge.h"

#include <rinruntime/frame_copy.h>

#include <limits.h>
#include <stdint.h>
#include <string.h>

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

int rinruntime_compositor_gpu_slot_reuse_status_v1(
    uint64_t submitted_sequence, uint64_t released_sequence) {
    if (released_sequence == submitted_sequence) return RIN_RESULT_OK;
    if (released_sequence < submitted_sequence) return RIN_RESULT_BUSY;
    return RIN_RESULT_CORRUPT_DATA;
}

int rinruntime_compositor_peer_identity_project_v1(
    const rin_unix_peer_identity_v1* peer,
    RinIpcPeerIdentityV1* identity_out) {
    rin_unix_peer_identity_v1 peer_copy;
    if (!identity_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(identity_out, 0, sizeof(*identity_out));
    if (!peer ||
        compositor_gpu_ranges_overlap((uintptr_t)peer, sizeof(*peer),
                                       (uintptr_t)identity_out,
                                       sizeof(*identity_out)))
        return RIN_RESULT_INVALID_ARGUMENT;
    memcpy(&peer_copy, peer, sizeof(peer_copy));
    if (!rin_unix_peer_identity_valid(&peer_copy))
        return RIN_RESULT_CORRUPT_DATA;
    identity_out->struct_size = sizeof(*identity_out);
    identity_out->version = RIN_SDK_STRUCT_VERSION_1;
    identity_out->process_id = peer_copy.process_id;
    identity_out->process_instance_cookie =
        peer_copy.process_instance_cookie;
    return RIN_RESULT_OK;
}

int rinruntime_compositor_peer_identity_query_v1(
    RinRuntimeCompositorPeerQueryV1Fn query, void* context,
    RinIpcPeerIdentityV1* identity_out) {
    rin_unix_peer_identity_v1 peer;
    uint32_t peer_size = 0u;
    int result;
    if (!identity_out) return RIN_RESULT_INVALID_ARGUMENT;
    memset(identity_out, 0, sizeof(*identity_out));
    if (!query) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&peer, 0, sizeof(peer));
    result = query(context, &peer, &peer_size);
    if (result != RIN_RESULT_OK) return result;
    if (peer_size != sizeof(peer)) return RIN_RESULT_CORRUPT_DATA;
    return rinruntime_compositor_peer_identity_project_v1(
        &peer, identity_out);
}

int rinruntime_compositor_shm_export_validate_v1(
    const RinCompositorGpuImageV1* image, uint32_t surface_id,
    uint32_t buffer_slot, uint64_t expected_surface_generation,
    uint32_t width, uint32_t height, uint32_t pitch, uint32_t format,
    uint64_t bytes) {
    uint64_t minimum_bytes;
    if (!image || surface_id == 0u ||
        buffer_slot >= RIN_COMPOSITOR_MAX_BUFFERS || width == 0u ||
        height == 0u || width > UINT32_MAX / 4u ||
        pitch < width * 4u || format > 1u || bytes == 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    minimum_bytes = (uint64_t)pitch * height;
    if (minimum_bytes > bytes) return RIN_RESULT_INVALID_ARGUMENT;
    if (image->struct_size != sizeof(*image) ||
        image->version != RIN_COMPOSITOR_GPU_SURFACE_ABI_VERSION ||
        image->surface_id != surface_id || image->buffer_slot != buffer_slot ||
        image->surface_generation == 0u || image->image_handle == 0u ||
        (expected_surface_generation != 0u &&
         image->surface_generation != expected_surface_generation) ||
        image->width != width || image->height != height ||
        image->pitch != pitch || image->format != format ||
        image->bytes != bytes || image->reserved[0] != 0u ||
        image->reserved[1] != 0u)
        return RIN_RESULT_CORRUPT_DATA;
    return RIN_RESULT_OK;
}

int rinruntime_compositor_gpu_copy_frame_v1(
    void* destination, uint64_t destination_bytes,
    uint32_t destination_pitch, uint32_t destination_format,
    const RinRuntimeCompositorGpuFrameV1* frame) {
    RinRuntimeFrameCopyV1 request;
    if (!destination || !frame) return RIN_RESULT_INVALID_ARGUMENT;
    if (frame->struct_size != sizeof(*frame) ||
        frame->version != RIN_RUNTIME_COMPOSITOR_GPU_FRAME_V1_VERSION ||
        frame->reserved[0] != 0u || frame->reserved[1] != 0u)
        return RIN_RESULT_INVALID_ARGUMENT;
    if ((frame->format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 &&
         frame->format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8) ||
        (destination_format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_BGRA8 &&
         destination_format != RIN_RUNTIME_COMPOSITOR_GPU_PIXEL_RGBA8))
        return RIN_RESULT_INVALID_ARGUMENT;
    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_FRAME_COPY_V1_VERSION;
    request.source.address = (uint64_t)(uintptr_t)frame->pixels;
    request.source.size = frame->bytes;
    request.destination.address = (uint64_t)(uintptr_t)destination;
    request.destination.size = destination_bytes;
    request.width = frame->width;
    request.height = frame->height;
    request.source_pitch = frame->row_pitch;
    request.destination_pitch = destination_pitch;
    request.source_format = frame->format;
    request.destination_format = destination_format;
    return rinruntime_frame_copy_v1(&request);
}
