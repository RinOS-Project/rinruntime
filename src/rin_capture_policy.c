/* SPDX-License-Identifier: MIT */

#include "rin_capture_policy.h"

#include <stddef.h>

static int capture_audio_chunk_is_valid(const RinCaptureChunkV1* chunk)
{
    uint32_t bytes_per_sample;
    uint32_t bytes_per_frame;

    if (chunk->width != 0u || chunk->height != 0u ||
        chunk->sample_rate < 8000u || chunk->sample_rate > 384000u ||
        chunk->channels == 0u || chunk->channels > 32u) {
        return 0;
    }
    if (chunk->format == RIN_CAPTURE_FORMAT_PCM_S16LE) {
        bytes_per_sample = 2u;
    } else if (chunk->format == RIN_CAPTURE_FORMAT_PCM_F32LE) {
        bytes_per_sample = 4u;
    } else {
        return 0;
    }
    bytes_per_frame = chunk->channels * bytes_per_sample;
    return chunk->total_size % bytes_per_frame == 0u &&
           chunk->offset % bytes_per_frame == 0u &&
           chunk->payload_size % bytes_per_frame == 0u;
}

static int capture_video_chunk_is_valid(const RinCaptureChunkV1* chunk)
{
    uint64_t pixels;
    uint64_t expected_size;

    if (chunk->sample_rate != 0u || chunk->channels != 0u ||
        chunk->width == 0u || chunk->width > 16384u ||
        chunk->height == 0u || chunk->height > 16384u) {
        return 0;
    }
    pixels = (uint64_t)chunk->width * (uint64_t)chunk->height;
    if (chunk->format == RIN_CAPTURE_FORMAT_RGBX8888) {
        expected_size = pixels * UINT64_C(4);
    } else if (chunk->format == RIN_CAPTURE_FORMAT_NV12) {
        if ((chunk->width & 1u) != 0u || (chunk->height & 1u) != 0u) {
            return 0;
        }
        expected_size = pixels + (pixels / UINT64_C(2));
    } else if (chunk->format == RIN_CAPTURE_FORMAT_MJPEG) {
        return 1;
    } else {
        return 0;
    }
    return expected_size == chunk->total_size;
}

int rin_capture_transport_profile_v1_is_valid(
    uint32_t resource,
    const RinCaptureTransportProfileV1* profile)
{
    uint32_t index;
    uint32_t bytes_per_sample;
    uint32_t bytes_per_frame;
    uint64_t pixels;
    uint64_t expected_size;

    if (profile == NULL || profile->struct_size != sizeof(*profile) ||
        profile->version != RIN_CAPTURE_TRANSPORT_PROFILE_VERSION ||
        profile->stream_id == 0u || profile->max_frame_size == 0u ||
        profile->max_frame_size > RIN_CAPTURE_MAX_FRAME_BYTES ||
        profile->flags != 0u || profile->reserved0 != 0u) {
        return 0;
    }
    for (index = 0u; index < 2u; ++index) {
        if (profile->reserved[index] != 0u) return 0;
    }
    if (resource == RIN_APP_RESOURCE_MICROPHONE) {
        if (profile->width != 0u || profile->height != 0u ||
            profile->sample_rate < 8000u ||
            profile->sample_rate > 384000u || profile->channels == 0u ||
            profile->channels > 32u) {
            return 0;
        }
        if (profile->format == RIN_CAPTURE_FORMAT_PCM_S16LE) {
            bytes_per_sample = 2u;
        } else if (profile->format == RIN_CAPTURE_FORMAT_PCM_F32LE) {
            bytes_per_sample = 4u;
        } else {
            return 0;
        }
        bytes_per_frame = profile->channels * bytes_per_sample;
        return bytes_per_frame != 0u &&
               profile->max_frame_size % bytes_per_frame == 0u;
    }
    if (resource != RIN_APP_RESOURCE_CAMERA || profile->sample_rate != 0u ||
        profile->channels != 0u || profile->width == 0u ||
        profile->width > 16384u || profile->height == 0u ||
        profile->height > 16384u) {
        return 0;
    }
    pixels = (uint64_t)profile->width * (uint64_t)profile->height;
    if (profile->format == RIN_CAPTURE_FORMAT_RGBX8888) {
        expected_size = pixels * UINT64_C(4);
    } else if (profile->format == RIN_CAPTURE_FORMAT_NV12) {
        if ((profile->width & 1u) != 0u ||
            (profile->height & 1u) != 0u) {
            return 0;
        }
        expected_size = pixels + (pixels / UINT64_C(2));
    } else if (profile->format == RIN_CAPTURE_FORMAT_MJPEG) {
        return 1;
    } else {
        return 0;
    }
    return expected_size == profile->max_frame_size;
}

int rin_capture_chunk_v1_is_valid(
    uint32_t resource,
    const RinCaptureChunkV1* chunk,
    uint32_t transferred)
{
    uint64_t chunk_end;

    if (chunk == NULL || chunk->struct_size != sizeof(*chunk) ||
        chunk->version != RIN_CAPTURE_CHUNK_VERSION ||
        chunk->sequence == 0u || chunk->monotonic_time_ns == 0u ||
        chunk->total_size == 0u ||
        chunk->total_size > RIN_CAPTURE_MAX_FRAME_BYTES ||
        chunk->payload_size == 0u || chunk->reserved0 != 0u ||
        (chunk->flags & ~RIN_CAPTURE_CHUNK_KNOWN_FLAGS) != 0u) {
        return 0;
    }
    chunk_end = (uint64_t)chunk->offset + (uint64_t)chunk->payload_size;
    if (chunk->offset >= chunk->total_size ||
        chunk_end > chunk->total_size ||
        transferred != RIN_CAPTURE_CHUNK_HEADER_SIZE +
                           chunk->payload_size) {
        return 0;
    }
    if (((chunk->flags & RIN_CAPTURE_CHUNK_FRAME_START) != 0u) !=
            (chunk->offset == 0u) ||
        ((chunk->flags & RIN_CAPTURE_CHUNK_FRAME_END) != 0u) !=
            (chunk_end == chunk->total_size) ||
        ((chunk->flags & RIN_CAPTURE_CHUNK_DROPPED_BEFORE) != 0u &&
         (chunk->flags & RIN_CAPTURE_CHUNK_FRAME_START) == 0u)) {
        return 0;
    }
    if (resource == RIN_APP_RESOURCE_MICROPHONE) {
        return capture_audio_chunk_is_valid(chunk);
    }
    if (resource == RIN_APP_RESOURCE_CAMERA) {
        return capture_video_chunk_is_valid(chunk);
    }
    return 0;
}
