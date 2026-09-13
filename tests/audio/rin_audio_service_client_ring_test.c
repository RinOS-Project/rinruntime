/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <rinruntime/rin_audio_service_client.h>

static RinAudioServiceSharedRingV1 valid_ring(void)
{
    RinAudioServiceSharedRingV1 ring;
    memset(&ring, 0, sizeof(ring));
    ring.magic = RIN_AUDIO_SERVICE_RING_MAGIC;
    ring.version = RIN_AUDIO_SERVICE_PROTOCOL_VERSION;
    ring.header_bytes = sizeof(ring);
    ring.frame_bytes = 4u;
    ring.capacity_frames = RIN_AUDIO_SERVICE_MIN_RING_FRAMES;
    ring.stream_generation = 1u;
    return ring;
}

int main(void)
{
    RinAudioServiceSharedRingV1 ring = valid_ring();
    RinAudioServiceFormatV1 format = {
        sizeof(format), RIN_AUDIO_SERVICE_PROTOCOL_VERSION, 48000u, 2u,
        RIN_AUDIO_SERVICE_FORMAT_S16LE, 0u,
    };

    assert(rin_audio_service_shared_ring_valid(&ring));
    assert(rin_audio_service_format_valid(&format));
    assert(rin_audio_service_format_frame_bytes(&format) == 4u);

    __atomic_store_n(&ring.producer_frames, 12u, __ATOMIC_RELEASE);
    __atomic_store_n(&ring.consumer_frames, 4u, __ATOMIC_RELEASE);
    assert(rin_audio_service_shared_ring_valid(&ring));

    __atomic_store_n(&ring.consumer_frames, 0u, __ATOMIC_RELEASE);
    __atomic_store_n(&ring.producer_frames,
                     RIN_AUDIO_SERVICE_MIN_RING_FRAMES + 1u,
                     __ATOMIC_RELEASE);
    assert(!rin_audio_service_shared_ring_valid(&ring));

    ring = valid_ring();
    ring.reserved0 = 1u;
    assert(!rin_audio_service_shared_ring_valid(&ring));

    return 0;
}
