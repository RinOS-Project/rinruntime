#ifndef RINRUNTIME_CI_CONSUMER_FRAME_COPY_H
#define RINRUNTIME_CI_CONSUMER_FRAME_COPY_H

#include <stdint.h>
#include <rinruntime/frame_copy.h>

static int rinruntime_ci_frame_copy(void)
{
    uint8_t source[4] = {3u, 2u, 1u, 255u};
    uint8_t destination[4] = {0u, 0u, 0u, 0u};
    RinRuntimeFrameCopyV1 request = {0};
    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_FRAME_COPY_V1_VERSION;
    request.source.address = (uint64_t)(uintptr_t)source;
    request.source.size = sizeof(source);
    request.destination.address = (uint64_t)(uintptr_t)destination;
    request.destination.size = sizeof(destination);
    request.width = 1u;
    request.height = 1u;
    request.source_pitch = 4u;
    request.destination_pitch = 4u;
    request.source_format = RINRUNTIME_FRAME_PIXEL_BGRA8;
    request.destination_format = RINRUNTIME_FRAME_PIXEL_RGBA8;
    if (rinruntime_frame_copy_v1(&request) != RIN_RESULT_OK) return 1;
    return destination[0] != 1u || destination[1] != 2u ||
           destination[2] != 3u || destination[3] != 255u;
}

#endif
