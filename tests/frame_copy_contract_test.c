/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <rinruntime/frame_copy.h>

static RinRuntimeFrameCopyV1 request_for(
    const void* source, uint64_t source_size, void* destination,
    uint64_t destination_size) {
    RinRuntimeFrameCopyV1 request = {0};
    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_FRAME_COPY_V1_VERSION;
    request.source = (RinSliceV1){(uint64_t)(uintptr_t)source, source_size};
    request.destination =
        (RinSliceV1){(uint64_t)(uintptr_t)destination, destination_size};
    request.width = 2u;
    request.height = 2u;
    request.source_pitch = 12u;
    request.destination_pitch = 12u;
    request.source_format = RINRUNTIME_FRAME_PIXEL_RGBA8;
    request.destination_format = RINRUNTIME_FRAME_PIXEL_BGRA8;
    return request;
}

static void assert_unchanged(const uint8_t* bytes, uint8_t value,
                            uint32_t size) {
    for (uint32_t index = 0u; index < size; ++index)
        assert(bytes[index] == value);
}

int main(void) {
    const uint8_t source[24] = {
        1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 0xeeu, 0xeeu, 0xeeu, 0xeeu,
        9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u, 0xeeu, 0xeeu, 0xeeu, 0xeeu
    };
    uint8_t destination[24];
    RinRuntimeFrameCopyV1 request;

    memset(destination, 0xa5, sizeof(destination));
    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    assert(rinruntime_frame_copy_v1(&request) == RIN_RESULT_OK);
    assert(memcmp(destination, (const uint8_t[]){
        3u, 2u, 1u, 4u, 7u, 6u, 5u, 8u, 0u, 0u, 0u, 0u,
        11u, 10u, 9u, 12u, 15u, 14u, 13u, 16u,
        0xa5u, 0xa5u, 0xa5u, 0xa5u
    }, sizeof(destination)) == 0);

    memset(destination, 0xa5, sizeof(destination));
    request = request_for(source, 19u, destination,
                          sizeof(destination));
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_BUFFER_TOO_SMALL);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination, 19u);
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_BUFFER_TOO_SMALL);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.destination_pitch = 7u;
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_BUFFER_TOO_SMALL);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.destination_format = UINT32_MAX;
    assert(rinruntime_frame_copy_v1(&request) == RIN_RESULT_NOT_SUPPORTED);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.version++;
    assert(rinruntime_frame_copy_v1(&request) == RIN_RESULT_VERSION_MISMATCH);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.reserved[1] = 1u;
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_INVALID_ARGUMENT);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.width = UINT32_MAX / 4u + 1u;
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_INVALID_ARGUMENT);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.destination.address = request.source.address + 4u;
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_INVALID_ARGUMENT);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.source.address = (uint64_t)(UINTPTR_MAX - 3u);
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_INVALID_ARGUMENT);
    assert_unchanged(destination, 0xa5u, sizeof(destination));

    request = request_for(source, sizeof(source), destination,
                          sizeof(destination));
    request.destination.address = (uint64_t)(uintptr_t)&request;
    assert(rinruntime_frame_copy_v1(&request) ==
           RIN_RESULT_INVALID_ARGUMENT);

    return 0;
}
