/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../include/rinruntime/cursor.h"

int main(void)
{
    const uint32_t pixels[4] = {0xff000000u, 0xffffffffu,
                                0xffffffffu, 0xff000000u};
    RinRuntimeCursorFrameV1 frame;
    RinRuntimeCursorImageV1 image;
    memset(&frame, 0, sizeof(frame));
    memset(&image, 0, sizeof(image));

    frame.struct_size = sizeof(frame);
    frame.version = RIN_RUNTIME_CURSOR_VERSION;
    frame.width = 2u;
    frame.height = 2u;
    frame.stride_bytes = 2u * sizeof(uint32_t);
    frame.hotspot_x = 1;
    frame.hotspot_y = 0;
    frame.pixels = pixels;
    assert(rinruntime_cursor_frame_validate(&frame) == RIN_RUNTIME_CURSOR_OK);

    image.struct_size = sizeof(image);
    image.version = RIN_RUNTIME_CURSOR_VERSION;
    image.frame_count = 1u;
    image.frames = &frame;
    assert(rinruntime_cursor_image_validate(&image) == RIN_RUNTIME_CURSOR_OK);

    frame.hotspot_x = 2;
    assert(rinruntime_cursor_frame_validate(&frame) ==
           RIN_RUNTIME_CURSOR_INVALID_ARGUMENT);
    frame.hotspot_x = 1;
    frame.stride_bytes = sizeof(uint32_t);
    assert(rinruntime_cursor_frame_validate(&frame) ==
           RIN_RUNTIME_CURSOR_INVALID_ARGUMENT);
    frame.stride_bytes = 2u * sizeof(uint32_t);
    frame.duration_ms = RIN_RUNTIME_CURSOR_MAX_DURATION_MS + 1u;
    assert(rinruntime_cursor_frame_validate(&frame) ==
           RIN_RUNTIME_CURSOR_INVALID_ARGUMENT);
    return 0;
}
