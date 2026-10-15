/* SPDX-License-Identifier: MIT */
/* Shared decoded cursor image model and bounded CUR/ANI loaders. */
#ifndef RINOS_CURSOR_H
#define RINOS_CURSOR_H

#include <stddef.h>
#include <stdint.h>

#include "rinruntime/cursor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_CURSOR_MAX_FRAMES 32u
#define RIN_CURSOR_MAX_DIMENSION 256u
#define RIN_CURSOR_MAX_PIXELS \
    (RIN_CURSOR_MAX_DIMENSION * RIN_CURSOR_MAX_DIMENSION)
#define RIN_CURSOR_MAX_FILE_BYTES (4u * 1024u * 1024u)
#define RIN_CURSOR_DEFAULT_DURATION_MS 60u
#define RIN_CURSOR_DEFAULT_THEME_ROOT "/res/cursors/"

/* Pixels are 0xAARRGGBB values, which are BGRA bytes in memory. */
typedef struct RinCursorFrame {
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    int32_t hotspot_x;
    int32_t hotspot_y;
    uint32_t duration_ms;
    uint32_t* pixels;
} RinCursorFrame;

typedef struct RinCursorImage {
    uint32_t frame_count;
    RinCursorFrame* frames;
} RinCursorImage;

int rin_cursor_load_cur(const void* data, size_t size,
                        RinCursorImage* image_out);
int rin_cursor_load_ani(const void* data, size_t size,
                        RinCursorImage* image_out);
void rin_cursor_destroy(RinCursorImage* image);

/* Convert the private decoded representation to a borrowed public runtime
 * view.  The public view owns neither the frame nor its pixels; the private
 * image must remain alive until all users stop reading the view. */
int rin_cursor_frame_export_runtime(
    const RinCursorFrame* frame,
    RinRuntimeCursorFrameV1* output);
int rin_cursor_image_export_runtime_view(
    const RinCursorImage* image,
    RinRuntimeCursorFrameV1* frames,
    uint32_t frame_capacity,
    RinRuntimeCursorImageV1* output);

#ifdef __cplusplus
}
#endif

#endif /* RINOS_CURSOR_H */
