// SPDX-License-Identifier: MIT

#ifndef RIN_WINCOMPAT_IMAGE_BMP_H
#define RIN_WINCOMPAT_IMAGE_BMP_H

#include <stddef.h>
#include <stdint.h>

#define WINCOMPAT_IMAGE_MAX_DIMENSION 8192u
#define WINCOMPAT_IMAGE_MAX_PIXELS 16777216u
#define WINCOMPAT_IMAGE_MAX_FILE_BYTES (256u * 1024u * 1024u)

typedef struct WincompatImageBitmap {
    int width;
    int height;
    int bits_per_pixel;
    uint32_t* pixels;
    size_t pixel_size;
} WincompatImageBitmap;

typedef enum WincompatImageScaleStatus {
    WINCOMPAT_IMAGE_SCALE_OK = 0,
    WINCOMPAT_IMAGE_SCALE_INVALID = -1,
    WINCOMPAT_IMAGE_SCALE_NO_MEMORY = -2
} WincompatImageScaleStatus;

WincompatImageBitmap* wincompat_image_decode_bmp(const uint8_t* data,
                                                 size_t size);
WincompatImageBitmap* wincompat_image_decode_dib(const uint8_t* data,
                                                 size_t size);
/* Decodes the 32-bit XOR/AND DIB payload used by a single RT_ICON or
 * RT_CURSOR image.  The caller supplies the raw image bytes, not an .ico
 * file header or group directory. */
WincompatImageBitmap* wincompat_image_decode_icon_dib(const uint8_t* data,
                                                      size_t size);
/* Replaces a valid decoded 32-bit bitmap with a nearest-neighbour scaled
 * version. On failure the bitmap, including its pixel ownership, is unchanged. */
WincompatImageScaleStatus wincompat_image_bitmap_scale_nearest(
    WincompatImageBitmap* bitmap, uint32_t width, uint32_t height);
void wincompat_image_bitmap_discard(WincompatImageBitmap* bitmap);

#endif
