/* SPDX-License-Identifier: MIT */

#include "rin_cursor.h"

#include <rinruntime/wincompat_image_bmp.h>
#include <rinpng/rpng.h>
#include "rinruntime/cursor.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define CUR_HEADER_SIZE 6u
#define CUR_ENTRY_SIZE 16u
#define PNG_SIGNATURE_SIZE 8u
#define ANI_MAX_RATES RIN_CURSOR_MAX_FRAMES

static uint16_t read_u16(const uint8_t* bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8u));
}

static uint32_t read_u32(const uint8_t* bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8u) |
           ((uint32_t)bytes[2] << 16u) |
           ((uint32_t)bytes[3] << 24u);
}

static int range_valid(size_t offset, size_t length, size_t total) {
    return offset <= total && length <= total - offset;
}

static int add_size(size_t left, size_t right, size_t* result) {
    if (!result || right > SIZE_MAX - left) return 0;
    *result = left + right;
    return 1;
}

static int mul_size(size_t left, size_t right, size_t* result) {
    if (!result || (left != 0u && right > SIZE_MAX / left)) return 0;
    *result = left * right;
    return 1;
}

static void clear_image(RinCursorImage* image) {
    if (!image) return;
    image->frame_count = 0u;
    image->frames = NULL;
}

/* CUR/ANI parsing and pixel ownership are private, but every decoded frame
 * must satisfy the public backend-independent cursor contract before it is
 * exposed to a compositor or another owner. */
int rin_cursor_frame_export_runtime(
    const RinCursorFrame* frame,
    RinRuntimeCursorFrameV1* output)
{
    if (output == NULL) return 0;
    memset(output, 0, sizeof(*output));
    if (frame == NULL) return 0;
    output->struct_size = sizeof(*output);
    output->version = RIN_RUNTIME_CURSOR_VERSION;
    output->width = frame->width;
    output->height = frame->height;
    output->stride_bytes = frame->pitch;
    output->hotspot_x = frame->hotspot_x;
    output->hotspot_y = frame->hotspot_y;
    output->duration_ms = frame->duration_ms;
    output->pixels = frame->pixels;
    if (rinruntime_cursor_frame_validate(output) != RIN_RUNTIME_CURSOR_OK) {
        memset(output, 0, sizeof(*output));
        return 0;
    }
    return 1;
}

int rin_cursor_image_export_runtime_view(
    const RinCursorImage* image,
    RinRuntimeCursorFrameV1* frames,
    uint32_t frame_capacity,
    RinRuntimeCursorImageV1* output)
{
    uint32_t index;
    if (output == NULL) return 0;
    memset(output, 0, sizeof(*output));
    if (image == NULL || image->frame_count == 0u ||
        image->frame_count > RIN_RUNTIME_CURSOR_MAX_FRAMES ||
        image->frames == NULL || frames == NULL ||
        frame_capacity < image->frame_count)
        return 0;
    for (index = 0u; index < image->frame_count; ++index) {
        if (!rin_cursor_frame_export_runtime(&image->frames[index],
                                             &frames[index])) {
            memset(frames, 0,
                   (size_t)image->frame_count * sizeof(*frames));
            return 0;
        }
    }
    output->struct_size = sizeof(*output);
    output->version = RIN_RUNTIME_CURSOR_VERSION;
    output->frame_count = image->frame_count;
    output->frames = frames;
    if (rinruntime_cursor_image_validate(output) != RIN_RUNTIME_CURSOR_OK) {
        memset(frames, 0,
               (size_t)image->frame_count * sizeof(*frames));
        memset(output, 0, sizeof(*output));
        return 0;
    }
    return 1;
}

void rin_cursor_destroy(RinCursorImage* image) {
    uint32_t index;
    if (!image) return;
    if (image->frames) {
        for (index = 0u; index < image->frame_count; ++index)
            free(image->frames[index].pixels);
        free(image->frames);
    }
    clear_image(image);
}

static int dimensions_valid(uint32_t width, uint32_t height) {
    uint64_t pixels = (uint64_t)width * (uint64_t)height;
    return width != 0u && height != 0u &&
           width <= RIN_CURSOR_MAX_DIMENSION &&
           height <= RIN_CURSOR_MAX_DIMENSION &&
           pixels <= RIN_CURSOR_MAX_PIXELS;
}

static int png_signature(const uint8_t* data, size_t size) {
    static const uint8_t signature[PNG_SIGNATURE_SIZE] = {
        0x89u, 'P', 'N', 'G', '\r', '\n', 0x1au, '\n'
    };
    return size >= PNG_SIGNATURE_SIZE &&
           memcmp(data, signature, sizeof(signature)) == 0;
}

/* A few ANI producers emit the legacy 1-bit AND plane byte-packed rather
 * than DWORD-padded and leave the DIB size field as the meaningful extent.
 * Keep the strict WinCompat decoder as the first path, then accept this
 * documented cursor-only layout with the same dimension and allocation caps. */
static int decode_relaxed_icon_dib(const uint8_t* data, size_t size,
                                   uint32_t expected_width,
                                   uint32_t expected_height,
                                   uint32_t* pixels) {
    uint32_t width;
    uint32_t encoded_height;
    uint32_t height;
    uint64_t xor_bytes;
    uint64_t mask_stride;
    uint64_t mask_bytes;
    int has_alpha = 0;
    uint32_t x;
    uint32_t y;
    const uint8_t* xor_pixels;
    const uint8_t* and_mask;
    if (!data || !pixels || size < 40u || read_u32(data) != 40u ||
        read_u16(data + 12u) != 1u || read_u16(data + 14u) != 32u ||
        read_u32(data + 16u) != 0u)
        return 0;
    width = read_u32(data + 4u);
    encoded_height = read_u32(data + 8u);
    if (width != expected_width || encoded_height == 0u ||
        (encoded_height & 1u) != 0u)
        return 0;
    height = encoded_height / 2u;
    if (height != expected_height) return 0;
    xor_bytes = (uint64_t)width * height * 4u;
    mask_stride = ((uint64_t)width + 7u) / 8u;
    mask_bytes = mask_stride * height;
    if (!dimensions_valid(width, height) || xor_bytes > SIZE_MAX - 40u ||
        mask_bytes > SIZE_MAX - (40u + (size_t)xor_bytes) ||
        !range_valid(40u, (size_t)xor_bytes + (size_t)mask_bytes, size))
        return 0;
    xor_pixels = data + 40u;
    and_mask = xor_pixels + (size_t)xor_bytes;
    for (y = 0u; y < height && !has_alpha; ++y) {
        const uint8_t* row = xor_pixels + (size_t)y * width * 4u;
        for (x = 0u; x < width; ++x)
            if (row[x * 4u + 3u] != 0u) has_alpha = 1;
    }
    for (y = 0u; y < height; ++y) {
        const uint8_t* xor_row = xor_pixels + (size_t)y * width * 4u;
        const uint8_t* mask_row = and_mask + (size_t)y * mask_stride;
        for (x = 0u; x < width; ++x) {
            const uint8_t* pixel = xor_row + x * 4u;
            uint32_t alpha = pixel[3];
            if (!has_alpha)
                alpha = ((mask_row[x / 8u] >> (7u - (x & 7u))) & 1u) ?
                            0u : 255u;
            pixels[(size_t)(height - 1u - y) * width + x] =
                (alpha << 24u) | ((uint32_t)pixel[2] << 16u) |
                ((uint32_t)pixel[1] << 8u) | pixel[0];
        }
    }
    return 1;
}

static int decode_payload(const uint8_t* data, size_t size,
                          uint32_t expected_width, uint32_t expected_height,
                          RinCursorFrame* frame) {
    uint32_t* pixels;
    uint64_t pixel_count;
    size_t pixel_bytes;
    int width;
    int height;

    if (!data || !frame || !dimensions_valid(expected_width, expected_height) ||
        size == 0u || size > RIN_CURSOR_MAX_FILE_BYTES)
        return 0;
    pixel_count = (uint64_t)expected_width * (uint64_t)expected_height;
    if (pixel_count > SIZE_MAX / sizeof(*pixels)) return 0;
    pixel_bytes = (size_t)pixel_count * sizeof(*pixels);
    pixels = (uint32_t*)malloc(pixel_bytes);
    if (!pixels) return 0;

    if (png_signature(data, size)) {
        if (rpng_get_info(data, size, &width, &height) != RPNG_OK ||
            width != (int)expected_width || height != (int)expected_height ||
            rpng_decode_rgba(data, size, pixels, width, height) != RPNG_OK) {
            free(pixels);
            return 0;
        }
    } else {
        WincompatImageBitmap* bitmap =
            wincompat_image_decode_icon_dib(data, size);
        if (!bitmap && decode_relaxed_icon_dib(data, size, expected_width,
                                               expected_height, pixels)) {
            frame->width = expected_width;
            frame->height = expected_height;
            frame->pitch = expected_width * (uint32_t)sizeof(*pixels);
            frame->pixels = pixels;
            if (rin_cursor_frame_export_runtime(frame, &(RinRuntimeCursorFrameV1){0}))
                return 1;
            free(frame->pixels);
            frame->pixels = NULL;
            return 0;
        }
        if (!bitmap || bitmap->width != (int)expected_width ||
            bitmap->height != (int)expected_height ||
            bitmap->bits_per_pixel != 32 || bitmap->pixel_size != pixel_bytes) {
            wincompat_image_bitmap_discard(bitmap);
            free(pixels);
            return 0;
        }
        memcpy(pixels, bitmap->pixels, pixel_bytes);
        wincompat_image_bitmap_discard(bitmap);
    }
    frame->width = expected_width;
    frame->height = expected_height;
    frame->pitch = expected_width * (uint32_t)sizeof(*pixels);
    frame->pixels = pixels;
    return 1;
}

static int cursor_entry_dimensions(const uint8_t* entry,
                                   uint32_t* width_out,
                                   uint32_t* height_out) {
    uint32_t width = entry[0] == 0u ? 256u : entry[0];
    uint32_t height = entry[1] == 0u ? 256u : entry[1];
    if (!dimensions_valid(width, height) || !width_out || !height_out)
        return 0;
    *width_out = width;
    *height_out = height;
    return 1;
}

/* Load one ICO/CUR container.  ICO is accepted for ANI's embedded icon form;
 * CUR carries the hotspot in each directory entry while ICO defaults to 0,0. */
static int load_container(const uint8_t* data, size_t size, int allow_ico,
                          RinCursorImage* image_out) {
    uint16_t type;
    uint16_t count;
    size_t directory_size;
    size_t directory_end;
    uint32_t best_index = UINT32_MAX;
    uint64_t best_distance = UINT64_MAX;
    uint32_t index;
    RinCursorFrame frame;

    if (!data || !image_out || size < CUR_HEADER_SIZE ||
        size > RIN_CURSOR_MAX_FILE_BYTES)
        return 0;
    type = read_u16(data + 2u);
    if (read_u16(data) != 0u || (type != 2u && !(allow_ico && type == 1u)))
        return 0;
    count = read_u16(data + 4u);
    if (count == 0u || count > RIN_CURSOR_MAX_FRAMES ||
        !mul_size((size_t)count, CUR_ENTRY_SIZE, &directory_size) ||
        !add_size(CUR_HEADER_SIZE, directory_size, &directory_end) ||
        !range_valid(CUR_HEADER_SIZE, directory_size, size))
        return 0;

    /* Prefer the native 32px entry, then the nearest bounded resolution. */
    for (index = 0u; index < count; ++index) {
        const uint8_t* entry = data + CUR_HEADER_SIZE +
                               (size_t)index * CUR_ENTRY_SIZE;
        uint32_t width;
        uint32_t height;
        uint64_t dx;
        uint64_t dy;
        uint64_t distance;
        if (!cursor_entry_dimensions(entry, &width, &height)) continue;
        dx = width > 32u ? width - 32u : 32u - width;
        dy = height > 32u ? height - 32u : 32u - height;
        distance = dx + dy;
        if (best_index == UINT32_MAX || distance < best_distance) {
            best_index = index;
            best_distance = distance;
        }
    }
    if (best_index == UINT32_MAX) return 0;
    {
        const uint8_t* entry = data + CUR_HEADER_SIZE +
                               (size_t)best_index * CUR_ENTRY_SIZE;
        uint32_t width;
        uint32_t height;
        uint32_t payload_size = read_u32(entry + 8u);
        uint32_t payload_offset = read_u32(entry + 12u);
        if (!cursor_entry_dimensions(entry, &width, &height) ||
            payload_size == 0u || payload_size > RIN_CURSOR_MAX_FILE_BYTES ||
            payload_offset < directory_end ||
            !range_valid((size_t)payload_offset, (size_t)payload_size, size))
            return 0;
        memset(&frame, 0, sizeof(frame));
        if (!decode_payload(data + payload_offset, payload_size, width, height,
                            &frame))
            return 0;
        if (type == 2u) {
            frame.hotspot_x = (int32_t)read_u16(entry + 4u);
            frame.hotspot_y = (int32_t)read_u16(entry + 6u);
            if ((uint32_t)frame.hotspot_x >= width ||
                (uint32_t)frame.hotspot_y >= height) {
                free(frame.pixels);
                return 0;
            }
        }
        if (!rin_cursor_frame_export_runtime(&frame,
                                             &(RinRuntimeCursorFrameV1){0})) {
            free(frame.pixels);
            return 0;
        }
        image_out->frames = (RinCursorFrame*)calloc(1u, sizeof(frame));
        if (!image_out->frames) {
            free(frame.pixels);
            return 0;
        }
        image_out->frames[0] = frame;
        image_out->frame_count = 1u;
    }
    return 1;
}

int rin_cursor_load_cur(const void* data, size_t size,
                        RinCursorImage* image_out) {
    if (!image_out) return 0;
    clear_image(image_out);
    return load_container((const uint8_t*)data, size, 0, image_out);
}

typedef struct AniFrameRef {
    const uint8_t* data;
    size_t size;
} AniFrameRef;

static int ani_duration(uint32_t rate, uint32_t* duration_out) {
    uint64_t milliseconds;
    if (!duration_out || rate == 0u || rate > UINT32_MAX / 1000u) return 0;
    /* ANI rates are 1/60 second ticks. */
    milliseconds = ((uint64_t)rate * 1000u + 59u) / 60u;
    if (milliseconds == 0u || milliseconds > UINT32_MAX) return 0;
    *duration_out = (uint32_t)milliseconds;
    return 1;
}

int rin_cursor_load_ani(const void* data, size_t size,
                        RinCursorImage* image_out) {
    const uint8_t* bytes = (const uint8_t*)data;
    AniFrameRef refs[RIN_CURSOR_MAX_FRAMES] = {};
    uint32_t rates[ANI_MAX_RATES] = {};
    uint32_t sequence[RIN_CURSOR_MAX_FRAMES] = {};
    uint32_t frame_count = 0u;
    uint32_t rate_count = 0u;
    uint32_t sequence_count = 0u;
    uint32_t declared_frames = 0u;
    uint32_t declared_steps = 0u;
    uint32_t display_rate = 0u;
    size_t position;
    uint32_t index;
    int have_anih = 0;
    int have_frames = 0;

    if (!image_out) return 0;
    clear_image(image_out);
    if (!bytes || size < 12u || size > RIN_CURSOR_MAX_FILE_BYTES ||
        memcmp(bytes, "RIFF", 4u) != 0 || memcmp(bytes + 8u, "ACON", 4u) != 0 ||
        read_u32(bytes + 4u) != (uint32_t)(size - 8u))
        return 0;

    position = 12u;
    while (position < size) {
        const uint8_t* chunk;
        uint32_t chunk_size;
        size_t data_end;
        size_t padded_size;
        if (!range_valid(position, 8u, size)) return 0;
        chunk = bytes + position;
        chunk_size = read_u32(chunk + 4u);
        if (!add_size(position, 8u, &data_end) ||
            !range_valid(data_end, chunk_size, size) ||
            !add_size((size_t)chunk_size, chunk_size & 1u, &padded_size) ||
            !range_valid(data_end, padded_size, size))
            return 0;
        if (memcmp(chunk, "anih", 4u) == 0) {
            if (chunk_size != 36u || read_u32(bytes + data_end) != 36u)
                return 0;
            declared_frames = read_u32(bytes + data_end + 4u);
            declared_steps = read_u32(bytes + data_end + 8u);
            display_rate = read_u32(bytes + data_end + 28u);
            if (declared_frames == 0u || declared_frames > RIN_CURSOR_MAX_FRAMES ||
                declared_steps == 0u || declared_steps > RIN_CURSOR_MAX_FRAMES ||
                display_rate == 0u)
                return 0;
            have_anih = 1;
        } else if (memcmp(chunk, "rate", 4u) == 0) {
            if (chunk_size == 0u || (chunk_size % 4u) != 0u ||
                chunk_size / 4u > ANI_MAX_RATES)
                return 0;
            rate_count = chunk_size / 4u;
            for (index = 0u; index < rate_count; ++index) {
                rates[index] = read_u32(bytes + data_end + index * 4u);
                if (rates[index] == 0u) return 0;
            }
        } else if (memcmp(chunk, "seq ", 4u) == 0) {
            if (chunk_size == 0u || (chunk_size % 4u) != 0u ||
                chunk_size / 4u > RIN_CURSOR_MAX_FRAMES)
                return 0;
            sequence_count = chunk_size / 4u;
            for (index = 0u; index < sequence_count; ++index)
                sequence[index] = read_u32(bytes + data_end + index * 4u);
        } else if (memcmp(chunk, "LIST", 4u) == 0) {
            size_t list_position;
            if (chunk_size < 4u || memcmp(bytes + data_end, "fram", 4u) != 0)
                return 0;
            list_position = data_end + 4u;
            while (list_position < data_end + chunk_size) {
                const uint8_t* child;
                uint32_t child_size;
                size_t child_data;
                size_t child_padded;
                size_t list_end = data_end + chunk_size;
                if (!range_valid(list_position, 8u, list_end)) return 0;
                child = bytes + list_position;
                child_size = read_u32(child + 4u);
                if (!add_size(list_position, 8u, &child_data) ||
                    !range_valid(child_data, child_size, list_end) ||
                    !add_size((size_t)child_size, child_size & 1u,
                              &child_padded) ||
                    !range_valid(child_data, child_padded, list_end))
                    return 0;
                if (memcmp(child, "icon", 4u) == 0) {
                    if (frame_count >= RIN_CURSOR_MAX_FRAMES || child_size == 0u)
                        return 0;
                    refs[frame_count].data = bytes + child_data;
                    refs[frame_count].size = child_size;
                    ++frame_count;
                }
                list_position = child_data + child_padded;
            }
            if (list_position != data_end + chunk_size) return 0;
            have_frames = 1;
        }
        position = data_end + padded_size;
    }
    if (!have_anih || !have_frames || frame_count == 0u ||
        frame_count != declared_frames || declared_steps == 0u ||
        (sequence_count != 0u && sequence_count != declared_steps) ||
        (rate_count != 0u && rate_count != declared_steps))
        return 0;
    if (sequence_count == 0u) {
        sequence_count = declared_steps;
        for (index = 0u; index < sequence_count; ++index) sequence[index] = index;
    }
    if (rate_count == 0u) {
        for (index = 0u; index < declared_steps; ++index) rates[index] = display_rate;
        rate_count = declared_steps;
    }
    image_out->frames = (RinCursorFrame*)calloc(
        declared_steps, sizeof(*image_out->frames));
    if (!image_out->frames) return 0;
    image_out->frame_count = declared_steps;
    for (index = 0u; index < declared_steps; ++index) {
        RinCursorImage decoded = {};
        uint32_t source_index = sequence[index];
        uint32_t duration;
        if (source_index >= frame_count ||
            !load_container(refs[source_index].data, refs[source_index].size,
                             1, &decoded) || decoded.frame_count != 1u ||
            !ani_duration(rates[index], &duration)) {
            rin_cursor_destroy(&decoded);
            rin_cursor_destroy(image_out);
            return 0;
        }
        image_out->frames[index] = decoded.frames[0];
        image_out->frames[index].duration_ms = duration;
        if (!rin_cursor_frame_export_runtime(
                &image_out->frames[index], &(RinRuntimeCursorFrameV1){0})) {
            free(image_out->frames[index].pixels);
            image_out->frames[index].pixels = NULL;
            free(decoded.frames);
            decoded.frames = NULL;
            decoded.frame_count = 0u;
            rin_cursor_destroy(image_out);
            return 0;
        }
        free(decoded.frames);
        decoded.frames = NULL;
        decoded.frame_count = 0u;
    }
    return 1;
}
