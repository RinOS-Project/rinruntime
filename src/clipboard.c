/* SPDX-License-Identifier: MIT */
/* Compatibility text clipboard API backed by the session clipboard owner. */

#include <rinruntime/clipboard.h>

#include <string.h>

static void clipboard_zero(void* value, uint64_t size)
{
    volatile unsigned char* bytes = (volatile unsigned char*)value;
    while (bytes != NULL && size-- != 0u) *bytes++ = 0u;
}

static int clipboard_result_valid(RinRuntimeClipboardResult result)
{
    switch (result) {
    case RINRUNTIME_CLIPBOARD_OK:
    case RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT:
    case RINRUNTIME_CLIPBOARD_NOT_FOUND:
    case RINRUNTIME_CLIPBOARD_KERNEL_REJECTED:
    case RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL:
    case RINRUNTIME_CLIPBOARD_MALFORMED_REPLY:
    case RINRUNTIME_CLIPBOARD_IO:
    case RINRUNTIME_CLIPBOARD_NO_MEMORY:
    case RINRUNTIME_CLIPBOARD_BUSY:
    case RINRUNTIME_CLIPBOARD_NOT_SUPPORTED:
    case RINRUNTIME_CLIPBOARD_LIMIT_EXCEEDED:
        return 1;
    default:
        return 0;
    }
}

RinRuntimeClipboardResult rinruntime_clipboard_set(
    uint32_t format, const void* data, uint64_t data_size,
    uint64_t* generation_out)
{
    RinRuntimeClipboardFormatInputV1 input;
    RinRuntimeClipboardResult result;
    if (generation_out != NULL) *generation_out = 0u;
    if (format != RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT ||
        data_size > RINRUNTIME_CLIPBOARD_MAX_BYTES ||
        (data_size != 0u && data == NULL))
        return RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT;
    memset(&input, 0, sizeof(input));
    input.struct_size = sizeof(input);
    input.type = RINRUNTIME_CLIPBOARD_TYPE_BYTES;
    input.mime = "text/plain";
    input.label = "Text";
    input.data = data;
    input.data_size = data_size;
    result = rinruntime_clipboard_set_formats_v1(&input, 1u, generation_out);
    memset(&input, 0, sizeof(input));
    return clipboard_result_valid(result)
        ? result : RINRUNTIME_CLIPBOARD_MALFORMED_REPLY;
}

RinRuntimeClipboardResult rinruntime_clipboard_get(
    uint32_t format, void* data, uint64_t data_capacity,
    uint64_t* required_out, uint64_t* generation_out)
{
    RinRuntimeClipboardFormatInfoV1 formats[RINRUNTIME_CLIPBOARD_MAX_FORMATS];
    uint32_t count = 0u;
    uint64_t generation = 0u;
    uint32_t format_index = UINT32_MAX;
    uint64_t required = 0u;
    if (required_out != NULL) *required_out = 0u;
    if (generation_out != NULL) *generation_out = 0u;
    if (format != RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT ||
        data_capacity > RINRUNTIME_CLIPBOARD_MAX_BYTES ||
        (data == NULL && data_capacity != 0u))
        return RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT;
    if (data != NULL) clipboard_zero(data, data_capacity);
    memset(formats, 0, sizeof(formats));
    RinRuntimeClipboardResult result = rinruntime_clipboard_query_v1(
        formats, RINRUNTIME_CLIPBOARD_MAX_FORMATS, &count, &generation);
    if (result != RINRUNTIME_CLIPBOARD_OK) {
        memset(formats, 0, sizeof(formats));
        return result;
    }
    for (uint32_t index = 0u; index < count; ++index) {
        if (formats[index].type == RINRUNTIME_CLIPBOARD_TYPE_BYTES &&
            formats[index].mime_size == sizeof("text/plain") - 1u &&
            memcmp(formats[index].mime, "text/plain",
                   sizeof("text/plain") - 1u) == 0) {
            format_index = index;
            required = formats[index].data_size;
            break;
        }
    }
    memset(formats, 0, sizeof(formats));
    if (format_index == UINT32_MAX) return RINRUNTIME_CLIPBOARD_NOT_FOUND;
    if (required_out != NULL) *required_out = required;
    if (generation_out != NULL) *generation_out = generation;
    if (required > data_capacity)
        return RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL;
    uint64_t offset = 0u;
    while (offset < required) {
        uint32_t capacity = (uint32_t)(required - offset);
        if (capacity > RINRUNTIME_CLIPBOARD_MAX_CHUNK_BYTES)
            capacity = RINRUNTIME_CLIPBOARD_MAX_CHUNK_BYTES;
        uint32_t received = 0u;
        result = rinruntime_clipboard_read_chunk_v1(
            generation, format_index, offset,
            (unsigned char*)data + (size_t)offset, capacity, &received);
        if (result != RINRUNTIME_CLIPBOARD_OK || received != capacity) {
            clipboard_zero(data, data_capacity);
            if (required_out != NULL) *required_out = 0u;
            if (generation_out != NULL) *generation_out = 0u;
            return clipboard_result_valid(result)
                ? result : RINRUNTIME_CLIPBOARD_MALFORMED_REPLY;
        }
        offset += received;
    }
    return RINRUNTIME_CLIPBOARD_OK;
}

int rin_app_clipboard_set(uint32_t format, const void* data,
                          size_t data_size, uint64_t* generation_out)
{
    return (int)rinruntime_clipboard_set(format, data,
                                         (uint64_t)data_size,
                                         generation_out);
}

int rin_app_clipboard_get(uint32_t format, void* data, size_t data_capacity,
                          uint64_t* required_out,
                          uint64_t* generation_out)
{
    if (required_out == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    return (int)rinruntime_clipboard_get(format, data,
                                         (uint64_t)data_capacity,
                                         required_out, generation_out);
}
