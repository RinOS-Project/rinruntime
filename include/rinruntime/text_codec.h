/* SPDX-License-Identifier: MIT */
/* Bounded, allocation-free text validation and legacy decoding helpers. */

#ifndef RINRUNTIME_TEXT_CODEC_H
#define RINRUNTIME_TEXT_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RinRuntimeTextCodecResult {
    RINRUNTIME_TEXT_CODEC_OK = 0,
    RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT = -1,
    RINRUNTIME_TEXT_CODEC_INVALID_UTF8 = -2,
    RINRUNTIME_TEXT_CODEC_CONTAINS_NUL = -3,
    RINRUNTIME_TEXT_CODEC_OUTPUT_TOO_SMALL = -4
} RinRuntimeTextCodecResult;

static inline int rinruntime_text_codec_append_utf8(
    uint32_t codepoint, char* output, size_t capacity, size_t* offset)
{
    char bytes[4];
    size_t count;
    size_t index;
    if (output == NULL || offset == NULL || *offset > capacity)
        return RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT;
    if (codepoint <= 0x7fu) {
        bytes[0] = (char)codepoint;
        count = 1u;
    } else if (codepoint <= 0x7ffu) {
        bytes[0] = (char)(0xc0u | (codepoint >> 6));
        bytes[1] = (char)(0x80u | (codepoint & 0x3fu));
        count = 2u;
    } else if (codepoint <= 0xffffu &&
               !(codepoint >= 0xd800u && codepoint <= 0xdfffu)) {
        bytes[0] = (char)(0xe0u | (codepoint >> 12));
        bytes[1] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
        bytes[2] = (char)(0x80u | (codepoint & 0x3fu));
        count = 3u;
    } else if (codepoint <= 0x10ffffu) {
        bytes[0] = (char)(0xf0u | (codepoint >> 18));
        bytes[1] = (char)(0x80u | ((codepoint >> 12) & 0x3fu));
        bytes[2] = (char)(0x80u | ((codepoint >> 6) & 0x3fu));
        bytes[3] = (char)(0x80u | (codepoint & 0x3fu));
        count = 4u;
    } else {
        return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
    }
    if (count > capacity - *offset || count == capacity - *offset)
        return RINRUNTIME_TEXT_CODEC_OUTPUT_TOO_SMALL;
    for (index = 0u; index < count; ++index)
        output[(*offset)++] = bytes[index];
    output[*offset] = '\0';
    return RINRUNTIME_TEXT_CODEC_OK;
}

static inline RinRuntimeTextCodecResult rinruntime_text_utf8_validate(
    const uint8_t* data, size_t size)
{
    size_t offset = 0u;
    if (data == NULL && size != 0u)
        return RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT;
    while (offset < size) {
        const uint8_t first = data[offset++];
        uint32_t codepoint;
        size_t continuation;
        size_t index;
        if (first == 0u) return RINRUNTIME_TEXT_CODEC_CONTAINS_NUL;
        if (first < 0x80u) continue;
        if (first >= 0xc2u && first <= 0xdfu) {
            codepoint = first & 0x1fu;
            continuation = 1u;
        } else if (first >= 0xe0u && first <= 0xefu) {
            codepoint = first & 0x0fu;
            continuation = 2u;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            codepoint = first & 0x07u;
            continuation = 3u;
        } else {
            return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
        }
        if (continuation > size - offset)
            return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
        for (index = 0u; index < continuation; ++index) {
            const uint8_t next = data[offset++];
            if ((next & 0xc0u) != 0x80u)
                return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
            codepoint = (codepoint << 6) | (next & 0x3fu);
        }
        if ((continuation == 1u && codepoint < 0x80u) ||
            (continuation == 2u && codepoint < 0x800u) ||
            (continuation == 3u && codepoint < 0x10000u) ||
            codepoint > 0x10ffffu ||
            (codepoint >= 0xd800u && codepoint <= 0xdfffu))
            return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
    }
    return RINRUNTIME_TEXT_CODEC_OK;
}

static inline uint16_t rinruntime_text_codec_u16(
    const uint8_t* bytes, int little_endian)
{
    return little_endian
               ? (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8)
               : ((uint16_t)bytes[0] << 8) | (uint16_t)bytes[1];
}

/* Decode UTF-16 bytes to strict UTF-8.  A leading matching BOM is consumed;
 * output_size excludes the trailing NUL, while capacity includes it. */
static inline RinRuntimeTextCodecResult rinruntime_text_utf16_to_utf8(
    const uint8_t* data, size_t size, int little_endian, char* output,
    size_t capacity, size_t* output_size)
{
    size_t offset = 0u;
    size_t written = 0u;
    if (output_size != NULL) *output_size = 0u;
    if ((data == NULL && size != 0u) || output == NULL || output_size == NULL ||
        capacity == 0u || (size & 1u) != 0u)
        return RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT;
    output[0] = '\0';
    if (size >= 2u && rinruntime_text_codec_u16(data, little_endian) == 0xfeffu)
        offset = 2u;
    while (offset < size) {
        uint16_t unit = rinruntime_text_codec_u16(data + offset, little_endian);
        uint32_t codepoint;
        offset += 2u;
        if (unit == 0u) return RINRUNTIME_TEXT_CODEC_CONTAINS_NUL;
        if (unit >= 0xd800u && unit <= 0xdbffu) {
            uint16_t low;
            if (offset >= size) return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
            low = rinruntime_text_codec_u16(data + offset, little_endian);
            if (low < 0xdc00u || low > 0xdfffu)
                return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
            offset += 2u;
            codepoint = 0x10000u +
                        (((uint32_t)unit - 0xd800u) << 10) +
                        ((uint32_t)low - 0xdc00u);
        } else if (unit >= 0xdc00u && unit <= 0xdfffu) {
            return RINRUNTIME_TEXT_CODEC_INVALID_UTF8;
        } else {
            codepoint = unit;
        }
        if (rinruntime_text_codec_append_utf8(codepoint, output, capacity,
                                              &written) !=
            RINRUNTIME_TEXT_CODEC_OK) {
            *output_size = 0u;
            output[0] = '\0';
            return RINRUNTIME_TEXT_CODEC_OUTPUT_TOO_SMALL;
        }
    }
    *output_size = written;
    return RINRUNTIME_TEXT_CODEC_OK;
}

/* Decode ISO-8859-1 bytes to strict UTF-8.  NUL is rejected as a document
 * terminator rather than copied into the output. */
static inline RinRuntimeTextCodecResult rinruntime_text_latin1_to_utf8(
    const uint8_t* data, size_t size, char* output, size_t capacity,
    size_t* output_size)
{
    size_t index;
    size_t written = 0u;
    if (output_size != NULL) *output_size = 0u;
    if ((data == NULL && size != 0u) || output == NULL || output_size == NULL ||
        capacity == 0u) return RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT;
    output[0] = '\0';
    for (index = 0u; index < size; ++index) {
        const uint8_t byte = data[index];
        const uint32_t codepoint = byte;
        if (byte == 0u) return RINRUNTIME_TEXT_CODEC_CONTAINS_NUL;
        if (rinruntime_text_codec_append_utf8(codepoint, output, capacity,
                                              &written) !=
            RINRUNTIME_TEXT_CODEC_OK) {
            *output_size = 0u;
            output[0] = '\0';
            return RINRUNTIME_TEXT_CODEC_OUTPUT_TOO_SMALL;
        }
    }
    *output_size = written;
    return RINRUNTIME_TEXT_CODEC_OK;
}

/* Encode strict UTF-8 as UTF-16LE/BE.  output_size is the number of bytes
 * written and capacity is measured in bytes; no terminator is emitted. */
static inline RinRuntimeTextCodecResult rinruntime_text_utf8_to_utf16(
    const uint8_t* data, size_t size, int little_endian, uint8_t* output,
    size_t capacity, size_t* output_size)
{
    size_t offset = 0u;
    size_t written = 0u;
    RinRuntimeTextCodecResult validation;
    if (output_size != NULL) *output_size = 0u;
    if ((data == NULL && size != 0u) || output == NULL || output_size == NULL ||
        capacity == 0u || (little_endian != 0 && little_endian != 1))
        return RINRUNTIME_TEXT_CODEC_INVALID_ARGUMENT;
    validation = rinruntime_text_utf8_validate(data, size);
    if (validation != RINRUNTIME_TEXT_CODEC_OK) return validation;
    while (offset < size) {
        const uint8_t first = data[offset++];
        uint32_t codepoint;
        size_t continuation;
        size_t index;
        if (first < 0x80u) {
            codepoint = first;
            continuation = 0u;
        } else if (first <= 0xdfu) {
            codepoint = first & 0x1fu;
            continuation = 1u;
        } else if (first <= 0xefu) {
            codepoint = first & 0x0fu;
            continuation = 2u;
        } else {
            codepoint = first & 0x07u;
            continuation = 3u;
        }
        for (index = 0u; index < continuation; ++index)
            codepoint = (codepoint << 6) | (data[offset++] & 0x3fu);

        uint32_t units = codepoint <= 0xffffu ? 1u : 2u;
        size_t byte_count = units * 2u;
        if (written > capacity || byte_count > capacity - written) {
            *output_size = 0u;
            return RINRUNTIME_TEXT_CODEC_OUTPUT_TOO_SMALL;
        }
        uint16_t first_unit;
        if (units == 1u) {
            first_unit = (uint16_t)codepoint;
        } else {
            codepoint -= 0x10000u;
            first_unit = (uint16_t)(0xd800u | (codepoint >> 10));
        }
        uint16_t values[2] = { first_unit, 0u };
        if (units == 2u)
            values[1] = (uint16_t)(0xdc00u | (codepoint & 0x3ffu));
        for (index = 0u; index < units; ++index) {
            uint16_t value = values[index];
            if (little_endian) {
                output[written++] = (uint8_t)value;
                output[written++] = (uint8_t)(value >> 8);
            } else {
                output[written++] = (uint8_t)(value >> 8);
                output[written++] = (uint8_t)value;
            }
        }
    }
    *output_size = written;
    return RINRUNTIME_TEXT_CODEC_OK;
}

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_TEXT_CODEC_H */


