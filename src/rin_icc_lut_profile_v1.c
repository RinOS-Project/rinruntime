/* SPDX-License-Identifier: MIT */
#include "rin_icc_lut_profile_v1.h"

#include <stdint.h>

#define ICC_HEADER_SIZE 128u
#define ICC_TAG_TABLE_OFFSET 128u
#define ICC_TAG_ENTRY_SIZE 12u
#define ICC_TAG_TABLE_PREFIX_SIZE 4u
#define ICC_SIG(a, b, c, d) \
    (((uint32_t)(a) << 24u) | ((uint32_t)(b) << 16u) | \
     ((uint32_t)(c) << 8u) | (uint32_t)(d))
#define ICC_TAG_A2B0 ICC_SIG('A', '2', 'B', '0')
#define ICC_TYPE_MFT1 ICC_SIG('m', 'f', 't', '1')
#define ICC_TYPE_MFT2 ICC_SIG('m', 'f', 't', '2')
#define ICC_FILE_SIGNATURE ICC_SIG('a', 'c', 's', 'p')
#define ICC_CLASS_DISPLAY ICC_SIG('m', 'n', 't', 'r')
#define ICC_SPACE_RGB ICC_SIG('R', 'G', 'B', ' ')
#define ICC_SPACE_XYZ ICC_SIG('X', 'Y', 'Z', ' ')
#define ICC_FIXED16_LIMIT (16 * 65536)

typedef struct IccLutTag {
    uint32_t signature;
    uint32_t offset;
    uint32_t size;
} IccLutTag;

static void lut_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static void lut_copy(uint8_t* destination, const uint8_t* source,
                     uint32_t size)
{
    volatile uint8_t* out = (volatile uint8_t*)destination;
    const volatile uint8_t* in = (const volatile uint8_t*)source;
    while (size-- != 0u) *out++ = *in++;
}

static uint16_t lut_be16(const uint8_t* bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint32_t lut_be32(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | bytes[3];
}

static int32_t lut_be_s32(const uint8_t* bytes)
{
    return (int32_t)lut_be32(bytes);
}

static int lut_ranges_overlap(const void* first, uint32_t first_size,
                              const void* second, uint32_t second_size)
{
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    if (first_size == 0u || second_size == 0u) return 0;
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

static int lut_tag_range_valid(const IccLutTag* tag, uint32_t length,
                               uint32_t table_end)
{
    return tag->offset >= table_end &&
           tag->offset <= length && (tag->offset & 3u) == 0u &&
           tag->size >= 8u &&
           tag->size <= length - tag->offset;
}

static RinIccLutProfileResult lut_tags_read(
    const uint8_t* bytes, uint32_t length, IccLutTag tags[],
    uint32_t* count_out, IccLutTag* lut_tag_out)
{
    uint32_t count;
    uint32_t table_end;
    uint32_t lut_count = 0u;
    if (length < ICC_TAG_TABLE_OFFSET + ICC_TAG_TABLE_PREFIX_SIZE)
        return RIN_ICC_LUT_PROFILE_MALFORMED;
    count = lut_be32(bytes + ICC_TAG_TABLE_OFFSET);
    if (count == 0u) return RIN_ICC_LUT_PROFILE_MALFORMED;
    if (count > RIN_ICC_LUT_PROFILE_MAX_TAGS)
        return RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED;
    if (count > (UINT32_MAX - ICC_TAG_TABLE_PREFIX_SIZE) /
                    ICC_TAG_ENTRY_SIZE)
        return RIN_ICC_LUT_PROFILE_MALFORMED;
    table_end = ICC_TAG_TABLE_OFFSET + ICC_TAG_TABLE_PREFIX_SIZE +
                count * ICC_TAG_ENTRY_SIZE;
    if (table_end > length) return RIN_ICC_LUT_PROFILE_MALFORMED;
    for (uint32_t index = 0u; index < count; ++index) {
        const uint8_t* entry = bytes + ICC_TAG_TABLE_OFFSET +
            ICC_TAG_TABLE_PREFIX_SIZE + index * ICC_TAG_ENTRY_SIZE;
        tags[index].signature = lut_be32(entry);
        tags[index].offset = lut_be32(entry + 4u);
        tags[index].size = lut_be32(entry + 8u);
        if (!lut_tag_range_valid(&tags[index], length, table_end))
            return RIN_ICC_LUT_PROFILE_MALFORMED;
        for (uint32_t other = 0u; other < index; ++other) {
            if (tags[other].signature == tags[index].signature)
                return RIN_ICC_LUT_PROFILE_MALFORMED;
            if (tags[index].offset < tags[other].offset + tags[other].size &&
                tags[other].offset < tags[index].offset + tags[index].size)
                return RIN_ICC_LUT_PROFILE_MALFORMED;
        }
        if (tags[index].signature == ICC_TAG_A2B0) {
            *lut_tag_out = tags[index];
            ++lut_count;
        }
    }
    *count_out = count;
    return lut_count == 0u ? RIN_ICC_LUT_PROFILE_UNSUPPORTED
                           : RIN_ICC_LUT_PROFILE_OK;
}

static int lut_table_monotonic(const uint8_t* table, uint32_t channels,
                               uint32_t entries, uint32_t entry_bytes,
                               uint32_t maximum)
{
    if (entries == 0u || channels != 3u ||
        (entry_bytes != 1u && entry_bytes != 2u)) return 0;
    for (uint32_t channel = 0u; channel < channels; ++channel) {
        uint32_t previous = 0u;
        for (uint32_t index = 0u; index < entries; ++index) {
            const uint8_t* value = table +
                (channel * entries + index) * entry_bytes;
            uint32_t current = entry_bytes == 1u ? value[0] : lut_be16(value);
            if ((index == 0u && current != 0u) ||
                (index != 0u && current < previous)) return 0;
            previous = current;
        }
        if (previous != maximum) return 0;
    }
    return 1;
}

static RinIccLutProfileResult lut_parse_tag(
    const uint8_t* bytes, const IccLutTag* tag,
    RinIccLutProfileV1* profile)
{
    const uint8_t* element = bytes + tag->offset;
    uint32_t type = lut_be32(element);
    uint32_t entry_bytes;
    uint32_t input_entries = 256u;
    uint32_t output_entries = 256u;
    uint32_t data_offset;
    uint32_t clut_count;
    uint32_t input_bytes;
    uint32_t clut_bytes;
    uint32_t output_bytes;
    uint32_t expected_size;
    uint32_t grid;

    if (type != ICC_TYPE_MFT1 && type != ICC_TYPE_MFT2)
        return RIN_ICC_LUT_PROFILE_UNSUPPORTED;
    if (tag->size < (type == ICC_TYPE_MFT1 ? 48u : 56u))
        return RIN_ICC_LUT_PROFILE_MALFORMED;
    if (element[8] != 3u || element[9] != 3u || element[10] < 2u ||
        element[10] > RIN_ICC_LUT_PROFILE_MAX_GRID_POINTS || element[11] != 0u)
        return element[8] != 3u || element[9] != 3u
            ? RIN_ICC_LUT_PROFILE_UNSUPPORTED
            : RIN_ICC_LUT_PROFILE_MALFORMED;
    grid = element[10];
    for (uint32_t index = 0u; index < 9u; ++index) {
        int32_t value = lut_be_s32(element + 12u + index * 4u);
        if (value < -ICC_FIXED16_LIMIT || value > ICC_FIXED16_LIMIT)
            return RIN_ICC_LUT_PROFILE_MALFORMED;
        profile->matrix_s15_fixed16[index] = value;
    }
    if (type == ICC_TYPE_MFT1) {
        entry_bytes = 1u;
        data_offset = 48u;
    } else {
        entry_bytes = 2u;
        input_entries = lut_be16(element + 48u);
        output_entries = lut_be16(element + 50u);
        if (lut_be32(element + 52u) != 0u || input_entries < 2u ||
            output_entries < 2u ||
            input_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES ||
            output_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES)
            return input_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES ||
                   output_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES
                ? RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED
                : RIN_ICC_LUT_PROFILE_MALFORMED;
        data_offset = 56u;
    }
    if (grid > UINT32_MAX / grid || grid * grid > UINT32_MAX / grid)
        return RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED;
    clut_count = grid * grid * grid * 3u;
    if (input_entries > UINT32_MAX / (3u * entry_bytes) ||
        output_entries > UINT32_MAX / (3u * entry_bytes) ||
        clut_count > UINT32_MAX / entry_bytes)
        return RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED;
    input_bytes = input_entries * 3u * entry_bytes;
    clut_bytes = clut_count * entry_bytes;
    output_bytes = output_entries * 3u * entry_bytes;
    if (data_offset > UINT32_MAX - input_bytes ||
        data_offset + input_bytes > UINT32_MAX - clut_bytes ||
        data_offset + input_bytes + clut_bytes > UINT32_MAX - output_bytes)
        return RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED;
    expected_size = data_offset + input_bytes + clut_bytes + output_bytes;
    if (expected_size != tag->size) return RIN_ICC_LUT_PROFILE_MALFORMED;
    if (!lut_table_monotonic(element + data_offset, 3u, input_entries,
                             entry_bytes, entry_bytes == 1u ? 255u : 65535u) ||
        !lut_table_monotonic(element + data_offset + input_bytes + clut_bytes,
                             3u, output_entries, entry_bytes,
                             entry_bytes == 1u ? 255u : 65535u))
        return RIN_ICC_LUT_PROFILE_MALFORMED;

    profile->tag_offset = tag->offset;
    profile->tag_size = tag->size;
    profile->tag_signature = tag->signature;
    profile->tag_type = type == ICC_TYPE_MFT1
        ? RIN_ICC_LUT_PROFILE_MFT1 : RIN_ICC_LUT_PROFILE_MFT2;
    profile->input_channels = 3u;
    profile->output_channels = 3u;
    profile->grid_points = grid;
    profile->input_table_offset = tag->offset + data_offset;
    profile->input_table_entries = input_entries;
    profile->input_table_entry_bytes = entry_bytes;
    profile->clut_offset = profile->input_table_offset + input_bytes;
    profile->clut_entry_count = clut_count;
    profile->clut_entry_bytes = entry_bytes;
    profile->output_table_offset = profile->clut_offset + clut_bytes;
    profile->output_table_entries = output_entries;
    profile->output_table_entry_bytes = entry_bytes;
    return RIN_ICC_LUT_PROFILE_OK;
}

RinIccLutProfileResult rin_icc_lut_profile_admit(
    const uint8_t* bytes, uint32_t length,
    uint8_t* snapshot, uint32_t snapshot_capacity,
    RinIccLutProfileV1* profile)
{
    IccLutTag tags[RIN_ICC_LUT_PROFILE_MAX_TAGS];
    IccLutTag lut_tag = {0u, 0u, 0u};
    RinIccLutProfileV1 candidate;
    RinIccLutProfileResult result;
    uint32_t tag_count = 0u;
    if (!profile) return RIN_ICC_LUT_PROFILE_INVALID_ARGUMENT;
    lut_zero(profile, sizeof(*profile));
    if (!bytes || !snapshot || length < ICC_HEADER_SIZE + 4u ||
        length > RIN_ICC_LUT_PROFILE_MAX_BYTES || snapshot_capacity < length ||
        lut_ranges_overlap(bytes, length, snapshot, length) ||
        lut_ranges_overlap(bytes, length, profile, sizeof(*profile)) ||
        lut_ranges_overlap(snapshot, length, profile, sizeof(*profile))) {
        return length > RIN_ICC_LUT_PROFILE_MAX_BYTES
            ? RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED
            : RIN_ICC_LUT_PROFILE_INVALID_ARGUMENT;
    }
    lut_zero(snapshot, length);
    lut_copy(snapshot, bytes, length);
    if (lut_be32(snapshot) != length || (length & 3u) != 0u ||
        lut_be32(snapshot + 36u) != ICC_FILE_SIGNATURE ||
        lut_be32(snapshot + 12u) != ICC_CLASS_DISPLAY ||
        lut_be32(snapshot + 16u) != ICC_SPACE_RGB ||
        lut_be32(snapshot + 20u) != ICC_SPACE_XYZ ||
        lut_be32(snapshot + 64u) > 3u)
        goto malformed;
    result = lut_tags_read(snapshot, length, tags, &tag_count, &lut_tag);
    if (result != RIN_ICC_LUT_PROFILE_OK) goto fail;
    lut_zero(&candidate, sizeof(candidate));
    candidate.abi_version = RIN_ICC_LUT_PROFILE_ABI_VERSION;
    candidate.struct_size = sizeof(candidate);
    candidate.profile_size = length;
    result = lut_parse_tag(snapshot, &lut_tag, &candidate);
    if (result != RIN_ICC_LUT_PROFILE_OK) goto fail;
    *profile = candidate;
    return RIN_ICC_LUT_PROFILE_OK;

malformed:
    result = RIN_ICC_LUT_PROFILE_MALFORMED;
fail:
    lut_zero(profile, sizeof(*profile));
    lut_zero(snapshot, length);
    return result;
}
