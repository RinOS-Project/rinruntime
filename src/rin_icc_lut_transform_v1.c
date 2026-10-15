/* SPDX-License-Identifier: MIT */
#include "rin_icc_lut_transform_v1.h"

#include <stdint.h>

#define ICC_FIXED16_LIMIT (16 * 65536)

static void transform_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static uint16_t transform_be16(const uint8_t* bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint32_t transform_be32(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | bytes[3];
}

static int transform_overlap(const void* first, uint32_t first_size,
                             const void* second, uint32_t second_size)
{
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    if (first_size == 0u || second_size == 0u) return 0;
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

static uint32_t transform_entry(const uint8_t* table, uint32_t channel,
                                uint32_t entries, uint32_t entry_bytes,
                                uint32_t index)
{
    const uint8_t* value = table +
        (channel * entries + index) * entry_bytes;
    return entry_bytes == 1u ? (uint32_t)value[0] * 257u :
                               (uint32_t)transform_be16(value);
}

static uint32_t transform_table_sample(const uint8_t* table,
                                       uint32_t channel, uint32_t entries,
                                       uint32_t entry_bytes, uint32_t value)
{
    uint64_t position = (uint64_t)value * (entries - 1u);
    uint32_t index = (uint32_t)(position >> 16u);
    uint32_t fraction = (uint32_t)(position & 0xffffu);
    uint32_t first;
    uint32_t second;
    int64_t delta;
    uint64_t result;

    if (index >= entries - 1u) return transform_entry(
        table, channel, entries, entry_bytes, entries - 1u);
    first = transform_entry(table, channel, entries, entry_bytes, index);
    second = transform_entry(table, channel, entries, entry_bytes, index + 1u);
    delta = (int64_t)second - (int64_t)first;
    if (delta < 0) {
        result = (uint64_t)((int64_t)first -
            ((-delta * (int64_t)fraction + 32767) / 65535));
    } else {
        result = (uint64_t)((int64_t)first +
            ((delta * (int64_t)fraction + 32767) / 65535));
    }
    return result > 65535u ? 65535u : (uint32_t)result;
}

static RinIccLutTransformResult transform_validate(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccLutProfileV1* profile, uint32_t* input_bytes_out,
    uint32_t* clut_bytes_out, uint32_t* output_bytes_out)
{
    uint32_t input_bytes;
    uint32_t clut_bytes;
    uint32_t output_bytes;
    uint32_t tag_end;
    uint32_t expected_size;
    uint32_t computed_clut_count;
    uint32_t type;
    if (!snapshot || !profile || snapshot_size == 0u ||
        snapshot_size > RIN_ICC_LUT_PROFILE_MAX_BYTES ||
        profile->abi_version != RIN_ICC_LUT_PROFILE_ABI_VERSION ||
        profile->struct_size != sizeof(*profile) ||
        profile->profile_size != snapshot_size ||
        profile->input_channels != 3u || profile->output_channels != 3u ||
        profile->grid_points < 2u ||
        profile->grid_points > RIN_ICC_LUT_PROFILE_MAX_GRID_POINTS ||
        profile->input_table_entries < 2u ||
        profile->output_table_entries < 2u ||
        profile->input_table_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES ||
        profile->output_table_entries > RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES ||
        (profile->input_table_entry_bytes != 1u &&
         profile->input_table_entry_bytes != 2u) ||
        profile->input_table_entry_bytes != profile->output_table_entry_bytes ||
        profile->clut_entry_bytes != profile->input_table_entry_bytes ||
        profile->tag_offset > snapshot_size || profile->tag_size < 56u ||
        profile->tag_size > snapshot_size - profile->tag_offset ||
        profile->input_table_offset > snapshot_size ||
        profile->clut_offset > snapshot_size ||
        profile->output_table_offset > snapshot_size ||
        profile->tag_offset + profile->tag_size > snapshot_size)
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    type = transform_be32(snapshot + profile->tag_offset);
    if ((type != ((uint32_t)'m' << 24u | (uint32_t)'f' << 16u |
                 (uint32_t)'t' << 8u | (uint32_t)'1') &&
         type != ((uint32_t)'m' << 24u | (uint32_t)'f' << 16u |
                 (uint32_t)'t' << 8u | (uint32_t)'2')) ||
        (type == ((uint32_t)'m' << 24u | (uint32_t)'f' << 16u |
                  (uint32_t)'t' << 8u | (uint32_t)'1') &&
         profile->tag_type != RIN_ICC_LUT_PROFILE_MFT1) ||
        (type == ((uint32_t)'m' << 24u | (uint32_t)'f' << 16u |
                  (uint32_t)'t' << 8u | (uint32_t)'2') &&
         profile->tag_type != RIN_ICC_LUT_PROFILE_MFT2))
        return RIN_ICC_LUT_TRANSFORM_UNSUPPORTED;
    if (snapshot[profile->tag_offset + 8u] != 3u ||
        snapshot[profile->tag_offset + 9u] != 3u ||
        snapshot[profile->tag_offset + 10u] != profile->grid_points ||
        snapshot[profile->tag_offset + 11u] != 0u)
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    if (profile->tag_type == RIN_ICC_LUT_PROFILE_MFT2 &&
        (transform_be16(snapshot + profile->tag_offset + 48u) !=
             profile->input_table_entries ||
         transform_be16(snapshot + profile->tag_offset + 50u) !=
             profile->output_table_entries ||
         transform_be32(snapshot + profile->tag_offset + 52u) != 0u))
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    if (profile->tag_type == RIN_ICC_LUT_PROFILE_MFT1 &&
        (profile->input_table_entries != 256u ||
         profile->output_table_entries != 256u))
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    if (profile->grid_points > UINT32_MAX / profile->grid_points ||
        profile->grid_points * profile->grid_points >
            UINT32_MAX / profile->grid_points ||
        profile->grid_points * profile->grid_points * profile->grid_points >
            UINT32_MAX / 3u)
        return RIN_ICC_LUT_TRANSFORM_LIMIT_EXCEEDED;
    computed_clut_count = profile->grid_points * profile->grid_points *
                          profile->grid_points * 3u;
    if (profile->input_table_entries > UINT32_MAX /
            (3u * profile->input_table_entry_bytes) ||
        profile->output_table_entries > UINT32_MAX /
            (3u * profile->output_table_entry_bytes) ||
        computed_clut_count > UINT32_MAX / profile->clut_entry_bytes)
        return RIN_ICC_LUT_TRANSFORM_LIMIT_EXCEEDED;
    input_bytes = profile->input_table_entries * 3u *
                  profile->input_table_entry_bytes;
    clut_bytes = computed_clut_count * profile->clut_entry_bytes;
    output_bytes = profile->output_table_entries * 3u *
                   profile->output_table_entry_bytes;
    expected_size = profile->tag_type == RIN_ICC_LUT_PROFILE_MFT1 ? 48u : 56u;
    if (expected_size > UINT32_MAX - input_bytes ||
        (expected_size += input_bytes) > UINT32_MAX - clut_bytes ||
        (expected_size += clut_bytes) > UINT32_MAX - output_bytes ||
        (expected_size += output_bytes) != profile->tag_size ||
        profile->input_table_offset != profile->tag_offset +
            (profile->tag_type == RIN_ICC_LUT_PROFILE_MFT1 ? 48u : 56u) ||
        profile->clut_offset != profile->input_table_offset + input_bytes ||
        profile->output_table_offset != profile->clut_offset + clut_bytes)
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    tag_end = profile->tag_offset + profile->tag_size;
    if (profile->output_table_offset > tag_end ||
        output_bytes > tag_end - profile->output_table_offset)
        return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    for (uint32_t channel = 0u; channel < 3u; ++channel) {
        uint32_t previous = 0u;
        for (uint32_t index = 0u; index < profile->input_table_entries;
             ++index) {
            uint32_t current = transform_entry(snapshot +
                profile->input_table_offset, channel,
                profile->input_table_entries,
                profile->input_table_entry_bytes, index);
            if ((index == 0u && current != 0u) ||
                (index != 0u && current < previous))
                return RIN_ICC_LUT_TRANSFORM_MALFORMED;
            previous = current;
        }
        if (previous != 65535u) return RIN_ICC_LUT_TRANSFORM_MALFORMED;
        previous = 0u;
        for (uint32_t index = 0u; index < profile->output_table_entries;
             ++index) {
            uint32_t current = transform_entry(snapshot +
                profile->output_table_offset, channel,
                profile->output_table_entries,
                profile->output_table_entry_bytes, index);
            if ((index == 0u && current != 0u) ||
                (index != 0u && current < previous))
                return RIN_ICC_LUT_TRANSFORM_MALFORMED;
            previous = current;
        }
        if (previous != 65535u) return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    }
    for (uint32_t index = 0u; index < 9u; ++index) {
        if (profile->matrix_s15_fixed16[index] < -ICC_FIXED16_LIMIT ||
            profile->matrix_s15_fixed16[index] > ICC_FIXED16_LIMIT)
            return RIN_ICC_LUT_TRANSFORM_MALFORMED;
    }
    *input_bytes_out = input_bytes;
    *clut_bytes_out = clut_bytes;
    *output_bytes_out = output_bytes;
    return RIN_ICC_LUT_TRANSFORM_OK;
}

static uint32_t transform_matrix_value(const RinIccLutProfileV1* profile,
                                       uint32_t row, const uint32_t input[3])
{
    int64_t sum = 0;
    int64_t rounded;
    for (uint32_t column = 0u; column < 3u; ++column)
        sum += (int64_t)profile->matrix_s15_fixed16[row * 3u + column] *
               (int64_t)input[column];
    if (sum >= 0) rounded = (sum + 32768) / 65536;
    else rounded = -(((-sum) + 32768) / 65536);
    if (rounded < 0) return 0u;
    if (rounded > 65535) return 65535u;
    return (uint32_t)rounded;
}

static uint32_t transform_clut_value(const uint8_t* snapshot,
                                     const RinIccLutProfileV1* profile,
                                     uint32_t channel, const uint32_t input[3])
{
    uint32_t grid = profile->grid_points;
    uint32_t index[3];
    uint32_t fraction[3];
    uint64_t weighted = 0u;
    for (uint32_t dimension = 0u; dimension < 3u; ++dimension) {
        uint64_t position = (uint64_t)input[dimension] * (grid - 1u);
        index[dimension] = (uint32_t)(position >> 16u);
        fraction[dimension] = (uint32_t)(position & 0xffffu);
        if (index[dimension] >= grid - 1u) {
            index[dimension] = grid - 1u;
            fraction[dimension] = 0u;
        }
    }
    for (uint32_t corner = 0u; corner < 8u; ++corner) {
        uint32_t coordinate[3];
        uint64_t weight = 1u;
        uint32_t linear;
        uint32_t sample;
        for (uint32_t dimension = 0u; dimension < 3u; ++dimension) {
            if ((corner & (1u << dimension)) != 0u) {
                coordinate[dimension] = index[dimension] +
                    (index[dimension] + 1u < grid ? 1u : 0u);
                weight *= fraction[dimension];
            } else {
                coordinate[dimension] = index[dimension];
                weight *= 65535u - fraction[dimension];
            }
        }
        linear = coordinate[0] + grid * (coordinate[1] +
                                         grid * coordinate[2]);
        linear = linear * 3u + channel;
        sample = transform_entry(snapshot + profile->clut_offset, 0u,
                                 profile->clut_entry_count,
                                 profile->clut_entry_bytes, linear);
        weighted += (uint64_t)sample * weight;
    }
    {
        const uint64_t denominator = 65535ull * 65535ull * 65535ull;
        return (uint32_t)((weighted + denominator / 2ull) / denominator);
    }
}

RinIccLutTransformResult rin_icc_lut_transform_apply_v1(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccLutProfileV1* profile,
    const uint16_t input[3], uint16_t output[3])
{
    uint32_t input_bytes;
    uint32_t clut_bytes;
    uint32_t output_bytes;
    uint32_t mapped[3];
    uint32_t transformed[3];
    RinIccLutTransformResult result;
    if (output) transform_zero(output, sizeof(uint16_t) * 3u);
    if (!snapshot || !profile || !input || !output ||
        transform_overlap(snapshot, snapshot_size, output,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(profile, sizeof(*profile), output,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(input, sizeof(uint16_t) * 3u, output,
                          sizeof(uint16_t) * 3u))
        return RIN_ICC_LUT_TRANSFORM_INVALID_ARGUMENT;
    result = transform_validate(snapshot, snapshot_size, profile,
                                &input_bytes, &clut_bytes, &output_bytes);
    (void)input_bytes;
    (void)clut_bytes;
    (void)output_bytes;
    if (result != RIN_ICC_LUT_TRANSFORM_OK) return result;
    for (uint32_t channel = 0u; channel < 3u; ++channel)
        mapped[channel] = transform_table_sample(snapshot +
            profile->input_table_offset, channel,
            profile->input_table_entries, profile->input_table_entry_bytes,
            input[channel]);
    for (uint32_t channel = 0u; channel < 3u; ++channel)
        transformed[channel] = transform_matrix_value(profile, channel,
                                                       mapped);
    for (uint32_t channel = 0u; channel < 3u; ++channel) {
        uint32_t clut = transform_clut_value(snapshot, profile, channel,
                                             transformed);
        output[channel] = (uint16_t)transform_table_sample(snapshot +
            profile->output_table_offset, channel,
            profile->output_table_entries, profile->output_table_entry_bytes,
            clut);
    }
    return RIN_ICC_LUT_TRANSFORM_OK;
}
