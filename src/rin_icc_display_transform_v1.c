/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rin_icc_display_transform_v1.h"

#include <stdint.h>

#define ICC_TRANSFORM_FIXED_LIMIT (16 * 65536)
#define ICC_TRANSFORM_TYPE_CURVE UINT32_C(0x63757276) /* curv */
#define ICC_TRANSFORM_TYPE_PARAMETRIC UINT32_C(0x70617261) /* para */

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
    if (first_start > UINTPTR_MAX - first_size ||
        second_start > UINTPTR_MAX - second_size) return 1;
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

static int transform_fixed_valid(int32_t value)
{
    return value >= -ICC_TRANSFORM_FIXED_LIMIT &&
           value <= ICC_TRANSFORM_FIXED_LIMIT;
}

static uint32_t transform_fixed_sqrt(uint32_t value)
{
    uint64_t target = (uint64_t)value * 65535u;
    uint32_t root = 0u;
    uint32_t bit = 1u << 15u;
    while (bit != 0u) {
        uint32_t candidate = root + bit;
        if ((uint64_t)candidate * candidate <= target) root = candidate;
        bit >>= 1u;
    }
    return root;
}

static uint32_t transform_fixed_multiply(uint32_t first, uint32_t second)
{
    return (uint32_t)(((uint64_t)first * second + 32767u) / 65535u);
}

/* Evaluate x^exponent in the same 0..65535 fixed domain as the ICC curve
 * samples.  The fractional exponent is decomposed into binary square roots,
 * avoiding floating point and keeping the work bounded at 16 iterations. */
static uint32_t transform_power(uint32_t value, int32_t exponent)
{
    uint32_t integer_part;
    uint32_t fraction;
    uint32_t result = 65535u;
    uint32_t power = value;
    uint32_t bit;
    if (exponent <= 0) return exponent == 0 ? 65535u : 0u;
    integer_part = (uint32_t)exponent >> 16u;
    fraction = (uint32_t)exponent & 0xffffu;
    for (uint32_t index = 0u; index < integer_part; ++index)
        result = transform_fixed_multiply(result, value);
    for (bit = 1u; bit != 0x10000u; bit <<= 1u) {
        power = transform_fixed_sqrt(power);
        if ((fraction & bit) != 0u)
            result = transform_fixed_multiply(result, power);
    }
    return result;
}

static int64_t transform_affine(int32_t slope, int32_t offset,
                                uint32_t input, int32_t extra)
{
    return ((int64_t)slope * input + (int64_t)offset * 65535 + extra) /
           65536;
}

static uint32_t transform_clamp_signed(int64_t value)
{
    if (value <= 0) return 0u;
    if (value >= 65535) return 65535u;
    return (uint32_t)value;
}

static RinIccDisplayTransformResult transform_validate(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccDisplayProfileV1* profile)
{
    uint32_t index;
    if (!snapshot || !profile || snapshot_size == 0u ||
        snapshot_size > RIN_ICC_DISPLAY_PROFILE_MAX_BYTES ||
        profile->abi_version != RIN_ICC_DISPLAY_PROFILE_ABI_VERSION ||
        profile->struct_size != sizeof(*profile) ||
        profile->profile_size != snapshot_size || profile->tag_count < 9u ||
        profile->tag_count > RIN_ICC_DISPLAY_PROFILE_MAX_TAGS ||
        (profile->flags & ~(RIN_ICC_DISPLAY_PROFILE_HAS_PROFILE_ID |
                            RIN_ICC_DISPLAY_PROFILE_HAS_CHROMATIC_ADAPTATION)) != 0u)
        return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
    for (index = 0u; index < 3u; ++index) {
        const RinIccCurveV1* curve = &profile->curves[index];
        if (curve->tag_offset > snapshot_size || curve->tag_size < 12u ||
            curve->tag_size > snapshot_size - curve->tag_offset ||
            curve->entry_count > RIN_ICC_DISPLAY_PROFILE_MAX_CURVE_ENTRIES)
            return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        if (curve->kind == RIN_ICC_CURVE_IDENTITY) {
            if (curve->entry_count != 0u || curve->tag_size != 12u ||
                transform_be32(snapshot + curve->tag_offset) !=
                    ICC_TRANSFORM_TYPE_CURVE ||
                transform_be32(snapshot + curve->tag_offset + 8u) != 0u)
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        } else if (curve->kind == RIN_ICC_CURVE_SAMPLED) {
            uint32_t previous = 0u;
            uint32_t expected_size;
            if (curve->entry_count < 2u ||
                curve->entry_count > (UINT32_MAX - 12u) / 2u)
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
            expected_size = 12u + curve->entry_count * 2u;
            if (curve->tag_size != expected_size ||
                transform_be32(snapshot + curve->tag_offset) !=
                    ICC_TRANSFORM_TYPE_CURVE ||
                transform_be32(snapshot + curve->tag_offset + 8u) !=
                    curve->entry_count)
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
            for (uint32_t sample = 0u; sample < curve->entry_count; ++sample) {
                uint32_t value = transform_be16(snapshot + curve->tag_offset +
                                                12u + sample * 2u);
                if ((sample == 0u && value != 0u) ||
                    (sample != 0u && value < previous))
                    return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
                previous = value;
            }
            if (previous != 65535u)
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        } else if (curve->kind == RIN_ICC_CURVE_GAMMA) {
            if (curve->entry_count != 1u || curve->function_type != 0u ||
                !transform_fixed_valid(curve->parameters_s15_fixed16[0]) ||
                curve->parameters_s15_fixed16[0] <= 0 ||
                curve->tag_size != 14u ||
                transform_be32(snapshot + curve->tag_offset) !=
                    ICC_TRANSFORM_TYPE_CURVE ||
                transform_be32(snapshot + curve->tag_offset + 8u) != 1u ||
                ((int32_t)transform_be16(snapshot + curve->tag_offset + 12u) << 8u) !=
                    curve->parameters_s15_fixed16[0])
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        } else if (curve->kind == RIN_ICC_CURVE_PARAMETRIC) {
            static const uint8_t parameter_count[5] = {1u, 3u, 4u, 5u, 7u};
            uint32_t function = curve->function_type;
            uint32_t count;
            if (function > 4u) return RIN_ICC_DISPLAY_TRANSFORM_UNSUPPORTED;
            count = parameter_count[function];
            if (curve->entry_count != count ||
                curve->tag_size != 12u + count * 4u ||
                transform_be32(snapshot + curve->tag_offset) !=
                    ICC_TRANSFORM_TYPE_PARAMETRIC ||
                transform_be16(snapshot + curve->tag_offset + 8u) != function ||
                snapshot[curve->tag_offset + 10u] != 0u ||
                snapshot[curve->tag_offset + 11u] != 0u)
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
            for (uint32_t parameter = 0u; parameter < count; ++parameter) {
                int32_t value = (int32_t)transform_be32(
                    snapshot + curve->tag_offset + 12u + parameter * 4u);
                if (value != curve->parameters_s15_fixed16[parameter] ||
                    !transform_fixed_valid(value))
                    return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
            }
            if (curve->parameters_s15_fixed16[0] <= 0 ||
                curve->parameters_s15_fixed16[0] > ICC_TRANSFORM_FIXED_LIMIT ||
                (function >= 1u &&
                 (curve->parameters_s15_fixed16[1] <= 0 ||
                  curve->parameters_s15_fixed16[2] < 0)) ||
                (function >= 2u &&
                 (curve->parameters_s15_fixed16[3] <= 0 ||
                  curve->parameters_s15_fixed16[4] < 0 ||
                  curve->parameters_s15_fixed16[4] > 65536)))
                return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        } else {
            return RIN_ICC_DISPLAY_TRANSFORM_UNSUPPORTED;
        }
    }
    for (index = 0u; index < 9u; ++index) {
        if (!transform_fixed_valid(profile->rgb_to_pcs_s15_fixed16[index]))
            return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
        if ((profile->flags & RIN_ICC_DISPLAY_PROFILE_HAS_CHROMATIC_ADAPTATION) != 0u &&
            !transform_fixed_valid(profile->chromatic_adaptation_s15_fixed16[index]))
            return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
    }
    for (index = 0u; index < 4u; ++index)
        if (profile->reserved[index] != 0u) return RIN_ICC_DISPLAY_TRANSFORM_MALFORMED;
    return RIN_ICC_DISPLAY_TRANSFORM_OK;
}

static uint32_t transform_curve_sample(const uint8_t* snapshot,
                                       const RinIccCurveV1* curve,
                                       uint32_t input)
{
    uint64_t position = (uint64_t)input * (curve->entry_count - 1u);
    uint32_t index = (uint32_t)(position / 65535u);
    uint32_t fraction = (uint32_t)(position % 65535u);
    const uint8_t* table = snapshot + curve->tag_offset + 12u;
    uint32_t first;
    uint32_t second;
    int64_t delta;
    int64_t result;
    if (index >= curve->entry_count - 1u)
        return transform_be16(table + (curve->entry_count - 1u) * 2u);
    first = transform_be16(table + index * 2u);
    second = transform_be16(table + (index + 1u) * 2u);
    delta = (int64_t)second - (int64_t)first;
    if (delta >= 0)
        result = (int64_t)first +
                 (delta * (int64_t)fraction + 32767) / 65535;
    else
        result = (int64_t)first -
                 ((-delta * (int64_t)fraction + 32767) / 65535);
    if (result < 0) return 0u;
    return result > 65535 ? 65535u : (uint32_t)result;
}

static uint32_t transform_curve_value(const uint8_t* snapshot,
                                      const RinIccCurveV1* curve,
                                      uint32_t input)
{
    if (curve->kind == RIN_ICC_CURVE_IDENTITY) return input;
    if (curve->kind == RIN_ICC_CURVE_SAMPLED)
        return transform_curve_sample(snapshot, curve, input);
    if (curve->kind == RIN_ICC_CURVE_GAMMA)
        return transform_power(input, curve->parameters_s15_fixed16[0]);
    if (curve->kind == RIN_ICC_CURVE_PARAMETRIC) {
        const int32_t* p = curve->parameters_s15_fixed16;
        uint32_t function = curve->function_type;
        int64_t threshold;
        int64_t base;
        if (function == 0u) return transform_power(input, p[0]);
        if (function == 1u) {
            /* p[1] is positive and p[2] nonnegative under admission, so the
             * type-1 lower branch is only reachable at malformed input. */
            threshold = -((int64_t)p[2] * 65535) / p[1];
            if ((int64_t)input < threshold) return 0u;
            base = transform_affine(p[1], p[2], input, 0);
            return transform_power(transform_clamp_signed(base), p[0]);
        }
        threshold = ((int64_t)p[3] * 65535) / 65536;
        if ((int64_t)input >= threshold) {
            base = transform_affine(p[1], p[2], input, 0);
            base = (int64_t)transform_power(transform_clamp_signed(base), p[0]);
            if (function == 4u) return transform_clamp_signed(base +
                ((int64_t)p[5] * 65535) / 65536);
            return transform_clamp_signed(base);
        }
        base = (int64_t)p[3] * input / 65536;
        if (function == 2u || function == 3u)
            return transform_clamp_signed(base);
        return transform_clamp_signed(base +
            ((int64_t)p[6] * 65535) / 65536);
    }
    return 0u;
}

static uint32_t transform_matrix_value(const int32_t matrix[9],
                                       uint32_t row,
                                       const uint32_t input[3])
{
    int64_t sum = 0;
    int64_t rounded;
    for (uint32_t column = 0u; column < 3u; ++column)
        sum += (int64_t)matrix[row * 3u + column] *
               (int64_t)input[column];
    if (sum >= 0) rounded = (sum + 32768) / 65536;
    else rounded = -(((-sum) + 32768) / 65536);
    if (rounded < 0) return 0u;
    return rounded > 65535 ? 65535u : (uint32_t)rounded;
}

RinIccDisplayTransformResult rin_icc_display_transform_apply_v1(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccDisplayProfileV1* profile,
    const uint16_t input_rgb[3], uint16_t output_xyz[3])
{
    RinIccDisplayTransformResult result;
    uint32_t linear[3];
    uint32_t pcs[3];
    if (output_xyz) transform_zero(output_xyz, sizeof(uint16_t) * 3u);
    if (!snapshot || !profile || !input_rgb || !output_xyz ||
        transform_overlap(snapshot, snapshot_size, input_rgb,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(snapshot, snapshot_size, output_xyz,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(profile, sizeof(*profile), input_rgb,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(profile, sizeof(*profile), output_xyz,
                          sizeof(uint16_t) * 3u) ||
        transform_overlap(input_rgb, sizeof(uint16_t) * 3u, output_xyz,
                          sizeof(uint16_t) * 3u))
        return RIN_ICC_DISPLAY_TRANSFORM_INVALID_ARGUMENT;
    result = transform_validate(snapshot, snapshot_size, profile);
    if (result != RIN_ICC_DISPLAY_TRANSFORM_OK) return result;
    for (uint32_t channel = 0u; channel < 3u; ++channel) {
        const RinIccCurveV1* curve = &profile->curves[channel];
        linear[channel] = transform_curve_value(snapshot, curve,
                                                input_rgb[channel]);
    }
    for (uint32_t row = 0u; row < 3u; ++row)
        pcs[row] = transform_matrix_value(profile->rgb_to_pcs_s15_fixed16,
                                          row, linear);
    if ((profile->flags & RIN_ICC_DISPLAY_PROFILE_HAS_CHROMATIC_ADAPTATION) != 0u) {
        uint32_t adapted[3];
        for (uint32_t row = 0u; row < 3u; ++row)
            adapted[row] = transform_matrix_value(
                profile->chromatic_adaptation_s15_fixed16, row, pcs);
        pcs[0] = adapted[0]; pcs[1] = adapted[1]; pcs[2] = adapted[2];
    }
    for (uint32_t channel = 0u; channel < 3u; ++channel)
        output_xyz[channel] = (uint16_t)pcs[channel];
    return RIN_ICC_DISPLAY_TRANSFORM_OK;
}
