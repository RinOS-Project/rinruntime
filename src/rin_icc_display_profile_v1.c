/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rin_icc_display_profile_v1.h"

#define ICC_HEADER_SIZE 128u
#define ICC_TAG_TABLE_OFFSET 128u
#define ICC_TAG_ENTRY_SIZE 12u
#define ICC_TAG_TABLE_PREFIX_SIZE 4u

#define ICC_SIG(a, b, c, d) \
    (((uint32_t)(a) << 24u) | ((uint32_t)(b) << 16u) | \
     ((uint32_t)(c) << 8u) | (uint32_t)(d))

#define ICC_CLASS_DISPLAY ICC_SIG('m', 'n', 't', 'r')
#define ICC_SPACE_RGB ICC_SIG('R', 'G', 'B', ' ')
#define ICC_SPACE_XYZ ICC_SIG('X', 'Y', 'Z', ' ')
#define ICC_FILE_SIGNATURE ICC_SIG('a', 'c', 's', 'p')
#define ICC_PLATFORM_APPL ICC_SIG('A', 'P', 'P', 'L')
#define ICC_PLATFORM_MSFT ICC_SIG('M', 'S', 'F', 'T')
#define ICC_PLATFORM_SGI ICC_SIG('S', 'G', 'I', ' ')
#define ICC_PLATFORM_SUNW ICC_SIG('S', 'U', 'N', 'W')

#define ICC_TAG_DESCRIPTION ICC_SIG('d', 'e', 's', 'c')
#define ICC_TAG_COPYRIGHT ICC_SIG('c', 'p', 'r', 't')
#define ICC_TAG_WHITE_POINT ICC_SIG('w', 't', 'p', 't')
#define ICC_TAG_RED_XYZ ICC_SIG('r', 'X', 'Y', 'Z')
#define ICC_TAG_GREEN_XYZ ICC_SIG('g', 'X', 'Y', 'Z')
#define ICC_TAG_BLUE_XYZ ICC_SIG('b', 'X', 'Y', 'Z')
#define ICC_TAG_RED_TRC ICC_SIG('r', 'T', 'R', 'C')
#define ICC_TAG_GREEN_TRC ICC_SIG('g', 'T', 'R', 'C')
#define ICC_TAG_BLUE_TRC ICC_SIG('b', 'T', 'R', 'C')
#define ICC_TAG_CHROMATIC_ADAPTATION ICC_SIG('c', 'h', 'a', 'd')

#define ICC_TYPE_XYZ ICC_SIG('X', 'Y', 'Z', ' ')
#define ICC_TYPE_CURVE ICC_SIG('c', 'u', 'r', 'v')
#define ICC_TYPE_PARAMETRIC_CURVE ICC_SIG('p', 'a', 'r', 'a')
#define ICC_TYPE_MLUC ICC_SIG('m', 'l', 'u', 'c')
#define ICC_TYPE_S15_FIXED16_ARRAY ICC_SIG('s', 'f', '3', '2')

#define ICC_D50_X 0x0000f6d6u
#define ICC_D50_Y 0x00010000u
#define ICC_D50_Z 0x0000d32du
#define ICC_FIXED16_LIMIT (16 * 65536)
#define ICC_WHITE_LIMIT (4 * 65536)

typedef struct IccTagEntry {
    uint32_t signature;
    uint32_t offset;
    uint32_t size;
} IccTagEntry;

static void icc_zero(void* destination, uint32_t size) {
    uint8_t* output = (uint8_t*)destination;
    for (uint32_t index = 0u; index < size; ++index) output[index] = 0u;
}

static void icc_copy(uint8_t* destination, const uint8_t* source,
                     uint32_t size) {
    for (uint32_t index = 0u; index < size; ++index) {
        destination[index] = source[index];
    }
}

static uint16_t icc_be16(const uint8_t* bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint32_t icc_be32(const uint8_t* bytes) {
    return ((uint32_t)bytes[0] << 24u) |
           ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) |
           (uint32_t)bytes[3];
}

static int32_t icc_be_s32(const uint8_t* bytes) {
    return (int32_t)icc_be32(bytes);
}

static uint32_t icc_all_zero(const uint8_t* bytes, uint32_t size) {
    uint8_t value = 0u;
    for (uint32_t index = 0u; index < size; ++index) value |= bytes[index];
    return value == 0u;
}

static uint32_t icc_aligned4(uint32_t value, uint32_t* aligned) {
    if (value > UINT32_MAX - 3u) return 0u;
    *aligned = (value + 3u) & ~3u;
    return 1u;
}

static uint32_t icc_ranges_overlap(const void* first, uint32_t first_size,
                                   const void* second, uint32_t second_size) {
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    uintptr_t first_end;
    uintptr_t second_end;
    if (first_start > UINTPTR_MAX - first_size ||
        second_start > UINTPTR_MAX - second_size) {
        return 1u;
    }
    first_end = first_start + first_size;
    second_end = second_start + second_size;
    return first_start < second_end && second_start < first_end;
}

static uint32_t icc_is_leap_year(uint32_t year) {
    return (year % 4u) == 0u &&
           ((year % 100u) != 0u || (year % 400u) == 0u);
}

static uint32_t icc_date_valid(const uint8_t* bytes) {
    static const uint8_t days[12] = {
        31u, 28u, 31u, 30u, 31u, 30u,
        31u, 31u, 30u, 31u, 30u, 31u
    };
    uint32_t year = icc_be16(bytes);
    uint32_t month = icc_be16(bytes + 2u);
    uint32_t day = icc_be16(bytes + 4u);
    uint32_t hour = icc_be16(bytes + 6u);
    uint32_t minute = icc_be16(bytes + 8u);
    uint32_t second = icc_be16(bytes + 10u);
    uint32_t maximum_day;
    if (year == 0u || month == 0u || month > 12u || hour > 23u ||
        minute > 59u || second > 59u) {
        return 0u;
    }
    maximum_day = days[month - 1u];
    if (month == 2u && icc_is_leap_year(year)) ++maximum_day;
    return day != 0u && day <= maximum_day;
}

static uint32_t icc_header_valid(const uint8_t* bytes, uint32_t length,
                                 RinIccDisplayProfileResult* result) {
    uint32_t platform;
    if (icc_be32(bytes) != length || (length & 3u) != 0u ||
        icc_be32(bytes + 36u) != ICC_FILE_SIGNATURE ||
        !icc_date_valid(bytes + 24u) ||
        !icc_all_zero(bytes + 100u, 28u)) {
        *result = RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        return 0u;
    }
    if (bytes[8] != 4u || (bytes[9] >> 4u) > 4u ||
        bytes[10] != 0u || bytes[11] != 0u ||
        icc_be32(bytes + 12u) != ICC_CLASS_DISPLAY ||
        icc_be32(bytes + 16u) != ICC_SPACE_RGB ||
        icc_be32(bytes + 20u) != ICC_SPACE_XYZ) {
        *result = RIN_ICC_DISPLAY_PROFILE_UNSUPPORTED;
        return 0u;
    }
    platform = icc_be32(bytes + 40u);
    if (platform != 0u && platform != ICC_PLATFORM_APPL &&
        platform != ICC_PLATFORM_MSFT && platform != ICC_PLATFORM_SGI &&
        platform != ICC_PLATFORM_SUNW) {
        *result = RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        return 0u;
    }
    if ((icc_be32(bytes + 44u) & ~3u) != 0u ||
        !icc_all_zero(bytes + 56u, 7u) || (bytes[63] & 0xf0u) != 0u ||
        icc_be32(bytes + 64u) > 3u ||
        icc_be32(bytes + 68u) != ICC_D50_X ||
        icc_be32(bytes + 72u) != ICC_D50_Y ||
        icc_be32(bytes + 76u) != ICC_D50_Z) {
        *result = RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        return 0u;
    }
    return 1u;
}

static void icc_sort_tags(IccTagEntry* tags, uint32_t count) {
    for (uint32_t index = 1u; index < count; ++index) {
        IccTagEntry value = tags[index];
        uint32_t position = index;
        while (position != 0u &&
               (tags[position - 1u].offset > value.offset ||
                (tags[position - 1u].offset == value.offset &&
                 tags[position - 1u].size > value.size))) {
            tags[position] = tags[position - 1u];
            --position;
        }
        tags[position] = value;
    }
}

static RinIccDisplayProfileResult icc_read_tag_table(
    const uint8_t* bytes, uint32_t length,
    IccTagEntry* tags, uint32_t* tag_count) {
    uint32_t count = icc_be32(bytes + ICC_TAG_TABLE_OFFSET);
    uint32_t table_size;
    uint32_t table_end;
    uint32_t expected_offset;
    uint32_t previous_offset = UINT32_MAX;
    uint32_t previous_size = 0u;

    if (count < 9u) return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
    if (count > RIN_ICC_DISPLAY_PROFILE_MAX_TAGS) {
        return RIN_ICC_DISPLAY_PROFILE_LIMIT_EXCEEDED;
    }
    table_size = ICC_TAG_TABLE_PREFIX_SIZE + count * ICC_TAG_ENTRY_SIZE;
    table_end = ICC_TAG_TABLE_OFFSET + table_size;
    if (table_end > length) return RIN_ICC_DISPLAY_PROFILE_MALFORMED;

    for (uint32_t index = 0u; index < count; ++index) {
        const uint8_t* entry = bytes + ICC_TAG_TABLE_OFFSET +
                               ICC_TAG_TABLE_PREFIX_SIZE +
                               index * ICC_TAG_ENTRY_SIZE;
        uint32_t end;
        tags[index].signature = icc_be32(entry);
        tags[index].offset = icc_be32(entry + 4u);
        tags[index].size = icc_be32(entry + 8u);
        if (tags[index].signature == 0u || tags[index].size < 8u ||
            (tags[index].offset & 3u) != 0u ||
            tags[index].offset < table_end ||
            tags[index].offset > UINT32_MAX - tags[index].size) {
            return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        }
        end = tags[index].offset + tags[index].size;
        if (end > length) return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        for (uint32_t other = 0u; other < index; ++other) {
            if (tags[other].signature == tags[index].signature) {
                return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
            }
        }
    }

    icc_sort_tags(tags, count);
    expected_offset = table_end;
    for (uint32_t index = 0u; index < count; ++index) {
        uint32_t element_end;
        uint32_t padded_end;
        if (tags[index].offset == previous_offset) {
            if (tags[index].size != previous_size) {
                return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
            }
            continue;
        }
        if (tags[index].offset != expected_offset) {
            return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        }
        if (!icc_all_zero(bytes + tags[index].offset + 4u, 4u)) {
            return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        }
        element_end = tags[index].offset + tags[index].size;
        if (!icc_aligned4(element_end, &padded_end) || padded_end > length ||
            !icc_all_zero(bytes + element_end, padded_end - element_end)) {
            return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        }
        previous_offset = tags[index].offset;
        previous_size = tags[index].size;
        expected_offset = padded_end;
    }
    if (expected_offset != length) return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
    *tag_count = count;
    return RIN_ICC_DISPLAY_PROFILE_OK;
}

static const IccTagEntry* icc_find_tag(const IccTagEntry* tags,
                                       uint32_t count, uint32_t signature) {
    for (uint32_t index = 0u; index < count; ++index) {
        if (tags[index].signature == signature) return tags + index;
    }
    return 0;
}

static uint32_t icc_ascii_lower(uint8_t value) {
    return value >= (uint8_t)'a' && value <= (uint8_t)'z';
}

static uint32_t icc_ascii_upper(uint8_t value) {
    return value >= (uint8_t)'A' && value <= (uint8_t)'Z';
}

static uint32_t icc_utf16be_valid(const uint8_t* bytes, uint32_t length) {
    uint32_t offset = 0u;
    while (offset < length) {
        uint32_t value = icc_be16(bytes + offset);
        offset += 2u;
        if (value == 0u || (value >= 0xdc00u && value <= 0xdfffu)) return 0u;
        if (value >= 0xd800u && value <= 0xdbffu) {
            uint32_t trailing;
            if (offset == length) return 0u;
            trailing = icc_be16(bytes + offset);
            if (trailing < 0xdc00u || trailing > 0xdfffu) return 0u;
            offset += 2u;
        }
    }
    return 1u;
}

static uint32_t icc_mluc_valid(const uint8_t* bytes,
                               const IccTagEntry* tag) {
    const uint8_t* element = bytes + tag->offset;
    uint32_t count;
    uint32_t table_end;
    if (tag->size < 28u || icc_be32(element) != ICC_TYPE_MLUC) return 0u;
    count = icc_be32(element + 8u);
    if (count == 0u || count > 32u || icc_be32(element + 12u) != 12u ||
        count > (UINT32_MAX - 16u) / 12u) {
        return 0u;
    }
    table_end = 16u + count * 12u;
    if (table_end > tag->size) return 0u;
    for (uint32_t index = 0u; index < count; ++index) {
        const uint8_t* record = element + 16u + index * 12u;
        uint32_t length = icc_be32(record + 4u);
        uint32_t offset = icc_be32(record + 8u);
        if (!icc_ascii_lower(record[0]) || !icc_ascii_lower(record[1]) ||
            !icc_ascii_upper(record[2]) || !icc_ascii_upper(record[3]) ||
            length == 0u || (length & 1u) != 0u ||
            offset < table_end || offset > tag->size ||
            length > tag->size - offset ||
            !icc_utf16be_valid(element + offset, length)) {
            return 0u;
        }
        for (uint32_t other = 0u; other < index; ++other) {
            const uint8_t* prior = element + 16u + other * 12u;
            if (record[0] == prior[0] && record[1] == prior[1] &&
                record[2] == prior[2] && record[3] == prior[3]) {
                return 0u;
            }
        }
    }
    return 1u;
}

static uint32_t icc_xyz_read(const uint8_t* bytes,
                             const IccTagEntry* tag, int32_t output[3]) {
    const uint8_t* element = bytes + tag->offset;
    if (tag->size != 20u || icc_be32(element) != ICC_TYPE_XYZ) return 0u;
    for (uint32_t index = 0u; index < 3u; ++index) {
        output[index] = icc_be_s32(element + 8u + index * 4u);
    }
    return 1u;
}

static uint32_t icc_fixed_bounded(int32_t value) {
    return value >= -ICC_FIXED16_LIMIT && value <= ICC_FIXED16_LIMIT;
}

static uint32_t icc_curve_read(const uint8_t* bytes,
                               const IccTagEntry* tag,
                               RinIccCurveV1* curve,
                               RinIccDisplayProfileResult* result) {
    const uint8_t* element = bytes + tag->offset;
    uint32_t type = icc_be32(element);
    icc_zero(curve, sizeof(*curve));
    curve->tag_offset = tag->offset;
    curve->tag_size = tag->size;
    if (type == ICC_TYPE_CURVE) {
        uint32_t count;
        uint32_t expected_size;
        uint32_t previous = 0u;
        if (tag->size < 12u) return 0u;
        count = icc_be32(element + 8u);
        if (count > RIN_ICC_DISPLAY_PROFILE_MAX_CURVE_ENTRIES) {
            *result = RIN_ICC_DISPLAY_PROFILE_LIMIT_EXCEEDED;
            return 0u;
        }
        if (count > (UINT32_MAX - 12u) / 2u) return 0u;
        expected_size = 12u + count * 2u;
        if (tag->size != expected_size) return 0u;
        curve->entry_count = count;
        if (count == 0u) {
            curve->kind = RIN_ICC_CURVE_IDENTITY;
            return 1u;
        }
        if (count == 1u) {
            uint32_t gamma = icc_be16(element + 12u);
            if (gamma == 0u || gamma > 16u * 256u) return 0u;
            curve->kind = RIN_ICC_CURVE_GAMMA;
            curve->parameters_s15_fixed16[0] = (int32_t)(gamma << 8u);
            return 1u;
        }
        for (uint32_t index = 0u; index < count; ++index) {
            uint32_t value = icc_be16(element + 12u + index * 2u);
            if ((index == 0u && value != 0u) ||
                (index != 0u && value < previous)) {
                return 0u;
            }
            previous = value;
        }
        if (previous != 65535u) return 0u;
        curve->kind = RIN_ICC_CURVE_SAMPLED;
        return 1u;
    }
    if (type == ICC_TYPE_PARAMETRIC_CURVE) {
        static const uint8_t parameter_count[5] = {1u, 3u, 4u, 5u, 7u};
        uint32_t function;
        uint32_t count;
        if (tag->size < 16u || !icc_all_zero(element + 10u, 2u)) return 0u;
        function = icc_be16(element + 8u);
        if (function > 4u) {
            *result = RIN_ICC_DISPLAY_PROFILE_UNSUPPORTED;
            return 0u;
        }
        count = parameter_count[function];
        if (tag->size != 12u + count * 4u) return 0u;
        for (uint32_t index = 0u; index < count; ++index) {
            int32_t value = icc_be_s32(element + 12u + index * 4u);
            if (!icc_fixed_bounded(value)) return 0u;
            curve->parameters_s15_fixed16[index] = value;
        }
        if (curve->parameters_s15_fixed16[0] <= 0 ||
            curve->parameters_s15_fixed16[0] > ICC_FIXED16_LIMIT ||
            (function >= 1u &&
             (curve->parameters_s15_fixed16[1] <= 0 ||
              curve->parameters_s15_fixed16[2] < 0)) ||
            (function >= 3u &&
             (curve->parameters_s15_fixed16[3] <= 0 ||
              curve->parameters_s15_fixed16[4] < 0 ||
              curve->parameters_s15_fixed16[4] > 65536))) {
            return 0u;
        }
        curve->kind = RIN_ICC_CURVE_PARAMETRIC;
        curve->function_type = function;
        curve->entry_count = count;
        return 1u;
    }
    *result = RIN_ICC_DISPLAY_PROFILE_UNSUPPORTED;
    return 0u;
}

static uint32_t icc_matrix_valid(const int32_t matrix[9]) {
    int64_t positive;
    int64_t negative;
    int64_t determinant;
    for (uint32_t index = 0u; index < 9u; ++index) {
        if (!icc_fixed_bounded(matrix[index])) return 0u;
    }
    positive = (int64_t)matrix[0] * matrix[4] * matrix[8] +
               (int64_t)matrix[1] * matrix[5] * matrix[6] +
               (int64_t)matrix[2] * matrix[3] * matrix[7];
    negative = (int64_t)matrix[2] * matrix[4] * matrix[6] +
               (int64_t)matrix[1] * matrix[3] * matrix[8] +
               (int64_t)matrix[0] * matrix[5] * matrix[7];
    determinant = positive - negative;
    return determinant > (int64_t)(1u << 20u) ||
           determinant < -(int64_t)(1u << 20u);
}

static uint32_t icc_s15_array_read(const uint8_t* bytes,
                                   const IccTagEntry* tag,
                                   int32_t output[9]) {
    const uint8_t* element = bytes + tag->offset;
    if (tag->size != 44u ||
        icc_be32(element) != ICC_TYPE_S15_FIXED16_ARRAY) {
        return 0u;
    }
    for (uint32_t index = 0u; index < 9u; ++index) {
        output[index] = icc_be_s32(element + 8u + index * 4u);
        if (!icc_fixed_bounded(output[index])) return 0u;
    }
    return 1u;
}

RinIccDisplayProfileResult rin_icc_display_profile_admit(
    const uint8_t* bytes, uint32_t length,
    uint8_t* snapshot, uint32_t snapshot_capacity,
    RinIccDisplayProfileV1* profile) {
    static const uint32_t xyz_signatures[3] = {
        ICC_TAG_RED_XYZ, ICC_TAG_GREEN_XYZ, ICC_TAG_BLUE_XYZ
    };
    static const uint32_t trc_signatures[3] = {
        ICC_TAG_RED_TRC, ICC_TAG_GREEN_TRC, ICC_TAG_BLUE_TRC
    };
    IccTagEntry tags[RIN_ICC_DISPLAY_PROFILE_MAX_TAGS];
    RinIccDisplayProfileV1 candidate;
    RinIccDisplayProfileResult result = RIN_ICC_DISPLAY_PROFILE_OK;
    uint32_t tag_count = 0u;
    const IccTagEntry* description;
    const IccTagEntry* copyright;
    const IccTagEntry* white_point;
    const IccTagEntry* adaptation;

    if (!profile) return RIN_ICC_DISPLAY_PROFILE_INVALID_ARGUMENT;
    if (!bytes || !snapshot || length < ICC_HEADER_SIZE + 4u ||
        length > RIN_ICC_DISPLAY_PROFILE_MAX_BYTES ||
        snapshot_capacity < length ||
        icc_ranges_overlap(bytes, length, snapshot, length) ||
        icc_ranges_overlap(bytes, length, profile, sizeof(*profile)) ||
        icc_ranges_overlap(snapshot, length, profile, sizeof(*profile))) {
        icc_zero(profile, sizeof(*profile));
        return length > RIN_ICC_DISPLAY_PROFILE_MAX_BYTES
            ? RIN_ICC_DISPLAY_PROFILE_LIMIT_EXCEEDED
            : RIN_ICC_DISPLAY_PROFILE_INVALID_ARGUMENT;
    }
    icc_zero(profile, sizeof(*profile));
    icc_copy(snapshot, bytes, length);
    if (!icc_header_valid(snapshot, length, &result)) return result;
    result = icc_read_tag_table(snapshot, length, tags, &tag_count);
    if (result != RIN_ICC_DISPLAY_PROFILE_OK) return result;

    description = icc_find_tag(tags, tag_count, ICC_TAG_DESCRIPTION);
    copyright = icc_find_tag(tags, tag_count, ICC_TAG_COPYRIGHT);
    white_point = icc_find_tag(tags, tag_count, ICC_TAG_WHITE_POINT);
    if (!description || !copyright || !white_point ||
        !icc_mluc_valid(snapshot, description) ||
        !icc_mluc_valid(snapshot, copyright)) {
        return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
    }

    icc_zero(&candidate, sizeof(candidate));
    candidate.abi_version = RIN_ICC_DISPLAY_PROFILE_ABI_VERSION;
    candidate.struct_size = sizeof(candidate);
    candidate.profile_size = length;
    candidate.profile_version = icc_be32(snapshot + 8u);
    candidate.rendering_intent = icc_be32(snapshot + 64u);
    candidate.tag_count = tag_count;
    icc_copy(candidate.profile_id, snapshot + 84u,
             sizeof(candidate.profile_id));
    if (!icc_all_zero(candidate.profile_id, sizeof(candidate.profile_id))) {
        candidate.flags |= RIN_ICC_DISPLAY_PROFILE_HAS_PROFILE_ID;
    }
    if (!icc_xyz_read(snapshot, white_point,
                      candidate.media_white_xyz_s15_fixed16) ||
        candidate.media_white_xyz_s15_fixed16[0] <= 0 ||
        candidate.media_white_xyz_s15_fixed16[1] <= 0 ||
        candidate.media_white_xyz_s15_fixed16[2] <= 0 ||
        candidate.media_white_xyz_s15_fixed16[0] > ICC_WHITE_LIMIT ||
        candidate.media_white_xyz_s15_fixed16[1] > ICC_WHITE_LIMIT ||
        candidate.media_white_xyz_s15_fixed16[2] > ICC_WHITE_LIMIT) {
        return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
    }

    for (uint32_t channel = 0u; channel < 3u; ++channel) {
        const IccTagEntry* xyz =
            icc_find_tag(tags, tag_count, xyz_signatures[channel]);
        const IccTagEntry* trc =
            icc_find_tag(tags, tag_count, trc_signatures[channel]);
        int32_t column[3];
        if (!xyz || !trc || !icc_xyz_read(snapshot, xyz, column) ||
            !icc_curve_read(snapshot, trc, &candidate.curves[channel],
                            &result)) {
            return result == RIN_ICC_DISPLAY_PROFILE_OK
                ? RIN_ICC_DISPLAY_PROFILE_MALFORMED : result;
        }
        for (uint32_t row = 0u; row < 3u; ++row) {
            candidate.rgb_to_pcs_s15_fixed16[row * 3u + channel] =
                column[row];
        }
    }
    if (!icc_matrix_valid(candidate.rgb_to_pcs_s15_fixed16)) {
        return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
    }

    adaptation = icc_find_tag(tags, tag_count,
                              ICC_TAG_CHROMATIC_ADAPTATION);
    if (adaptation) {
        if (!icc_s15_array_read(snapshot, adaptation,
                                candidate.chromatic_adaptation_s15_fixed16)) {
            return RIN_ICC_DISPLAY_PROFILE_MALFORMED;
        }
        candidate.flags |=
            RIN_ICC_DISPLAY_PROFILE_HAS_CHROMATIC_ADAPTATION;
    }
    *profile = candidate;
    return RIN_ICC_DISPLAY_PROFILE_OK;
}
