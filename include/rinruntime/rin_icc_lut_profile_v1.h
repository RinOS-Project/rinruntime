/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_ICC_LUT_PROFILE_V1_H
#define RIN_SHARED_ICC_LUT_PROFILE_V1_H

#include <stdint.h>

#define RIN_ICC_LUT_PROFILE_ABI_VERSION 1u
#define RIN_ICC_LUT_PROFILE_MAX_BYTES (1024u * 1024u)
#define RIN_ICC_LUT_PROFILE_MAX_TAGS 128u
#define RIN_ICC_LUT_PROFILE_MAX_GRID_POINTS 17u
#define RIN_ICC_LUT_PROFILE_MAX_TABLE_ENTRIES 4096u

typedef enum RinIccLutProfileResult {
    RIN_ICC_LUT_PROFILE_OK = 0,
    RIN_ICC_LUT_PROFILE_INVALID_ARGUMENT = -1,
    RIN_ICC_LUT_PROFILE_MALFORMED = -2,
    RIN_ICC_LUT_PROFILE_UNSUPPORTED = -3,
    RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED = -4
} RinIccLutProfileResult;

typedef enum RinIccLutProfileType {
    RIN_ICC_LUT_PROFILE_MFT1 = 1u,
    RIN_ICC_LUT_PROFILE_MFT2 = 2u
} RinIccLutProfileType;

/* Offsets refer to the immutable caller-owned snapshot supplied to admit(). */
typedef struct RinIccLutProfileV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t profile_size;
    uint32_t tag_offset;
    uint32_t tag_size;
    uint32_t tag_signature;
    uint32_t tag_type;
    uint32_t input_channels;
    uint32_t output_channels;
    uint32_t grid_points;
    int32_t matrix_s15_fixed16[9];
    uint32_t input_table_offset;
    uint32_t input_table_entries;
    uint32_t input_table_entry_bytes;
    uint32_t clut_offset;
    uint32_t clut_entry_count;
    uint32_t clut_entry_bytes;
    uint32_t output_table_offset;
    uint32_t output_table_entries;
    uint32_t output_table_entry_bytes;
    uint32_t reserved[4];
} RinIccLutProfileV1;

RinIccLutProfileResult rin_icc_lut_profile_admit(
    const uint8_t* bytes, uint32_t length,
    uint8_t* snapshot, uint32_t snapshot_capacity,
    RinIccLutProfileV1* profile);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinIccLutProfileV1) == 128u,
               "ICC LUT profile ABI drift");
#endif

#endif /* RIN_SHARED_ICC_LUT_PROFILE_V1_H */
