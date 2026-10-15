/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_SHARED_ICC_DISPLAY_PROFILE_V1_H
#define RIN_SHARED_ICC_DISPLAY_PROFILE_V1_H

#include <stdint.h>

#define RIN_ICC_DISPLAY_PROFILE_ABI_VERSION 1u
#define RIN_ICC_DISPLAY_PROFILE_MAX_BYTES (1024u * 1024u)
#define RIN_ICC_DISPLAY_PROFILE_MAX_TAGS 128u
#define RIN_ICC_DISPLAY_PROFILE_MAX_CURVE_ENTRIES 4096u

#define RIN_ICC_DISPLAY_PROFILE_HAS_PROFILE_ID (1u << 0)
#define RIN_ICC_DISPLAY_PROFILE_HAS_CHROMATIC_ADAPTATION (1u << 1)

#define RIN_ICC_CURVE_IDENTITY 0u
#define RIN_ICC_CURVE_GAMMA 1u
#define RIN_ICC_CURVE_SAMPLED 2u
#define RIN_ICC_CURVE_PARAMETRIC 3u

typedef enum RinIccDisplayProfileResult {
    RIN_ICC_DISPLAY_PROFILE_OK = 0,
    RIN_ICC_DISPLAY_PROFILE_INVALID_ARGUMENT = -1,
    RIN_ICC_DISPLAY_PROFILE_MALFORMED = -2,
    RIN_ICC_DISPLAY_PROFILE_UNSUPPORTED = -3,
    RIN_ICC_DISPLAY_PROFILE_LIMIT_EXCEEDED = -4
} RinIccDisplayProfileResult;

typedef struct RinIccCurveV1 {
    uint32_t kind;
    uint32_t tag_offset;
    uint32_t tag_size;
    uint32_t entry_count;
    uint32_t function_type;
    int32_t parameters_s15_fixed16[7];
} RinIccCurveV1;

typedef struct RinIccDisplayProfileV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t profile_size;
    uint32_t profile_version;
    uint32_t rendering_intent;
    uint32_t flags;
    uint32_t tag_count;
    uint8_t profile_id[16];
    int32_t media_white_xyz_s15_fixed16[3];
    /* Row-major RGB-to-PCS matrix. ICC rXYZ/gXYZ/bXYZ are its columns. */
    int32_t rgb_to_pcs_s15_fixed16[9];
    int32_t chromatic_adaptation_s15_fixed16[9];
    RinIccCurveV1 curves[3];
    uint32_t reserved[4];
} RinIccDisplayProfileV1;

/*
 * Copies bytes into a disjoint caller-owned snapshot before parsing. On
 * success the snapshot is the canonical profile storage and must remain
 * immutable while tag_offset/tag_size values are in use.
 */
RinIccDisplayProfileResult rin_icc_display_profile_admit(
    const uint8_t* bytes, uint32_t length,
    uint8_t* snapshot, uint32_t snapshot_capacity,
    RinIccDisplayProfileV1* profile);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinIccCurveV1) == 48u, "ICC curve ABI drift");
_Static_assert(sizeof(RinIccDisplayProfileV1) == 288u,
               "ICC display profile ABI drift");
#endif

#endif
