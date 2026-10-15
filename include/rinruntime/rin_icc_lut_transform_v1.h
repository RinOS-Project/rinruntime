/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_ICC_LUT_TRANSFORM_V1_H
#define RIN_SHARED_ICC_LUT_TRANSFORM_V1_H

#include <stdint.h>

#include "rin_icc_lut_profile_v1.h"

typedef enum RinIccLutTransformResult {
    RIN_ICC_LUT_TRANSFORM_OK = 0,
    RIN_ICC_LUT_TRANSFORM_INVALID_ARGUMENT = -1,
    RIN_ICC_LUT_TRANSFORM_MALFORMED = -2,
    RIN_ICC_LUT_TRANSFORM_UNSUPPORTED = -3,
    RIN_ICC_LUT_TRANSFORM_LIMIT_EXCEEDED = -4
} RinIccLutTransformResult;

/*
 * Applies an admitted mft1/mft2 snapshot using a bounded 16-bit path.  The
 * snapshot and profile are read-only; output is zeroed before any failure is
 * returned.  The input and output arrays must be disjoint from each other,
 * the snapshot, and the profile descriptor.
 */
RinIccLutTransformResult rin_icc_lut_transform_apply_v1(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccLutProfileV1* profile,
    const uint16_t input[3], uint16_t output[3]);

#endif /* RIN_SHARED_ICC_LUT_TRANSFORM_V1_H */
