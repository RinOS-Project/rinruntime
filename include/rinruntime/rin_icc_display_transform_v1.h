/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_SHARED_ICC_DISPLAY_TRANSFORM_V1_H
#define RIN_SHARED_ICC_DISPLAY_TRANSFORM_V1_H

#include <stdint.h>

#include "rin_icc_display_profile_v1.h"

typedef enum RinIccDisplayTransformResult {
    RIN_ICC_DISPLAY_TRANSFORM_OK = 0,
    RIN_ICC_DISPLAY_TRANSFORM_INVALID_ARGUMENT = -1,
    RIN_ICC_DISPLAY_TRANSFORM_MALFORMED = -2,
    RIN_ICC_DISPLAY_TRANSFORM_UNSUPPORTED = -3,
    RIN_ICC_DISPLAY_TRANSFORM_LIMIT_EXCEEDED = -4
} RinIccDisplayTransformResult;

/*
 * Applies an admitted RGB display profile to a bounded 16-bit RGB sample.
 * Identity and sampled TRCs are evaluated before the profile matrix and the
 * optional chromatic-adaptation matrix.  The snapshot and descriptor are
 * immutable; output is zeroed before any failure is returned.
 */
RinIccDisplayTransformResult rin_icc_display_transform_apply_v1(
    const uint8_t* snapshot, uint32_t snapshot_size,
    const RinIccDisplayProfileV1* profile,
    const uint16_t input_rgb[3], uint16_t output_xyz[3]);

#endif /* RIN_SHARED_ICC_DISPLAY_TRANSFORM_V1_H */
