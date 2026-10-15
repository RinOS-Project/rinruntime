/* SPDX-License-Identifier: MIT */
/* Bounded font-scale packing shared by GUI clients and kernel owners. */
#ifndef RIN_SHARED_RIN_GUI_TEXT_POLICY_H
#define RIN_SHARED_RIN_GUI_TEXT_POLICY_H

#include <stdint.h>

#define RIN_GUI_V2_TEXT_SCALE_PACK(numerator, denominator) \
    ((((uint32_t)(numerator) & UINT32_C(0xffff)) << 16) | \
     ((uint32_t)(denominator) & UINT32_C(0xffff)))

static inline int rin_gui_v2_text_scale_valid(uint32_t numerator,
                                              uint32_t denominator)
{
    return numerator != 0u && denominator != 0u &&
           numerator <= UINT32_C(0xffff) && denominator <= UINT32_C(0xffff) &&
           (uint64_t)numerator <= (uint64_t)denominator * 8u &&
           (uint64_t)denominator <= (uint64_t)numerator * 8u;
}

static inline int rin_gui_v2_text_scale_unpack(uint32_t packed,
                                               uint32_t* numerator,
                                               uint32_t* denominator)
{
    uint32_t num = packed == 0u ? 1u : packed >> 16;
    uint32_t den = packed == 0u ? 1u : packed & UINT32_C(0xffff);
    if (!rin_gui_v2_text_scale_valid(num, den))
        return 0;
    if (numerator) *numerator = num;
    if (denominator) *denominator = den;
    return 1;
}

#endif
