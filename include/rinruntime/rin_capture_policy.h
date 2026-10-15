/* SPDX-License-Identifier: MIT */
/* Shared validator for the fixed privacy-gated capture chunk ABI. */

#ifndef RIN_SHARED_RIN_CAPTURE_POLICY_H
#define RIN_SHARED_RIN_CAPTURE_POLICY_H

#include <stdint.h>

#include <rin/capture.h>
#include <rin/resource/capability.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_capture_chunk_v1_is_valid(
    uint32_t resource,
    const RinCaptureChunkV1* chunk,
    uint32_t transferred);

int rin_capture_transport_profile_v1_is_valid(
    uint32_t resource,
    const RinCaptureTransportProfileV1* profile);

#ifdef __cplusplus
}
#endif

#endif /* RIN_SHARED_RIN_CAPTURE_POLICY_H */
