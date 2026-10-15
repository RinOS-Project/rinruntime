/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_RIN_TRUST_STORE_BUNDLE_V1_H
#define RIN_SHARED_RIN_TRUST_STORE_BUNDLE_V1_H

#include "rin_trust_store_update.h"

#include <stdint.h>

/* RCA1 is the bounded, canonical root-certificate container emitted by the
 * installer.  The update owner still delegates signature, issuer and scope
 * checks to its authenticated verifier; this boundary only proves that the
 * bytes have a complete, unambiguous certificate framing before any callback
 * or state mutation is attempted. */
#define RIN_TRUST_STORE_BUNDLE_VERSION UINT32_C(0x00010000)
#define RIN_TRUST_STORE_BUNDLE_MAX_CERTIFICATES UINT32_C(256)
#define RIN_TRUST_STORE_BUNDLE_MAX_CERTIFICATE_BYTES UINT32_C(65535)
#define RIN_TRUST_STORE_BUNDLE_HEADER_BYTES UINT32_C(8)
#define RIN_TRUST_STORE_BUNDLE_RECORD_HEADER_BYTES UINT32_C(4)

typedef enum RinTrustStoreBundleStatus {
    RIN_TRUST_STORE_BUNDLE_OK = 0,
    RIN_TRUST_STORE_BUNDLE_INVALID = -1,
    RIN_TRUST_STORE_BUNDLE_UPDATE_FAILED = -2
} RinTrustStoreBundleStatus;

/* `bundle` is never retained.  `certificate_count_out` may be NULL when the
 * caller only needs admission. */
RinTrustStoreBundleStatus rin_trust_store_bundle_validate_v1(
    const uint8_t* bundle, uint32_t bundle_bytes,
    uint32_t* certificate_count_out);

/* Validate the RCA1 framing, then run the existing authenticated update owner.
 * No verifier/commit callback is entered for malformed framing. */
RinTrustStoreBundleStatus rin_trust_store_bundle_apply_v1(
    RinTrustStoreUpdateOwnerV1* owner, const uint8_t* bundle,
    uint32_t bundle_bytes, uint64_t sequence,
    RinTrustStoreUpdateReceiptV1* receipt_out);

#endif /* RIN_SHARED_RIN_TRUST_STORE_BUNDLE_V1_H */
