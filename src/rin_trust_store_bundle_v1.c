/* SPDX-License-Identifier: MIT */

#include "rin_trust_store_bundle_v1.h"

#include <stddef.h>

static uint32_t bundle_read_le32(const uint8_t* value)
{
    return (uint32_t)value[0] | ((uint32_t)value[1] << 8) |
           ((uint32_t)value[2] << 16) | ((uint32_t)value[3] << 24);
}

/* Parse only the DER outer TLV.  A certificate verifier owns the inner
 * certificate semantics, but accepting an indefinite or truncated outer
 * sequence here would make the persisted bundle ambiguous. */
static int bundle_der_outer_length(const uint8_t* der, uint32_t der_bytes,
                                   uint32_t* encoded_bytes)
{
    uint32_t content_bytes;
    uint32_t header_bytes;
    uint8_t length_octet;

    if (der == NULL || encoded_bytes == NULL || der_bytes < 2u ||
        der[0] != 0x30u)
        return 0;
    length_octet = der[1];
    if (length_octet < 0x80u) {
        content_bytes = length_octet;
        header_bytes = 2u;
    } else {
        const uint32_t length_octets = length_octet & 0x7fu;
        if (length_octets == 0u || length_octets > 2u ||
            2u + length_octets > der_bytes || der[2] == 0u)
            return 0;
        content_bytes = 0u;
        for (uint32_t index = 0u; index < length_octets; ++index) {
            if (content_bytes > UINT32_MAX / 256u) return 0;
            content_bytes = (content_bytes << 8) | der[2u + index];
        }
        if (content_bytes < 0x80u) return 0;
        header_bytes = 2u + length_octets;
    }
    if (content_bytes > der_bytes - header_bytes) return 0;
    *encoded_bytes = header_bytes + content_bytes;
    return *encoded_bytes == der_bytes;
}

RinTrustStoreBundleStatus rin_trust_store_bundle_validate_v1(
    const uint8_t* bundle, uint32_t bundle_bytes,
    uint32_t* certificate_count_out)
{
    uint32_t count;
    uint32_t offset;

    if (certificate_count_out != NULL) *certificate_count_out = 0u;
    if (bundle == NULL || bundle_bytes < RIN_TRUST_STORE_BUNDLE_HEADER_BYTES ||
        bundle_bytes > RIN_TRUST_STORE_UPDATE_MAX_BUNDLE_BYTES ||
        bundle[0] != 'R' || bundle[1] != 'C' || bundle[2] != 'A' ||
        bundle[3] != '1')
        return RIN_TRUST_STORE_BUNDLE_INVALID;
    count = bundle_read_le32(bundle + 4u);
    if (count == 0u || count > RIN_TRUST_STORE_BUNDLE_MAX_CERTIFICATES)
        return RIN_TRUST_STORE_BUNDLE_INVALID;
    offset = RIN_TRUST_STORE_BUNDLE_HEADER_BYTES;
    for (uint32_t index = 0u; index < count; ++index) {
        uint32_t certificate_bytes;
        uint32_t encoded_bytes;
        if (offset > bundle_bytes ||
            bundle_bytes - offset < RIN_TRUST_STORE_BUNDLE_RECORD_HEADER_BYTES)
            return RIN_TRUST_STORE_BUNDLE_INVALID;
        certificate_bytes = bundle_read_le32(bundle + offset);
        offset += RIN_TRUST_STORE_BUNDLE_RECORD_HEADER_BYTES;
        if (certificate_bytes == 0u ||
            certificate_bytes > RIN_TRUST_STORE_BUNDLE_MAX_CERTIFICATE_BYTES ||
            certificate_bytes > bundle_bytes - offset ||
            !bundle_der_outer_length(bundle + offset, certificate_bytes,
                                      &encoded_bytes))
            return RIN_TRUST_STORE_BUNDLE_INVALID;
        offset += certificate_bytes;
    }
    if (offset != bundle_bytes) return RIN_TRUST_STORE_BUNDLE_INVALID;
    if (certificate_count_out != NULL) *certificate_count_out = count;
    return RIN_TRUST_STORE_BUNDLE_OK;
}

RinTrustStoreBundleStatus rin_trust_store_bundle_apply_v1(
    RinTrustStoreUpdateOwnerV1* owner, const uint8_t* bundle,
    uint32_t bundle_bytes, uint64_t sequence,
    RinTrustStoreUpdateReceiptV1* receipt_out)
{
    if (rin_trust_store_bundle_validate_v1(bundle, bundle_bytes, NULL) !=
        RIN_TRUST_STORE_BUNDLE_OK)
        return RIN_TRUST_STORE_BUNDLE_INVALID;
    return rin_trust_store_update_apply(owner, bundle, bundle_bytes, sequence,
                                        receipt_out) ==
            RIN_TRUST_STORE_UPDATE_OK
        ? RIN_TRUST_STORE_BUNDLE_OK
        : RIN_TRUST_STORE_BUNDLE_UPDATE_FAILED;
}
