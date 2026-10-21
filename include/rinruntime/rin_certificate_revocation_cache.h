/* SPDX-License-Identifier: MIT */
/* Bounded generation-bound cache for already authenticated revocation evidence. */

#ifndef RIN_SHARED_RIN_CERTIFICATE_REVOCATION_CACHE_H
#define RIN_SHARED_RIN_CERTIFICATE_REVOCATION_CACHE_H

#include "rin_certificate_revocation.h"
#include "cxx_compat.h"

#include <stdint.h>

#define RIN_CERTIFICATE_REVOCATION_CACHE_VERSION UINT32_C(0x00010000)
#define RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY UINT32_C(16)

typedef enum RinCertificateRevocationCacheResult {
    RIN_CERTIFICATE_REVOCATION_CACHE_OK = 0,
    RIN_CERTIFICATE_REVOCATION_CACHE_INVALID = -1,
    RIN_CERTIFICATE_REVOCATION_CACHE_NOT_FOUND = -2,
    RIN_CERTIFICATE_REVOCATION_CACHE_FULL = -3,
    RIN_CERTIFICATE_REVOCATION_CACHE_CONFLICT = -4,
    RIN_CERTIFICATE_REVOCATION_CACHE_STALE = -5,
    RIN_CERTIFICATE_REVOCATION_CACHE_FUTURE = -6,
    RIN_CERTIFICATE_REVOCATION_CACHE_REVOKED = -7,
    RIN_CERTIFICATE_REVOCATION_CACHE_UNAVAILABLE = -8
} RinCertificateRevocationCacheResult;

typedef struct RinCertificateRevocationCacheSlotV1 {
    uint32_t active;
    uint32_t reserved0;
    uint8_t certificate_sha256[32];
    uint8_t issuer_sha256[32];
    RinCertificateRevocationEvidenceV1 evidence;
} RinCertificateRevocationCacheSlotV1;

typedef struct RinCertificateRevocationCacheV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t generation;
    uint32_t active_count;
    uint32_t reserved0;
    uint64_t next_sequence;
    RinCertificateRevocationCacheSlotV1 slots[
        RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY];
    uint64_t reserved[2];
} RinCertificateRevocationCacheV1;

RinCertificateRevocationCacheResult
rin_certificate_revocation_cache_initialize(
    RinCertificateRevocationCacheV1* cache, uint64_t generation);

RinCertificateRevocationCacheResult rin_certificate_revocation_cache_put(
    RinCertificateRevocationCacheV1* cache,
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32], const uint8_t issuer_sha256[32],
    const RinCertificateRevocationEvidenceV1* evidence);

RinCertificateRevocationCacheResult rin_certificate_revocation_cache_lookup(
    const RinCertificateRevocationCacheV1* cache,
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32], const uint8_t issuer_sha256[32],
    RinCertificateRevocationEvidenceV1* evidence_out);

RINRUNTIME_STATIC_ASSERT(sizeof(RinCertificateRevocationCacheSlotV1) == 208u,
                          "certificate revocation cache slot ABI drift");
RINRUNTIME_STATIC_ASSERT(sizeof(RinCertificateRevocationCacheV1) == 3376u,
                          "certificate revocation cache ABI drift");

#endif /* RIN_SHARED_RIN_CERTIFICATE_REVOCATION_CACHE_H */
