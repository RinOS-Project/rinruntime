/* SPDX-License-Identifier: MIT */
/* Shared fail-closed OCSP/CRL evidence policy for TLS consumers. */

#ifndef RIN_SHARED_RIN_CERTIFICATE_REVOCATION_H
#define RIN_SHARED_RIN_CERTIFICATE_REVOCATION_H

#include <stdint.h>

#define RIN_CERTIFICATE_REVOCATION_VERSION UINT32_C(0x00010000)

#define RIN_CERTIFICATE_REVOCATION_SOURCE_OCSP UINT32_C(1)
#define RIN_CERTIFICATE_REVOCATION_SOURCE_CRL UINT32_C(2)

#define RIN_CERTIFICATE_REVOCATION_STATUS_GOOD UINT32_C(1)
#define RIN_CERTIFICATE_REVOCATION_STATUS_REVOKED UINT32_C(2)
#define RIN_CERTIFICATE_REVOCATION_STATUS_UNKNOWN UINT32_C(3)

#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_SIGNATURE_VERIFIED \
    UINT32_C(0x00000001)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_CERTIFICATE_MATCHED \
    UINT32_C(0x00000002)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_ISSUER_MATCHED \
    UINT32_C(0x00000004)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_AUTHORITY_AUTHORIZED \
    UINT32_C(0x00000008)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_NONCE_VERIFIED \
    UINT32_C(0x00000010)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_REQUIRED \
    (RIN_CERTIFICATE_REVOCATION_EVIDENCE_SIGNATURE_VERIFIED | \
     RIN_CERTIFICATE_REVOCATION_EVIDENCE_CERTIFICATE_MATCHED | \
     RIN_CERTIFICATE_REVOCATION_EVIDENCE_ISSUER_MATCHED | \
     RIN_CERTIFICATE_REVOCATION_EVIDENCE_AUTHORITY_AUTHORIZED)
#define RIN_CERTIFICATE_REVOCATION_EVIDENCE_ALL \
    (RIN_CERTIFICATE_REVOCATION_EVIDENCE_REQUIRED | \
     RIN_CERTIFICATE_REVOCATION_EVIDENCE_NONCE_VERIFIED)

#define RIN_CERTIFICATE_REVOCATION_POLICY_REQUIRE_OCSP_NONCE \
    UINT32_C(0x00000001)
#define RIN_CERTIFICATE_REVOCATION_POLICY_ALL \
    RIN_CERTIFICATE_REVOCATION_POLICY_REQUIRE_OCSP_NONCE

#define RIN_CERTIFICATE_REVOCATION_OCSP_MAX_VALIDITY_SECONDS \
    UINT64_C(604800)
#define RIN_CERTIFICATE_REVOCATION_CRL_MAX_VALIDITY_SECONDS \
    UINT64_C(2592000)

typedef struct RinCertificateRevocationEvidenceV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t status;
    uint32_t source;
    uint32_t evidence_flags;
    uint32_t reserved0;
    uint64_t this_update_unix_time;
    uint64_t next_update_unix_time;
    uint64_t produced_at_unix_time;
    uint8_t certificate_sha256[32];
    uint8_t issuer_sha256[32];
    uint64_t sequence;
    uint64_t reserved[2];
} RinCertificateRevocationEvidenceV1;

typedef struct RinCertificateRevocationPolicyV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t trusted_unix_time;
    uint64_t maximum_ocsp_validity_seconds;
    uint64_t maximum_crl_validity_seconds;
    uint32_t required_evidence_flags;
    uint32_t policy_flags;
    uint64_t reserved[2];
} RinCertificateRevocationPolicyV1;

typedef enum RinCertificateRevocationResult {
    RIN_CERTIFICATE_REVOCATION_OK = 0,
    RIN_CERTIFICATE_REVOCATION_INVALID = -1,
    RIN_CERTIFICATE_REVOCATION_UNAVAILABLE = -2,
    RIN_CERTIFICATE_REVOCATION_REVOKED = -3,
    RIN_CERTIFICATE_REVOCATION_STALE = -4,
    RIN_CERTIFICATE_REVOCATION_FUTURE = -5,
    RIN_CERTIFICATE_REVOCATION_SCOPE_MISMATCH = -6,
    RIN_CERTIFICATE_REVOCATION_UNSUPPORTED = -7
} RinCertificateRevocationResult;

RinCertificateRevocationResult rin_certificate_revocation_policy_initialize(
    RinCertificateRevocationPolicyV1* policy,
    uint64_t trusted_unix_time);

int rin_certificate_revocation_policy_valid(
    const RinCertificateRevocationPolicyV1* policy);

/* `certificate_sha256` must be derived from the leaf certificate used by the
 * same authenticated TLS connection.  The evidence producer is responsible
 * for OCSP/CRL signature, CertID/issuer, and responder authorization checks;
 * this boundary revalidates their exact evidence, scope, and trusted-time
 * lifetime before any response body is consumed. */
RinCertificateRevocationResult rin_certificate_revocation_validate(
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32],
    const RinCertificateRevocationEvidenceV1* evidence);

_Static_assert(sizeof(RinCertificateRevocationEvidenceV1) == 136u,
               "certificate revocation evidence ABI drift");
_Static_assert(sizeof(RinCertificateRevocationPolicyV1) == 56u,
               "certificate revocation policy ABI drift");

#endif /* RIN_SHARED_RIN_CERTIFICATE_REVOCATION_H */
