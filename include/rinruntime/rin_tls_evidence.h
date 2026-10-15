/* SPDX-License-Identifier: MIT */
/* Verified TLS peer evidence shared with package/update transports. */

#ifndef RIN_SHARED_TLS_EVIDENCE_H
#define RIN_SHARED_TLS_EVIDENCE_H

#include <stdint.h>

#define RIN_TLS_EVIDENCE_VERSION UINT32_C(0x00010000)
#define RIN_TLS_EVIDENCE_CHAIN_VERIFIED UINT32_C(0x00000001)
#define RIN_TLS_EVIDENCE_HOSTNAME_VERIFIED UINT32_C(0x00000002)
#define RIN_TLS_EVIDENCE_TRUSTED_TIME UINT32_C(0x00000004)
#define RIN_TLS_EVIDENCE_REQUIRED UINT32_C(0x00000007)
#define RIN_TLS_EVIDENCE_ALL RIN_TLS_EVIDENCE_REQUIRED

typedef struct RinTlsPeerEvidenceV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t evidence_flags;
    uint32_t tls_version;
    uint32_t cipher_suite;
    uint32_t reserved0;
    uint64_t trusted_unix_time;
    uint8_t peer_certificate_sha256[32];
    char peer_dns_name[256];
    uint64_t reserved[2];
} RinTlsPeerEvidenceV1;

#define RIN_TLS_CERTIFICATE_BINDING_VERSION UINT32_C(0x00010000)
#define RIN_TLS_CERTIFICATE_BINDING_LEAF UINT32_C(0x00000001)
#define RIN_TLS_CERTIFICATE_BINDING_ISSUER UINT32_C(0x00000002)
#define RIN_TLS_CERTIFICATE_BINDING_REQUIRED \
    (RIN_TLS_CERTIFICATE_BINDING_LEAF | RIN_TLS_CERTIFICATE_BINDING_ISSUER)

/* The issuer digest is available only when the authenticated peer sent the
 * immediate issuer certificate.  Consumers must not infer it from a trust
 * anchor or a subject name before accepting revocation evidence. */
typedef struct RinTlsCertificateBindingV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t binding_flags;
    uint32_t reserved0;
    uint8_t leaf_sha256[32];
    uint8_t issuer_sha256[32];
    uint64_t reserved[2];
} RinTlsCertificateBindingV1;

#define RIN_TLS_REVOCATION_ENDPOINTS_VERSION UINT32_C(0x00010000)
#define RIN_TLS_MAX_REVOCATION_URL_BYTES UINT32_C(256)

/* Certificate-discovered locations are transport input, not revocation
 * evidence. A caller must authenticate OCSP/CRL data against the same peer
 * certificate and trusted-time policy before accepting it. */
typedef struct RinTlsRevocationEndpointsV1 {
    uint32_t struct_size;
    uint32_t version;
    char ocsp_url[RIN_TLS_MAX_REVOCATION_URL_BYTES];
    char crl_url[RIN_TLS_MAX_REVOCATION_URL_BYTES];
    uint64_t reserved[2];
} RinTlsRevocationEndpointsV1;

#ifdef __cplusplus
static_assert(sizeof(RinTlsPeerEvidenceV1) == 336u,
              "RinTlsPeerEvidenceV1 ABI drift");
static_assert(sizeof(RinTlsCertificateBindingV1) == 96u,
              "RinTlsCertificateBindingV1 ABI drift");
static_assert(sizeof(RinTlsRevocationEndpointsV1) == 536u,
              "RinTlsRevocationEndpointsV1 ABI drift");
#else
_Static_assert(sizeof(RinTlsPeerEvidenceV1) == 336u,
               "RinTlsPeerEvidenceV1 ABI drift");
_Static_assert(sizeof(RinTlsCertificateBindingV1) == 96u,
               "RinTlsCertificateBindingV1 ABI drift");
_Static_assert(sizeof(RinTlsRevocationEndpointsV1) == 536u,
               "RinTlsRevocationEndpointsV1 ABI drift");
#endif

#endif /* RIN_SHARED_TLS_EVIDENCE_H */
