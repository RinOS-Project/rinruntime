/* SPDX-License-Identifier: MIT */

#include "rin_certificate_revocation.h"

#include <stddef.h>

static void revocation_zero(void* destination, size_t size)
{
    uint8_t* bytes = (uint8_t*)destination;
    if (destination == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int revocation_all_zero(const void* value, size_t size)
{
    const uint8_t* bytes = (const uint8_t*)value;
    uint8_t observed = 0u;
    if (value == NULL) return 1;
    while (size-- != 0u) observed |= *bytes++;
    return observed == 0u;
}

static int revocation_equal(const void* left, const void* right, size_t size)
{
    const uint8_t* left_bytes = (const uint8_t*)left;
    const uint8_t* right_bytes = (const uint8_t*)right;
    uint8_t difference = 0u;
    if (left == NULL || right == NULL) return 0;
    while (size-- != 0u)
        difference |= (uint8_t)(*left_bytes++ ^ *right_bytes++);
    return difference == 0u;
}

int rin_certificate_revocation_policy_valid(
    const RinCertificateRevocationPolicyV1* policy)
{
    return policy != NULL && policy->struct_size == sizeof(*policy) &&
           policy->version == RIN_CERTIFICATE_REVOCATION_VERSION &&
           policy->trusted_unix_time != 0u &&
           policy->maximum_ocsp_validity_seconds != 0u &&
           policy->maximum_ocsp_validity_seconds <=
               RIN_CERTIFICATE_REVOCATION_OCSP_MAX_VALIDITY_SECONDS &&
           policy->maximum_crl_validity_seconds != 0u &&
           policy->maximum_crl_validity_seconds <=
               RIN_CERTIFICATE_REVOCATION_CRL_MAX_VALIDITY_SECONDS &&
           (policy->required_evidence_flags &
            RIN_CERTIFICATE_REVOCATION_EVIDENCE_REQUIRED) ==
               RIN_CERTIFICATE_REVOCATION_EVIDENCE_REQUIRED &&
           (policy->required_evidence_flags &
            ~RIN_CERTIFICATE_REVOCATION_EVIDENCE_ALL) == 0u &&
           (policy->policy_flags &
            ~RIN_CERTIFICATE_REVOCATION_POLICY_ALL) == 0u &&
           policy->reserved[0] == 0u && policy->reserved[1] == 0u;
}

RinCertificateRevocationResult rin_certificate_revocation_policy_initialize(
    RinCertificateRevocationPolicyV1* policy,
    uint64_t trusted_unix_time)
{
    if (policy != NULL) revocation_zero(policy, sizeof(*policy));
    if (policy == NULL || trusted_unix_time == 0u)
        return RIN_CERTIFICATE_REVOCATION_INVALID;
    policy->struct_size = sizeof(*policy);
    policy->version = RIN_CERTIFICATE_REVOCATION_VERSION;
    policy->trusted_unix_time = trusted_unix_time;
    policy->maximum_ocsp_validity_seconds =
        RIN_CERTIFICATE_REVOCATION_OCSP_MAX_VALIDITY_SECONDS;
    policy->maximum_crl_validity_seconds =
        RIN_CERTIFICATE_REVOCATION_CRL_MAX_VALIDITY_SECONDS;
    policy->required_evidence_flags =
        RIN_CERTIFICATE_REVOCATION_EVIDENCE_REQUIRED;
    return RIN_CERTIFICATE_REVOCATION_OK;
}

RinCertificateRevocationResult rin_certificate_revocation_validate(
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32],
    const RinCertificateRevocationEvidenceV1* evidence)
{
    uint64_t maximum_validity;
    if (!rin_certificate_revocation_policy_valid(policy) ||
        certificate_sha256 == NULL ||
        evidence == NULL || evidence->struct_size != sizeof(*evidence) ||
        evidence->version != RIN_CERTIFICATE_REVOCATION_VERSION ||
        evidence->reserved0 != 0u || evidence->reserved[0] != 0u ||
        evidence->reserved[1] != 0u || evidence->sequence == 0u ||
        revocation_all_zero(certificate_sha256, 32u) ||
        revocation_all_zero(evidence->certificate_sha256, 32u) ||
        revocation_all_zero(evidence->issuer_sha256, 32u) ||
        (evidence->evidence_flags &
         ~RIN_CERTIFICATE_REVOCATION_EVIDENCE_ALL) != 0u)
        return RIN_CERTIFICATE_REVOCATION_INVALID;
    if (!revocation_equal(certificate_sha256,
                          evidence->certificate_sha256, 32u))
        return RIN_CERTIFICATE_REVOCATION_SCOPE_MISMATCH;
    if ((evidence->evidence_flags & policy->required_evidence_flags) !=
        policy->required_evidence_flags)
        return RIN_CERTIFICATE_REVOCATION_UNAVAILABLE;
    if (evidence->source == RIN_CERTIFICATE_REVOCATION_SOURCE_OCSP) {
        maximum_validity = policy->maximum_ocsp_validity_seconds;
        if ((policy->policy_flags &
             RIN_CERTIFICATE_REVOCATION_POLICY_REQUIRE_OCSP_NONCE) != 0u &&
            (evidence->evidence_flags &
             RIN_CERTIFICATE_REVOCATION_EVIDENCE_NONCE_VERIFIED) == 0u)
            return RIN_CERTIFICATE_REVOCATION_UNAVAILABLE;
    } else if (evidence->source ==
               RIN_CERTIFICATE_REVOCATION_SOURCE_CRL) {
        maximum_validity = policy->maximum_crl_validity_seconds;
    } else {
        return RIN_CERTIFICATE_REVOCATION_UNSUPPORTED;
    }
    if (evidence->this_update_unix_time == 0u ||
        evidence->next_update_unix_time <=
            evidence->this_update_unix_time ||
        evidence->produced_at_unix_time <
            evidence->this_update_unix_time ||
        evidence->produced_at_unix_time >
            evidence->next_update_unix_time ||
        evidence->next_update_unix_time -
                evidence->this_update_unix_time > maximum_validity)
        return RIN_CERTIFICATE_REVOCATION_INVALID;
    if (policy->trusted_unix_time < evidence->this_update_unix_time ||
        policy->trusted_unix_time < evidence->produced_at_unix_time)
        return RIN_CERTIFICATE_REVOCATION_FUTURE;
    if (policy->trusted_unix_time > evidence->next_update_unix_time)
        return RIN_CERTIFICATE_REVOCATION_STALE;
    if (evidence->status == RIN_CERTIFICATE_REVOCATION_STATUS_REVOKED)
        return RIN_CERTIFICATE_REVOCATION_REVOKED;
    if (evidence->status != RIN_CERTIFICATE_REVOCATION_STATUS_GOOD)
        return RIN_CERTIFICATE_REVOCATION_UNAVAILABLE;
    return RIN_CERTIFICATE_REVOCATION_OK;
}
