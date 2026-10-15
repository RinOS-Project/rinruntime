/* SPDX-License-Identifier: MIT */

#include "rin_certificate_revocation_cache.h"

#include <stddef.h>
#include <string.h>

static void cache_zero(void* destination, size_t bytes)
{
    uint8_t* output = (uint8_t*)destination;
    while (bytes-- != 0u) *output++ = 0u;
}

static int cache_all_zero(const void* value, size_t bytes)
{
    const uint8_t* input = (const uint8_t*)value;
    uint8_t observed = 0u;
    if (value == NULL) return 1;
    while (bytes-- != 0u) observed |= *input++;
    return observed == 0u;
}

static int cache_equal(const void* left, const void* right, size_t bytes)
{
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    if (left == NULL || right == NULL) return 0;
    while (bytes-- != 0u) difference |= (uint8_t)(*a++ ^ *b++);
    return difference == 0u;
}

static int cache_digest_valid(const uint8_t digest[32])
{
    return digest != NULL && !cache_all_zero(digest, 32u);
}

static int cache_valid(const RinCertificateRevocationCacheV1* cache)
{
    uint32_t active_count = 0u;
    if (cache == NULL || cache->struct_size != sizeof(*cache) ||
        cache->version != RIN_CERTIFICATE_REVOCATION_CACHE_VERSION ||
        cache->generation == 0u || cache->active_count >
            RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY ||
        cache->next_sequence == 0u || cache->reserved0 != 0u ||
        cache->reserved[0] != 0u ||
        cache->reserved[1] != 0u)
        return 0;
    for (uint32_t index = 0u;
         index < RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY; ++index) {
        const RinCertificateRevocationCacheSlotV1* slot = &cache->slots[index];
        if (slot->active > 1u || slot->reserved0 != 0u) return 0;
        if (slot->active == 0u) {
            if (!cache_all_zero(slot->certificate_sha256, 32u) ||
                !cache_all_zero(slot->issuer_sha256, 32u) ||
                !cache_all_zero(&slot->evidence, sizeof(slot->evidence)))
                return 0;
            continue;
        }
        if (!cache_digest_valid(slot->certificate_sha256) ||
            !cache_digest_valid(slot->issuer_sha256) ||
            slot->evidence.struct_size != sizeof(slot->evidence) ||
            slot->evidence.version != RIN_CERTIFICATE_REVOCATION_VERSION ||
            !cache_equal(slot->certificate_sha256,
                         slot->evidence.certificate_sha256, 32u) ||
            !cache_equal(slot->issuer_sha256,
                         slot->evidence.issuer_sha256, 32u) ||
            slot->evidence.sequence == 0u ||
            (cache->next_sequence != UINT64_MAX &&
             slot->evidence.sequence >= cache->next_sequence))
            return 0;
        ++active_count;
    }
    return active_count == cache->active_count;
}

static RinCertificateRevocationCacheResult cache_map_validation(
    RinCertificateRevocationResult result)
{
    switch (result) {
    case RIN_CERTIFICATE_REVOCATION_OK:
        return RIN_CERTIFICATE_REVOCATION_CACHE_OK;
    case RIN_CERTIFICATE_REVOCATION_REVOKED:
        return RIN_CERTIFICATE_REVOCATION_CACHE_REVOKED;
    case RIN_CERTIFICATE_REVOCATION_STALE:
        return RIN_CERTIFICATE_REVOCATION_CACHE_STALE;
    case RIN_CERTIFICATE_REVOCATION_FUTURE:
        return RIN_CERTIFICATE_REVOCATION_CACHE_FUTURE;
    case RIN_CERTIFICATE_REVOCATION_UNAVAILABLE:
        return RIN_CERTIFICATE_REVOCATION_CACHE_UNAVAILABLE;
    case RIN_CERTIFICATE_REVOCATION_INVALID:
    case RIN_CERTIFICATE_REVOCATION_SCOPE_MISMATCH:
    case RIN_CERTIFICATE_REVOCATION_UNSUPPORTED:
        return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
    }
    return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
}

RinCertificateRevocationCacheResult
rin_certificate_revocation_cache_initialize(
    RinCertificateRevocationCacheV1* cache, uint64_t generation)
{
    if (cache != NULL) cache_zero(cache, sizeof(*cache));
    if (cache == NULL || generation == 0u) return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
    cache->struct_size = sizeof(*cache);
    cache->version = RIN_CERTIFICATE_REVOCATION_CACHE_VERSION;
    cache->generation = generation;
    cache->next_sequence = 1u;
    return RIN_CERTIFICATE_REVOCATION_CACHE_OK;
}

RinCertificateRevocationCacheResult rin_certificate_revocation_cache_put(
    RinCertificateRevocationCacheV1* cache,
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32], const uint8_t issuer_sha256[32],
    const RinCertificateRevocationEvidenceV1* evidence)
{
    RinCertificateRevocationCacheSlotV1 candidate;
    uint32_t selected = RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY;
    uint32_t oldest = RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY;
    int selected_was_active = 0;
    uint64_t oldest_sequence = UINT64_MAX;
    RinCertificateRevocationResult validation;
    if (!cache_valid(cache) || !rin_certificate_revocation_policy_valid(policy) ||
        !cache_digest_valid(certificate_sha256) || !cache_digest_valid(issuer_sha256) ||
        evidence == NULL || !cache_equal(issuer_sha256, evidence->issuer_sha256, 32u))
        return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
    validation = rin_certificate_revocation_validate(
        policy, certificate_sha256, evidence);
    if (validation != RIN_CERTIFICATE_REVOCATION_OK &&
        validation != RIN_CERTIFICATE_REVOCATION_REVOKED)
        return cache_map_validation(validation);
    cache_zero(&candidate, sizeof(candidate));
    candidate.active = 1u;
    memcpy(candidate.certificate_sha256, certificate_sha256, 32u);
    memcpy(candidate.issuer_sha256, issuer_sha256, 32u);
    candidate.evidence = *evidence;
    for (uint32_t index = 0u;
         index < RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY; ++index) {
        const RinCertificateRevocationCacheSlotV1* slot = &cache->slots[index];
        if (slot->active != 0u &&
            cache_equal(slot->certificate_sha256, certificate_sha256, 32u) &&
            cache_equal(slot->issuer_sha256, issuer_sha256, 32u)) {
            if (evidence->sequence < slot->evidence.sequence)
                return RIN_CERTIFICATE_REVOCATION_CACHE_CONFLICT;
            if (evidence->sequence == slot->evidence.sequence) {
                return cache_equal(&slot->evidence, evidence, sizeof(*evidence))
                    ? (validation == RIN_CERTIFICATE_REVOCATION_REVOKED
                        ? RIN_CERTIFICATE_REVOCATION_CACHE_REVOKED
                        : RIN_CERTIFICATE_REVOCATION_CACHE_OK)
                    : RIN_CERTIFICATE_REVOCATION_CACHE_CONFLICT;
            }
            selected = index;
            selected_was_active = 1;
            break;
        }
        if (slot->active == 0u && selected == RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY)
            selected = index;
        if (slot->active != 0u && slot->evidence.sequence < oldest_sequence) {
            oldest_sequence = slot->evidence.sequence;
            oldest = index;
        }
    }
    if (selected == RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY) {
        if (oldest == RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY ||
            evidence->sequence <= oldest_sequence)
            return RIN_CERTIFICATE_REVOCATION_CACHE_FULL;
        selected = oldest;
        selected_was_active = 1;
    }
    if (cache->next_sequence == UINT64_MAX || cache->generation == UINT64_MAX)
        return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
    cache->slots[selected] = candidate;
    if (!selected_was_active)
        ++cache->active_count;
    if (evidence->sequence >= cache->next_sequence)
        cache->next_sequence = evidence->sequence == UINT64_MAX
            ? UINT64_MAX : evidence->sequence + 1u;
    ++cache->generation;
    return validation == RIN_CERTIFICATE_REVOCATION_REVOKED
        ? RIN_CERTIFICATE_REVOCATION_CACHE_REVOKED
        : RIN_CERTIFICATE_REVOCATION_CACHE_OK;
}

RinCertificateRevocationCacheResult rin_certificate_revocation_cache_lookup(
    const RinCertificateRevocationCacheV1* cache,
    const RinCertificateRevocationPolicyV1* policy,
    const uint8_t certificate_sha256[32], const uint8_t issuer_sha256[32],
    RinCertificateRevocationEvidenceV1* evidence_out)
{
    if (evidence_out != NULL) cache_zero(evidence_out, sizeof(*evidence_out));
    if (!cache_valid(cache) || !rin_certificate_revocation_policy_valid(policy) ||
        !cache_digest_valid(certificate_sha256) || !cache_digest_valid(issuer_sha256) ||
        evidence_out == NULL)
        return RIN_CERTIFICATE_REVOCATION_CACHE_INVALID;
    for (uint32_t index = 0u;
         index < RIN_CERTIFICATE_REVOCATION_CACHE_CAPACITY; ++index) {
        const RinCertificateRevocationCacheSlotV1* slot = &cache->slots[index];
        RinCertificateRevocationResult validation;
        if (slot->active == 0u ||
            !cache_equal(slot->certificate_sha256, certificate_sha256, 32u) ||
            !cache_equal(slot->issuer_sha256, issuer_sha256, 32u))
            continue;
        validation = rin_certificate_revocation_validate(
            policy, certificate_sha256, &slot->evidence);
        if (validation == RIN_CERTIFICATE_REVOCATION_OK ||
            validation == RIN_CERTIFICATE_REVOCATION_REVOKED)
            *evidence_out = slot->evidence;
        return cache_map_validation(validation);
    }
    return RIN_CERTIFICATE_REVOCATION_CACHE_NOT_FOUND;
}
