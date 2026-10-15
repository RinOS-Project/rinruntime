/* SPDX-License-Identifier: MIT */

#include "rin_trust_store_update.h"

#include <stddef.h>

static void trust_zero(void* destination, size_t size)
{
    volatile uint8_t* bytes = destination;

    while (size-- != 0u)
        *bytes++ = 0u;
}

static void trust_copy(void* destination, const void* source, size_t size)
{
    uint8_t* out = destination;
    const uint8_t* in = source;

    while (size-- != 0u)
        *out++ = *in++;
}

static int trust_zeroed(const void* value, size_t size)
{
    const uint8_t* bytes = value;

    while (size-- != 0u) {
        if (*bytes++ != 0u)
            return 0;
    }
    return 1;
}

static int trust_bytes_equal(const void* left, const void* right, size_t size)
{
    const uint8_t* a = left;
    const uint8_t* b = right;

    if (a == NULL || b == NULL) return 0;
    while (size-- != 0u) {
        if (*a++ != *b++) return 0;
    }
    return 1;
}

/* Callback code is outside the owner lock and is not trusted to preserve the
 * state it was handed.  Compare the complete authenticated config, including
 * callback/context identity, before publishing a candidate. */
static int trust_config_equal(const RinTrustStoreUpdateConfigV1* left,
                              const RinTrustStoreUpdateConfigV1* right)
{
    return left != NULL && right != NULL &&
           left->struct_size == right->struct_size &&
           left->version == right->version && left->flags == right->flags &&
           left->reserved0 == right->reserved0 &&
           left->generation == right->generation &&
           left->sequence == right->sequence &&
           left->bundle_bytes == right->bundle_bytes &&
           left->reserved1 == right->reserved1 &&
           trust_bytes_equal(left->bundle_sha256, right->bundle_sha256, 32u) &&
           left->context == right->context &&
           left->verify_call == right->verify_call &&
           left->commit_call == right->commit_call &&
           left->confirm_call == right->confirm_call &&
           trust_bytes_equal(left->reserved, right->reserved,
                             sizeof(left->reserved));
}

static int trust_candidate_equal(const RinTrustStoreUpdateOwnerV1* owner,
                                 uint32_t bytes, uint64_t generation,
                                 uint64_t sequence, const uint8_t digest[32])
{
    return owner != NULL && owner->candidate_bytes == bytes &&
           owner->candidate_generation == generation &&
           owner->candidate_sequence == sequence &&
           (digest == NULL ||
            trust_bytes_equal(owner->candidate_digest, digest, 32u));
}

static int trust_digest_valid(const uint8_t digest[32])
{
    return digest != NULL && !trust_zeroed(digest, 32u);
}

static void trust_lock(RinTrustStoreUpdateOwnerV1* owner)
{
    while (__atomic_exchange_n(&owner->lock, 1u, __ATOMIC_ACQUIRE) != 0u)
        ;
}

static void trust_unlock(RinTrustStoreUpdateOwnerV1* owner)
{
    __atomic_store_n(&owner->lock, 0u, __ATOMIC_RELEASE);
}

static void trust_clear_candidate(RinTrustStoreUpdateOwnerV1* owner)
{
    owner->candidate_bytes = 0u;
    owner->candidate_generation = 0u;
    owner->candidate_sequence = 0u;
    trust_zero(owner->candidate_digest, sizeof(owner->candidate_digest));
}

static int trust_config_valid(const RinTrustStoreUpdateConfigV1* config)
{
    return config != NULL && config->struct_size == sizeof(*config) &&
           config->version == RIN_TRUST_STORE_UPDATE_VERSION &&
           config->flags == 0u && config->reserved0 == 0u &&
           config->verify_call != NULL && config->commit_call != NULL &&
           config->confirm_call != NULL &&
           config->reserved1 == 0u &&
           ((config->sequence == 0u && config->bundle_bytes == 0u &&
             trust_zeroed(config->bundle_sha256, 32u)) ||
            (config->sequence != 0u && config->generation != 0u &&
             config->bundle_bytes != 0u &&
             config->bundle_bytes <= RIN_TRUST_STORE_UPDATE_MAX_BUNDLE_BYTES &&
             trust_digest_valid(config->bundle_sha256))) &&
           trust_zeroed(config->reserved, sizeof(config->reserved));
}

static void trust_publish_receipt(const RinTrustStoreUpdateOwnerV1* owner,
                                  uint32_t state,
                                  RinTrustStoreUpdateReceiptV1* receipt_out)
{
    trust_zero(receipt_out, sizeof(*receipt_out));
    receipt_out->struct_size = sizeof(*receipt_out);
    receipt_out->version = RIN_TRUST_STORE_UPDATE_VERSION;
    receipt_out->state = state;
    receipt_out->generation = state == RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN
                                  ? owner->candidate_generation
                                  : owner->config.generation;
    receipt_out->sequence = state == RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN
                                ? owner->candidate_sequence
                                : owner->config.sequence;
    receipt_out->bundle_bytes = state == RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN
                                    ? owner->candidate_bytes
                                    : owner->config.bundle_bytes;
    if (state == RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN)
        trust_copy(receipt_out->bundle_sha256, owner->candidate_digest, 32u);
    else
        trust_copy(receipt_out->bundle_sha256, owner->config.bundle_sha256, 32u);
}

RinTrustStoreUpdateStatus rin_trust_store_update_init(
    RinTrustStoreUpdateOwnerV1* owner,
    const RinTrustStoreUpdateConfigV1* config)
{
    if (owner == NULL || !trust_config_valid(config))
        return RIN_TRUST_STORE_UPDATE_INVALID;
    trust_zero(owner, sizeof(*owner));
    trust_copy(&owner->config, config, sizeof(owner->config));
    owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
    __atomic_store_n(&owner->initialized, 1u, __ATOMIC_RELEASE);
    return RIN_TRUST_STORE_UPDATE_OK;
}

RinTrustStoreUpdateStatus rin_trust_store_update_apply(
    RinTrustStoreUpdateOwnerV1* owner, const uint8_t* bundle,
    uint32_t bundle_bytes, uint64_t sequence,
    RinTrustStoreUpdateReceiptV1* receipt_out)
{
    uint8_t digest[32];
    uint64_t generation;
    RinTrustStoreUpdateConfigV1 config_snapshot;
    uint32_t candidate_bytes;
    uint64_t candidate_generation;
    uint64_t candidate_sequence;
    RinTrustStoreUpdateStatus status;

    if (receipt_out != NULL)
        trust_zero(receipt_out, sizeof(*receipt_out));
    if (owner == NULL || bundle == NULL || receipt_out == NULL ||
        __atomic_load_n(&owner->initialized, __ATOMIC_ACQUIRE) != 1u ||
        bundle_bytes == 0u ||
        bundle_bytes > RIN_TRUST_STORE_UPDATE_MAX_BUNDLE_BYTES || sequence == 0u)
        return RIN_TRUST_STORE_UPDATE_INVALID;
    trust_lock(owner);
    if (owner->state != RIN_TRUST_STORE_UPDATE_STATE_READY) {
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_BUSY;
    }
    if (sequence <= owner->config.sequence) {
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_STALE;
    }
    owner->state = RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT;
    owner->candidate_bytes = bundle_bytes;
    owner->candidate_sequence = sequence;
    owner->candidate_generation = owner->config.generation;
    config_snapshot = owner->config;
    candidate_bytes = owner->candidate_bytes;
    candidate_generation = owner->candidate_generation;
    candidate_sequence = owner->candidate_sequence;
    trust_unlock(owner);

    trust_zero(digest, sizeof(digest));
    status = owner->config.verify_call(owner->config.context, bundle,
                                       bundle_bytes, sequence, digest);
    if (status != RIN_TRUST_STORE_UPDATE_OK || !trust_digest_valid(digest)) {
        trust_lock(owner);
        trust_clear_candidate(owner);
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
        trust_unlock(owner);
        return status == RIN_TRUST_STORE_UPDATE_OK
                   ? RIN_TRUST_STORE_UPDATE_VERIFY_FAILED
                   : status;
    }
    trust_lock(owner);
    if (owner->state != RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT ||
        !trust_config_equal(&owner->config, &config_snapshot) ||
        !trust_candidate_equal(owner, candidate_bytes, candidate_generation,
                               candidate_sequence, NULL)) {
        /* A callback must not be able to publish an untrusted mutation. */
        owner->config = config_snapshot;
        trust_clear_candidate(owner);
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_PROTOCOL;
    }
    trust_copy(owner->candidate_digest, digest, sizeof(digest));
    generation = owner->candidate_generation;
    trust_unlock(owner);
    status = owner->config.commit_call(owner->config.context, bundle,
                                       bundle_bytes, generation, sequence,
                                       digest, &generation);
    trust_lock(owner);
    if (owner->state != RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT ||
        !trust_config_equal(&owner->config, &config_snapshot) ||
        !trust_candidate_equal(owner, candidate_bytes, candidate_generation,
                               candidate_sequence, digest)) {
        owner->config = config_snapshot;
        trust_clear_candidate(owner);
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_PROTOCOL;
    }
    if (status == RIN_TRUST_STORE_UPDATE_OK && generation > owner->config.generation) {
        owner->config.generation = generation;
        owner->config.sequence = sequence;
        owner->config.bundle_bytes = bundle_bytes;
        trust_copy(owner->config.bundle_sha256, digest, sizeof(digest));
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
        trust_publish_receipt(owner, RIN_TRUST_STORE_UPDATE_STATE_READY,
                              receipt_out);
        trust_clear_candidate(owner);
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_OK;
    }
    if (status == RIN_TRUST_STORE_UPDATE_COMMIT_UNKNOWN) {
        owner->candidate_generation = generation;
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN;
        trust_publish_receipt(owner, RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN,
                              receipt_out);
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_COMMIT_UNKNOWN;
    }
    owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
    trust_clear_candidate(owner);
    trust_unlock(owner);
    return status == RIN_TRUST_STORE_UPDATE_OK
               ? RIN_TRUST_STORE_UPDATE_PROTOCOL
               : status;
}

RinTrustStoreUpdateStatus rin_trust_store_update_confirm(
    RinTrustStoreUpdateOwnerV1* owner,
    RinTrustStoreUpdateReceiptV1* receipt_out)
{
    uint64_t generation;
    RinTrustStoreUpdateConfigV1 config_snapshot;
    uint32_t candidate_bytes;
    uint64_t candidate_generation;
    uint64_t candidate_sequence;
    uint8_t candidate_digest[32];
    RinTrustStoreUpdateStatus status;

    if (receipt_out != NULL)
        trust_zero(receipt_out, sizeof(*receipt_out));
    if (owner == NULL || receipt_out == NULL ||
        __atomic_load_n(&owner->initialized, __ATOMIC_ACQUIRE) != 1u)
        return RIN_TRUST_STORE_UPDATE_INVALID;
    trust_lock(owner);
    if (owner->state == RIN_TRUST_STORE_UPDATE_STATE_CONFIRM_IN_FLIGHT ||
        owner->state == RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT) {
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_BUSY;
    }
    if (owner->state != RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN) {
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_NOT_FOUND;
    }
    trust_publish_receipt(owner, RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN,
                          receipt_out);
    generation = owner->candidate_generation;
    config_snapshot = owner->config;
    candidate_bytes = owner->candidate_bytes;
    candidate_generation = owner->candidate_generation;
    candidate_sequence = owner->candidate_sequence;
    trust_copy(candidate_digest, owner->candidate_digest,
               sizeof(candidate_digest));
    owner->state = RIN_TRUST_STORE_UPDATE_STATE_CONFIRM_IN_FLIGHT;
    trust_unlock(owner);
    status = owner->config.confirm_call(owner->config.context, generation,
                                        owner->candidate_sequence,
                                        owner->candidate_digest, &generation);
    trust_lock(owner);
    if (owner->state != RIN_TRUST_STORE_UPDATE_STATE_CONFIRM_IN_FLIGHT ||
        !trust_config_equal(&owner->config, &config_snapshot) ||
        !trust_candidate_equal(owner, candidate_bytes, candidate_generation,
                               candidate_sequence, candidate_digest)) {
        owner->config = config_snapshot;
        owner->candidate_bytes = candidate_bytes;
        owner->candidate_generation = candidate_generation;
        owner->candidate_sequence = candidate_sequence;
        trust_copy(owner->candidate_digest, candidate_digest,
                   sizeof(candidate_digest));
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN;
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_PROTOCOL;
    }
    if (status == RIN_TRUST_STORE_UPDATE_OK &&
        generation > owner->config.generation) {
        owner->config.generation = generation;
        owner->config.sequence = owner->candidate_sequence;
        owner->config.bundle_bytes = owner->candidate_bytes;
        trust_copy(owner->config.bundle_sha256, owner->candidate_digest, 32u);
        owner->state = RIN_TRUST_STORE_UPDATE_STATE_READY;
        trust_publish_receipt(owner, RIN_TRUST_STORE_UPDATE_STATE_READY,
                              receipt_out);
        trust_clear_candidate(owner);
        trust_unlock(owner);
        return RIN_TRUST_STORE_UPDATE_OK;
    }
    owner->state = RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN;
    trust_unlock(owner);
    return status == RIN_TRUST_STORE_UPDATE_OK
               ? RIN_TRUST_STORE_UPDATE_PROTOCOL
               : status;
}

RinTrustStoreUpdateStatus rin_trust_store_update_snapshot(
    const RinTrustStoreUpdateOwnerV1* owner,
    RinTrustStoreUpdateReceiptV1* receipt_out)
{
    RinTrustStoreUpdateOwnerV1* mutable_owner =
        (RinTrustStoreUpdateOwnerV1*)(uintptr_t)owner;

    if (receipt_out != NULL)
        trust_zero(receipt_out, sizeof(*receipt_out));
    if (mutable_owner == NULL || receipt_out == NULL ||
        __atomic_load_n(&mutable_owner->initialized, __ATOMIC_ACQUIRE) != 1u)
        return RIN_TRUST_STORE_UPDATE_INVALID;
    trust_lock(mutable_owner);
    if (mutable_owner->state == RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT ||
        mutable_owner->state == RIN_TRUST_STORE_UPDATE_STATE_CONFIRM_IN_FLIGHT) {
        trust_unlock(mutable_owner);
        return RIN_TRUST_STORE_UPDATE_BUSY;
    }
    if (mutable_owner->state == RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN)
        trust_publish_receipt(mutable_owner,
                              RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN,
                              receipt_out);
    else
        trust_publish_receipt(mutable_owner, RIN_TRUST_STORE_UPDATE_STATE_READY,
                              receipt_out);
    trust_unlock(mutable_owner);
    return RIN_TRUST_STORE_UPDATE_OK;
}
