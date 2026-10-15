/* SPDX-License-Identifier: MIT */
/* Authenticated root-store replacement transaction owner. */
#ifndef RIN_SHARED_TRUST_STORE_UPDATE_H
#define RIN_SHARED_TRUST_STORE_UPDATE_H

#include <stdint.h>

#define RIN_TRUST_STORE_UPDATE_VERSION UINT32_C(0x00010000)
#define RIN_TRUST_STORE_UPDATE_MAX_BUNDLE_BYTES UINT32_C(262144)

typedef enum RinTrustStoreUpdateStatus {
    RIN_TRUST_STORE_UPDATE_OK = 0,
    RIN_TRUST_STORE_UPDATE_INVALID = -1,
    RIN_TRUST_STORE_UPDATE_BUSY = -2,
    RIN_TRUST_STORE_UPDATE_STALE = -3,
    RIN_TRUST_STORE_UPDATE_VERIFY_FAILED = -4,
    RIN_TRUST_STORE_UPDATE_COMMIT_UNKNOWN = -5,
    RIN_TRUST_STORE_UPDATE_NOT_FOUND = -6,
    RIN_TRUST_STORE_UPDATE_PROTOCOL = -7
} RinTrustStoreUpdateStatus;

typedef struct RinTrustStoreUpdateConfigV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t reserved0;
    uint64_t generation;
    uint64_t sequence;
    uint32_t bundle_bytes;
    uint32_t reserved1;
    uint8_t bundle_sha256[32];
    void* context;
    RinTrustStoreUpdateStatus (*verify_call)(
        void* context, const uint8_t* bundle, uint32_t bundle_bytes,
        uint64_t sequence, uint8_t digest_out[32]);
    RinTrustStoreUpdateStatus (*commit_call)(
        void* context, const uint8_t* bundle, uint32_t bundle_bytes,
        uint64_t expected_generation, uint64_t sequence,
        const uint8_t digest[32], uint64_t* generation_out);
    RinTrustStoreUpdateStatus (*confirm_call)(
        void* context, uint64_t expected_generation, uint64_t sequence,
        const uint8_t digest[32], uint64_t* generation_out);
    uint64_t reserved[2];
} RinTrustStoreUpdateConfigV1;

typedef struct RinTrustStoreUpdateReceiptV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t state;
    uint32_t reserved0;
    uint64_t generation;
    uint64_t sequence;
    uint32_t bundle_bytes;
    uint32_t reserved1;
    uint8_t bundle_sha256[32];
    uint64_t reserved[2];
} RinTrustStoreUpdateReceiptV1;

typedef struct RinTrustStoreUpdateOwnerV1 {
    volatile uint32_t lock;
    uint32_t initialized;
    RinTrustStoreUpdateConfigV1 config;
    uint32_t state;
    uint32_t candidate_bytes;
    uint64_t candidate_generation;
    uint64_t candidate_sequence;
    uint8_t candidate_digest[32];
} RinTrustStoreUpdateOwnerV1;

enum {
    RIN_TRUST_STORE_UPDATE_STATE_READY = 1u,
    RIN_TRUST_STORE_UPDATE_STATE_IN_FLIGHT = 2u,
    RIN_TRUST_STORE_UPDATE_STATE_COMMIT_UNKNOWN = 3u,
    RIN_TRUST_STORE_UPDATE_STATE_CONFIRM_IN_FLIGHT = 4u
};

#ifdef __cplusplus
extern "C" {
#endif

RinTrustStoreUpdateStatus rin_trust_store_update_init(
    RinTrustStoreUpdateOwnerV1* owner,
    const RinTrustStoreUpdateConfigV1* config);
RinTrustStoreUpdateStatus rin_trust_store_update_apply(
    RinTrustStoreUpdateOwnerV1* owner, const uint8_t* bundle,
    uint32_t bundle_bytes, uint64_t sequence,
    RinTrustStoreUpdateReceiptV1* receipt_out);
RinTrustStoreUpdateStatus rin_trust_store_update_confirm(
    RinTrustStoreUpdateOwnerV1* owner,
    RinTrustStoreUpdateReceiptV1* receipt_out);
RinTrustStoreUpdateStatus rin_trust_store_update_snapshot(
    const RinTrustStoreUpdateOwnerV1* owner,
    RinTrustStoreUpdateReceiptV1* receipt_out);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
static_assert(sizeof(RinTrustStoreUpdateReceiptV1) == 88u,
              "trust-store update receipt ABI drift");
#else
_Static_assert(sizeof(RinTrustStoreUpdateReceiptV1) == 88u,
               "trust-store update receipt ABI drift");
#endif

#endif /* RIN_SHARED_TRUST_STORE_UPDATE_H */
