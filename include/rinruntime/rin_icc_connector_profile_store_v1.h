/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_ICC_CONNECTOR_PROFILE_STORE_V1_H
#define RIN_SHARED_ICC_CONNECTOR_PROFILE_STORE_V1_H

#include <stdint.h>

#include "rin_icc_display_profile_v1.h"
#include "rin_icc_lut_profile_v1.h"

#define RIN_ICC_CONNECTOR_PROFILE_STORE_ABI_VERSION 1u
#define RIN_ICC_CONNECTOR_PROFILE_STORE_MAGIC UINT32_C(0x31534349)
#define RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS 8u
#define RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES 65536u

typedef enum RinIccConnectorProfileStoreResult {
    RIN_ICC_CONNECTOR_PROFILE_STORE_OK = 0,
    RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT = -1,
    RIN_ICC_CONNECTOR_PROFILE_STORE_MALFORMED = -2,
    RIN_ICC_CONNECTOR_PROFILE_STORE_UNSUPPORTED = -3,
    RIN_ICC_CONNECTOR_PROFILE_STORE_LIMIT_EXCEEDED = -4,
    RIN_ICC_CONNECTOR_PROFILE_STORE_STALE = -5,
    RIN_ICC_CONNECTOR_PROFILE_STORE_NOT_FOUND = -6,
    RIN_ICC_CONNECTOR_PROFILE_STORE_BUSY = -7
} RinIccConnectorProfileStoreResult;

typedef enum RinIccConnectorProfileStoreKind {
    RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX = 1u,
    RIN_ICC_CONNECTOR_PROFILE_STORE_LUT = 2u
} RinIccConnectorProfileStoreKind;

typedef struct RinIccConnectorProfileStoreConfigV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint8_t* scratch;
    uint32_t scratch_capacity;
    uint32_t reserved[4];
} RinIccConnectorProfileStoreConfigV1;

typedef struct RinIccConnectorProfileStoreRecordV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint64_t connector_id;
    uint64_t profile_id;
    uint32_t generation;
    uint32_t kind;
    uint32_t profile_size;
    uint32_t reserved[7];
} RinIccConnectorProfileStoreRecordV1;

typedef struct RinIccConnectorProfileStoreSlotV1 {
    uint64_t connector_id;
    uint64_t profile_id;
    uint32_t generation;
    uint32_t kind;
    uint32_t profile_size;
    uint32_t occupied;
} RinIccConnectorProfileStoreSlotV1;

typedef struct RinIccConnectorProfileStoreV1 {
    uint32_t magic;
    volatile uint32_t lock;
    uint32_t initialized;
    uint32_t reserved0;
    uint8_t* scratch;
    uint32_t scratch_capacity;
    uint32_t reserved1;
    RinIccConnectorProfileStoreSlotV1 slots[
        RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS];
    uint8_t profiles[RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS]
                    [RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES];
} RinIccConnectorProfileStoreV1;

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_init(
    RinIccConnectorProfileStoreV1* store,
    const RinIccConnectorProfileStoreConfigV1* config);

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_install(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t kind, uint32_t expected_generation,
    const uint8_t* profile, uint32_t profile_size,
    RinIccConnectorProfileStoreRecordV1* record_out);

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_read(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation, uint8_t* profile_out,
    uint32_t profile_capacity, uint32_t* profile_size_out,
    RinIccConnectorProfileStoreRecordV1* record_out);

/* Revalidates the generation-bound profile and evaluates RGB into PCS. */
RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_apply(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation, const uint16_t input[3],
    uint16_t output[3]);

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_remove(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation);

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinIccConnectorProfileStoreRecordV1) == 64u,
               "ICC connector record ABI drift");
#endif

#endif /* RIN_SHARED_ICC_CONNECTOR_PROFILE_STORE_V1_H */
