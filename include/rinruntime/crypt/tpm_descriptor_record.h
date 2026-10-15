/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Canonical on-disk record for one RinCrypt TPM auto-unlock descriptor. */

#ifndef RIN_SHARED_CRYPT_TPM_DESCRIPTOR_RECORD_H
#define RIN_SHARED_CRYPT_TPM_DESCRIPTOR_RECORD_H

#include <stdint.h>

#include "tpm_auto_unlock_config.h"

#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_VERSION UINT32_C(1)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE UINT32_C(2560)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SECTORS UINT32_C(5)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_COPY_COUNT UINT32_C(2)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_A UINT32_C(1)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_B UINT32_C(2)
#define RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_BOTH UINT32_C(3)
#define RIN_CRYPT_TPM_DESCRIPTOR_IDENTITY_VERSION UINT32_C(1)
#define RIN_CRYPT_TPM_DESCRIPTOR_SCOPE_VERSION UINT32_C(1)
#define RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_A UINT32_C(1)
#define RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_B UINT32_C(2)
#define RIN_CRYPT_TPM_DESCRIPTOR_ROLE_DATA UINT32_C(3)
#define RIN_CRYPT_TPM_DESCRIPTOR_LOGICAL_BLOCK_SIZE UINT32_C(512)
#define RIN_CRYPT_TPM_DESCRIPTOR_MAX_STRIDE_BLOCKS UINT32_C(128)

typedef enum RinCryptTpmDescriptorRecordResult {
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK = 0,
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID = -1,
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY = -2,
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT = -3,
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH = -4,
    RIN_CRYPT_TPM_DESCRIPTOR_RECORD_AMBIGUOUS = -5
} RinCryptTpmDescriptorRecordResult;

typedef struct RinCryptTpmDescriptorIdentityV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t role;
    uint32_t reserved;
    uint64_t partition_first_lba;
    uint64_t partition_block_count;
    uint32_t logical_block_size;
    uint32_t header_copy_stride_blocks;
    uint8_t disk_guid[16];
    uint8_t install_nonce[16];
    uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint64_t header_generation;
    uint64_t key_epoch;
} RinCryptTpmDescriptorIdentityV1;

/* Stable installation scope used only to authorize replacement of an orphan
 * descriptor before its encrypted header is committed. Keyslot and key epoch
 * deliberately remain outside this scope because replacement creates them
 * anew; disk/install/partition identity must remain exact. */
typedef struct RinCryptTpmDescriptorScopeV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t role;
    uint32_t reserved;
    uint64_t partition_first_lba;
    uint64_t partition_block_count;
    uint32_t logical_block_size;
    uint32_t header_copy_stride_blocks;
    uint8_t disk_guid[16];
    uint8_t install_nonce[16];
    uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE];
} RinCryptTpmDescriptorScopeV1;

/* This is the validated in-memory form. The persistent form is encoded
 * explicitly and never depends on host structure padding or endianness. */
typedef struct RinCryptTpmDescriptorRecordV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t role;
    uint32_t reserved;
    uint64_t generation;
    uint64_t partition_first_lba;
    uint64_t partition_block_count;
    uint32_t logical_block_size;
    uint32_t header_copy_stride_blocks;
    uint8_t disk_guid[16];
    uint8_t install_nonce[16];
    RinCryptTpmAutoUnlockConfigV1 descriptor;
} RinCryptTpmDescriptorRecordV1;

_Static_assert(sizeof(RinCryptTpmDescriptorRecordV1) == 2216u,
               "RinCrypt TPM descriptor record memory ABI drift");
_Static_assert(sizeof(RinCryptTpmDescriptorIdentityV1) == 120u,
               "RinCrypt TPM descriptor identity ABI drift");
_Static_assert(sizeof(RinCryptTpmDescriptorScopeV1) == 88u,
               "RinCrypt TPM descriptor scope ABI drift");

int rin_crypt_tpm_descriptor_identity_valid(
    const RinCryptTpmDescriptorIdentityV1* identity);
int rin_crypt_tpm_descriptor_scope_valid(
    const RinCryptTpmDescriptorScopeV1* scope);
int rin_crypt_tpm_descriptor_record_valid(
    const RinCryptTpmDescriptorRecordV1* record);
int rin_crypt_tpm_descriptor_record_matches_identity(
    const RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorIdentityV1* identity);
int rin_crypt_tpm_descriptor_record_matches_scope(
    const RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorScopeV1* scope);

RinCryptTpmDescriptorRecordResult
rin_crypt_tpm_descriptor_record_initialize_v1(
    RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorIdentityV1* identity,
    const RinCryptTpmAutoUnlockConfigV1* descriptor,
    uint64_t generation);

RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_encode_v1(
    const RinCryptTpmDescriptorRecordV1* record,
    uint8_t output[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE]);

RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_decode_v1(
    const uint8_t input[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    RinCryptTpmDescriptorRecordV1* record);

/* Selects the highest-generation valid record. One corrupt/torn copy may be
 * ignored when the other copy is valid. Equal generations must be identical.
 * A valid record for another enrollment is never ignored. */
RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_select_v1(
    const uint8_t slot_a[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const uint8_t slot_b[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const RinCryptTpmDescriptorIdentityV1* identity,
    RinCryptTpmDescriptorRecordV1* record,
    uint32_t* valid_slot_mask);

/* Selects the highest valid record in a stable installation scope. A valid
 * foreign-scope copy and an equal-generation disagreement are never ignored.
 * This does not authorize boot use; it only supplies the generation floor for
 * pre-DATA replacement under the retained destructive-install authority. */
RinCryptTpmDescriptorRecordResult
rin_crypt_tpm_descriptor_record_select_scope_v1(
    const uint8_t slot_a[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const uint8_t slot_b[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const RinCryptTpmDescriptorScopeV1* scope,
    RinCryptTpmDescriptorRecordV1* record,
    uint32_t* valid_slot_mask);

#endif /* RIN_SHARED_CRYPT_TPM_DESCRIPTOR_RECORD_H */
