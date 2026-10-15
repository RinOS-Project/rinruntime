/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "tpm_descriptor_record.h"

#include <stddef.h>

#if defined(RIN_TPM2_KERNEL64_RENAMED_SHA256)
#define sha256_init rin_driver_sha256_init
#define sha256_update rin_driver_sha256_update
#define sha256_final rin_driver_sha256_final
#endif
#include "../../../public-base/libs/rintls/crypto/sha256.h"

#define RECORD_DESCRIPTOR_OFFSET UINT32_C(80)
#define RECORD_RESERVED_OFFSET UINT32_C(2216)
#define RECORD_DIGEST_OFFSET UINT32_C(2528)

static const uint8_t g_record_magic[4] = {'R', 'T', 'D', '1'};
static const uint8_t g_record_hash_domain[28] = {
    'R', 'i', 'n', 'C', 'r', 'y', 'p', 't', '-', 'T', 'P', 'M', '-',
    'D', 'e', 's', 'c', 'r', 'i', 'p', 't', 'o', 'r', '-', 'v', '1', 0, 0
};

static void record_zero(void* pointer, uint64_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static void record_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    while (size-- != 0u) *destination++ = *source++;
}

static int record_equal(const void* left, const void* right, uint32_t size)
{
    const uint8_t* first = (const uint8_t*)left;
    const uint8_t* second = (const uint8_t*)right;
    uint8_t difference = 0u;
    uint32_t index;
    if (!left || !right) return 0;
    for (index = 0u; index < size; ++index)
        difference |= (uint8_t)(first[index] ^ second[index]);
    return difference == 0u;
}

static int record_is_zero(const void* pointer, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)pointer;
    uint8_t combined = 0u;
    uint32_t index;
    if (!pointer) return 1;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static int record_ranges_overlap(const void* first, uint64_t first_size,
                                 const void* second, uint64_t second_size)
{
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    uintptr_t first_end;
    uintptr_t second_end;
    if (!first || !second || first_size == 0u || second_size == 0u)
        return 0;
    if (first_size > UINTPTR_MAX - first_start ||
        second_size > UINTPTR_MAX - second_start)
        return 1;
    first_end = first_start + (uintptr_t)first_size;
    second_end = second_start + (uintptr_t)second_size;
    return first_start < second_end && second_start < first_end;
}

static void record_write_le32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8u);
    output[2] = (uint8_t)(value >> 16u);
    output[3] = (uint8_t)(value >> 24u);
}

static void record_write_le64(uint8_t output[8], uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        output[index] = (uint8_t)(value >> (index * 8u));
}

static uint32_t record_read_le32(const uint8_t input[4])
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8u) |
           ((uint32_t)input[2] << 16u) | ((uint32_t)input[3] << 24u);
}

static uint64_t record_read_le64(const uint8_t input[8])
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        value |= (uint64_t)input[index] << (index * 8u);
    return value;
}

static void record_hash(const uint8_t* bytes, uint8_t digest[32])
{
    sha256_ctx hash;
    sha256_init(&hash);
    sha256_update(&hash, g_record_hash_domain, sizeof(g_record_hash_domain));
    sha256_update(&hash, bytes, RECORD_DIGEST_OFFSET);
    sha256_final(&hash, digest);
    record_zero(&hash, sizeof(hash));
}

static void descriptor_encode(const RinCryptTpmAutoUnlockConfigV1* descriptor,
                              uint8_t output[2136])
{
    const RinTpm2PolicyApprovalV1* approval = &descriptor->approval;
    const RinTpm2SealedObjectV1* sealed = &descriptor->sealed_key;
    record_write_le32(output, descriptor->version);
    record_write_le32(output + 4u, descriptor->struct_size);
    record_write_le32(output + 8u, descriptor->parent_handle);
    record_write_le32(output + 12u, descriptor->rollback_nv_index);
    record_write_le64(output + 16u, descriptor->boot_generation);
    record_write_le64(output + 24u, descriptor->header_generation);
    record_write_le64(output + 32u, descriptor->key_epoch);
    record_write_le64(output + 40u, descriptor->rollback_counter);
    record_copy(output + 48u, descriptor->volume_id, 16u);
    record_copy(output + 64u, descriptor->keyslot_id, 16u);
    record_copy(output + 80u, descriptor->parent_name, 34u);
    record_copy(output + 114u, descriptor->rollback_nv_name, 34u);
    record_copy(output + 148u, descriptor->release_key_name, 34u);
    record_copy(output + 182u, descriptor->reserved, 10u);

    output += 192u;
    record_write_le32(output, approval->version);
    record_write_le32(output + 4u, approval->struct_size);
    record_write_le64(output + 8u, approval->boot_generation);
    record_write_le32(output + 16u, approval->pcr_index);
    record_write_le32(output + 20u, approval->release_key_handle);
    record_copy(output + 24u, approval->pcr_selection_digest, 32u);
    record_copy(output + 56u, approval->approved_policy, 32u);
    record_copy(output + 88u, approval->release_key_name, 34u);
    record_copy(output + 122u, approval->signature_r, 32u);
    record_copy(output + 154u, approval->signature_s, 32u);
    record_copy(output + 186u, approval->reserved, 6u);

    output += 192u;
    record_write_le32(output, sealed->version);
    record_write_le32(output + 4u, sealed->struct_size);
    record_write_le32(output + 8u, sealed->private_size);
    record_write_le32(output + 12u, sealed->public_size);
    record_copy(output + 16u, sealed->policy_digest, 32u);
    record_copy(output + 48u, sealed->name, 34u);
    record_copy(output + 82u, sealed->reserved, 6u);
    record_copy(output + 88u, sealed->private_blob,
                RIN_TPM2_SEALED_PRIVATE_MAX);
    record_copy(output + 1624u, sealed->public_blob,
                RIN_TPM2_SEALED_PUBLIC_MAX);
}

static void descriptor_decode(const uint8_t input[2136],
                              RinCryptTpmAutoUnlockConfigV1* descriptor)
{
    RinTpm2PolicyApprovalV1* approval = &descriptor->approval;
    RinTpm2SealedObjectV1* sealed = &descriptor->sealed_key;
    descriptor->version = record_read_le32(input);
    descriptor->struct_size = record_read_le32(input + 4u);
    descriptor->parent_handle = record_read_le32(input + 8u);
    descriptor->rollback_nv_index = record_read_le32(input + 12u);
    descriptor->boot_generation = record_read_le64(input + 16u);
    descriptor->header_generation = record_read_le64(input + 24u);
    descriptor->key_epoch = record_read_le64(input + 32u);
    descriptor->rollback_counter = record_read_le64(input + 40u);
    record_copy(descriptor->volume_id, input + 48u, 16u);
    record_copy(descriptor->keyslot_id, input + 64u, 16u);
    record_copy(descriptor->parent_name, input + 80u, 34u);
    record_copy(descriptor->rollback_nv_name, input + 114u, 34u);
    record_copy(descriptor->release_key_name, input + 148u, 34u);
    record_copy(descriptor->reserved, input + 182u, 10u);

    input += 192u;
    approval->version = record_read_le32(input);
    approval->struct_size = record_read_le32(input + 4u);
    approval->boot_generation = record_read_le64(input + 8u);
    approval->pcr_index = record_read_le32(input + 16u);
    approval->release_key_handle = record_read_le32(input + 20u);
    record_copy(approval->pcr_selection_digest, input + 24u, 32u);
    record_copy(approval->approved_policy, input + 56u, 32u);
    record_copy(approval->release_key_name, input + 88u, 34u);
    record_copy(approval->signature_r, input + 122u, 32u);
    record_copy(approval->signature_s, input + 154u, 32u);
    record_copy(approval->reserved, input + 186u, 6u);

    input += 192u;
    sealed->version = record_read_le32(input);
    sealed->struct_size = record_read_le32(input + 4u);
    sealed->private_size = record_read_le32(input + 8u);
    sealed->public_size = record_read_le32(input + 12u);
    record_copy(sealed->policy_digest, input + 16u, 32u);
    record_copy(sealed->name, input + 48u, 34u);
    record_copy(sealed->reserved, input + 82u, 6u);
    record_copy(sealed->private_blob, input + 88u,
                RIN_TPM2_SEALED_PRIVATE_MAX);
    record_copy(sealed->public_blob, input + 1624u,
                RIN_TPM2_SEALED_PUBLIC_MAX);
}

int rin_crypt_tpm_descriptor_identity_valid(
    const RinCryptTpmDescriptorIdentityV1* identity)
{
    if (!identity ||
        identity->version != RIN_CRYPT_TPM_DESCRIPTOR_IDENTITY_VERSION ||
        identity->struct_size != sizeof(*identity) ||
        identity->reserved != 0u ||
        identity->logical_block_size !=
            RIN_CRYPT_TPM_DESCRIPTOR_LOGICAL_BLOCK_SIZE ||
        identity->header_copy_stride_blocks == 0u ||
        (identity->header_copy_stride_blocks &
         (identity->header_copy_stride_blocks - 1u)) != 0u ||
        identity->header_copy_stride_blocks >
            RIN_CRYPT_TPM_DESCRIPTOR_MAX_STRIDE_BLOCKS ||
        identity->partition_first_lba %
                identity->header_copy_stride_blocks != 0u ||
        identity->partition_block_count <=
            (uint64_t)identity->header_copy_stride_blocks *
                RIN_CRYPT_TPM_DESCRIPTOR_RECORD_COPY_COUNT ||
        identity->partition_first_lba >
            UINT64_MAX - identity->partition_block_count ||
        record_is_zero(identity->disk_guid, sizeof(identity->disk_guid)) ||
        record_is_zero(identity->install_nonce,
                       sizeof(identity->install_nonce)) ||
        record_is_zero(identity->volume_id, sizeof(identity->volume_id)) ||
        record_is_zero(identity->keyslot_id, sizeof(identity->keyslot_id)) ||
        identity->header_generation == 0u || identity->key_epoch == 0u) {
        return 0;
    }
    return identity->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_A ||
           identity->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_B ||
           identity->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_DATA;
}

int rin_crypt_tpm_descriptor_scope_valid(
    const RinCryptTpmDescriptorScopeV1* scope)
{
    if (!scope ||
        scope->version != RIN_CRYPT_TPM_DESCRIPTOR_SCOPE_VERSION ||
        scope->struct_size != sizeof(*scope) || scope->reserved != 0u ||
        scope->logical_block_size !=
            RIN_CRYPT_TPM_DESCRIPTOR_LOGICAL_BLOCK_SIZE ||
        scope->header_copy_stride_blocks == 0u ||
        (scope->header_copy_stride_blocks &
         (scope->header_copy_stride_blocks - 1u)) != 0u ||
        scope->header_copy_stride_blocks >
            RIN_CRYPT_TPM_DESCRIPTOR_MAX_STRIDE_BLOCKS ||
        scope->partition_first_lba % scope->header_copy_stride_blocks != 0u ||
        scope->partition_block_count <=
            (uint64_t)scope->header_copy_stride_blocks *
                RIN_CRYPT_TPM_DESCRIPTOR_RECORD_COPY_COUNT ||
        scope->partition_first_lba >
            UINT64_MAX - scope->partition_block_count ||
        record_is_zero(scope->disk_guid, sizeof(scope->disk_guid)) ||
        record_is_zero(scope->install_nonce, sizeof(scope->install_nonce)) ||
        record_is_zero(scope->volume_id, sizeof(scope->volume_id))) {
        return 0;
    }
    return scope->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_A ||
           scope->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_SYSTEM_B ||
           scope->role == RIN_CRYPT_TPM_DESCRIPTOR_ROLE_DATA;
}

int rin_crypt_tpm_descriptor_record_valid(
    const RinCryptTpmDescriptorRecordV1* record)
{
    RinCryptTpmDescriptorIdentityV1 identity;
    int valid;
    if (!record ||
        record->version != RIN_CRYPT_TPM_DESCRIPTOR_RECORD_VERSION ||
        record->struct_size != sizeof(*record) || record->reserved != 0u ||
        record->generation == 0u || record->generation == UINT64_MAX ||
        rin_crypt_tpm_auto_unlock_config_valid(&record->descriptor) == 0)
        return 0;
    record_zero(&identity, sizeof(identity));
    identity.version = RIN_CRYPT_TPM_DESCRIPTOR_IDENTITY_VERSION;
    identity.struct_size = sizeof(identity);
    identity.role = record->role;
    identity.partition_first_lba = record->partition_first_lba;
    identity.partition_block_count = record->partition_block_count;
    identity.logical_block_size = record->logical_block_size;
    identity.header_copy_stride_blocks = record->header_copy_stride_blocks;
    record_copy(identity.disk_guid, record->disk_guid, 16u);
    record_copy(identity.install_nonce, record->install_nonce, 16u);
    record_copy(identity.volume_id, record->descriptor.volume_id, 16u);
    record_copy(identity.keyslot_id, record->descriptor.keyslot_id, 16u);
    identity.header_generation = record->descriptor.header_generation;
    identity.key_epoch = record->descriptor.key_epoch;
    valid = rin_crypt_tpm_descriptor_identity_valid(&identity);
    record_zero(&identity, sizeof(identity));
    return valid;
}

int rin_crypt_tpm_descriptor_record_matches_identity(
    const RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorIdentityV1* identity)
{
    if (!record || !identity ||
        !rin_crypt_tpm_descriptor_record_valid(record) ||
        !rin_crypt_tpm_descriptor_identity_valid(identity))
        return 0;
    return record->role == identity->role &&
           record->partition_first_lba == identity->partition_first_lba &&
           record->partition_block_count == identity->partition_block_count &&
           record->logical_block_size == identity->logical_block_size &&
           record->header_copy_stride_blocks ==
               identity->header_copy_stride_blocks &&
           record_equal(record->disk_guid, identity->disk_guid, 16u) &&
           record_equal(record->install_nonce, identity->install_nonce,
                        16u) &&
           record_equal(record->descriptor.volume_id,
                        identity->volume_id, 16u) &&
           record_equal(record->descriptor.keyslot_id,
                        identity->keyslot_id, 16u) &&
           record->descriptor.header_generation ==
               identity->header_generation &&
           record->descriptor.key_epoch == identity->key_epoch;
}

int rin_crypt_tpm_descriptor_record_matches_scope(
    const RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorScopeV1* scope)
{
    if (!record || !scope ||
        !rin_crypt_tpm_descriptor_record_valid(record) ||
        !rin_crypt_tpm_descriptor_scope_valid(scope)) {
        return 0;
    }
    return record->role == scope->role &&
           record->partition_first_lba == scope->partition_first_lba &&
           record->partition_block_count == scope->partition_block_count &&
           record->logical_block_size == scope->logical_block_size &&
           record->header_copy_stride_blocks ==
               scope->header_copy_stride_blocks &&
           record_equal(record->disk_guid, scope->disk_guid, 16u) &&
           record_equal(record->install_nonce, scope->install_nonce, 16u) &&
           record_equal(record->descriptor.volume_id, scope->volume_id, 16u);
}

RinCryptTpmDescriptorRecordResult
rin_crypt_tpm_descriptor_record_initialize_v1(
    RinCryptTpmDescriptorRecordV1* record,
    const RinCryptTpmDescriptorIdentityV1* identity,
    const RinCryptTpmAutoUnlockConfigV1* descriptor,
    uint64_t generation)
{
    RinCryptTpmDescriptorRecordV1 candidate;
    if (record_ranges_overlap(record, record ? sizeof(*record) : 0u,
                              identity,
                              identity ? sizeof(*identity) : 0u) ||
        record_ranges_overlap(record, record ? sizeof(*record) : 0u,
                              descriptor,
                              descriptor ? sizeof(*descriptor) : 0u)) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    if (record) record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    if (!record || !identity || !descriptor ||
        !rin_crypt_tpm_descriptor_identity_valid(identity) ||
        !rin_crypt_tpm_auto_unlock_config_valid(descriptor) ||
        generation == 0u || generation == UINT64_MAX) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    candidate.version = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_VERSION;
    candidate.struct_size = sizeof(candidate);
    candidate.role = identity->role;
    candidate.generation = generation;
    candidate.partition_first_lba = identity->partition_first_lba;
    candidate.partition_block_count = identity->partition_block_count;
    candidate.logical_block_size = identity->logical_block_size;
    candidate.header_copy_stride_blocks =
        identity->header_copy_stride_blocks;
    record_copy(candidate.disk_guid, identity->disk_guid, 16u);
    record_copy(candidate.install_nonce, identity->install_nonce, 16u);
    candidate.descriptor = *descriptor;
    if (!rin_crypt_tpm_descriptor_record_matches_identity(
            &candidate, identity)) {
        record_zero(&candidate, sizeof(candidate));
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH;
    }
    *record = candidate;
    record_zero(&candidate, sizeof(candidate));
    return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK;
}

RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_encode_v1(
    const RinCryptTpmDescriptorRecordV1* record,
    uint8_t output[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE])
{
    uint8_t digest[32];
    if (record_ranges_overlap(record, record ? sizeof(*record) : 0u,
                              output,
                              output ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u)) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    if (output) record_zero(output, RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE);
    record_zero(digest, sizeof(digest));
    if (!rin_crypt_tpm_descriptor_record_valid(record) || !output)
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    record_copy(output, g_record_magic, sizeof(g_record_magic));
    record_write_le32(output + 4u, record->version);
    record_write_le32(output + 8u, RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE);
    record_write_le32(output + 12u, record->role);
    record_write_le64(output + 16u, record->generation);
    record_write_le64(output + 24u, record->partition_first_lba);
    record_write_le64(output + 32u, record->partition_block_count);
    record_write_le32(output + 40u, record->logical_block_size);
    record_write_le32(output + 44u, record->header_copy_stride_blocks);
    record_copy(output + 48u, record->disk_guid, 16u);
    record_copy(output + 64u, record->install_nonce, 16u);
    descriptor_encode(&record->descriptor,
                      output + RECORD_DESCRIPTOR_OFFSET);
    record_hash(output, digest);
    record_copy(output + RECORD_DIGEST_OFFSET, digest, sizeof(digest));
    record_zero(digest, sizeof(digest));
    return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK;
}

RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_decode_v1(
    const uint8_t input[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    RinCryptTpmDescriptorRecordV1* record)
{
    RinCryptTpmDescriptorRecordV1 candidate;
    uint8_t digest[32];
    RinCryptTpmDescriptorRecordResult result =
        RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT;
    if (record_ranges_overlap(input,
                              input ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                      0u,
                              record, record ? sizeof(*record) : 0u)) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    if (record) record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    record_zero(digest, sizeof(digest));
    if (!input || !record) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
        goto done;
    }
    if (record_is_zero(input, RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE)) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY;
        goto done;
    }
    record_hash(input, digest);
    if (!record_equal(input, g_record_magic, sizeof(g_record_magic)) ||
        record_read_le32(input + 4u) !=
            RIN_CRYPT_TPM_DESCRIPTOR_RECORD_VERSION ||
        record_read_le32(input + 8u) !=
            RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE ||
        !record_is_zero(input + RECORD_RESERVED_OFFSET,
                        RECORD_DIGEST_OFFSET - RECORD_RESERVED_OFFSET) ||
        !record_equal(digest, input + RECORD_DIGEST_OFFSET,
                      sizeof(digest))) {
        goto done;
    }
    candidate.version = record_read_le32(input + 4u);
    candidate.struct_size = sizeof(candidate);
    candidate.role = record_read_le32(input + 12u);
    candidate.generation = record_read_le64(input + 16u);
    candidate.partition_first_lba = record_read_le64(input + 24u);
    candidate.partition_block_count = record_read_le64(input + 32u);
    candidate.logical_block_size = record_read_le32(input + 40u);
    candidate.header_copy_stride_blocks = record_read_le32(input + 44u);
    record_copy(candidate.disk_guid, input + 48u, 16u);
    record_copy(candidate.install_nonce, input + 64u, 16u);
    descriptor_decode(input + RECORD_DESCRIPTOR_OFFSET,
                      &candidate.descriptor);
    if (!rin_crypt_tpm_descriptor_record_valid(&candidate)) goto done;
    *record = candidate;
    result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK;
done:
    record_zero(&candidate, sizeof(candidate));
    record_zero(digest, sizeof(digest));
    return result;
}

RinCryptTpmDescriptorRecordResult rin_crypt_tpm_descriptor_record_select_v1(
    const uint8_t slot_a[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const uint8_t slot_b[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const RinCryptTpmDescriptorIdentityV1* identity,
    RinCryptTpmDescriptorRecordV1* record,
    uint32_t* valid_slot_mask)
{
    RinCryptTpmDescriptorRecordV1 candidate;
    RinCryptTpmDescriptorRecordResult decoded[2];
    uint32_t mask = 0u;
    RinCryptTpmDescriptorRecordResult result =
        RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT;
    if (valid_slot_mask) *valid_slot_mask = 0u;
    if (record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u) ||
        record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(identity,
                              identity ? sizeof(*identity) : 0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(identity,
                              identity ? sizeof(*identity) : 0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(record, record ? sizeof(*record) : 0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u)) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    if (record) record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    if (!slot_a || !slot_b || !record || !valid_slot_mask ||
        !rin_crypt_tpm_descriptor_identity_valid(identity)) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
        goto done;
    }
    decoded[0] = rin_crypt_tpm_descriptor_record_decode_v1(
        slot_a, record);
    decoded[1] = rin_crypt_tpm_descriptor_record_decode_v1(
        slot_b, &candidate);
    if (decoded[0] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK) {
        if (!rin_crypt_tpm_descriptor_record_matches_identity(record,
                                                               identity)) {
            result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH;
            goto done;
        }
        mask |= RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_A;
    }
    if (decoded[1] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK) {
        if (!rin_crypt_tpm_descriptor_record_matches_identity(&candidate,
                                                               identity)) {
            result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH;
            goto done;
        }
        mask |= RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_B;
    }
    if (mask == 0u) {
        result = decoded[0] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY &&
                         decoded[1] ==
                             RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY
                     ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY
                     : RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT;
        goto done;
    }
    if (mask == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_BOTH &&
        record->generation == candidate.generation &&
        !record_equal(record, &candidate, sizeof(candidate))) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_AMBIGUOUS;
        goto done;
    }
    if ((mask & RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_A) == 0u ||
        ((mask & RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_B) != 0u &&
         candidate.generation > record->generation)) {
        *record = candidate;
    }
    *valid_slot_mask = mask;
    result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK;
done:
    if (result != RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK && record)
        record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    return result;
}

RinCryptTpmDescriptorRecordResult
rin_crypt_tpm_descriptor_record_select_scope_v1(
    const uint8_t slot_a[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const uint8_t slot_b[RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE],
    const RinCryptTpmDescriptorScopeV1* scope,
    RinCryptTpmDescriptorRecordV1* record,
    uint32_t* valid_slot_mask)
{
    RinCryptTpmDescriptorRecordV1 candidate;
    RinCryptTpmDescriptorRecordResult decoded[2];
    uint32_t mask = 0u;
    RinCryptTpmDescriptorRecordResult result =
        RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT;
    if (valid_slot_mask) *valid_slot_mask = 0u;
    if (record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u) ||
        record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(scope, scope ? sizeof(*scope) : 0u,
                              record, record ? sizeof(*record) : 0u) ||
        record_ranges_overlap(slot_a,
                              slot_a ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(slot_b,
                              slot_b ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SIZE :
                                       0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(scope, scope ? sizeof(*scope) : 0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u) ||
        record_ranges_overlap(record, record ? sizeof(*record) : 0u,
                              valid_slot_mask,
                              valid_slot_mask ? sizeof(*valid_slot_mask) :
                                                0u)) {
        return RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
    }
    if (record) record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    if (!slot_a || !slot_b || !record || !valid_slot_mask ||
        !rin_crypt_tpm_descriptor_scope_valid(scope)) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_INVALID;
        goto done;
    }
    decoded[0] = rin_crypt_tpm_descriptor_record_decode_v1(slot_a, record);
    decoded[1] = rin_crypt_tpm_descriptor_record_decode_v1(slot_b,
                                                           &candidate);
    if (decoded[0] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK) {
        if (!rin_crypt_tpm_descriptor_record_matches_scope(record, scope)) {
            result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH;
            goto done;
        }
        mask |= RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_A;
    }
    if (decoded[1] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK) {
        if (!rin_crypt_tpm_descriptor_record_matches_scope(&candidate,
                                                            scope)) {
            result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_BINDING_MISMATCH;
            goto done;
        }
        mask |= RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_B;
    }
    if (mask == 0u) {
        result = decoded[0] == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY &&
                         decoded[1] ==
                             RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY
                     ? RIN_CRYPT_TPM_DESCRIPTOR_RECORD_EMPTY
                     : RIN_CRYPT_TPM_DESCRIPTOR_RECORD_CORRUPT;
        goto done;
    }
    if (mask == RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_BOTH &&
        record->generation == candidate.generation &&
        !record_equal(record, &candidate, sizeof(candidate))) {
        result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_AMBIGUOUS;
        goto done;
    }
    if ((mask & RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_A) == 0u ||
        ((mask & RIN_CRYPT_TPM_DESCRIPTOR_RECORD_SLOT_MASK_B) != 0u &&
         candidate.generation > record->generation)) {
        *record = candidate;
    }
    *valid_slot_mask = mask;
    result = RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK;
done:
    if (result != RIN_CRYPT_TPM_DESCRIPTOR_RECORD_OK && record)
        record_zero(record, sizeof(*record));
    record_zero(&candidate, sizeof(candidate));
    return result;
}
