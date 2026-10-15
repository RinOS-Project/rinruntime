/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Validation and deterministic digests for stable TPM on-disk formats. */

#include "formats.h"

#include <stddef.h>

#include <crypto/sha256.h>

#define RIN_TPM2_HANDLE_TRANSIENT UINT32_C(0x80000000)
#define RIN_TPM2_HANDLE_PERSISTENT UINT32_C(0x81000000)
#define RIN_TPM2_RH_OWNER UINT32_C(0x40000001)
#define RIN_TPM2_RH_ENDORSEMENT UINT32_C(0x4000000B)
#define RIN_TPM2_RH_PLATFORM UINT32_C(0x4000000C)
#define RIN_TPM2_ALG_SHA256_VALUE UINT16_C(0x000B)

static void format_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int format_nonzero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    if (!bytes) return 0;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined != 0u;
}

static int format_zero_bytes(const uint8_t* bytes, uint32_t size)
{
    return !format_nonzero(bytes, size);
}

static int format_equal(const uint8_t* left, const uint8_t* right,
                        uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    if (!left || !right) return 0;
    for (index = 0u; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0u;
}

static uint16_t read_be16(const uint8_t* bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
}

static uint32_t read_be32(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | bytes[3];
}

static void write_be32(uint8_t* bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24u);
    bytes[1] = (uint8_t)(value >> 16u);
    bytes[2] = (uint8_t)(value >> 8u);
    bytes[3] = (uint8_t)value;
}

static int hash_sha256(const uint8_t* input, uint32_t size,
                       uint8_t output[RIN_TPM2_SHA256_DIGEST_SIZE])
{
    sha256_ctx context;
    if ((!input && size != 0u) || !output) return 0;
    sha256_init(&context);
    if (size != 0u) sha256_update(&context, input, size);
    sha256_final(&context, output);
    format_zero(&context, (uint32_t)sizeof(context));
    return 1;
}

static int valid_name(const uint8_t name[RIN_TPM2_SEALED_NAME_SIZE])
{
    return name && read_be16(name) == RIN_TPM2_ALG_SHA256_VALUE &&
           format_nonzero(name + 2u, RIN_TPM2_SHA256_DIGEST_SIZE);
}

static int valid_key_handle(uint32_t handle)
{
    uint32_t type = handle & UINT32_C(0xFF000000);
    return type == RIN_TPM2_HANDLE_TRANSIENT ||
           type == RIN_TPM2_HANDLE_PERSISTENT;
}

static int valid_key_name(
    const uint8_t name[RIN_TPM2_POLICY_NAME_SIZE])
{
    return name && read_be16(name) == RIN_TPM2_ALG_SHA256_VALUE &&
           format_nonzero(name + 2u, RIN_TPM2_SHA256_DIGEST_SIZE);
}

int rin_tpm2_named_handle_valid(const RinTpm2NamedHandleV1* object)
{
    return object && object->version == RIN_TPM2_SEALED_VERSION &&
           object->struct_size == sizeof(*object) &&
           object->reserved == 0u && valid_key_handle(object->handle) &&
           valid_name(object->name) &&
           format_zero_bytes(object->reserved_tail,
                             (uint32_t)sizeof(object->reserved_tail));
}

RinResultCode rin_tpm2_policy_compute_approved(
    uint32_t pcr_index,
    const uint8_t selection_digest[RIN_TPM2_SHA256_DIGEST_SIZE],
    uint8_t approved_policy[RIN_TPM2_SHA256_DIGEST_SIZE])
{
    uint8_t input[78];
    uint8_t* cursor;
    if (approved_policy) format_zero(approved_policy,
                                     RIN_TPM2_SHA256_DIGEST_SIZE);
    if (pcr_index >= 24u || !selection_digest || !approved_policy)
        return RIN_RESULT_INVALID_ARGUMENT;
    format_zero(input, sizeof(input));
    cursor = input + RIN_TPM2_SHA256_DIGEST_SIZE;
    write_be32(cursor, RIN_TPM2_CC_POLICY_PCR);
    cursor += 4u;
    write_be32(cursor, 1u); /* one TPML_PCR_SELECTION */
    cursor += 4u;
    cursor[0] = (uint8_t)(RIN_TPM2_ALG_SHA256_VALUE >> 8u);
    cursor[1] = (uint8_t)RIN_TPM2_ALG_SHA256_VALUE;
    cursor[2] = 3u;
    cursor += 3u;
    cursor[pcr_index / 8u] = (uint8_t)(1u << (pcr_index & 7u));
    cursor += 3u;
    for (uint32_t index = 0u; index < RIN_TPM2_SHA256_DIGEST_SIZE; ++index)
        cursor[index] = selection_digest[index];
    if (!hash_sha256(input, (uint32_t)sizeof(input), approved_policy)) {
        format_zero(input, sizeof(input));
        return RIN_RESULT_CORRUPT_DATA;
    }
    format_zero(input, sizeof(input));
    return RIN_RESULT_OK;
}

RinResultCode rin_tpm2_policy_compute_authorized_with_reference(
    const uint8_t release_key_name[RIN_TPM2_POLICY_NAME_SIZE],
    const uint8_t policy_reference[RIN_TPM2_POLICY_REF_SIZE],
    uint8_t authorized_policy[RIN_TPM2_SHA256_DIGEST_SIZE])
{
    uint8_t first[70];
    uint8_t second[RIN_TPM2_SHA256_DIGEST_SIZE + RIN_TPM2_POLICY_REF_SIZE];
    if (authorized_policy) format_zero(authorized_policy,
                                       RIN_TPM2_SHA256_DIGEST_SIZE);
    if (!valid_key_name(release_key_name) ||
        !format_nonzero(policy_reference, RIN_TPM2_POLICY_REF_SIZE) ||
        !authorized_policy)
        return RIN_RESULT_INVALID_ARGUMENT;
    format_zero(first, sizeof(first));
    write_be32(first + RIN_TPM2_SHA256_DIGEST_SIZE,
               RIN_TPM2_CC_POLICY_AUTHORIZE);
    for (uint32_t index = 0u; index < RIN_TPM2_POLICY_NAME_SIZE; ++index)
        first[RIN_TPM2_SHA256_DIGEST_SIZE + 4u + index] =
            release_key_name[index];
    if (!hash_sha256(first, (uint32_t)sizeof(first), second)) {
        format_zero(first, sizeof(first));
        return RIN_RESULT_CORRUPT_DATA;
    }
    for (uint32_t index = 0u; index < RIN_TPM2_POLICY_REF_SIZE; ++index)
        second[RIN_TPM2_SHA256_DIGEST_SIZE + index] = policy_reference[index];
    if (!hash_sha256(second, (uint32_t)sizeof(second), authorized_policy)) {
        format_zero(first, sizeof(first));
        format_zero(second, sizeof(second));
        return RIN_RESULT_CORRUPT_DATA;
    }
    format_zero(first, sizeof(first));
    format_zero(second, sizeof(second));
    return RIN_RESULT_OK;
}

int rin_tpm2_policy_approval_valid(
    const RinTpm2PolicyApprovalV1* approval,
    const uint8_t expected_release_key_name[RIN_TPM2_POLICY_NAME_SIZE],
    uint64_t expected_boot_generation)
{
    uint8_t computed[RIN_TPM2_SHA256_DIGEST_SIZE];
    int valid;
    if (!approval || !expected_release_key_name ||
        approval->version != RIN_TPM2_POLICY_VERSION ||
        approval->struct_size != sizeof(*approval) ||
        approval->boot_generation == 0u ||
        approval->boot_generation != expected_boot_generation ||
        approval->pcr_index != 11u ||
        !valid_key_handle(approval->release_key_handle) ||
        !valid_key_name(approval->release_key_name) ||
        !valid_key_name(expected_release_key_name) ||
        !format_equal(approval->release_key_name,
                      expected_release_key_name,
                      RIN_TPM2_POLICY_NAME_SIZE) ||
        !format_nonzero(approval->pcr_selection_digest,
                        RIN_TPM2_SHA256_DIGEST_SIZE) ||
        !format_nonzero(approval->signature_r, RIN_TPM2_POLICY_SIGNATURE_SIZE) ||
        !format_nonzero(approval->signature_s, RIN_TPM2_POLICY_SIGNATURE_SIZE) ||
        !format_zero_bytes(approval->reserved,
                           (uint32_t)sizeof(approval->reserved)))
        return 0;
    if (rin_tpm2_policy_compute_approved(
            approval->pcr_index, approval->pcr_selection_digest,
            computed) != RIN_RESULT_OK)
        return 0;
    valid = format_equal(computed, approval->approved_policy,
                         RIN_TPM2_SHA256_DIGEST_SIZE);
    format_zero(computed, sizeof(computed));
    return valid;
}

int rin_tpm2_sealed_object_valid(const RinTpm2SealedObjectV1* object)
{
    uint8_t expected_name[RIN_TPM2_SEALED_NAME_SIZE];
    const uint8_t* public_blob;
    uint32_t public_size;
    int valid;
    if (!object || object->version != RIN_TPM2_SEALED_VERSION ||
        object->struct_size != sizeof(*object) || object->private_size == 0u ||
        object->private_size > RIN_TPM2_SEALED_PRIVATE_MAX ||
        object->public_size != RIN_TPM2_SEALED_KEYEDHASH_PUBLIC_SIZE ||
        !format_nonzero(object->policy_digest, RIN_TPM2_SHA256_DIGEST_SIZE) ||
        !format_zero_bytes(object->reserved, (uint32_t)sizeof(object->reserved)) ||
        !format_zero_bytes(object->private_blob + object->private_size,
                           RIN_TPM2_SEALED_PRIVATE_MAX - object->private_size) ||
        !format_zero_bytes(object->public_blob + object->public_size,
                           RIN_TPM2_SEALED_PUBLIC_MAX - object->public_size))
        return 0;
    public_blob = object->public_blob;
    public_size = object->public_size;
    if (read_be16(public_blob) != RIN_TPM2_ALG_KEYEDHASH ||
        read_be16(public_blob + 2u) != RIN_TPM2_ALG_SHA256_VALUE ||
        read_be32(public_blob + 4u) != RIN_TPM2_SEALED_OBJECT_ATTRIBUTES ||
        read_be16(public_blob + 8u) != RIN_TPM2_SHA256_DIGEST_SIZE ||
        !format_equal(public_blob + 10u, object->policy_digest,
                      RIN_TPM2_SHA256_DIGEST_SIZE) ||
        read_be16(public_blob + 42u) != RIN_TPM2_ALG_NULL ||
        read_be16(public_blob + 44u) != 0u)
        return 0;
    expected_name[0] = (uint8_t)(RIN_TPM2_ALG_SHA256_VALUE >> 8u);
    expected_name[1] = (uint8_t)RIN_TPM2_ALG_SHA256_VALUE;
    if (!hash_sha256(public_blob, public_size, expected_name + 2u)) return 0;
    valid = format_equal(expected_name, object->name,
                         RIN_TPM2_SEALED_NAME_SIZE);
    format_zero(expected_name, (uint32_t)sizeof(expected_name));
    return valid;
}
