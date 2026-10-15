/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Shared validation of the stable RinCrypt TPM auto-unlock record. */

#include "rinruntime/crypt/tpm_auto_unlock_config.h"

#include <stddef.h>

#include "crypto/sha256.h"

#define RIN_TPM2_HANDLE_PERSISTENT UINT32_C(0x81000000)

static const uint8_t g_policy_domain[16] = {
    'R', 'i', 'n', 'C', 'r', 'y', 'p', 't', '-', 'T', 'P', 'M', '-', 'v', '1', 0
};

static void config_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static void config_copy(uint8_t* output, const uint8_t* input,
                        uint32_t size)
{
    uint32_t index;
    for (index = 0u; index < size; ++index) output[index] = input[index];
}

static int config_equal(const uint8_t* left, const uint8_t* right,
                        uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    if (!left || !right) return 0;
    for (index = 0u; index < size; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0u;
}

static int config_nonzero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    if (!bytes) return 0;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined != 0u;
}

static int config_zero_bytes(const uint8_t* bytes, uint32_t size)
{
    return !config_nonzero(bytes, size);
}

static void write_le32(uint8_t* output, uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8u);
    output[2] = (uint8_t)(value >> 16u);
    output[3] = (uint8_t)(value >> 24u);
}

static void write_le64(uint8_t* output, uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        output[index] = (uint8_t)(value >> (index * 8u));
}

RinResultCode rin_crypt_tpm_policy_reference(
    const RinCryptTpmAutoUnlockConfigV1* config,
    uint8_t reference[RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE])
{
    uint8_t input[152];
    uint8_t digest[RIN_TPM2_SHA256_DIGEST_SIZE];
    sha256_ctx hash;
    if (reference)
        config_zero(reference, RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE);
    config_zero(input, (uint32_t)sizeof(input));
    config_zero(digest, (uint32_t)sizeof(digest));
    if (!config || !reference) return RIN_RESULT_INVALID_ARGUMENT;
    config_copy(input, g_policy_domain, (uint32_t)sizeof(g_policy_domain));
    config_copy(input + 16u, config->volume_id, RIN_CRYPT_VOLUME_ID_SIZE);
    config_copy(input + 32u, config->keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE);
    write_le64(input + 48u, config->boot_generation);
    write_le64(input + 56u, config->header_generation);
    write_le64(input + 64u, config->key_epoch);
    write_le64(input + 72u, config->rollback_counter);
    write_le32(input + 80u, config->rollback_nv_index);
    config_copy(input + 84u, config->rollback_nv_name,
                RIN_TPM2_SEALED_NAME_SIZE);
    config_copy(input + 118u, config->parent_name,
                RIN_TPM2_SEALED_NAME_SIZE);
    sha256_init(&hash);
    sha256_update(&hash, input, (uint32_t)sizeof(input));
    sha256_final(&hash, digest);
    config_copy(reference, digest, RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE);
    config_zero(&hash, (uint32_t)sizeof(hash));
    config_zero(input, (uint32_t)sizeof(input));
    config_zero(digest, (uint32_t)sizeof(digest));
    return RIN_RESULT_OK;
}

int rin_crypt_tpm_auto_unlock_config_valid(
    const RinCryptTpmAutoUnlockConfigV1* config)
{
    RinTpm2NamedHandleV1 parent;
    uint8_t reference[RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE];
    uint8_t authorized[RIN_TPM2_SHA256_DIGEST_SIZE];
    int valid = 0;
    config_zero(&parent, (uint32_t)sizeof(parent));
    config_zero(reference, (uint32_t)sizeof(reference));
    config_zero(authorized, (uint32_t)sizeof(authorized));
    if (!config || config->version != RIN_CRYPT_TPM_AUTO_UNLOCK_VERSION ||
        config->struct_size != sizeof(*config) ||
        (config->parent_handle & UINT32_C(0xFF000000)) !=
            RIN_TPM2_HANDLE_PERSISTENT ||
        config->rollback_nv_index == 0u || config->boot_generation == 0u ||
        config->header_generation == 0u || config->key_epoch == 0u ||
        config->rollback_counter == 0u ||
        config->rollback_counter == UINT64_MAX ||
        !config_nonzero(config->volume_id, sizeof(config->volume_id)) ||
        !config_nonzero(config->keyslot_id, sizeof(config->keyslot_id)) ||
        !config_nonzero(config->rollback_nv_name,
                        RIN_TPM2_SEALED_NAME_SIZE) ||
        config->rollback_nv_name[0] != 0u ||
        config->rollback_nv_name[1] != (uint8_t)RIN_TPM2_ALG_SHA256 ||
        !config_nonzero(config->rollback_nv_name + 2u,
                        RIN_TPM2_SHA256_DIGEST_SIZE) ||
        !config_zero_bytes(config->reserved, (uint32_t)sizeof(config->reserved)) ||
        !rin_tpm2_sealed_object_valid(&config->sealed_key) ||
        !rin_tpm2_policy_approval_valid(&config->approval,
                                        config->release_key_name,
                                        config->boot_generation))
        goto done;
    parent.version = RIN_TPM2_SEALED_VERSION;
    parent.struct_size = sizeof(parent);
    parent.handle = config->parent_handle;
    config_copy(parent.name, config->parent_name, sizeof(parent.name));
    if (!rin_tpm2_named_handle_valid(&parent) ||
        rin_crypt_tpm_policy_reference(config, reference) != RIN_RESULT_OK ||
        rin_tpm2_policy_compute_authorized_with_reference(
            config->release_key_name, reference, authorized) != RIN_RESULT_OK)
        goto done;
    valid = config_equal(authorized, config->sealed_key.policy_digest,
                         RIN_TPM2_SHA256_DIGEST_SIZE);
done:
    config_zero(&parent, (uint32_t)sizeof(parent));
    config_zero(reference, (uint32_t)sizeof(reference));
    config_zero(authorized, (uint32_t)sizeof(authorized));
    return valid;
}
