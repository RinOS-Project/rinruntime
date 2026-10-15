/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_KERNEL_RIN_CRYPT_RECOVERY_KEY_H
#define RIN_KERNEL_RIN_CRYPT_RECOVERY_KEY_H

#include <stdint.h>

#include "keyslot.h"

#define RIN_CRYPT_RECOVERY_KEY_MAGIC UINT32_C(0x314b5252) /* "RRK1" */
#define RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE 20u
#define RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH 41u
#define RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE 42u

typedef struct RinCryptRecoveryKeyProvider {
    uint32_t magic;
    uint32_t reserved;
    RinCryptKeyslotProvider keyslot_provider;
    uint8_t secret[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE];
} RinCryptRecoveryKeyProvider;

/* Generate and format a dedicated recovery keyslot. The returned code uses
 * six groups of six Crockford Base32 characters. Its CRC is typo detection,
 * not authentication; the keyslot AES-GCM tag remains authoritative. All
 * supplied buffers must be disjoint; an alias is rejected before mutation. */
int rin_crypt_recovery_keyslot_format_v1(
    RinCryptKeyslotV1* keyslot,
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* parameters,
    char recovery_key_out[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE],
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size);

/* Enrolls password and offline-recovery slots around the same XTS key and
 * epoch. On every non-alias path the mutable password is consumed and
 * cleared. All supplied buffers must be pairwise disjoint; aliases are
 * rejected before mutation. */
int rin_crypt_recovery_keyslot_pair_format_v1(
    RinCryptKeyslotV1 keyslots[RIN_CRYPT_KEYSLOT_PAIR_COUNT],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t password_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* password_parameters,
    uint8_t* password, uint32_t password_size,
    const uint8_t recovery_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* recovery_parameters,
    char recovery_key_out[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE],
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size);

/* Pair enrollment variant that seals the exact shared key before either
 * keyslot or the recovery text is published. */
int rin_crypt_recovery_keyslot_pair_format_and_seal_v1(
    RinCryptKeyslotV1 keyslots[RIN_CRYPT_KEYSLOT_PAIR_COUNT],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t password_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* password_parameters,
    uint8_t* password, uint32_t password_size,
    const uint8_t recovery_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* recovery_parameters,
    char recovery_key_out[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE],
    RinCryptKeyslotPairSealFn seal_key, void* seal_context,
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size);

/* Initialization consumes and clears exactly TEXT_LENGTH mutable characters.
 * All buffers must be disjoint; an alias is rejected before mutation. The
 * provider is one-shot and must remain at a stable address until clear. */
int rin_crypt_recovery_key_provider_init(
    RinCryptRecoveryKeyProvider* provider,
    const RinCryptKeyslotV1* keyslot, char* recovery_key,
    uint32_t recovery_key_size, uint8_t* workspace,
    uint64_t workspace_size);
void rin_crypt_recovery_key_provider_clear(
    RinCryptRecoveryKeyProvider* provider);
const RinCryptKeyProviderV1* rin_crypt_recovery_key_provider_api(void);

#endif /* RIN_KERNEL_RIN_CRYPT_RECOVERY_KEY_H */
