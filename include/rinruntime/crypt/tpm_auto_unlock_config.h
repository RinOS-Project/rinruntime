/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Stable data portion of the kernel-owned TPM auto-unlock contract. */

#ifndef RIN_SHARED_CRYPT_TPM_AUTO_UNLOCK_CONFIG_H
#define RIN_SHARED_CRYPT_TPM_AUTO_UNLOCK_CONFIG_H

#include <stdint.h>

#include <rin/crypt.h>
#include <rin/contract_abi.h>
#include "../tpm2/formats.h"

#define RIN_CRYPT_TPM_AUTO_UNLOCK_VERSION UINT32_C(1)
#define RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE RIN_TPM2_POLICY_REF_SIZE

typedef struct RinCryptTpmRollbackEvidenceV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t nv_index;
    uint32_t reserved;
    uint64_t counter;
    uint8_t nv_name[RIN_TPM2_SEALED_NAME_SIZE];
    uint8_t reserved_tail[6];
} RinCryptTpmRollbackEvidenceV1;

typedef struct RinCryptTpmAutoUnlockConfigV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t parent_handle;
    uint32_t rollback_nv_index;
    uint64_t boot_generation;
    uint64_t header_generation;
    uint64_t key_epoch;
    uint64_t rollback_counter;
    uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint8_t parent_name[RIN_TPM2_SEALED_NAME_SIZE];
    uint8_t rollback_nv_name[RIN_TPM2_SEALED_NAME_SIZE];
    uint8_t release_key_name[RIN_TPM2_POLICY_NAME_SIZE];
    uint8_t reserved[10];
    RinTpm2PolicyApprovalV1 approval;
    RinTpm2SealedObjectV1 sealed_key;
} RinCryptTpmAutoUnlockConfigV1;

/* Shared validators for the stable config/on-disk format. Runtime ownership
 * and TPM transport remain private to kernel security. */
RinResultCode rin_crypt_tpm_policy_reference(
    const RinCryptTpmAutoUnlockConfigV1* config,
    uint8_t reference[RIN_CRYPT_TPM_POLICY_REFERENCE_SIZE]);
int rin_crypt_tpm_auto_unlock_config_valid(
    const RinCryptTpmAutoUnlockConfigV1* config);

#if defined(__cplusplus)
static_assert(sizeof(RinCryptTpmRollbackEvidenceV1) == 64u,
              "RinCrypt TPM rollback evidence ABI drift");
static_assert(sizeof(RinCryptTpmAutoUnlockConfigV1) == 2136u,
              "RinCrypt TPM auto-unlock config ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinCryptTpmRollbackEvidenceV1) == 64u,
               "RinCrypt TPM rollback evidence ABI drift");
_Static_assert(sizeof(RinCryptTpmAutoUnlockConfigV1) == 2136u,
               "RinCrypt TPM auto-unlock config ABI drift");
#endif

#endif /* RIN_SHARED_CRYPT_TPM_AUTO_UNLOCK_CONFIG_H */
