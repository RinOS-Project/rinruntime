/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Stable TPM data formats shared by kernel and installer code. */

#ifndef RIN_SHARED_TPM2_FORMATS_H
#define RIN_SHARED_TPM2_FORMATS_H

#include <stdint.h>

#include <rin/contract_abi.h>

#define RIN_TPM2_SHA256_DIGEST_SIZE UINT32_C(32)
#define RIN_TPM2_POLICY_NAME_SIZE UINT32_C(34)
#define RIN_TPM2_POLICY_SIGNATURE_SIZE UINT32_C(32)
#define RIN_TPM2_POLICY_REF_SIZE UINT32_C(22)
#define RIN_TPM2_POLICY_VERSION UINT32_C(1)
#define RIN_TPM2_CC_POLICY_AUTHORIZE UINT32_C(0x0000016A)
#define RIN_TPM2_CC_POLICY_AUTH_VALUE UINT32_C(0x0000016B)
#define RIN_TPM2_CC_POLICY_PCR UINT32_C(0x0000017F)
#define RIN_TPM2_ALG_SHA256 UINT16_C(0x000B)

#define RIN_TPM2_SEALED_NAME_SIZE UINT32_C(34)
#define RIN_TPM2_SEALED_VERSION UINT32_C(1)
#define RIN_TPM2_SEALED_KEYEDHASH_PUBLIC_SIZE UINT32_C(46)
#define RIN_TPM2_SEALED_DATA_MAX UINT32_C(64)
#define RIN_TPM2_SEALED_PRIVATE_MAX UINT32_C(1536)
#define RIN_TPM2_SEALED_PUBLIC_MAX UINT32_C(128)
#define RIN_TPM2_ALG_KEYEDHASH UINT16_C(0x0008)
#define RIN_TPM2_ALG_NULL UINT16_C(0x0010)
#define RIN_TPM2_OBJECT_FIXED_TPM UINT32_C(0x00000002)
#define RIN_TPM2_OBJECT_FIXED_PARENT UINT32_C(0x00000010)
#define RIN_TPM2_OBJECT_ADMIN_WITH_POLICY UINT32_C(0x00000080)
#define RIN_TPM2_OBJECT_NO_DA UINT32_C(0x00000400)
#define RIN_TPM2_SEALED_OBJECT_ATTRIBUTES                              \
    (RIN_TPM2_OBJECT_FIXED_TPM | RIN_TPM2_OBJECT_FIXED_PARENT |       \
     RIN_TPM2_OBJECT_ADMIN_WITH_POLICY)

#if defined(__cplusplus)
static_assert((RIN_TPM2_SEALED_OBJECT_ATTRIBUTES &
              RIN_TPM2_OBJECT_NO_DA) == 0u,
              "sealed objects must remain under TPM DA protection");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert((RIN_TPM2_SEALED_OBJECT_ATTRIBUTES &
                RIN_TPM2_OBJECT_NO_DA) == 0u,
               "sealed objects must remain under TPM DA protection");
#endif

typedef struct RinTpm2PolicyApprovalV1 {
    uint32_t version;
    uint32_t struct_size;
    uint64_t boot_generation;
    uint32_t pcr_index;
    uint32_t release_key_handle;
    uint8_t pcr_selection_digest[RIN_TPM2_SHA256_DIGEST_SIZE];
    uint8_t approved_policy[RIN_TPM2_SHA256_DIGEST_SIZE];
    uint8_t release_key_name[RIN_TPM2_POLICY_NAME_SIZE];
    uint8_t signature_r[RIN_TPM2_POLICY_SIGNATURE_SIZE];
    uint8_t signature_s[RIN_TPM2_POLICY_SIGNATURE_SIZE];
    uint8_t reserved[6];
} RinTpm2PolicyApprovalV1;

typedef struct RinTpm2NamedHandleV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t handle;
    uint32_t reserved;
    uint8_t name[RIN_TPM2_SEALED_NAME_SIZE];
    uint8_t reserved_tail[6];
} RinTpm2NamedHandleV1;

typedef struct RinTpm2SealedObjectV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t private_size;
    uint32_t public_size;
    uint8_t policy_digest[RIN_TPM2_SHA256_DIGEST_SIZE];
    uint8_t name[RIN_TPM2_SEALED_NAME_SIZE];
    uint8_t reserved[6];
    uint8_t private_blob[RIN_TPM2_SEALED_PRIVATE_MAX];
    uint8_t public_blob[RIN_TPM2_SEALED_PUBLIC_MAX];
} RinTpm2SealedObjectV1;

/* Format-level checks and deterministic policy digests are shared by the
 * kernel and installer. TPM transport and command execution stay in kernel. */
int rin_tpm2_named_handle_valid(const RinTpm2NamedHandleV1* object);
int rin_tpm2_sealed_object_valid(const RinTpm2SealedObjectV1* object);
int rin_tpm2_policy_approval_valid(
    const RinTpm2PolicyApprovalV1* approval,
    const uint8_t expected_release_key_name[RIN_TPM2_POLICY_NAME_SIZE],
    uint64_t expected_boot_generation);
RinResultCode rin_tpm2_policy_compute_approved(
    uint32_t pcr_index,
    const uint8_t selection_digest[RIN_TPM2_SHA256_DIGEST_SIZE],
    uint8_t approved_policy[RIN_TPM2_SHA256_DIGEST_SIZE]);
RinResultCode rin_tpm2_policy_compute_authorized_with_reference(
    const uint8_t release_key_name[RIN_TPM2_POLICY_NAME_SIZE],
    const uint8_t policy_reference[RIN_TPM2_POLICY_REF_SIZE],
    uint8_t authorized_policy[RIN_TPM2_SHA256_DIGEST_SIZE]);

#if defined(__cplusplus)
static_assert(sizeof(RinTpm2PolicyApprovalV1) == 192u,
              "RinTpm2PolicyApprovalV1 layout changed");
static_assert(sizeof(RinTpm2NamedHandleV1) == 56u,
              "RinTpm2 named-handle layout changed");
static_assert(sizeof(RinTpm2SealedObjectV1) == 1752u,
              "RinTpm2 sealed-object layout changed");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinTpm2PolicyApprovalV1) == 192u,
               "RinTpm2PolicyApprovalV1 layout changed");
_Static_assert(sizeof(RinTpm2NamedHandleV1) == 56u,
               "RinTpm2 named-handle layout changed");
_Static_assert(sizeof(RinTpm2SealedObjectV1) == 1752u,
               "RinTpm2 sealed-object layout changed");
#endif

#endif /* RIN_SHARED_TPM2_FORMATS_H */
