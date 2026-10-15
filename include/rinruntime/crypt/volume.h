/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_KERNEL_RIN_CRYPT_H
#define RIN_KERNEL_RIN_CRYPT_H

#include <stdint.h>
#include <rin/crypt.h>
#include "../../../public-base/libs/rintls/crypto/aes.h"

#define RIN_CRYPT_SESSION_MAGIC UINT32_C(0x31584352) /* "RCX1" */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RinCryptKeyProviderV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    int (*unlock)(void* context, const RinCryptKeyRequestV1* request,
                  uint8_t key[RIN_CRYPT_XTS_256_KEY_SIZE],
                  uint64_t* key_epoch, uint32_t* evidence_flags);
} RinCryptKeyProviderV1;

typedef struct RinCryptSessionConfigV1 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t data_unit_size;
    uint32_t reserved;
    RinCryptKeyRequestV1 key_request;
    const RinCryptKeyProviderV1* key_provider;
    void* key_provider_context;
} RinCryptSessionConfigV1;

typedef struct RinCryptSession {
    uint32_t magic;
    uint32_t data_unit_size;
    uint32_t evidence_flags;
    uint32_t active;
    uint64_t key_epoch;
    aes_ctx data_key;
    aes_ctx tweak_key;
} RinCryptSession;

int rin_crypt_session_open(RinCryptSession* session,
                           const RinCryptSessionConfigV1* config);
void rin_crypt_session_close(RinCryptSession* session);

/* Encrypts/decrypts whole data units in place. XTS ciphertext stealing is not
 * used: data_unit_size is always a multiple of the AES block size. */
int rin_crypt_encrypt(RinCryptSession* session, uint64_t first_data_unit,
                      uint32_t data_unit_count, uint8_t* buffer,
                      uint64_t buffer_size);
int rin_crypt_decrypt(RinCryptSession* session, uint64_t first_data_unit,
                      uint32_t data_unit_count, uint8_t* buffer,
                      uint64_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* RIN_KERNEL_RIN_CRYPT_H */
