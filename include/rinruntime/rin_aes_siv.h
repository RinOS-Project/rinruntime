/* SPDX-License-Identifier: MIT */
/* Allocation-free AES-SIV-CMAC-256 (RFC 5297, AEAD algorithm 15). */

#ifndef RIN_SHARED_RIN_AES_SIV_H
#define RIN_SHARED_RIN_AES_SIV_H

#include <stddef.h>
#include <stdint.h>

#define RIN_AES_SIV_CMAC_256_KEY_BYTES 32u
#define RIN_AES_SIV_TAG_BYTES 16u
#define RIN_AES_SIV_MAX_ASSOCIATED_DATA 126u

typedef struct RinAesSivComponent {
    const uint8_t* bytes;
    size_t size;
} RinAesSivComponent;

/* output is SIV || ciphertext.  The output and plaintext ranges must not
 * overlap.  Empty components are permitted and are still authenticated. */
int rin_aes_siv_cmac_256_seal(
    const uint8_t key[RIN_AES_SIV_CMAC_256_KEY_BYTES],
    const RinAesSivComponent* associated_data,
    size_t associated_data_count,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

/* Authentication is checked in constant time.  The ciphertext and output
 * ranges must not overlap.  No unauthenticated plaintext remains in output
 * when verification fails. */
int rin_aes_siv_cmac_256_open(
    const uint8_t key[RIN_AES_SIV_CMAC_256_KEY_BYTES],
    const RinAesSivComponent* associated_data,
    size_t associated_data_count,
    const uint8_t* ciphertext,
    size_t ciphertext_size,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size);

#endif /* RIN_SHARED_RIN_AES_SIV_H */
