/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_SHARED_CRYPT_HEADER_H
#define RIN_SHARED_CRYPT_HEADER_H

#include <stdint.h>

#include "keyslot.h"

#define RIN_CRYPT_HEADER_VERSION 1u
#define RIN_CRYPT_HEADER_SIZE 512u
#define RIN_CRYPT_HEADER_COPY_COUNT 2u
#define RIN_CRYPT_HEADER_KEYSLOT_COUNT 2u

#define RIN_CRYPT_HEADER_STATE_PREPARED 1u
#define RIN_CRYPT_HEADER_STATE_COMMITTED 2u

typedef enum RinCryptHeaderResult {
    RIN_CRYPT_HEADER_OK = 0,
    RIN_CRYPT_HEADER_INVALID = -1,
    RIN_CRYPT_HEADER_NOT_FOUND = -2,
    RIN_CRYPT_HEADER_CORRUPT = -3,
    RIN_CRYPT_HEADER_AMBIGUOUS = -4,
    RIN_CRYPT_HEADER_IO = -5,
    RIN_CRYPT_HEADER_READ_ONLY = -6,
    RIN_CRYPT_HEADER_TIMEOUT = -7,
    RIN_CRYPT_HEADER_CANCELLED = -8,
    RIN_CRYPT_HEADER_REMOVED = -9,
    RIN_CRYPT_HEADER_BUSY = -10
} RinCryptHeaderResult;

typedef struct RinCryptVolumeHeaderV1 {
    uint8_t magic[4];
    uint8_t version[2];
    uint8_t header_size[2];
    uint8_t state[4];
    uint8_t keyslot_count[4];
    uint8_t generation[8];
    uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE];
    RinCryptKeyslotV1 keyslots[RIN_CRYPT_HEADER_KEYSLOT_COUNT];
    uint8_t reserved[124];
    uint8_t checksum[4];
} RinCryptVolumeHeaderV1;

#if defined(__cplusplus)
static_assert(sizeof(RinCryptVolumeHeaderV1) == RIN_CRYPT_HEADER_SIZE,
              "RinCrypt volume header format drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinCryptVolumeHeaderV1) == RIN_CRYPT_HEADER_SIZE,
               "RinCrypt volume header format drift");
#endif

int rin_crypt_header_format_initial_v1(
    const RinCryptKeyslotV1* keyslots, uint32_t keyslot_count,
    RinCryptVolumeHeaderV1* header);
int rin_crypt_header_validate(const RinCryptVolumeHeaderV1* header,
                              int require_committed);
int rin_crypt_header_find_keyslot(
    const RinCryptVolumeHeaderV1* header,
    const uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    RinCryptKeyslotV1* keyslot);

#endif /* RIN_SHARED_CRYPT_HEADER_H */
