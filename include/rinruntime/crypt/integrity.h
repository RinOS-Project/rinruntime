/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef RIN_SHARED_CRYPT_INTEGRITY_H
#define RIN_SHARED_CRYPT_INTEGRITY_H

#include <stdint.h>

#include "rinruntime/crypt/volume.h"
#include "libs/rintls/crypto/hmac.h"

#define RIN_CRYPT_INTEGRITY_VERSION UINT32_C(1)
#define RIN_CRYPT_INTEGRITY_TAG_SIZE UINT32_C(16)
#define RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK UINT32_C(32)
#define RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS UINT32_C(4)
#define RIN_CRYPT_INTEGRITY_STATE_BLOCKS UINT32_C(2)
#define RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS \
    (RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS + \
     RIN_CRYPT_INTEGRITY_STATE_BLOCKS)
#define RIN_CRYPT_INTEGRITY_BLOCK_SIZE UINT32_C(512)

typedef struct RinCryptIntegrityLayout {
    uint64_t state_first_lba;
    uint64_t journal_first_lba;
    uint64_t tag_first_lba;
    uint64_t tag_block_count;
    uint64_t payload_first_lba;
    uint64_t payload_block_count;
} RinCryptIntegrityLayout;

typedef struct RinCryptIntegrityIo {
    void* context;
    int (*read_block)(void* context, uint64_t lba, uint8_t block[512]);
    int (*write_block)(void* context, uint64_t lba,
                       const uint8_t block[512], uint32_t flags);
    int (*flush)(void* context);
    int (*write_zero_blocks)(void* context, uint64_t lba, uint32_t count);
} RinCryptIntegrityIo;

typedef enum RinCryptIntegrityResult {
    RIN_CRYPT_INTEGRITY_OK = 0,
    RIN_CRYPT_INTEGRITY_ZERO_SECTOR = 1,
    RIN_CRYPT_INTEGRITY_IO = -1,
    RIN_CRYPT_INTEGRITY_AUTH = -2,
    RIN_CRYPT_INTEGRITY_INVALID = -3
} RinCryptIntegrityResult;

/* Tags bind one payload-relative sector position, volume ID and key epoch.
 * They reject bit flips and cross-sector replay. Restoring a prior valid
 * ciphertext/tag pair for the same sector, or restoring the whole medium,
 * requires a separate TPM-backed monotonic root to detect. */

/* The fixed point reserves one 512-byte tag block per 32 data sectors. The
 * journal owns mirrored descriptors, one ciphertext sector and one tag page. */
static inline int rin_crypt_integrity_layout(
    uint64_t partition_first_lba, uint64_t partition_block_count,
    uint64_t header_block_count, RinCryptIntegrityLayout* layout)
{
    uint64_t available;
    uint64_t payload;
    uint64_t tags = 0u;
    uint32_t iteration;
    if (!layout || partition_block_count == 0u ||
        header_block_count > partition_block_count ||
        partition_first_lba > UINT64_MAX - partition_block_count) {
        return 0;
    }
    available = partition_block_count - header_block_count;
    if (available <= RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS) return 0;
    payload = available - RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS;
    for (iteration = 0u; iteration < 64u; ++iteration) {
        uint64_t next_tags = payload / RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK;
        uint64_t next_payload;
        if ((payload % RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK) != 0u)
            ++next_tags;
        if (next_tags > available - RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS)
            return 0;
        next_payload = available - RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS -
                       next_tags;
        if (next_payload == payload) {
            tags = next_tags;
            break;
        }
        payload = next_payload;
    }
    if (iteration == 64u || payload == 0u || tags == 0u ||
        partition_first_lba > UINT64_MAX - header_block_count ||
        partition_first_lba + header_block_count >
            UINT64_MAX - RIN_CRYPT_INTEGRITY_STATE_BLOCKS ||
        partition_first_lba + header_block_count +
                RIN_CRYPT_INTEGRITY_STATE_BLOCKS >
            UINT64_MAX - RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS ||
        partition_first_lba + header_block_count +
                RIN_CRYPT_INTEGRITY_RESERVED_BLOCKS > UINT64_MAX - tags) {
        return 0;
    }
    layout->state_first_lba = partition_first_lba + header_block_count;
    layout->journal_first_lba = layout->state_first_lba +
                                RIN_CRYPT_INTEGRITY_STATE_BLOCKS;
    layout->tag_first_lba = layout->journal_first_lba +
                            RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS;
    layout->tag_block_count = tags;
    layout->payload_first_lba = layout->tag_first_lba + tags;
    layout->payload_block_count = payload;
    return layout->payload_first_lba + payload ==
           partition_first_lba + partition_block_count;
}

static inline int rin_crypt_integrity_layout_valid(
    const RinCryptIntegrityLayout* layout)
{
    uint64_t expected_tags;
    if (!layout || layout->payload_block_count == 0u ||
        layout->tag_block_count == 0u) {
        return 0;
    }
    expected_tags = layout->payload_block_count /
                    RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK;
    if ((layout->payload_block_count %
         RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK) != 0u) ++expected_tags;
    return layout->tag_block_count == expected_tags &&
           layout->state_first_lba <= UINT64_MAX -
                                          RIN_CRYPT_INTEGRITY_STATE_BLOCKS &&
           layout->state_first_lba + RIN_CRYPT_INTEGRITY_STATE_BLOCKS ==
               layout->journal_first_lba &&
           layout->journal_first_lba <= UINT64_MAX -
                                            RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS &&
           layout->journal_first_lba + RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS ==
               layout->tag_first_lba &&
           layout->tag_first_lba <= UINT64_MAX - layout->tag_block_count &&
           layout->tag_first_lba + layout->tag_block_count ==
               layout->payload_first_lba &&
           layout->payload_first_lba <= UINT64_MAX -
                                            layout->payload_block_count;
}

static inline void rin_crypt_integrity_tag(
    const uint8_t key[32], const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    uint64_t key_epoch, uint64_t payload_position,
    const uint8_t ciphertext[RIN_CRYPT_INTEGRITY_BLOCK_SIZE],
    uint8_t tag[RIN_CRYPT_INTEGRITY_TAG_SIZE])
{
    static const uint8_t domain[] = "RinOS RCT2 sector tag";
    uint8_t fields[32];
    uint8_t digest[HMAC_SHA256_SIZE];
    hmac_sha256_ctx hmac;
    volatile uint8_t* wipe;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        fields[index] = (uint8_t)(key_epoch >> (index * 8u));
        fields[8u + index] = (uint8_t)(payload_position >> (index * 8u));
    }
    for (index = 0u; index < RIN_CRYPT_VOLUME_ID_SIZE; ++index)
        fields[16u + index] = volume_id[index];
    hmac_sha256_init(&hmac, key, 32u);
    hmac_sha256_update(&hmac, domain, sizeof(domain) - 1u);
    hmac_sha256_update(&hmac, fields, sizeof(fields));
    hmac_sha256_update(&hmac, ciphertext, RIN_CRYPT_INTEGRITY_BLOCK_SIZE);
    hmac_sha256_final(&hmac, digest);
    wipe = (volatile uint8_t*)&hmac;
    for (index = 0u; index < sizeof(hmac); ++index) wipe[index] = 0u;
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_TAG_SIZE; ++index)
        tag[index] = digest[index];
    wipe = (volatile uint8_t*)digest;
    for (index = 0u; index < sizeof(digest); ++index) wipe[index] = 0u;
    wipe = (volatile uint8_t*)fields;
    for (index = 0u; index < sizeof(fields); ++index) wipe[index] = 0u;
}

static inline void rin_crypt_integrity_zero(void* data, uint32_t size);

static inline void rin_crypt_integrity_zero_sector_tag(
    const uint8_t key[32], const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    uint64_t key_epoch, uint64_t payload_position,
    uint8_t tag[RIN_CRYPT_INTEGRITY_TAG_SIZE])
{
    static const uint8_t domain[] = "RinOS RCT2 logical zero sector";
    uint8_t fields[32];
    uint8_t digest[HMAC_SHA256_SIZE];
    hmac_sha256_ctx hmac;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        fields[index] = (uint8_t)(key_epoch >> (index * 8u));
        fields[8u + index] = (uint8_t)(payload_position >> (index * 8u));
    }
    for (index = 0u; index < RIN_CRYPT_VOLUME_ID_SIZE; ++index)
        fields[16u + index] = volume_id[index];
    hmac_sha256_init(&hmac, key, 32u);
    hmac_sha256_update(&hmac, domain, sizeof(domain) - 1u);
    hmac_sha256_update(&hmac, fields, sizeof(fields));
    hmac_sha256_final(&hmac, digest);
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_TAG_SIZE; ++index)
        tag[index] = digest[index];
    rin_crypt_integrity_zero(&hmac, sizeof(hmac));
    rin_crypt_integrity_zero(digest, sizeof(digest));
    rin_crypt_integrity_zero(fields, sizeof(fields));
}

static inline int rin_crypt_integrity_tag_equal(
    const uint8_t left[RIN_CRYPT_INTEGRITY_TAG_SIZE],
    const uint8_t right[RIN_CRYPT_INTEGRITY_TAG_SIZE])
{
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_TAG_SIZE; ++index)
        difference |= (uint8_t)(left[index] ^ right[index]);
    return difference == 0u;
}

static inline void rin_crypt_integrity_zero(void* data, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)data;
    while (size-- != 0u) *bytes++ = 0u;
}

static inline void rin_crypt_integrity_write_le32(uint8_t out[4],
                                                   uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
    out[2] = (uint8_t)(value >> 16u);
    out[3] = (uint8_t)(value >> 24u);
}

static inline void rin_crypt_integrity_write_le64(uint8_t out[8],
                                                   uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        out[index] = (uint8_t)(value >> (index * 8u));
}

static inline uint32_t rin_crypt_integrity_read_le32(const uint8_t in[4])
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8u) |
           ((uint32_t)in[2] << 16u) | ((uint32_t)in[3] << 24u);
}

static inline uint64_t rin_crypt_integrity_read_le64(const uint8_t in[8])
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        value |= (uint64_t)in[index] << (index * 8u);
    return value;
}

#define RIN_CRYPT_INTEGRITY_STATE_EMPTY 0
#define RIN_CRYPT_INTEGRITY_STATE_PENDING 1
#define RIN_CRYPT_INTEGRITY_STATE_READY 2
#define RIN_CRYPT_INTEGRITY_STATE_INVALID (-1)
#define RIN_CRYPT_INTEGRITY_STATE_IO (-2)

static inline void rin_crypt_integrity_state_mac(
    const uint8_t key[32], const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t state[512], uint8_t mac[32])
{
    static const uint8_t domain[] = "RinOS RCT2 initialized volume state";
    hmac_sha256_ctx hmac;
    hmac_sha256_init(&hmac, key, 32u);
    hmac_sha256_update(&hmac, domain, sizeof(domain) - 1u);
    hmac_sha256_update(&hmac, volume_id, RIN_CRYPT_VOLUME_ID_SIZE);
    hmac_sha256_update(&hmac, state, 56u);
    hmac_sha256_final(&hmac, mac);
    rin_crypt_integrity_zero(&hmac, sizeof(hmac));
}

static inline int rin_crypt_integrity_state_valid(
    const uint8_t state[512], const RinCryptIntegrityLayout* layout,
    const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch)
{
    static const uint8_t magic[4] = {'R', 'I', 'V', '2'};
    uint8_t mac[32];
    uint8_t difference = 0u;
    uint32_t status;
    uint32_t index;
    int valid;
    if (!state || !layout || !key || !volume_id || key_epoch == 0u ||
        state[0] != magic[0] || state[1] != magic[1] ||
        state[2] != magic[2] || state[3] != magic[3] ||
        rin_crypt_integrity_read_le32(state + 4u) !=
            RIN_CRYPT_INTEGRITY_VERSION ||
        rin_crypt_integrity_read_le64(state + 16u) != key_epoch ||
        rin_crypt_integrity_read_le64(state + 24u) !=
            layout->payload_block_count ||
        rin_crypt_integrity_read_le64(state + 32u) !=
            layout->tag_block_count ||
        rin_crypt_integrity_read_le64(state + 40u) !=
            (layout->payload_first_lba >= layout->state_first_lba
                 ? layout->payload_first_lba - layout->state_first_lba
                 : UINT64_MAX) ||
        rin_crypt_integrity_read_le64(state + 48u) !=
            (layout->tag_first_lba >= layout->state_first_lba
                 ? layout->tag_first_lba - layout->state_first_lba
                 : UINT64_MAX)) {
        return 0;
    }
    status = rin_crypt_integrity_read_le32(state + 8u);
    if (status != (uint32_t)RIN_CRYPT_INTEGRITY_STATE_PENDING &&
        status != (uint32_t)RIN_CRYPT_INTEGRITY_STATE_READY) return 0;
    for (index = 12u; index < 16u; ++index) difference |= state[index];
    for (index = 88u; index < RIN_CRYPT_INTEGRITY_BLOCK_SIZE; ++index)
        difference |= state[index];
    if (difference != 0u) return 0;
    rin_crypt_integrity_state_mac(key, volume_id, state, mac);
    difference = 0u;
    for (index = 0u; index < sizeof(mac); ++index)
        difference |= (uint8_t)(mac[index] ^ state[56u + index]);
    rin_crypt_integrity_zero(mac, sizeof(mac));
    valid = difference == 0u;
    return valid ? (int)status : 0;
}

static inline int rin_crypt_integrity_state_read(
    const RinCryptIntegrityLayout* layout, const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, uint8_t scratch[1536])
{
    uint8_t second[512];
    uint32_t index;
    int first_zero = 1;
    int second_zero = 1;
    int first_state;
    int second_state;
    int result;
    if (!rin_crypt_integrity_layout_valid(layout) || !key || !volume_id ||
        !io || !io->read_block || !scratch ||
        layout->state_first_lba > UINT64_MAX - 1u)
        return RIN_CRYPT_INTEGRITY_STATE_INVALID;
    if (io->read_block(io->context, layout->state_first_lba, scratch) != 0 ||
        io->read_block(io->context, layout->state_first_lba + 1u,
                       second) != 0) {
        rin_crypt_integrity_zero(second, sizeof(second));
        rin_crypt_integrity_zero(scratch, 1536u);
        return RIN_CRYPT_INTEGRITY_STATE_IO;
    }
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_BLOCK_SIZE; ++index) {
        first_zero &= scratch[index] == 0u;
        second_zero &= second[index] == 0u;
    }
    first_state = first_zero ? 0 : rin_crypt_integrity_state_valid(
        scratch, layout, key, volume_id, key_epoch);
    second_state = second_zero ? 0 : rin_crypt_integrity_state_valid(
        second, layout, key, volume_id, key_epoch);
    /* Initialization publishes READY to each mirrored state block in
     * separate flushes.  A single READY copy is not sufficient: the other
     * copy may still say PENDING because power was lost during publication.
     * Requiring both copies also keeps a torn/corrupt marker fail-closed. */
    if (first_state == RIN_CRYPT_INTEGRITY_STATE_READY &&
        second_state == RIN_CRYPT_INTEGRITY_STATE_READY) {
        result = RIN_CRYPT_INTEGRITY_STATE_READY;
    } else if (first_state == RIN_CRYPT_INTEGRITY_STATE_PENDING ||
               second_state == RIN_CRYPT_INTEGRITY_STATE_PENDING) {
        result = RIN_CRYPT_INTEGRITY_STATE_PENDING;
    } else if (first_zero && second_zero) {
        result = RIN_CRYPT_INTEGRITY_STATE_EMPTY;
    } else {
        result = RIN_CRYPT_INTEGRITY_STATE_INVALID;
    }
    rin_crypt_integrity_zero(second, sizeof(second));
    rin_crypt_integrity_zero(scratch, 1536u);
    return result;
}

static inline int rin_crypt_integrity_state_write(
    const RinCryptIntegrityLayout* layout, const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, uint64_t copy_index, uint32_t state_value,
    uint8_t scratch[1536])
{
    static const uint8_t magic[4] = {'R', 'I', 'V', '2'};
    uint64_t lba;
    if (!rin_crypt_integrity_layout_valid(layout) || !key || !volume_id ||
        !io || !io->write_block ||
        !io->flush || !scratch || copy_index >=
            RIN_CRYPT_INTEGRITY_STATE_BLOCKS || key_epoch == 0u ||
        (state_value != (uint32_t)RIN_CRYPT_INTEGRITY_STATE_PENDING &&
         state_value != (uint32_t)RIN_CRYPT_INTEGRITY_STATE_READY) ||
        layout->state_first_lba > UINT64_MAX - copy_index) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    lba = layout->state_first_lba + copy_index;
    rin_crypt_integrity_zero(scratch, RIN_CRYPT_INTEGRITY_BLOCK_SIZE);
    scratch[0] = magic[0]; scratch[1] = magic[1];
    scratch[2] = magic[2]; scratch[3] = magic[3];
    rin_crypt_integrity_write_le32(scratch + 4u,
                                  RIN_CRYPT_INTEGRITY_VERSION);
    rin_crypt_integrity_write_le32(scratch + 8u, state_value);
    rin_crypt_integrity_write_le64(scratch + 16u, key_epoch);
    rin_crypt_integrity_write_le64(scratch + 24u,
                                   layout->payload_block_count);
    rin_crypt_integrity_write_le64(scratch + 32u,
                                   layout->tag_block_count);
    rin_crypt_integrity_write_le64(scratch + 40u,
                                   layout->payload_first_lba -
                                       layout->state_first_lba);
    rin_crypt_integrity_write_le64(scratch + 48u,
                                   layout->tag_first_lba -
                                       layout->state_first_lba);
    rin_crypt_integrity_state_mac(key, volume_id, scratch, scratch + 56u);
    if (io->write_block(io->context, lba, scratch, 0u) != 0 ||
        io->flush(io->context) != 0) {
        rin_crypt_integrity_zero(scratch, 1536u);
        return RIN_CRYPT_INTEGRITY_IO;
    }
    rin_crypt_integrity_zero(scratch, 1536u);
    return RIN_CRYPT_INTEGRITY_OK;
}

static inline int rin_crypt_integrity_is_ready(
    const RinCryptIntegrityLayout* layout, const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, uint8_t scratch[1536])
{
    return rin_crypt_integrity_state_read(layout, key, volume_id, key_epoch,
                                          io, scratch) ==
           RIN_CRYPT_INTEGRITY_STATE_READY;
}

/* Establish the authenticated tag table before an installer exposes the new
 * volume. A pending, MACed state permits this initialization to restart after
 * power loss; normal readers reject pending or absent state. It zeros the raw
 * payload and records a position-bound logical-zero tag for every sector. */
static inline int rin_crypt_integrity_initialize(
    const RinCryptIntegrityLayout* layout, const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, uint8_t scratch[1536])
{
    uint64_t tag_index;
    uint64_t payload_index;
    uint32_t slot;
    uint32_t index;
    int state;
    int result = RIN_CRYPT_INTEGRITY_INVALID;
    if (!rin_crypt_integrity_layout_valid(layout) || !key || !volume_id ||
        key_epoch == 0u || !io ||
        !io->read_block || !io->write_block || !io->flush || !scratch ||
        layout->state_first_lba > UINT64_MAX - 1u) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    state = rin_crypt_integrity_state_read(layout, key, volume_id, key_epoch,
                                           io, scratch);
    if (state == RIN_CRYPT_INTEGRITY_STATE_READY)
        return RIN_CRYPT_INTEGRITY_OK;
    if (state == RIN_CRYPT_INTEGRITY_STATE_IO)
        return RIN_CRYPT_INTEGRITY_IO;
    if (state == RIN_CRYPT_INTEGRITY_STATE_INVALID)
        return RIN_CRYPT_INTEGRITY_AUTH;

    if (rin_crypt_integrity_state_write(
            layout, key, volume_id, key_epoch, io, 0u,
            RIN_CRYPT_INTEGRITY_STATE_PENDING, scratch) !=
            RIN_CRYPT_INTEGRITY_OK ||
        rin_crypt_integrity_state_write(
            layout, key, volume_id, key_epoch, io, 1u,
            RIN_CRYPT_INTEGRITY_STATE_PENDING, scratch) !=
            RIN_CRYPT_INTEGRITY_OK) {
        return RIN_CRYPT_INTEGRITY_IO;
    }
    rin_crypt_integrity_zero(scratch, RIN_CRYPT_INTEGRITY_BLOCK_SIZE);
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_JOURNAL_BLOCKS; ++index) {
        if (io->write_block(io->context,
                            layout->journal_first_lba + index, scratch,
                            0u) != 0) {
            result = RIN_CRYPT_INTEGRITY_IO;
            goto done;
        }
    }
    for (tag_index = 0u; tag_index < layout->tag_block_count; ++tag_index) {
        uint32_t sector_count = RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK;
        rin_crypt_integrity_zero(scratch, RIN_CRYPT_INTEGRITY_BLOCK_SIZE);
        if (layout->payload_block_count -
                tag_index * RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK <
            sector_count) {
            sector_count = (uint32_t)(layout->payload_block_count -
                tag_index * RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK);
        }
        if (layout->payload_first_lba > UINT64_MAX -
                tag_index * RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK) {
            result = RIN_CRYPT_INTEGRITY_INVALID;
            goto done;
        }
        if (io->write_zero_blocks) {
            if (io->write_zero_blocks(
                    io->context,
                    layout->payload_first_lba +
                        tag_index * RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK,
                    sector_count) != 0) {
                result = RIN_CRYPT_INTEGRITY_IO;
                goto done;
            }
        } else {
            for (slot = 0u; slot < sector_count; ++slot) {
                if (io->write_block(
                        io->context,
                        layout->payload_first_lba +
                            tag_index * RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK +
                            slot,
                        scratch + 512u, 0u) != 0) {
                    result = RIN_CRYPT_INTEGRITY_IO;
                    goto done;
                }
            }
        }
        for (slot = 0u; slot < RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK; ++slot) {
            uint8_t tag[RIN_CRYPT_INTEGRITY_TAG_SIZE];
            if (tag_index > UINT64_MAX /
                                RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK) {
                result = RIN_CRYPT_INTEGRITY_INVALID;
                goto done;
            }
            payload_index = tag_index *
                                RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK + slot;
            if (payload_index >= layout->payload_block_count) break;
            rin_crypt_integrity_zero_sector_tag(
                key, volume_id, key_epoch, payload_index, tag);
            for (index = 0u; index < RIN_CRYPT_INTEGRITY_TAG_SIZE; ++index)
                scratch[slot * RIN_CRYPT_INTEGRITY_TAG_SIZE + index] =
                    tag[index];
            rin_crypt_integrity_zero(tag, sizeof(tag));
        }
        if (layout->tag_first_lba > UINT64_MAX - tag_index ||
            io->write_block(io->context, layout->tag_first_lba + tag_index,
                            scratch, 0u) != 0) {
            result = RIN_CRYPT_INTEGRITY_IO;
            goto done;
        }
    }
    if (io->flush(io->context) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    if (rin_crypt_integrity_state_write(
            layout, key, volume_id, key_epoch, io, 0u,
            RIN_CRYPT_INTEGRITY_STATE_READY, scratch) !=
            RIN_CRYPT_INTEGRITY_OK ||
        rin_crypt_integrity_state_write(
            layout, key, volume_id, key_epoch, io, 1u,
            RIN_CRYPT_INTEGRITY_STATE_READY, scratch) !=
            RIN_CRYPT_INTEGRITY_OK) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    result = RIN_CRYPT_INTEGRITY_OK;
done:
    rin_crypt_integrity_zero(scratch, 1536u);
    return result;
}

static inline void rin_crypt_integrity_journal_mac(
    const uint8_t key[32], const uint8_t descriptor[512],
    const uint8_t ciphertext[512], const uint8_t tag_page[512],
    uint8_t mac[32])
{
    static const uint8_t domain[] = "RinOS RCT2 write-ahead journal";
    hmac_sha256_ctx hmac;
    hmac_sha256_init(&hmac, key, 32u);
    hmac_sha256_update(&hmac, domain, sizeof(domain) - 1u);
    hmac_sha256_update(&hmac, descriptor, 40u);
    hmac_sha256_update(&hmac, ciphertext, 512u);
    hmac_sha256_update(&hmac, tag_page, 512u);
    hmac_sha256_final(&hmac, mac);
    rin_crypt_integrity_zero(&hmac, sizeof(hmac));
}

static inline int rin_crypt_integrity_journal_valid(
    const uint8_t descriptor[512], const uint8_t ciphertext[512],
    const uint8_t tag_page[512], const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityLayout* layout)
{
    static const uint8_t magic[4] = {'R', 'C', 'J', '2'};
    uint8_t mac[32];
    uint8_t expected_tag[RIN_CRYPT_INTEGRITY_TAG_SIZE];
    uint8_t difference = 0u;
    uint64_t payload_index;
    uint64_t tag_index;
    uint32_t slot;
    uint32_t index;
    int valid;
    if (!descriptor || !ciphertext || !tag_page || !key || !volume_id ||
        !rin_crypt_integrity_layout_valid(layout) ||
        descriptor[0] != magic[0] ||
        descriptor[1] != magic[1] || descriptor[2] != magic[2] ||
        descriptor[3] != magic[3] ||
        rin_crypt_integrity_read_le32(descriptor + 4u) !=
            RIN_CRYPT_INTEGRITY_VERSION ||
        rin_crypt_integrity_read_le64(descriptor + 32u) != key_epoch) {
        return 0;
    }
    for (index = 28u; index < 32u; ++index) difference |= descriptor[index];
    for (index = 72u; index < 512u; ++index) difference |= descriptor[index];
    if (difference != 0u) return 0;
    payload_index = rin_crypt_integrity_read_le64(descriptor + 8u);
    tag_index = rin_crypt_integrity_read_le64(descriptor + 16u);
    slot = rin_crypt_integrity_read_le32(descriptor + 24u);
    if (payload_index >= layout->payload_block_count ||
        tag_index != payload_index / RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK ||
        slot != payload_index % RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK ||
        tag_index >= layout->tag_block_count) return 0;
    rin_crypt_integrity_journal_mac(key, descriptor, ciphertext, tag_page,
                                    mac);
    difference = 0u;
    for (index = 0u; index < sizeof(mac); ++index)
        difference |= (uint8_t)(mac[index] ^ descriptor[40u + index]);
    rin_crypt_integrity_zero(mac, sizeof(mac));
    if (difference != 0u) return 0;
    rin_crypt_integrity_tag(key, volume_id, key_epoch, payload_index,
                            ciphertext, expected_tag);
    valid = rin_crypt_integrity_tag_equal(
        expected_tag, tag_page + slot * RIN_CRYPT_INTEGRITY_TAG_SIZE);
    rin_crypt_integrity_zero(expected_tag, sizeof(expected_tag));
    return valid;
}

static inline int rin_crypt_integrity_recover(
    const RinCryptIntegrityLayout* layout, const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, uint8_t scratch[1536])
{
    uint8_t second_descriptor[512];
    uint8_t difference = 0u;
    uint32_t index;
    uint64_t tag_index;
    uint64_t payload_index;
    uint64_t physical_lba;
    int first_zero;
    int second_zero;
    int first_valid;
    int second_valid;
    int state;
    int result = RIN_CRYPT_INTEGRITY_INVALID;
    if (!layout || !key || !volume_id || key_epoch == 0u || !io ||
        !io->read_block || !io->write_block || !io->flush || !scratch) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    state = rin_crypt_integrity_state_read(layout, key, volume_id, key_epoch,
                                          io, scratch);
    if (state != RIN_CRYPT_INTEGRITY_STATE_READY) {
        rin_crypt_integrity_zero(second_descriptor,
                                 sizeof(second_descriptor));
        return state == RIN_CRYPT_INTEGRITY_STATE_IO
                   ? RIN_CRYPT_INTEGRITY_IO
                   : RIN_CRYPT_INTEGRITY_AUTH;
    }
    if (layout->journal_first_lba > UINT64_MAX - 3u ||
        io->read_block(io->context, layout->journal_first_lba,
                       scratch) != 0 ||
        io->read_block(io->context, layout->journal_first_lba + 1u,
                       second_descriptor) != 0) {
        rin_crypt_integrity_zero(second_descriptor, sizeof(second_descriptor));
        rin_crypt_integrity_zero(scratch, 1536u);
        return RIN_CRYPT_INTEGRITY_IO;
    }
    first_zero = 1;
    second_zero = 1;
    for (index = 0u; index < 512u; ++index) {
        first_zero &= scratch[index] == 0u;
        second_zero &= second_descriptor[index] == 0u;
    }
    if (first_zero && second_zero) {
        rin_crypt_integrity_zero(second_descriptor, sizeof(second_descriptor));
        rin_crypt_integrity_zero(scratch, 1536u);
        return RIN_CRYPT_INTEGRITY_OK;
    }
    if (io->read_block(io->context, layout->journal_first_lba + 2u,
                       scratch + 512u) != 0 ||
        io->read_block(io->context, layout->journal_first_lba + 3u,
                       scratch + 1024u) != 0) {
        rin_crypt_integrity_zero(second_descriptor, sizeof(second_descriptor));
        rin_crypt_integrity_zero(scratch, 1536u);
        return RIN_CRYPT_INTEGRITY_IO;
    }
    first_valid = !first_zero && rin_crypt_integrity_journal_valid(
        scratch, scratch + 512u, scratch + 1024u, key, volume_id,
        key_epoch, layout);
    second_valid = !second_zero && rin_crypt_integrity_journal_valid(
        second_descriptor, scratch + 512u, scratch + 1024u, key, volume_id,
        key_epoch, layout);
    if (!first_valid && !second_valid) goto done;
    if (first_valid && second_valid) {
        difference = 0u;
        for (index = 0u; index < 512u; ++index)
            difference |= (uint8_t)(scratch[index] ^ second_descriptor[index]);
        if (difference != 0u) goto done;
    } else if (second_valid) {
        for (index = 0u; index < 512u; ++index)
            scratch[index] = second_descriptor[index];
    }
    payload_index = rin_crypt_integrity_read_le64(scratch + 8u);
    tag_index = rin_crypt_integrity_read_le64(scratch + 16u);
    if (payload_index >= layout->payload_block_count ||
        tag_index != payload_index / RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK ||
        tag_index >= layout->tag_block_count ||
        layout->payload_first_lba > UINT64_MAX - payload_index ||
        layout->tag_first_lba > UINT64_MAX - tag_index) {
        goto done;
    }
    physical_lba = layout->payload_first_lba + payload_index;
    if (io->write_block(io->context, physical_lba, scratch + 512u, 0u) != 0 ||
        io->flush(io->context) != 0 ||
        io->write_block(io->context, layout->tag_first_lba + tag_index,
                        scratch + 1024u, 0u) != 0 ||
        io->flush(io->context) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    rin_crypt_integrity_zero(scratch, 512u);
    if (io->write_block(io->context, layout->journal_first_lba, scratch,
                        0u) != 0 ||
        io->write_block(io->context, layout->journal_first_lba + 1u,
                        scratch, 0u) != 0 || io->flush(io->context) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    result = RIN_CRYPT_INTEGRITY_OK;
done:
    rin_crypt_integrity_zero(second_descriptor, sizeof(second_descriptor));
    rin_crypt_integrity_zero(scratch, 1536u);
    return result;
}

static inline int rin_crypt_integrity_verify_cipher(
    const RinCryptIntegrityLayout* layout, uint64_t payload_index,
    const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, const uint8_t ciphertext[512],
    uint8_t scratch[1536])
{
    uint64_t tag_index;
    uint64_t payload_position;
    uint32_t slot;
    uint8_t expected[RIN_CRYPT_INTEGRITY_TAG_SIZE];
    uint8_t zero_expected[RIN_CRYPT_INTEGRITY_TAG_SIZE];
    int result = RIN_CRYPT_INTEGRITY_INVALID;
    if (!rin_crypt_integrity_layout_valid(layout) ||
        payload_index >= layout->payload_block_count || !key ||
        !volume_id || key_epoch == 0u || !io || !io->read_block ||
        !ciphertext || !scratch) return RIN_CRYPT_INTEGRITY_INVALID;
    tag_index = payload_index / RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK;
    slot = (uint32_t)(payload_index % RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK);
    if (tag_index >= layout->tag_block_count ||
        layout->payload_first_lba > UINT64_MAX - payload_index ||
        layout->tag_first_lba > UINT64_MAX - tag_index) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    rin_crypt_integrity_zero(expected, sizeof(expected));
    rin_crypt_integrity_zero(zero_expected, sizeof(zero_expected));
    if (io->read_block(io->context, layout->tag_first_lba + tag_index,
                       scratch) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    payload_position = payload_index;
    rin_crypt_integrity_tag(key, volume_id, key_epoch, payload_position,
                            ciphertext, expected);
    rin_crypt_integrity_zero_sector_tag(
        key, volume_id, key_epoch, payload_position, zero_expected);
    {
        const uint8_t* stored =
            scratch + slot * RIN_CRYPT_INTEGRITY_TAG_SIZE;
        uint8_t cipher_value = 0u;
        for (uint32_t index = 0u; index < 512u; ++index)
            cipher_value |= ciphertext[index];
        if (cipher_value == 0u &&
            rin_crypt_integrity_tag_equal(zero_expected, stored)) {
            /* The initializer gives logical-zero sectors a keyed,
             * sector-specific tag. Restoring an earlier same-sector value is
             * the rollback case excluded by this format's threat boundary. */
            result = RIN_CRYPT_INTEGRITY_ZERO_SECTOR;
        } else {
            result = rin_crypt_integrity_tag_equal(expected, stored)
                         ? RIN_CRYPT_INTEGRITY_OK
                         : RIN_CRYPT_INTEGRITY_AUTH;
        }
    }
done:
    rin_crypt_integrity_zero(expected, sizeof(expected));
    rin_crypt_integrity_zero(zero_expected, sizeof(zero_expected));
    rin_crypt_integrity_zero(scratch, 1536u);
    return result;
}

static inline int rin_crypt_integrity_write_cipher(
    const RinCryptIntegrityLayout* layout, uint64_t payload_index,
    const uint8_t key[32],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE], uint64_t key_epoch,
    const RinCryptIntegrityIo* io, const uint8_t ciphertext[512],
    uint32_t flags, uint8_t scratch[1536])
{
    static const uint8_t magic[4] = {'R', 'C', 'J', '2'};
    uint64_t tag_index;
    uint64_t payload_position;
    uint64_t physical_lba;
    uint32_t slot;
    uint32_t index;
    uint8_t tag[RIN_CRYPT_INTEGRITY_TAG_SIZE];
    int result;
    if (!rin_crypt_integrity_layout_valid(layout) ||
        payload_index >= layout->payload_block_count || !key ||
        !volume_id || key_epoch == 0u || !io || !io->read_block ||
        !io->write_block || !io->flush || !ciphertext || !scratch) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    tag_index = payload_index / RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK;
    slot = (uint32_t)(payload_index % RIN_CRYPT_INTEGRITY_TAGS_PER_BLOCK);
    if (tag_index >= layout->tag_block_count ||
        layout->payload_first_lba > UINT64_MAX - payload_index ||
        layout->tag_first_lba > UINT64_MAX - tag_index ||
        layout->journal_first_lba > UINT64_MAX - 3u) {
        return RIN_CRYPT_INTEGRITY_INVALID;
    }
    result = rin_crypt_integrity_recover(layout, key, volume_id, key_epoch,
                                         io, scratch);
    if (result != RIN_CRYPT_INTEGRITY_OK) return result;
    physical_lba = layout->payload_first_lba + payload_index;
    payload_position = payload_index;
    rin_crypt_integrity_tag(key, volume_id, key_epoch, payload_position,
                            ciphertext, tag);
    if (io->read_block(io->context, layout->tag_first_lba + tag_index,
                       scratch + 512u) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    for (index = 0u; index < RIN_CRYPT_INTEGRITY_TAG_SIZE; ++index) {
        scratch[512u + slot * RIN_CRYPT_INTEGRITY_TAG_SIZE + index] =
            tag[index];
    }
    rin_crypt_integrity_zero(scratch, 512u);
    scratch[0] = magic[0]; scratch[1] = magic[1];
    scratch[2] = magic[2]; scratch[3] = magic[3];
    rin_crypt_integrity_write_le32(scratch + 4u,
                                   RIN_CRYPT_INTEGRITY_VERSION);
    rin_crypt_integrity_write_le64(scratch + 8u, payload_index);
    rin_crypt_integrity_write_le64(scratch + 16u, tag_index);
    rin_crypt_integrity_write_le32(scratch + 24u, slot);
    rin_crypt_integrity_write_le64(scratch + 32u, key_epoch);
    rin_crypt_integrity_journal_mac(key, scratch, ciphertext,
                                    scratch + 512u, scratch + 40u);
    if (io->write_block(io->context, layout->journal_first_lba + 2u,
                        ciphertext, 0u) != 0 ||
        io->write_block(io->context, layout->journal_first_lba + 3u,
                        scratch + 512u, 0u) != 0 ||
        io->flush(io->context) != 0 ||
        io->write_block(io->context, layout->journal_first_lba, scratch,
                        0u) != 0 ||
        io->write_block(io->context, layout->journal_first_lba + 1u, scratch,
                        0u) != 0 || io->flush(io->context) != 0 ||
        io->write_block(io->context, physical_lba, ciphertext, flags) != 0 ||
        io->flush(io->context) != 0 ||
        io->write_block(io->context, layout->tag_first_lba + tag_index,
                        scratch + 512u, flags) != 0 ||
        io->flush(io->context) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    rin_crypt_integrity_zero(scratch, 512u);
    if (io->write_block(io->context, layout->journal_first_lba, scratch,
                        0u) != 0 ||
        io->write_block(io->context, layout->journal_first_lba + 1u,
                        scratch, 0u) != 0 || io->flush(io->context) != 0) {
        result = RIN_CRYPT_INTEGRITY_IO;
        goto done;
    }
    result = RIN_CRYPT_INTEGRITY_OK;
done:
    rin_crypt_integrity_zero(tag, sizeof(tag));
    rin_crypt_integrity_zero(scratch, 1536u);
    return result;
}

#endif /* RIN_SHARED_CRYPT_INTEGRITY_H */
