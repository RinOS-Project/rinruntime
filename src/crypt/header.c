/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "header.h"

static void header_zero(void* pointer, uint64_t size)
{
    volatile uint8_t* output = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *output++ = 0u;
}

static void header_copy(void* destination, const void* source, uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *output++ = *input++;
}

static int header_equal(const void* left, const void* right, uint32_t size)
{
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        difference |= (uint8_t)(a[index] ^ b[index]);
    }
    return difference == 0u;
}

static int header_is_zero(const void* pointer, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)pointer;
    uint8_t combined = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static int header_ranges_overlap(const void* first, uint64_t first_size,
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

static uint16_t header_read_le16(const uint8_t input[2])
{
    return (uint16_t)((uint16_t)input[0] | ((uint16_t)input[1] << 8));
}

static uint32_t header_read_le32(const uint8_t input[4])
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t header_read_le64(const uint8_t input[8])
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        value |= (uint64_t)input[index] << (index * 8u);
    }
    return value;
}

static void header_write_le16(uint8_t output[2], uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void header_write_le32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void header_write_le64(uint8_t output[8], uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        output[index] = (uint8_t)(value >> (index * 8u));
    }
}

static uint32_t header_checksum(const RinCryptVolumeHeaderV1* header)
{
    const uint8_t* bytes = (const uint8_t*)header;
    uint32_t crc = UINT32_C(0xffffffff);
    uint32_t index;
    uint32_t bit;

    for (index = 0u; index < RIN_CRYPT_HEADER_SIZE; ++index) {
        uint8_t value = index >= RIN_CRYPT_HEADER_SIZE - 4u ? 0u
                                                            : bytes[index];
        crc ^= value;
        for (bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1) ^
                  (UINT32_C(0xedb88320) & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

int rin_crypt_header_validate(const RinCryptVolumeHeaderV1* header,
                              int require_committed)
{
    static const uint8_t magic[4] = {'R', 'V', 'H', '1'};
    uint32_t state;
    uint32_t keyslot_count;
    uint32_t index;

    if (!header || !header_equal(header->magic, magic, sizeof(magic)) ||
        header_read_le16(header->version) != RIN_CRYPT_HEADER_VERSION ||
        header_read_le16(header->header_size) != RIN_CRYPT_HEADER_SIZE ||
        header_read_le64(header->generation) == 0u ||
        header_is_zero(header->volume_id, sizeof(header->volume_id)) ||
        !header_is_zero(header->reserved, sizeof(header->reserved)) ||
        header_read_le32(header->checksum) != header_checksum(header)) {
        return RIN_CRYPT_HEADER_CORRUPT;
    }
    state = header_read_le32(header->state);
    if ((state != RIN_CRYPT_HEADER_STATE_PREPARED &&
         state != RIN_CRYPT_HEADER_STATE_COMMITTED) ||
        (require_committed && state != RIN_CRYPT_HEADER_STATE_COMMITTED)) {
        return RIN_CRYPT_HEADER_CORRUPT;
    }
    keyslot_count = header_read_le32(header->keyslot_count);
    if (keyslot_count == 0u ||
        keyslot_count > RIN_CRYPT_HEADER_KEYSLOT_COUNT) {
        return RIN_CRYPT_HEADER_CORRUPT;
    }
    for (index = 0u; index < keyslot_count; ++index) {
        if (rin_crypt_keyslot_validate_v1(&header->keyslots[index]) !=
                RIN_CRYPT_OK ||
            !header_equal(header->keyslots[index].volume_id,
                          header->volume_id, RIN_CRYPT_VOLUME_ID_SIZE)) {
            return RIN_CRYPT_HEADER_CORRUPT;
        }
        if (index != 0u &&
            (header_equal(header->keyslots[0].keyslot_id,
                          header->keyslots[index].keyslot_id,
                          RIN_CRYPT_KEYSLOT_ID_SIZE) ||
             !header_equal(header->keyslots[0].key_epoch,
                           header->keyslots[index].key_epoch,
                           sizeof(header->keyslots[0].key_epoch)))) {
            return RIN_CRYPT_HEADER_CORRUPT;
        }
    }
    for (; index < RIN_CRYPT_HEADER_KEYSLOT_COUNT; ++index) {
        if (!header_is_zero(&header->keyslots[index],
                            sizeof(header->keyslots[index]))) {
            return RIN_CRYPT_HEADER_CORRUPT;
        }
    }
    return RIN_CRYPT_HEADER_OK;
}

int rin_crypt_header_format_initial_v1(
    const RinCryptKeyslotV1* keyslots, uint32_t keyslot_count,
    RinCryptVolumeHeaderV1* header)
{
    static const uint8_t magic[4] = {'R', 'V', 'H', '1'};
    RinCryptVolumeHeaderV1 candidate;
    RinCryptKeyslotV1 input_slots[RIN_CRYPT_HEADER_KEYSLOT_COUNT];
    uint32_t index;
    int result = RIN_CRYPT_HEADER_INVALID;
    if (header_ranges_overlap(
            keyslots,
            (uint64_t)keyslot_count * sizeof(RinCryptKeyslotV1),
            header, sizeof(*header))) {
        return RIN_CRYPT_HEADER_INVALID;
    }
    if (header) header_zero(header, sizeof(*header));
    header_zero(&candidate, sizeof(candidate));
    header_zero(input_slots, sizeof(input_slots));
    if (!keyslots || !header || keyslot_count == 0u ||
        keyslot_count > RIN_CRYPT_HEADER_KEYSLOT_COUNT) {
        goto done;
    }
    header_copy(input_slots, keyslots,
                keyslot_count * sizeof(input_slots[0]));
    for (index = 0u; index < keyslot_count; ++index) {
        if (rin_crypt_keyslot_validate_v1(&input_slots[index]) !=
                RIN_CRYPT_OK ||
            !header_equal(input_slots[0].volume_id,
                          input_slots[index].volume_id,
                          RIN_CRYPT_VOLUME_ID_SIZE) ||
            (index != 0u &&
             (header_equal(input_slots[0].keyslot_id,
                           input_slots[index].keyslot_id,
                           RIN_CRYPT_KEYSLOT_ID_SIZE) ||
              !header_equal(input_slots[0].key_epoch,
                            input_slots[index].key_epoch,
                            sizeof(input_slots[0].key_epoch))))) {
            goto done;
        }
    }
    header_copy(candidate.magic, magic, sizeof(magic));
    header_write_le16(candidate.version, RIN_CRYPT_HEADER_VERSION);
    header_write_le16(candidate.header_size, RIN_CRYPT_HEADER_SIZE);
    header_write_le32(candidate.state,
                      RIN_CRYPT_HEADER_STATE_COMMITTED);
    header_write_le32(candidate.keyslot_count, keyslot_count);
    header_write_le64(candidate.generation, 1u);
    header_copy(candidate.volume_id, input_slots[0].volume_id,
                sizeof(candidate.volume_id));
    for (index = 0u; index < keyslot_count; ++index) {
        header_copy(&candidate.keyslots[index], &input_slots[index],
                    sizeof(candidate.keyslots[index]));
    }
    header_write_le32(candidate.checksum, header_checksum(&candidate));
    if (rin_crypt_header_validate(&candidate, 1) !=
        RIN_CRYPT_HEADER_OK) {
        goto done;
    }
    header_copy(header, &candidate, sizeof(*header));
    result = RIN_CRYPT_HEADER_OK;
done:
    header_zero(&candidate, sizeof(candidate));
    header_zero(input_slots, sizeof(input_slots));
    if (result != RIN_CRYPT_HEADER_OK && header) {
        header_zero(header, sizeof(*header));
    }
    return result;
}

int rin_crypt_header_find_keyslot(
    const RinCryptVolumeHeaderV1* header,
    const uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    RinCryptKeyslotV1* keyslot)
{
    uint32_t count;
    uint32_t index;
    if (keyslot) header_zero(keyslot, sizeof(*keyslot));
    if (!header || !keyslot_id || !keyslot ||
        rin_crypt_header_validate(header, 1) != RIN_CRYPT_HEADER_OK) {
        return RIN_CRYPT_HEADER_INVALID;
    }
    count = header_read_le32(header->keyslot_count);
    for (index = 0u; index < count; ++index) {
        if (header_equal(header->keyslots[index].keyslot_id, keyslot_id,
                         RIN_CRYPT_KEYSLOT_ID_SIZE)) {
            header_copy(keyslot, &header->keyslots[index], sizeof(*keyslot));
            return RIN_CRYPT_HEADER_OK;
        }
    }
    return RIN_CRYPT_HEADER_NOT_FOUND;
}

