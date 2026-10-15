/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "recovery_key.h"

#define RECOVERY_PAYLOAD_SIZE (RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE + 2u)
#define RECOVERY_BASE32_COUNT 36u

static const char g_recovery_alphabet[33] =
    "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

static void recovery_zero(void* pointer, uint64_t size)
{
    volatile uint8_t* output = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *output++ = 0u;
}

static void recovery_copy(void* destination, const void* source,
                          uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *output++ = *input++;
}

static int recovery_is_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static int recovery_equal(const uint8_t* left, const uint8_t* right,
                          uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int recovery_ranges_overlap(const void* first, uint64_t first_size,
                                   const void* second, uint64_t second_size)
{
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    uintptr_t first_end;
    uintptr_t second_end;
    if (!first || !second || first_size == 0u || second_size == 0u) {
        return 0;
    }
    if (first_size > UINTPTR_MAX - first_start ||
        second_size > UINTPTR_MAX - second_start) {
        return 1;
    }
    first_end = first_start + (uintptr_t)first_size;
    second_end = second_start + (uintptr_t)second_size;
    return first_start < second_end && second_start < first_end;
}

static int recovery_format_arguments_overlap(
    const RinCryptKeyslotV1* keyslot, const uint8_t* volume_id,
    const uint8_t* keyslot_id,
    const RinCryptKeyslotParametersV1* parameters,
    const char* recovery_key, const uint8_t* workspace,
    uint64_t workspace_size)
{
    return recovery_ranges_overlap(keyslot, sizeof(*keyslot), recovery_key,
                                   RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), volume_id,
                                   RIN_CRYPT_VOLUME_ID_SIZE) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), keyslot_id,
                                   RIN_CRYPT_KEYSLOT_ID_SIZE) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), parameters,
                                   sizeof(*parameters)) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), workspace,
                                   workspace_size) ||
           recovery_ranges_overlap(
               recovery_key, RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE, volume_id,
               RIN_CRYPT_VOLUME_ID_SIZE) ||
           recovery_ranges_overlap(
               recovery_key, RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE, keyslot_id,
               RIN_CRYPT_KEYSLOT_ID_SIZE) ||
           recovery_ranges_overlap(
               recovery_key, RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE, parameters,
               sizeof(*parameters)) ||
           recovery_ranges_overlap(
               recovery_key, RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE, workspace,
               workspace_size) ||
           recovery_ranges_overlap(volume_id, RIN_CRYPT_VOLUME_ID_SIZE,
                                   keyslot_id,
                                   RIN_CRYPT_KEYSLOT_ID_SIZE) ||
           recovery_ranges_overlap(volume_id, RIN_CRYPT_VOLUME_ID_SIZE,
                                   parameters, sizeof(*parameters)) ||
           recovery_ranges_overlap(keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE,
                                   parameters, sizeof(*parameters)) ||
           recovery_ranges_overlap(volume_id, RIN_CRYPT_VOLUME_ID_SIZE,
                                   workspace, workspace_size) ||
           recovery_ranges_overlap(keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE,
                                   workspace, workspace_size) ||
           recovery_ranges_overlap(parameters, sizeof(*parameters),
                                   workspace, workspace_size);
}

static int recovery_pair_arguments_overlap(
    const RinCryptKeyslotV1* keyslots, const uint8_t* volume_id,
    const uint8_t* password_keyslot_id,
    const RinCryptKeyslotParametersV1* password_parameters,
    const uint8_t* password, uint32_t password_size,
    const uint8_t* recovery_keyslot_id,
    const RinCryptKeyslotParametersV1* recovery_parameters,
    const char* recovery_key, const uint8_t* workspace,
    uint64_t workspace_size)
{
    const void* pointers[9];
    uint64_t sizes[9];
    uint32_t first;
    uint32_t second;
    pointers[0] = keyslots;
    sizes[0] = sizeof(RinCryptKeyslotV1) *
               RIN_CRYPT_KEYSLOT_PAIR_COUNT;
    pointers[1] = volume_id;
    sizes[1] = RIN_CRYPT_VOLUME_ID_SIZE;
    pointers[2] = password_keyslot_id;
    sizes[2] = RIN_CRYPT_KEYSLOT_ID_SIZE;
    pointers[3] = password_parameters;
    sizes[3] = sizeof(*password_parameters);
    pointers[4] = password;
    sizes[4] = password_size;
    pointers[5] = recovery_keyslot_id;
    sizes[5] = RIN_CRYPT_KEYSLOT_ID_SIZE;
    pointers[6] = recovery_parameters;
    sizes[6] = sizeof(*recovery_parameters);
    pointers[7] = recovery_key;
    sizes[7] = RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE;
    pointers[8] = workspace;
    sizes[8] = workspace_size;
    for (first = 0u; first < 9u; ++first) {
        for (second = first + 1u; second < 9u; ++second) {
            if (recovery_ranges_overlap(pointers[first], sizes[first],
                                        pointers[second], sizes[second])) {
                return 1;
            }
        }
    }
    return 0;
}

static void recovery_clear_password(uint8_t* password, uint32_t size)
{
    if (size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE) {
        size = RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE;
    }
    recovery_zero(password, size);
}

static int recovery_provider_arguments_overlap(
    const RinCryptRecoveryKeyProvider* provider,
    const RinCryptKeyslotV1* keyslot, const char* recovery_key,
    uint32_t recovery_key_size, const uint8_t* workspace,
    uint64_t workspace_size)
{
    uint64_t text_size = recovery_key_size;
    if (text_size > RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH) {
        text_size = RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH;
    }
    return recovery_ranges_overlap(provider, sizeof(*provider), keyslot,
                                   sizeof(*keyslot)) ||
           recovery_ranges_overlap(provider, sizeof(*provider), recovery_key,
                                   text_size) ||
           recovery_ranges_overlap(provider, sizeof(*provider), workspace,
                                   workspace_size) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), recovery_key,
                                   text_size) ||
           recovery_ranges_overlap(keyslot, sizeof(*keyslot), workspace,
                                   workspace_size) ||
           recovery_ranges_overlap(recovery_key, text_size, workspace,
                                   workspace_size);
}

static uint16_t recovery_crc16(const uint8_t* secret)
{
    static const uint8_t domain[] = {
        'R', 'i', 'n', 'C', 'r', 'y', 'p', 't', '-', 'R', 'R', 'K', '1'
    };
    uint16_t crc = UINT16_C(0xffff);
    uint32_t phase;
    uint32_t index;
    for (phase = 0u; phase < 2u; ++phase) {
        const uint8_t* input = phase == 0u ? domain : secret;
        uint32_t size = phase == 0u ? (uint32_t)sizeof(domain) :
                                      RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE;
        for (index = 0u; index < size; ++index) {
            uint32_t bit;
            crc ^= (uint16_t)input[index] << 8u;
            for (bit = 0u; bit < 8u; ++bit) {
                crc = (crc & UINT16_C(0x8000)) != 0u
                          ? (uint16_t)((crc << 1u) ^ UINT16_C(0x1021))
                          : (uint16_t)(crc << 1u);
            }
        }
    }
    return crc;
}

static uint8_t recovery_payload_bit(const uint8_t* payload,
                                    uint32_t bit_index)
{
    if (bit_index >= RECOVERY_PAYLOAD_SIZE * 8u) return 0u;
    return (uint8_t)((payload[bit_index / 8u] >>
                      (7u - (bit_index % 8u))) & 1u);
}

static void recovery_encode(const uint8_t* secret,
                            char output[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE])
{
    uint8_t payload[RECOVERY_PAYLOAD_SIZE];
    uint16_t crc = recovery_crc16(secret);
    uint32_t character;
    uint32_t output_index = 0u;
    recovery_copy(payload, secret, RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE);
    payload[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE] = (uint8_t)(crc >> 8u);
    payload[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE + 1u] = (uint8_t)crc;
    for (character = 0u; character < RECOVERY_BASE32_COUNT; ++character) {
        uint8_t value = 0u;
        uint32_t bit;
        if (character != 0u && character % 6u == 0u) {
            output[output_index++] = '-';
        }
        for (bit = 0u; bit < 5u; ++bit) {
            value = (uint8_t)((value << 1u) |
                              recovery_payload_bit(
                                  payload, character * 5u + bit));
        }
        output[output_index++] = g_recovery_alphabet[value];
    }
    output[output_index] = '\0';
    recovery_zero(payload, sizeof(payload));
}

static int recovery_alphabet_value(char character, uint8_t* value_out)
{
    uint32_t index;
    if (!value_out) return 0;
    *value_out = 0u;
    for (index = 0u; index < 32u; ++index) {
        if (character == g_recovery_alphabet[index]) {
            *value_out = (uint8_t)index;
            return 1;
        }
    }
    return 0;
}

static int recovery_decode(
    const char* text, uint32_t text_size,
    uint8_t secret_out[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE])
{
    uint8_t payload[RECOVERY_PAYLOAD_SIZE];
    uint8_t expected_crc[2];
    uint32_t text_index = 0u;
    uint32_t character;
    uint32_t bit_index = 0u;
    int valid = 1;
    recovery_zero(payload, sizeof(payload));
    recovery_zero(expected_crc, sizeof(expected_crc));
    if (secret_out) {
        recovery_zero(secret_out, RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE);
    }
    if (!text || !secret_out ||
        text_size != RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH) {
        return RIN_CRYPT_INVALID;
    }
    for (character = 0u; character < RECOVERY_BASE32_COUNT; ++character) {
        uint8_t value = 0u;
        uint32_t bit;
        if (character != 0u && character % 6u == 0u) {
            if (text[text_index++] != '-') valid = 0;
        }
        if (!recovery_alphabet_value(text[text_index++], &value)) valid = 0;
        for (bit = 0u; bit < 5u; ++bit, ++bit_index) {
            uint8_t set = (uint8_t)((value >> (4u - bit)) & 1u);
            if (bit_index < RECOVERY_PAYLOAD_SIZE * 8u) {
                payload[bit_index / 8u] |=
                    (uint8_t)(set << (7u - (bit_index % 8u)));
            } else if (set != 0u) {
                valid = 0;
            }
        }
    }
    if (text_index != RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH) valid = 0;
    {
        uint16_t crc = recovery_crc16(payload);
        expected_crc[0] = (uint8_t)(crc >> 8u);
        expected_crc[1] = (uint8_t)crc;
    }
    if (!recovery_equal(
            payload + RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE,
            expected_crc, sizeof(expected_crc)) ||
        recovery_is_zero(payload, RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE)) {
        valid = 0;
    }
    if (valid) {
        recovery_copy(secret_out, payload,
                      RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE);
    }
    recovery_zero(expected_crc, sizeof(expected_crc));
    recovery_zero(payload, sizeof(payload));
    return valid ? RIN_CRYPT_OK : RIN_CRYPT_KEY_REJECTED;
}

int rin_crypt_recovery_keyslot_format_v1(
    RinCryptKeyslotV1* keyslot,
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* parameters,
    char recovery_key_out[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE],
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size)
{
    uint8_t secret[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE];
    uint8_t volume_id_snapshot[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t keyslot_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    RinCryptKeyslotParametersV1 parameters_snapshot;
    char encoded[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE];
    int result = RIN_CRYPT_INVALID;
    recovery_zero(secret, sizeof(secret));
    recovery_zero(volume_id_snapshot, sizeof(volume_id_snapshot));
    recovery_zero(keyslot_id_snapshot, sizeof(keyslot_id_snapshot));
    recovery_zero(&parameters_snapshot, sizeof(parameters_snapshot));
    recovery_zero(encoded, sizeof(encoded));
    if (recovery_format_arguments_overlap(
            keyslot, volume_id, keyslot_id, parameters, recovery_key_out,
            workspace, workspace_size)) {
        return RIN_CRYPT_INVALID;
    }
    if (keyslot) recovery_zero(keyslot, sizeof(*keyslot));
    if (recovery_key_out) {
        recovery_zero(recovery_key_out, RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE);
    }
    if (!keyslot || !volume_id || !keyslot_id || !parameters ||
        !recovery_key_out || !random_bytes || !workspace) {
        goto done;
    }
    recovery_copy(volume_id_snapshot, volume_id,
                  sizeof(volume_id_snapshot));
    recovery_copy(keyslot_id_snapshot, keyslot_id,
                  sizeof(keyslot_id_snapshot));
    recovery_copy(&parameters_snapshot, parameters,
                  sizeof(parameters_snapshot));
    if (random_bytes(random_context, secret, sizeof(secret)) != 0 ||
        recovery_is_zero(secret, sizeof(secret))) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }
    recovery_encode(secret, encoded);
    result = rin_crypt_keyslot_format_v1(
        keyslot, volume_id_snapshot, keyslot_id_snapshot,
        &parameters_snapshot, secret, sizeof(secret), random_bytes,
        random_context, workspace, workspace_size);
    if (result == RIN_CRYPT_OK &&
        (!recovery_is_zero((const uint8_t*)recovery_key_out,
                           RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE) ||
         !recovery_equal(volume_id_snapshot, volume_id,
                         sizeof(volume_id_snapshot)) ||
         !recovery_equal(keyslot_id_snapshot, keyslot_id,
                         sizeof(keyslot_id_snapshot)) ||
         !recovery_equal((const uint8_t*)&parameters_snapshot,
                         (const uint8_t*)parameters,
                         sizeof(parameters_snapshot)))) {
        result = RIN_CRYPT_KEY_REJECTED;
    }
    if (result == RIN_CRYPT_OK) {
        recovery_copy(recovery_key_out, encoded, sizeof(encoded));
    }
done:
    recovery_zero(secret, sizeof(secret));
    recovery_zero(volume_id_snapshot, sizeof(volume_id_snapshot));
    recovery_zero(keyslot_id_snapshot, sizeof(keyslot_id_snapshot));
    recovery_zero(&parameters_snapshot, sizeof(parameters_snapshot));
    recovery_zero(encoded, sizeof(encoded));
    if (result != RIN_CRYPT_OK) {
        if (keyslot) recovery_zero(keyslot, sizeof(*keyslot));
        if (recovery_key_out) {
            recovery_zero(recovery_key_out,
                          RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE);
        }
    }
    return result;
}

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
    uint8_t* workspace, uint64_t workspace_size)
{
    uint8_t secret[RIN_CRYPT_RECOVERY_KEY_SECRET_SIZE];
    uint8_t volume_snapshot[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t password_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint8_t recovery_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    RinCryptKeyslotParametersV1 password_parameters_snapshot;
    RinCryptKeyslotParametersV1 recovery_parameters_snapshot;
    char encoded[RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE];
    int result = RIN_CRYPT_INVALID;
    recovery_zero(secret, sizeof(secret));
    recovery_zero(volume_snapshot, sizeof(volume_snapshot));
    recovery_zero(password_id_snapshot, sizeof(password_id_snapshot));
    recovery_zero(recovery_id_snapshot, sizeof(recovery_id_snapshot));
    recovery_zero(&password_parameters_snapshot,
                  sizeof(password_parameters_snapshot));
    recovery_zero(&recovery_parameters_snapshot,
                  sizeof(recovery_parameters_snapshot));
    recovery_zero(encoded, sizeof(encoded));
    if (recovery_pair_arguments_overlap(
            keyslots, volume_id, password_keyslot_id, password_parameters,
            password, password_size, recovery_keyslot_id,
            recovery_parameters, recovery_key_out, workspace,
            workspace_size)) {
        return RIN_CRYPT_INVALID;
    }
    if (keyslots) {
        recovery_zero(keyslots, sizeof(*keyslots) *
                                   RIN_CRYPT_KEYSLOT_PAIR_COUNT);
    }
    if (recovery_key_out) {
        recovery_zero(recovery_key_out,
                      RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE);
    }
    if (!keyslots || !volume_id || !password_keyslot_id ||
        !password_parameters || !password || !recovery_keyslot_id ||
        !recovery_parameters || !recovery_key_out || !seal_key ||
        !random_bytes || !workspace ||
        password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE) {
        goto done;
    }
    recovery_copy(volume_snapshot, volume_id, sizeof(volume_snapshot));
    recovery_copy(password_id_snapshot, password_keyslot_id,
                  sizeof(password_id_snapshot));
    recovery_copy(recovery_id_snapshot, recovery_keyslot_id,
                  sizeof(recovery_id_snapshot));
    recovery_copy(&password_parameters_snapshot, password_parameters,
                  sizeof(password_parameters_snapshot));
    recovery_copy(&recovery_parameters_snapshot, recovery_parameters,
                  sizeof(recovery_parameters_snapshot));
    if (random_bytes(random_context, secret, sizeof(secret)) != 0 ||
        recovery_is_zero(secret, sizeof(secret))) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }
    if (!recovery_is_zero((const uint8_t*)keyslots,
                          sizeof(*keyslots) *
                              RIN_CRYPT_KEYSLOT_PAIR_COUNT) ||
        !recovery_is_zero((const uint8_t*)recovery_key_out,
                          RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE) ||
        !recovery_equal(volume_snapshot, volume_id,
                        sizeof(volume_snapshot)) ||
        !recovery_equal(password_id_snapshot, password_keyslot_id,
                        sizeof(password_id_snapshot)) ||
        !recovery_equal(recovery_id_snapshot, recovery_keyslot_id,
                        sizeof(recovery_id_snapshot)) ||
        !recovery_equal(
            (const uint8_t*)&password_parameters_snapshot,
            (const uint8_t*)password_parameters,
            sizeof(password_parameters_snapshot)) ||
        !recovery_equal(
            (const uint8_t*)&recovery_parameters_snapshot,
            (const uint8_t*)recovery_parameters,
            sizeof(recovery_parameters_snapshot))) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }
    recovery_encode(secret, encoded);
    result = rin_crypt_keyslot_format_pair_and_seal_v1(
        keyslots, volume_snapshot, password_id_snapshot,
        &password_parameters_snapshot, password, password_size,
        recovery_id_snapshot, &recovery_parameters_snapshot, secret,
        sizeof(secret), seal_key, seal_context, random_bytes, random_context,
        workspace, workspace_size);
    if (result == RIN_CRYPT_OK &&
        (!recovery_is_zero((const uint8_t*)recovery_key_out,
                           RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE) ||
         !recovery_equal(volume_snapshot, volume_id,
                         sizeof(volume_snapshot)) ||
         !recovery_equal(password_id_snapshot, password_keyslot_id,
                         sizeof(password_id_snapshot)) ||
         !recovery_equal(recovery_id_snapshot, recovery_keyslot_id,
                         sizeof(recovery_id_snapshot)) ||
         !recovery_equal(
             (const uint8_t*)&password_parameters_snapshot,
             (const uint8_t*)password_parameters,
             sizeof(password_parameters_snapshot)) ||
         !recovery_equal(
             (const uint8_t*)&recovery_parameters_snapshot,
             (const uint8_t*)recovery_parameters,
             sizeof(recovery_parameters_snapshot)))) {
        result = RIN_CRYPT_KEY_REJECTED;
    }
    if (result == RIN_CRYPT_OK) {
        recovery_copy(recovery_key_out, encoded, sizeof(encoded));
    }
done:
    recovery_clear_password(password, password_size);
    recovery_zero(secret, sizeof(secret));
    recovery_zero(volume_snapshot, sizeof(volume_snapshot));
    recovery_zero(password_id_snapshot, sizeof(password_id_snapshot));
    recovery_zero(recovery_id_snapshot, sizeof(recovery_id_snapshot));
    recovery_zero(&password_parameters_snapshot,
                  sizeof(password_parameters_snapshot));
    recovery_zero(&recovery_parameters_snapshot,
                  sizeof(recovery_parameters_snapshot));
    recovery_zero(encoded, sizeof(encoded));
    if (result != RIN_CRYPT_OK) {
        if (keyslots) {
            recovery_zero(keyslots, sizeof(*keyslots) *
                                       RIN_CRYPT_KEYSLOT_PAIR_COUNT);
        }
        if (recovery_key_out) {
            recovery_zero(recovery_key_out,
                          RIN_CRYPT_RECOVERY_KEY_TEXT_SIZE);
        }
    }
    return result;
}

static int recovery_pair_accept(void* context, const uint8_t* volume_id,
                                const uint8_t* primary_keyslot_id,
                                uint64_t key_epoch, const uint8_t* key)
{
    (void)context;
    (void)volume_id;
    (void)primary_keyslot_id;
    (void)key_epoch;
    (void)key;
    return RIN_CRYPT_OK;
}

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
    uint8_t* workspace, uint64_t workspace_size)
{
    return rin_crypt_recovery_keyslot_pair_format_and_seal_v1(
        keyslots, volume_id, password_keyslot_id, password_parameters,
        password, password_size, recovery_keyslot_id, recovery_parameters,
        recovery_key_out, recovery_pair_accept, (void*)0, random_bytes,
        random_context, workspace, workspace_size);
}

int rin_crypt_recovery_key_provider_init(
    RinCryptRecoveryKeyProvider* provider,
    const RinCryptKeyslotV1* keyslot, char* recovery_key,
    uint32_t recovery_key_size, uint8_t* workspace,
    uint64_t workspace_size)
{
    uint32_t clear_size = recovery_key_size;
    int result;
    if (clear_size > RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH) {
        clear_size = RIN_CRYPT_RECOVERY_KEY_TEXT_LENGTH;
    }
    if (recovery_provider_arguments_overlap(
            provider, keyslot, recovery_key, recovery_key_size, workspace,
            workspace_size)) {
        return RIN_CRYPT_INVALID;
    }
    if (provider) recovery_zero(provider, sizeof(*provider));
    if (!provider || !keyslot || !recovery_key || !workspace) {
        if (recovery_key) recovery_zero(recovery_key, clear_size);
        return RIN_CRYPT_INVALID;
    }
    result = recovery_decode(recovery_key, recovery_key_size,
                             provider->secret);
    recovery_zero(recovery_key, clear_size);
    if (result != RIN_CRYPT_OK) {
        recovery_zero(provider, sizeof(*provider));
        return result;
    }
    result = rin_crypt_keyslot_provider_init(
        &provider->keyslot_provider, keyslot, provider->secret,
        sizeof(provider->secret), workspace, workspace_size);
    if (result != RIN_CRYPT_OK) {
        recovery_zero(provider, sizeof(*provider));
        return result;
    }
    provider->magic = RIN_CRYPT_RECOVERY_KEY_MAGIC;
    return RIN_CRYPT_OK;
}

static int recovery_provider_unlock(
    void* context, const RinCryptKeyRequestV1* request,
    uint8_t key[RIN_CRYPT_XTS_256_KEY_SIZE], uint64_t* key_epoch,
    uint32_t* evidence_flags)
{
    RinCryptRecoveryKeyProvider* provider =
        (RinCryptRecoveryKeyProvider*)context;
    if (key) recovery_zero(key, RIN_CRYPT_XTS_256_KEY_SIZE);
    if (key_epoch) *key_epoch = 0u;
    if (evidence_flags) *evidence_flags = 0u;
    if (!provider || provider->magic != RIN_CRYPT_RECOVERY_KEY_MAGIC ||
        provider->reserved != 0u) {
        return -1;
    }
    return rin_crypt_keyslot_provider_api()->unlock(
        &provider->keyslot_provider, request, key, key_epoch,
        evidence_flags);
}

static const RinCryptKeyProviderV1 g_recovery_provider_api = {
    RIN_CRYPT_ABI_VERSION,
    sizeof(RinCryptKeyProviderV1),
    recovery_provider_unlock
};

void rin_crypt_recovery_key_provider_clear(
    RinCryptRecoveryKeyProvider* provider)
{
    if (!provider) return;
    if (provider->magic == RIN_CRYPT_RECOVERY_KEY_MAGIC) {
        rin_crypt_keyslot_provider_clear(&provider->keyslot_provider);
    }
    recovery_zero(provider, sizeof(*provider));
}

const RinCryptKeyProviderV1* rin_crypt_recovery_key_provider_api(void)
{
    return &g_recovery_provider_api;
}
