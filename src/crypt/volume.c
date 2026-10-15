/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "volume.h"

static void crypt_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* output = (volatile uint8_t*)pointer;
    while (size-- != 0u) *output++ = 0u;
}

static int crypt_equal(const uint8_t* left, const uint8_t* right,
                       uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int crypt_is_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static void crypt_encode_data_unit(uint64_t data_unit, uint8_t tweak[16])
{
    uint32_t index;
    crypt_zero(tweak, 16u);
    for (index = 0u; index < 8u; ++index) {
        tweak[index] = (uint8_t)(data_unit >> (index * 8u));
    }
}

static void crypt_multiply_tweak_alpha(uint8_t tweak[16])
{
    uint8_t carry = 0u;
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        uint8_t next_carry = (uint8_t)(tweak[index] >> 7);
        tweak[index] = (uint8_t)((tweak[index] << 1) | carry);
        carry = next_carry;
    }
    if (carry != 0u) tweak[0] ^= 0x87u;
}

static void crypt_transform_unit(const RinCryptSession* session,
                                 uint64_t data_unit, uint8_t* buffer,
                                 int decrypt)
{
    uint8_t tweak[16];
    uint8_t mixed[16];
    uint32_t offset;
    uint32_t index;

    crypt_encode_data_unit(data_unit, tweak);
    aes_encrypt_block(&session->tweak_key, tweak, tweak);
    for (offset = 0u; offset < session->data_unit_size;
         offset += AES_BLOCK_SIZE) {
        for (index = 0u; index < AES_BLOCK_SIZE; ++index) {
            mixed[index] = (uint8_t)(buffer[offset + index] ^ tweak[index]);
        }
        if (decrypt) {
            aes_decrypt_block(&session->data_key, mixed, mixed);
        } else {
            aes_encrypt_block(&session->data_key, mixed, mixed);
        }
        for (index = 0u; index < AES_BLOCK_SIZE; ++index) {
            buffer[offset + index] = (uint8_t)(mixed[index] ^ tweak[index]);
        }
        crypt_multiply_tweak_alpha(tweak);
    }
    crypt_zero(tweak, sizeof(tweak));
    crypt_zero(mixed, sizeof(mixed));
}

static int crypt_transform(RinCryptSession* session,
                           uint64_t first_data_unit,
                           uint32_t data_unit_count, uint8_t* buffer,
                           uint64_t buffer_size, int decrypt)
{
    uint64_t required_size;
    uint32_t index;
    if (!session || session->magic != RIN_CRYPT_SESSION_MAGIC ||
        __atomic_load_n(&session->active, __ATOMIC_ACQUIRE) != 1u) {
        return RIN_CRYPT_INACTIVE;
    }
    if (!buffer || data_unit_count == 0u ||
        first_data_unit > UINT64_MAX - ((uint64_t)data_unit_count - 1u)) {
        return RIN_CRYPT_INVALID;
    }
    required_size = (uint64_t)data_unit_count * session->data_unit_size;
    if (required_size > buffer_size) return RIN_CRYPT_RANGE;

    for (index = 0u; index < data_unit_count; ++index) {
        crypt_transform_unit(session, first_data_unit + index,
                             buffer + (uint64_t)index * session->data_unit_size,
                             decrypt);
    }
    return RIN_CRYPT_OK;
}

int rin_crypt_session_open(RinCryptSession* session,
                           const RinCryptSessionConfigV1* config)
{
    uint8_t key[RIN_CRYPT_XTS_256_KEY_SIZE];
    uint64_t key_epoch = 0u;
    uint32_t evidence_flags = 0u;
    uint32_t required_flags;
    uint32_t volume_unlock_method;
    int result;

    if (!session || !config ||
        config->abi_version != RIN_CRYPT_ABI_VERSION ||
        config->struct_size < sizeof(RinCryptSessionConfigV1) ||
        config->reserved != 0u ||
        config->data_unit_size < RIN_CRYPT_MIN_DATA_UNIT_SIZE ||
        config->data_unit_size > RIN_CRYPT_MAX_DATA_UNIT_SIZE ||
        (config->data_unit_size % AES_BLOCK_SIZE) != 0u ||
        config->key_request.struct_size != sizeof(RinCryptKeyRequestV1) ||
        config->key_request.version != RIN_CRYPT_KEY_REQUEST_VERSION ||
        !config->key_provider ||
        config->key_provider->abi_version != RIN_CRYPT_ABI_VERSION ||
        config->key_provider->struct_size < sizeof(RinCryptKeyProviderV1) ||
        !config->key_provider->unlock) {
        return RIN_CRYPT_INVALID;
    }
    if (config->key_request.purpose == RIN_CRYPT_PURPOSE_VOLUME) {
        required_flags = RIN_CRYPT_KEY_KEYSLOT_AUTHENTICATED;
    } else if (config->key_request.purpose == RIN_CRYPT_PURPOSE_SWAP) {
        required_flags = RIN_CRYPT_KEY_EPHEMERAL_BOOT |
                         RIN_CRYPT_KEY_CSPRNG_GENERATED;
    } else {
        return RIN_CRYPT_INVALID;
    }

    crypt_zero(key, sizeof(key));
    result = config->key_provider->unlock(config->key_provider_context,
                                          &config->key_request, key,
                                          &key_epoch, &evidence_flags);
    if (result != 0) {
        crypt_zero(key, sizeof(key));
        return RIN_CRYPT_LOCKED;
    }
    volume_unlock_method = evidence_flags &
        (RIN_CRYPT_KEY_ARGON2ID_DERIVED |
         RIN_CRYPT_KEY_TPM2_POLICY_AUTHENTICATED);
    if (key_epoch == 0u ||
        (evidence_flags & ~RIN_CRYPT_KEY_FLAG_MASK) != 0u ||
        (evidence_flags & required_flags) != required_flags ||
        (config->key_request.purpose == RIN_CRYPT_PURPOSE_VOLUME &&
         volume_unlock_method != RIN_CRYPT_KEY_ARGON2ID_DERIVED &&
         volume_unlock_method !=
             RIN_CRYPT_KEY_TPM2_POLICY_AUTHENTICATED) ||
        crypt_is_zero(key, sizeof(key)) ||
        crypt_equal(key, key + AES256_KEY_SIZE, AES256_KEY_SIZE)) {
        crypt_zero(key, sizeof(key));
        return RIN_CRYPT_KEY_REJECTED;
    }

    crypt_zero(session, sizeof(*session));
    if (aes_init(&session->data_key, key, AES256_KEY_SIZE) != 0 ||
        aes_init(&session->tweak_key, key + AES256_KEY_SIZE,
                 AES256_KEY_SIZE) != 0) {
        crypt_zero(key, sizeof(key));
        crypt_zero(session, sizeof(*session));
        return RIN_CRYPT_NOT_SUPPORTED;
    }
    session->data_unit_size = config->data_unit_size;
    session->evidence_flags = evidence_flags;
    session->key_epoch = key_epoch;
    session->magic = RIN_CRYPT_SESSION_MAGIC;
    __atomic_store_n(&session->active, 1u, __ATOMIC_RELEASE);
    crypt_zero(key, sizeof(key));
    return RIN_CRYPT_OK;
}

void rin_crypt_session_close(RinCryptSession* session)
{
    if (!session) return;
    __atomic_store_n(&session->active, 0u, __ATOMIC_RELEASE);
    crypt_zero(session, sizeof(*session));
}

int rin_crypt_encrypt(RinCryptSession* session, uint64_t first_data_unit,
                      uint32_t data_unit_count, uint8_t* buffer,
                      uint64_t buffer_size)
{
    return crypt_transform(session, first_data_unit, data_unit_count, buffer,
                           buffer_size, 0);
}

int rin_crypt_decrypt(RinCryptSession* session, uint64_t first_data_unit,
                      uint32_t data_unit_count, uint8_t* buffer,
                      uint64_t buffer_size)
{
    return crypt_transform(session, first_data_unit, data_unit_count, buffer,
                           buffer_size, 1);
}
