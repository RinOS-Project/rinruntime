/* SPDX-License-Identifier: GPL-2.0-or-later */
#include "rinruntime/crypt/keyslot.h"

#include "argon2.h"

typedef struct RinCryptArgonAllocator {
    uint8_t* workspace;
    uint64_t capacity;
    uint64_t allocated;
    uint32_t active;
} RinCryptArgonAllocator;

static volatile uint32_t g_argon_lock;
static RinCryptArgonAllocator g_argon_allocator;

static void keyslot_zero(void* pointer, uint64_t size)
{
    volatile uint8_t* output = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *output++ = 0u;
}

static void keyslot_clear_password(uint8_t* password, uint32_t size)
{
    if (!password) return;
    if (size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE) {
        size = RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE;
    }
    keyslot_zero(password, size);
}

static void keyslot_copy(void* destination, const void* source, uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *output++ = *input++;
}

static int keyslot_equal(const uint8_t* left, const uint8_t* right,
                         uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
    }
    return difference == 0u;
}

static int keyslot_is_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static int keyslot_ranges_overlap(const void* first, uint64_t first_size,
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

static uint32_t keyslot_read_le32(const uint8_t input[4])
{
    return (uint32_t)input[0] | ((uint32_t)input[1] << 8) |
           ((uint32_t)input[2] << 16) | ((uint32_t)input[3] << 24);
}

static uint64_t keyslot_read_le64(const uint8_t input[8])
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        value |= (uint64_t)input[index] << (index * 8u);
    }
    return value;
}

static void keyslot_write_le16(uint8_t output[2], uint16_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
}

static void keyslot_write_le32(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8);
    output[2] = (uint8_t)(value >> 16);
    output[3] = (uint8_t)(value >> 24);
}

static void keyslot_lock(volatile uint32_t* lock)
{
    while (__atomic_exchange_n(lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
        while (__atomic_load_n(lock, __ATOMIC_RELAXED) != 0u) {
        }
    }
}

static void keyslot_unlock(volatile uint32_t* lock)
{
    __atomic_store_n(lock, 0u, __ATOMIC_RELEASE);
}

static int keyslot_parameters_valid(uint32_t memory_kib, uint32_t time_cost,
                                    uint32_t lanes)
{
    return memory_kib >= RIN_CRYPT_KEYSLOT_MIN_MEMORY_KIB &&
           memory_kib <= RIN_CRYPT_KEYSLOT_MAX_MEMORY_KIB &&
           time_cost >= RIN_CRYPT_KEYSLOT_MIN_TIME_COST &&
           time_cost <= RIN_CRYPT_KEYSLOT_MAX_TIME_COST && lanes != 0u &&
           lanes <= RIN_CRYPT_KEYSLOT_MAX_LANES &&
           memory_kib >= 8u * lanes;
}

static int keyslot_argon_allocate(uint8_t** memory, size_t size)
{
    if (memory) *memory = 0;
    if (!memory || g_argon_allocator.active != 1u || size == 0u ||
        g_argon_allocator.allocated != 0u ||
        (uint64_t)size > g_argon_allocator.capacity) {
        return -1;
    }
    *memory = g_argon_allocator.workspace;
    g_argon_allocator.allocated = (uint64_t)size;
    return 0;
}

static void keyslot_argon_free(uint8_t* memory, size_t size)
{
    if (g_argon_allocator.active == 1u &&
        memory == g_argon_allocator.workspace &&
        (uint64_t)size <= g_argon_allocator.capacity) {
        keyslot_zero(memory, (uint64_t)size);
    }
    g_argon_allocator.allocated = 0u;
}

static int keyslot_argon2id(uint8_t output[RIN_CRYPT_KEYSLOT_KEK_SIZE],
                            uint8_t* password, uint32_t password_size,
                            const uint8_t salt[RIN_CRYPT_KEYSLOT_SALT_SIZE],
                            uint32_t memory_kib, uint32_t time_cost,
                            uint32_t lanes, uint8_t* workspace,
                            uint64_t workspace_size)
{
    argon2_context context;
    uint64_t required_size = (uint64_t)memory_kib * 1024u;
    int result;

    keyslot_zero(output, RIN_CRYPT_KEYSLOT_KEK_SIZE);
    if (!password || password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE || !salt ||
        !keyslot_parameters_valid(memory_kib, time_cost, lanes) ||
        !workspace || ((uintptr_t)workspace & 7u) != 0u ||
        workspace_size < required_size) {
        keyslot_clear_password(password, password_size);
        return -1;
    }

    keyslot_lock(&g_argon_lock);
    keyslot_zero(&context, sizeof(context));
    keyslot_zero(workspace, required_size);
    g_argon_allocator.workspace = workspace;
    g_argon_allocator.capacity = required_size;
    g_argon_allocator.allocated = 0u;
    g_argon_allocator.active = 1u;

    context.out = output;
    context.outlen = RIN_CRYPT_KEYSLOT_KEK_SIZE;
    context.pwd = password;
    context.pwdlen = password_size;
    context.salt = (uint8_t*)salt;
    context.saltlen = RIN_CRYPT_KEYSLOT_SALT_SIZE;
    context.t_cost = time_cost;
    context.m_cost = memory_kib;
    context.lanes = lanes;
    context.threads = 1u;
    context.version = ARGON2_VERSION_13;
    context.allocate_cbk = keyslot_argon_allocate;
    context.free_cbk = keyslot_argon_free;
    context.flags = ARGON2_FLAG_CLEAR_PASSWORD;

    result = argon2_ctx(&context, Argon2_id);
    keyslot_clear_password(password, password_size);
    keyslot_zero(workspace, required_size);
    keyslot_zero(&context, sizeof(context));
    keyslot_zero(&g_argon_allocator, sizeof(g_argon_allocator));
    keyslot_unlock(&g_argon_lock);
    if (result != ARGON2_OK) {
        keyslot_zero(output, RIN_CRYPT_KEYSLOT_KEK_SIZE);
        return -1;
    }
    return 0;
}

int rin_crypt_keyslot_validate_v1(const RinCryptKeyslotV1* keyslot)
{
    static const uint8_t magic[4] = {'R', 'K', 'S', '1'};
    uint32_t memory_kib;
    uint32_t time_cost;
    uint32_t lanes;

    if (!keyslot || !keyslot_equal(keyslot->magic, magic, sizeof(magic)) ||
        keyslot->version[0] != RIN_CRYPT_KEYSLOT_VERSION ||
        keyslot->version[1] != 0u ||
        keyslot->header_size[0] != RIN_CRYPT_KEYSLOT_AAD_SIZE ||
        keyslot->header_size[1] != 0u ||
        !keyslot_is_zero(keyslot->reserved, sizeof(keyslot->reserved)) ||
        keyslot_read_le64(keyslot->key_epoch) == 0u ||
        keyslot_is_zero(keyslot->volume_id, sizeof(keyslot->volume_id)) ||
        keyslot_is_zero(keyslot->keyslot_id, sizeof(keyslot->keyslot_id)) ||
        keyslot_is_zero(keyslot->salt, sizeof(keyslot->salt)) ||
        keyslot_is_zero(keyslot->nonce, sizeof(keyslot->nonce))) {
        return RIN_CRYPT_INVALID;
    }
    memory_kib = keyslot_read_le32(keyslot->memory_kib);
    time_cost = keyslot_read_le32(keyslot->time_cost);
    lanes = keyslot_read_le32(keyslot->lanes);
    return keyslot_parameters_valid(memory_kib, time_cost, lanes)
               ? RIN_CRYPT_OK
               : RIN_CRYPT_INVALID;
}

int rin_crypt_keyslot_format_v1(
    RinCryptKeyslotV1* keyslot,
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* parameters, uint8_t* password,
    uint32_t password_size, RinCryptKeyslotRandomFn random_bytes,
    void* random_context, uint8_t* workspace, uint64_t workspace_size)
{
    static const uint8_t magic[4] = {'R', 'K', 'S', '1'};
    uint8_t material[RIN_CRYPT_KEYSLOT_SALT_SIZE +
                     RIN_CRYPT_KEYSLOT_NONCE_SIZE +
                     RIN_CRYPT_XTS_256_KEY_SIZE + 8u];
    uint8_t kek[RIN_CRYPT_KEYSLOT_KEK_SIZE];
    uint8_t* volume_key = material + RIN_CRYPT_KEYSLOT_SALT_SIZE +
                          RIN_CRYPT_KEYSLOT_NONCE_SIZE;
    uint8_t* epoch = volume_key + RIN_CRYPT_XTS_256_KEY_SIZE;
    int result = RIN_CRYPT_INVALID;

    if (keyslot) keyslot_zero(keyslot, sizeof(*keyslot));
    keyslot_zero(material, sizeof(material));
    keyslot_zero(kek, sizeof(kek));
    if (!keyslot || !volume_id || !keyslot_id || !parameters || !password ||
        password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE ||
        !random_bytes || !workspace ||
        !keyslot_parameters_valid(parameters->memory_kib,
                                  parameters->time_cost,
                                  parameters->lanes) ||
        parameters->reserved != 0u ||
        keyslot_is_zero(volume_id, RIN_CRYPT_VOLUME_ID_SIZE) ||
        keyslot_is_zero(keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE)) {
        goto done;
    }
    if (random_bytes(random_context, material, sizeof(material)) != 0 ||
        keyslot_is_zero(material, RIN_CRYPT_KEYSLOT_SALT_SIZE) ||
        keyslot_is_zero(material + RIN_CRYPT_KEYSLOT_SALT_SIZE,
                        RIN_CRYPT_KEYSLOT_NONCE_SIZE) ||
        keyslot_is_zero(volume_key, RIN_CRYPT_XTS_256_KEY_SIZE) ||
        keyslot_equal(volume_key, volume_key + AES256_KEY_SIZE,
                      AES256_KEY_SIZE) || keyslot_is_zero(epoch, 8u)) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }

    keyslot_copy(keyslot->magic, magic, sizeof(magic));
    keyslot_write_le16(keyslot->version, RIN_CRYPT_KEYSLOT_VERSION);
    keyslot_write_le16(keyslot->header_size, RIN_CRYPT_KEYSLOT_AAD_SIZE);
    keyslot_write_le32(keyslot->memory_kib, parameters->memory_kib);
    keyslot_write_le32(keyslot->time_cost, parameters->time_cost);
    keyslot_write_le32(keyslot->lanes, parameters->lanes);
    keyslot_copy(keyslot->key_epoch, epoch, sizeof(keyslot->key_epoch));
    keyslot_copy(keyslot->volume_id, volume_id, sizeof(keyslot->volume_id));
    keyslot_copy(keyslot->keyslot_id, keyslot_id,
                 sizeof(keyslot->keyslot_id));
    keyslot_copy(keyslot->salt, material, sizeof(keyslot->salt));
    keyslot_copy(keyslot->nonce, material + RIN_CRYPT_KEYSLOT_SALT_SIZE,
                 sizeof(keyslot->nonce));

    if (keyslot_argon2id(kek, password, password_size, keyslot->salt,
                         parameters->memory_kib, parameters->time_cost,
                         parameters->lanes, workspace, workspace_size) != 0 ||
        aes_gcm_encrypt_full(kek, sizeof(kek), keyslot->nonce,
                             sizeof(keyslot->nonce), (const uint8_t*)keyslot,
                             RIN_CRYPT_KEYSLOT_AAD_SIZE, volume_key,
                             RIN_CRYPT_XTS_256_KEY_SIZE, keyslot->wrapped_key,
                             keyslot->tag) != 0) {
        result = RIN_CRYPT_LOCKED;
        goto done;
    }
    result = rin_crypt_keyslot_validate_v1(keyslot);

done:
    keyslot_clear_password(password, password_size);
    keyslot_zero(kek, sizeof(kek));
    keyslot_zero(material, sizeof(material));
    if (result != RIN_CRYPT_OK && keyslot) {
        keyslot_zero(keyslot, sizeof(*keyslot));
    }
    return result;
}

static int keyslot_pair_aliases(
    RinCryptKeyslotV1* keyslots, const uint8_t* volume_id,
    const uint8_t* first_keyslot_id,
    const RinCryptKeyslotParametersV1* first_parameters,
    uint8_t* first_password, uint32_t first_password_size,
    const uint8_t* second_keyslot_id,
    const RinCryptKeyslotParametersV1* second_parameters,
    uint8_t* second_password, uint32_t second_password_size,
    uint8_t* workspace, uint64_t workspace_size)
{
    const void* pointers[8];
    uint64_t sizes[8];
    uint32_t first;
    uint32_t second;
    pointers[0] = keyslots;
    sizes[0] = sizeof(RinCryptKeyslotV1) * RIN_CRYPT_KEYSLOT_PAIR_COUNT;
    pointers[1] = volume_id;
    sizes[1] = RIN_CRYPT_VOLUME_ID_SIZE;
    pointers[2] = first_keyslot_id;
    sizes[2] = RIN_CRYPT_KEYSLOT_ID_SIZE;
    pointers[3] = first_parameters;
    sizes[3] = sizeof(*first_parameters);
    pointers[4] = first_password;
    sizes[4] = first_password_size;
    pointers[5] = second_keyslot_id;
    sizes[5] = RIN_CRYPT_KEYSLOT_ID_SIZE;
    pointers[6] = second_parameters;
    sizes[6] = sizeof(*second_parameters);
    pointers[7] = second_password;
    sizes[7] = second_password_size;
    for (first = 0u; first < 8u; ++first) {
        if (keyslot_ranges_overlap(pointers[first], sizes[first], workspace,
                                   workspace_size))
            return 1;
        for (second = first + 1u; second < 8u; ++second) {
            if (keyslot_ranges_overlap(pointers[first], sizes[first],
                                       pointers[second], sizes[second]))
                return 1;
        }
    }
    return 0;
}

static int keyslot_wrap_shared(
    RinCryptKeyslotV1* keyslot, const uint8_t* volume_id,
    const uint8_t* keyslot_id,
    const RinCryptKeyslotParametersV1* parameters, uint8_t* password,
    uint32_t password_size, const uint8_t* salt, const uint8_t* nonce,
    const uint8_t* volume_key, const uint8_t* epoch, uint8_t* workspace,
    uint64_t workspace_size)
{
    static const uint8_t magic[4] = {'R', 'K', 'S', '1'};
    uint8_t kek[RIN_CRYPT_KEYSLOT_KEK_SIZE];
    int result = RIN_CRYPT_INVALID;
    keyslot_zero(kek, sizeof(kek));
    keyslot_zero(keyslot, sizeof(*keyslot));
    keyslot_copy(keyslot->magic, magic, sizeof(magic));
    keyslot_write_le16(keyslot->version, RIN_CRYPT_KEYSLOT_VERSION);
    keyslot_write_le16(keyslot->header_size, RIN_CRYPT_KEYSLOT_AAD_SIZE);
    keyslot_write_le32(keyslot->memory_kib, parameters->memory_kib);
    keyslot_write_le32(keyslot->time_cost, parameters->time_cost);
    keyslot_write_le32(keyslot->lanes, parameters->lanes);
    keyslot_copy(keyslot->key_epoch, epoch, sizeof(keyslot->key_epoch));
    keyslot_copy(keyslot->volume_id, volume_id, sizeof(keyslot->volume_id));
    keyslot_copy(keyslot->keyslot_id, keyslot_id,
                 sizeof(keyslot->keyslot_id));
    keyslot_copy(keyslot->salt, salt, sizeof(keyslot->salt));
    keyslot_copy(keyslot->nonce, nonce, sizeof(keyslot->nonce));
    if (keyslot_argon2id(kek, password, password_size, salt,
                         parameters->memory_kib, parameters->time_cost,
                         parameters->lanes, workspace, workspace_size) != 0 ||
        aes_gcm_encrypt_full(kek, sizeof(kek), nonce,
                            RIN_CRYPT_KEYSLOT_NONCE_SIZE,
                            (const uint8_t*)keyslot,
                            RIN_CRYPT_KEYSLOT_AAD_SIZE, volume_key,
                            RIN_CRYPT_XTS_256_KEY_SIZE,
                            keyslot->wrapped_key, keyslot->tag) != 0) {
        result = RIN_CRYPT_LOCKED;
        goto done;
    }
    result = rin_crypt_keyslot_validate_v1(keyslot);
done:
    keyslot_clear_password(password, password_size);
    keyslot_zero(kek, sizeof(kek));
    if (result != RIN_CRYPT_OK) keyslot_zero(keyslot, sizeof(*keyslot));
    return result;
}

int rin_crypt_keyslot_format_pair_and_seal_v1(
    RinCryptKeyslotV1 keyslots[RIN_CRYPT_KEYSLOT_PAIR_COUNT],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t first_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* first_parameters,
    uint8_t* first_password, uint32_t first_password_size,
    const uint8_t second_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* second_parameters,
    uint8_t* second_password, uint32_t second_password_size,
    RinCryptKeyslotPairSealFn seal_key, void* seal_context,
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size)
{
    enum {
        FIRST_SALT = 0,
        FIRST_NONCE = FIRST_SALT + RIN_CRYPT_KEYSLOT_SALT_SIZE,
        SECOND_SALT = FIRST_NONCE + RIN_CRYPT_KEYSLOT_NONCE_SIZE,
        SECOND_NONCE = SECOND_SALT + RIN_CRYPT_KEYSLOT_SALT_SIZE,
        SHARED_KEY = SECOND_NONCE + RIN_CRYPT_KEYSLOT_NONCE_SIZE,
        SHARED_EPOCH = SHARED_KEY + RIN_CRYPT_XTS_256_KEY_SIZE,
        PAIR_MATERIAL_SIZE = SHARED_EPOCH + 8
    };
    uint8_t material[PAIR_MATERIAL_SIZE];
    uint8_t volume_snapshot[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t first_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint8_t second_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint8_t seal_volume_snapshot[RIN_CRYPT_VOLUME_ID_SIZE];
    uint8_t seal_id_snapshot[RIN_CRYPT_KEYSLOT_ID_SIZE];
    uint8_t seal_key_snapshot[RIN_CRYPT_XTS_256_KEY_SIZE];
    RinCryptKeyslotV1 keyslots_snapshot[RIN_CRYPT_KEYSLOT_PAIR_COUNT];
    RinCryptKeyslotParametersV1 first_parameters_snapshot;
    RinCryptKeyslotParametersV1 second_parameters_snapshot;
    int result = RIN_CRYPT_INVALID;
    keyslot_zero(material, sizeof(material));
    keyslot_zero(volume_snapshot, sizeof(volume_snapshot));
    keyslot_zero(first_id_snapshot, sizeof(first_id_snapshot));
    keyslot_zero(second_id_snapshot, sizeof(second_id_snapshot));
    keyslot_zero(seal_volume_snapshot, sizeof(seal_volume_snapshot));
    keyslot_zero(seal_id_snapshot, sizeof(seal_id_snapshot));
    keyslot_zero(seal_key_snapshot, sizeof(seal_key_snapshot));
    keyslot_zero(keyslots_snapshot, sizeof(keyslots_snapshot));
    keyslot_zero(&first_parameters_snapshot,
                 sizeof(first_parameters_snapshot));
    keyslot_zero(&second_parameters_snapshot,
                 sizeof(second_parameters_snapshot));
    if (keyslot_pair_aliases(
            keyslots, volume_id, first_keyslot_id, first_parameters,
            first_password, first_password_size, second_keyslot_id,
            second_parameters, second_password, second_password_size,
            workspace, workspace_size)) {
        return RIN_CRYPT_INVALID;
    }
    if (keyslots) keyslot_zero(keyslots, sizeof(*keyslots) * 2u);
    if (!keyslots || !volume_id || !first_keyslot_id || !first_parameters ||
        !first_password || !second_keyslot_id || !second_parameters ||
        !second_password || !seal_key || !random_bytes || !workspace ||
        first_password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        first_password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE ||
        second_password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        second_password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE ||
        !keyslot_parameters_valid(first_parameters->memory_kib,
                                  first_parameters->time_cost,
                                  first_parameters->lanes) ||
        first_parameters->reserved != 0u ||
        !keyslot_parameters_valid(second_parameters->memory_kib,
                                  second_parameters->time_cost,
                                  second_parameters->lanes) ||
        second_parameters->reserved != 0u ||
        keyslot_is_zero(volume_id, RIN_CRYPT_VOLUME_ID_SIZE) ||
        keyslot_is_zero(first_keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE) ||
        keyslot_is_zero(second_keyslot_id, RIN_CRYPT_KEYSLOT_ID_SIZE) ||
        keyslot_equal(first_keyslot_id, second_keyslot_id,
                      RIN_CRYPT_KEYSLOT_ID_SIZE)) {
        goto done;
    }
    keyslot_copy(volume_snapshot, volume_id, sizeof(volume_snapshot));
    keyslot_copy(first_id_snapshot, first_keyslot_id,
                 sizeof(first_id_snapshot));
    keyslot_copy(second_id_snapshot, second_keyslot_id,
                 sizeof(second_id_snapshot));
    keyslot_copy(&first_parameters_snapshot, first_parameters,
                 sizeof(first_parameters_snapshot));
    keyslot_copy(&second_parameters_snapshot, second_parameters,
                 sizeof(second_parameters_snapshot));
    if (random_bytes(random_context, material, sizeof(material)) != 0 ||
        keyslot_is_zero(material + FIRST_SALT,
                        RIN_CRYPT_KEYSLOT_SALT_SIZE) ||
        keyslot_is_zero(material + FIRST_NONCE,
                        RIN_CRYPT_KEYSLOT_NONCE_SIZE) ||
        keyslot_is_zero(material + SECOND_SALT,
                        RIN_CRYPT_KEYSLOT_SALT_SIZE) ||
        keyslot_is_zero(material + SECOND_NONCE,
                        RIN_CRYPT_KEYSLOT_NONCE_SIZE) ||
        keyslot_equal(material + FIRST_SALT, material + SECOND_SALT,
                      RIN_CRYPT_KEYSLOT_SALT_SIZE) ||
        keyslot_equal(material + FIRST_NONCE, material + SECOND_NONCE,
                      RIN_CRYPT_KEYSLOT_NONCE_SIZE) ||
        keyslot_is_zero(material + SHARED_KEY,
                        RIN_CRYPT_XTS_256_KEY_SIZE) ||
        keyslot_equal(material + SHARED_KEY,
                      material + SHARED_KEY + AES256_KEY_SIZE,
                      AES256_KEY_SIZE) ||
        keyslot_is_zero(material + SHARED_EPOCH, 8u)) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }
    if (!keyslot_equal(volume_snapshot, volume_id, sizeof(volume_snapshot)) ||
        !keyslot_equal(first_id_snapshot, first_keyslot_id,
                       sizeof(first_id_snapshot)) ||
        !keyslot_equal(second_id_snapshot, second_keyslot_id,
                       sizeof(second_id_snapshot)) ||
        !keyslot_equal((const uint8_t*)&first_parameters_snapshot,
                       (const uint8_t*)first_parameters,
                       sizeof(first_parameters_snapshot)) ||
        !keyslot_equal((const uint8_t*)&second_parameters_snapshot,
                       (const uint8_t*)second_parameters,
                       sizeof(second_parameters_snapshot)) ||
        !keyslot_is_zero((const uint8_t*)keyslots,
                         sizeof(*keyslots) *
                             RIN_CRYPT_KEYSLOT_PAIR_COUNT)) {
        result = RIN_CRYPT_KEY_REJECTED;
        goto done;
    }
    result = keyslot_wrap_shared(
        &keyslots[0], volume_snapshot, first_id_snapshot,
        &first_parameters_snapshot, first_password, first_password_size,
        material + FIRST_SALT, material + FIRST_NONCE,
        material + SHARED_KEY, material + SHARED_EPOCH, workspace,
        workspace_size);
    if (result != RIN_CRYPT_OK) goto done;
    result = keyslot_wrap_shared(
        &keyslots[1], volume_snapshot, second_id_snapshot,
        &second_parameters_snapshot, second_password,
        second_password_size, material + SECOND_SALT,
        material + SECOND_NONCE, material + SHARED_KEY,
        material + SHARED_EPOCH, workspace, workspace_size);
    if (result != RIN_CRYPT_OK) goto done;
    keyslot_copy(seal_volume_snapshot, volume_snapshot,
                 sizeof(seal_volume_snapshot));
    keyslot_copy(seal_id_snapshot, first_id_snapshot,
                 sizeof(seal_id_snapshot));
    keyslot_copy(seal_key_snapshot, material + SHARED_KEY,
                 sizeof(seal_key_snapshot));
    keyslot_copy(keyslots_snapshot, keyslots, sizeof(keyslots_snapshot));
    if (seal_key(seal_context, seal_volume_snapshot, seal_id_snapshot,
                 keyslot_read_le64(material + SHARED_EPOCH),
                 seal_key_snapshot) != RIN_CRYPT_OK ||
        !keyslot_equal(seal_volume_snapshot, volume_snapshot,
                       sizeof(seal_volume_snapshot)) ||
        !keyslot_equal(seal_id_snapshot, first_id_snapshot,
                       sizeof(seal_id_snapshot)) ||
        !keyslot_equal(seal_key_snapshot, material + SHARED_KEY,
                       sizeof(seal_key_snapshot)) ||
        !keyslot_equal((const uint8_t*)keyslots_snapshot,
                       (const uint8_t*)keyslots,
                       sizeof(keyslots_snapshot)) ||
        !keyslot_equal(volume_snapshot, volume_id,
                       sizeof(volume_snapshot)) ||
        !keyslot_equal(first_id_snapshot, first_keyslot_id,
                       sizeof(first_id_snapshot)) ||
        !keyslot_equal(second_id_snapshot, second_keyslot_id,
                       sizeof(second_id_snapshot)) ||
        !keyslot_equal((const uint8_t*)&first_parameters_snapshot,
                       (const uint8_t*)first_parameters,
                       sizeof(first_parameters_snapshot)) ||
        !keyslot_equal((const uint8_t*)&second_parameters_snapshot,
                       (const uint8_t*)second_parameters,
                       sizeof(second_parameters_snapshot)) ||
        rin_crypt_keyslot_validate_v1(&keyslots[0]) != RIN_CRYPT_OK ||
        rin_crypt_keyslot_validate_v1(&keyslots[1]) != RIN_CRYPT_OK ||
        !keyslot_equal(keyslots[0].key_epoch, material + SHARED_EPOCH, 8u) ||
        !keyslot_equal(keyslots[1].key_epoch, material + SHARED_EPOCH, 8u)) {
        result = RIN_CRYPT_KEY_REJECTED;
    }
done:
    keyslot_clear_password(first_password, first_password_size);
    keyslot_clear_password(second_password, second_password_size);
    keyslot_zero(material, sizeof(material));
    keyslot_zero(volume_snapshot, sizeof(volume_snapshot));
    keyslot_zero(first_id_snapshot, sizeof(first_id_snapshot));
    keyslot_zero(second_id_snapshot, sizeof(second_id_snapshot));
    keyslot_zero(seal_volume_snapshot, sizeof(seal_volume_snapshot));
    keyslot_zero(seal_id_snapshot, sizeof(seal_id_snapshot));
    keyslot_zero(seal_key_snapshot, sizeof(seal_key_snapshot));
    keyslot_zero(keyslots_snapshot, sizeof(keyslots_snapshot));
    keyslot_zero(&first_parameters_snapshot,
                 sizeof(first_parameters_snapshot));
    keyslot_zero(&second_parameters_snapshot,
                 sizeof(second_parameters_snapshot));
    if (result != RIN_CRYPT_OK && keyslots)
        keyslot_zero(keyslots, sizeof(*keyslots) * 2u);
    return result;
}

static int keyslot_pair_accept(void* context, const uint8_t* volume_id,
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

int rin_crypt_keyslot_format_pair_v1(
    RinCryptKeyslotV1 keyslots[RIN_CRYPT_KEYSLOT_PAIR_COUNT],
    const uint8_t volume_id[RIN_CRYPT_VOLUME_ID_SIZE],
    const uint8_t first_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* first_parameters,
    uint8_t* first_password, uint32_t first_password_size,
    const uint8_t second_keyslot_id[RIN_CRYPT_KEYSLOT_ID_SIZE],
    const RinCryptKeyslotParametersV1* second_parameters,
    uint8_t* second_password, uint32_t second_password_size,
    RinCryptKeyslotRandomFn random_bytes, void* random_context,
    uint8_t* workspace, uint64_t workspace_size)
{
    return rin_crypt_keyslot_format_pair_and_seal_v1(
        keyslots, volume_id, first_keyslot_id, first_parameters,
        first_password, first_password_size, second_keyslot_id,
        second_parameters, second_password, second_password_size,
        keyslot_pair_accept, (void*)0, random_bytes, random_context, workspace,
        workspace_size);
}

int rin_crypt_keyslot_provider_init(RinCryptKeyslotProvider* provider,
                                    const RinCryptKeyslotV1* keyslot,
                                    uint8_t* password,
                                    uint32_t password_size,
                                    uint8_t* workspace,
                                    uint64_t workspace_size)
{
    uint64_t required_size;
    uint32_t memory_kib;

    if (provider) keyslot_zero(provider, sizeof(*provider));
    if (!provider || !keyslot || !password ||
        password_size < RIN_CRYPT_KEYSLOT_MIN_PASSWORD_SIZE ||
        password_size > RIN_CRYPT_KEYSLOT_MAX_PASSWORD_SIZE || !workspace ||
        ((uintptr_t)workspace & 7u) != 0u ||
        rin_crypt_keyslot_validate_v1(keyslot) != RIN_CRYPT_OK) {
        keyslot_clear_password(password, password_size);
        return RIN_CRYPT_INVALID;
    }
    memory_kib = keyslot_read_le32(keyslot->memory_kib);
    required_size = (uint64_t)memory_kib * 1024u;
    if (workspace_size < required_size) {
        keyslot_clear_password(password, password_size);
        return RIN_CRYPT_RANGE;
    }

    keyslot_copy(&provider->keyslot, keyslot, sizeof(*keyslot));
    provider->password = password;
    provider->password_size = password_size;
    provider->workspace = workspace;
    provider->workspace_size = required_size;
    provider->magic = RIN_CRYPT_KEYSLOT_PROVIDER_MAGIC;
    __atomic_store_n(&provider->active, 1u, __ATOMIC_RELEASE);
    return RIN_CRYPT_OK;
}

static int keyslot_provider_unlock_request(
    void* context, const RinCryptKeyRequestV1* request,
    uint8_t key[RIN_CRYPT_XTS_256_KEY_SIZE], uint64_t* key_epoch,
    uint32_t* evidence_flags)
{
    RinCryptKeyslotProvider* provider = (RinCryptKeyslotProvider*)context;
    uint8_t kek[RIN_CRYPT_KEYSLOT_KEK_SIZE];
    aes_ctx aes;
    rin_size_t plaintext_size = 0u;
    uint32_t memory_kib;
    uint32_t time_cost;
    uint32_t lanes;
    int result = -1;

    if (key) keyslot_zero(key, RIN_CRYPT_XTS_256_KEY_SIZE);
    if (key_epoch) *key_epoch = 0u;
    if (evidence_flags) *evidence_flags = 0u;
    keyslot_zero(kek, sizeof(kek));
    keyslot_zero(&aes, sizeof(aes));
    if (!provider || !request || !key || !key_epoch || !evidence_flags) {
        return -1;
    }

    keyslot_lock(&provider->lock);
    if (provider->magic != RIN_CRYPT_KEYSLOT_PROVIDER_MAGIC ||
        provider->active != 1u || provider->attempted != 0u ||
        !provider->password || !provider->workspace) {
        goto done;
    }
    provider->attempted = 1u;
    if (request->struct_size != sizeof(*request) ||
        request->version != RIN_CRYPT_KEY_REQUEST_VERSION ||
        request->purpose != RIN_CRYPT_PURPOSE_VOLUME) {
        goto done;
    }
    if (!keyslot_equal(request->volume_id, provider->keyslot.volume_id,
                       RIN_CRYPT_VOLUME_ID_SIZE) ||
        !keyslot_equal(request->keyslot_id, provider->keyslot.keyslot_id,
                       RIN_CRYPT_KEYSLOT_ID_SIZE)) {
        goto done;
    }

    memory_kib = keyslot_read_le32(provider->keyslot.memory_kib);
    time_cost = keyslot_read_le32(provider->keyslot.time_cost);
    lanes = keyslot_read_le32(provider->keyslot.lanes);
    if (keyslot_argon2id(kek, provider->password, provider->password_size,
                         provider->keyslot.salt, memory_kib, time_cost, lanes,
                         provider->workspace, provider->workspace_size) != 0 ||
        aes_init(&aes, kek, sizeof(kek)) != 0 ||
        aes_gcm_decrypt(&aes, provider->keyslot.nonce,
                        sizeof(provider->keyslot.nonce),
                        (const uint8_t*)&provider->keyslot,
                        RIN_CRYPT_KEYSLOT_AAD_SIZE,
                        provider->keyslot.wrapped_key,
                        sizeof(provider->keyslot.wrapped_key),
                        provider->keyslot.tag, sizeof(provider->keyslot.tag),
                        key, &plaintext_size) != 0 ||
        plaintext_size != RIN_CRYPT_XTS_256_KEY_SIZE ||
        keyslot_is_zero(key, RIN_CRYPT_XTS_256_KEY_SIZE) ||
        keyslot_equal(key, key + AES256_KEY_SIZE, AES256_KEY_SIZE)) {
        goto done;
    }
    *key_epoch = keyslot_read_le64(provider->keyslot.key_epoch);
    *evidence_flags = RIN_CRYPT_KEY_ARGON2ID_DERIVED |
                      RIN_CRYPT_KEY_KEYSLOT_AUTHENTICATED;
    result = 0;

done:
    if (provider->password) {
        keyslot_clear_password(provider->password, provider->password_size);
    }
    provider->password = 0;
    provider->password_size = 0u;
    provider->active = 0u;
    keyslot_zero(&provider->keyslot, sizeof(provider->keyslot));
    keyslot_zero(kek, sizeof(kek));
    keyslot_zero(&aes, sizeof(aes));
    if (result != 0) {
        keyslot_zero(key, RIN_CRYPT_XTS_256_KEY_SIZE);
        *key_epoch = 0u;
        *evidence_flags = 0u;
    }
    keyslot_unlock(&provider->lock);
    return result;
}

static const RinCryptKeyProviderV1 g_keyslot_provider_api = {
    RIN_CRYPT_ABI_VERSION,
    sizeof(RinCryptKeyProviderV1),
    keyslot_provider_unlock_request
};

void rin_crypt_keyslot_provider_clear(RinCryptKeyslotProvider* provider)
{
    if (!provider) return;
    keyslot_lock(&provider->lock);
    if (provider->password) {
        keyslot_clear_password(provider->password, provider->password_size);
    }
    if (provider->workspace && provider->workspace_size != 0u &&
        provider->workspace_size <=
            (uint64_t)RIN_CRYPT_KEYSLOT_MAX_MEMORY_KIB * 1024u) {
        keyslot_zero(provider->workspace, provider->workspace_size);
    }
    keyslot_zero(&provider->keyslot, sizeof(provider->keyslot));
    provider->active = 0u;
    provider->magic = 0u;
    keyslot_unlock(&provider->lock);
    keyslot_zero(provider, sizeof(*provider));
}

const RinCryptKeyProviderV1* rin_crypt_keyslot_provider_api(void)
{
    return &g_keyslot_provider_api;
}
