/* SPDX-License-Identifier: MIT */

#include "rin_aes_siv.h"

#include "crypto/aes.h"

static void rin_siv_zero(void* pointer, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    while (size-- != 0u)
        *bytes++ = 0u;
}

static void rin_siv_copy(uint8_t* destination, const uint8_t* source,
                         size_t size)
{
    size_t index;
    for (index = 0u; index < size; ++index)
        destination[index] = source[index];
}

static void rin_siv_xor(uint8_t destination[16], const uint8_t source[16])
{
    size_t index;
    for (index = 0u; index < 16u; ++index)
        destination[index] ^= source[index];
}

static void rin_siv_double(uint8_t block[16])
{
    uint8_t carry = 0u;
    size_t index = 16u;

    while (index != 0u) {
        uint8_t next;
        --index;
        next = (uint8_t)(block[index] >> 7u);
        block[index] = (uint8_t)((block[index] << 1u) | carry);
        carry = next;
    }
    if (carry != 0u)
        block[15] ^= UINT8_C(0x87);
}

static uint8_t rin_siv_virtual_byte(const uint8_t* bytes, size_t size,
                                    size_t index, const uint8_t* xor_end)
{
    uint8_t value = bytes[index];
    if (xor_end != NULL && index >= size - 16u)
        value ^= xor_end[index - (size - 16u)];
    return value;
}

static void rin_siv_cmac(const aes_ctx* aes, const uint8_t* bytes,
                         size_t size, const uint8_t* xor_end,
                         uint8_t result[16])
{
    uint8_t encrypted_zero[16] = {0};
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t state[16] = {0};
    uint8_t block[16];
    size_t block_count;
    size_t block_index;
    size_t index;
    int complete;

    aes_encrypt_block(aes, encrypted_zero, k1);
    rin_siv_double(k1);
    rin_siv_copy(k2, k1, sizeof(k2));
    rin_siv_double(k2);

    block_count = (size + 15u) / 16u;
    if (block_count == 0u)
        block_count = 1u;
    complete = size != 0u && (size & 15u) == 0u;

    for (block_index = 0u; block_index + 1u < block_count; ++block_index) {
        for (index = 0u; index < 16u; ++index) {
            block[index] = rin_siv_virtual_byte(
                bytes, size, block_index * 16u + index, xor_end);
            block[index] ^= state[index];
        }
        aes_encrypt_block(aes, block, state);
    }

    for (index = 0u; index < 16u; ++index)
        block[index] = 0u;
    if (complete) {
        const size_t offset = (block_count - 1u) * 16u;
        for (index = 0u; index < 16u; ++index)
            block[index] = rin_siv_virtual_byte(bytes, size, offset + index,
                                                xor_end);
        rin_siv_xor(block, k1);
    } else {
        const size_t offset = (block_count - 1u) * 16u;
        const size_t remainder = size - offset;
        for (index = 0u; index < remainder; ++index)
            block[index] = rin_siv_virtual_byte(bytes, size, offset + index,
                                                xor_end);
        block[remainder] = UINT8_C(0x80);
        rin_siv_xor(block, k2);
    }
    rin_siv_xor(block, state);
    aes_encrypt_block(aes, block, result);

    rin_siv_zero(encrypted_zero, sizeof(encrypted_zero));
    rin_siv_zero(k1, sizeof(k1));
    rin_siv_zero(k2, sizeof(k2));
    rin_siv_zero(state, sizeof(state));
    rin_siv_zero(block, sizeof(block));
}

static void rin_siv_s2v(const aes_ctx* aes,
                        const RinAesSivComponent* associated_data,
                        size_t associated_data_count,
                        const uint8_t* plaintext, size_t plaintext_size,
                        uint8_t result[16])
{
    uint8_t zero[16] = {0};
    uint8_t component_cmac[16];
    uint8_t padded[16];
    size_t component_index;
    size_t index;

    rin_siv_cmac(aes, zero, sizeof(zero), NULL, result);
    for (component_index = 0u;
         component_index < associated_data_count; ++component_index) {
        rin_siv_double(result);
        rin_siv_cmac(aes, associated_data[component_index].bytes,
                     associated_data[component_index].size, NULL,
                     component_cmac);
        rin_siv_xor(result, component_cmac);
    }

    if (plaintext_size >= 16u) {
        rin_siv_cmac(aes, plaintext, plaintext_size, result, component_cmac);
        rin_siv_copy(result, component_cmac, 16u);
    } else {
        rin_siv_double(result);
        for (index = 0u; index < sizeof(padded); ++index)
            padded[index] = 0u;
        for (index = 0u; index < plaintext_size; ++index)
            padded[index] = plaintext[index];
        padded[plaintext_size] = UINT8_C(0x80);
        rin_siv_xor(padded, result);
        rin_siv_cmac(aes, padded, sizeof(padded), NULL, result);
    }

    rin_siv_zero(zero, sizeof(zero));
    rin_siv_zero(component_cmac, sizeof(component_cmac));
    rin_siv_zero(padded, sizeof(padded));
}

static void rin_siv_ctr(const aes_ctx* aes, const uint8_t tag[16],
                        const uint8_t* input, size_t size, uint8_t* output)
{
    uint8_t counter[16];
    uint8_t stream[16];
    size_t offset = 0u;
    size_t index;

    rin_siv_copy(counter, tag, sizeof(counter));
    counter[8] &= UINT8_C(0x7f);
    counter[12] &= UINT8_C(0x7f);
    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > 16u)
            chunk = 16u;
        aes_encrypt_block(aes, counter, stream);
        for (index = 0u; index < chunk; ++index)
            output[offset + index] = input[offset + index] ^ stream[index];
        offset += chunk;
        for (index = 16u; index != 12u;) {
            --index;
            ++counter[index];
            if (counter[index] != 0u)
                break;
        }
    }
    rin_siv_zero(counter, sizeof(counter));
    rin_siv_zero(stream, sizeof(stream));
}

static int rin_siv_inputs_valid(
    const uint8_t* key, const RinAesSivComponent* associated_data,
    size_t associated_data_count)
{
    size_t index;

    if (key == NULL || associated_data_count > RIN_AES_SIV_MAX_ASSOCIATED_DATA ||
        (associated_data_count != 0u && associated_data == NULL))
        return 0;
    for (index = 0u; index < associated_data_count; ++index) {
        if (associated_data[index].size != 0u &&
            associated_data[index].bytes == NULL)
            return 0;
    }
    return 1;
}

static int rin_siv_ranges_overlap(const void* left, size_t left_size,
                                  const void* right, size_t right_size)
{
    uintptr_t left_address;
    uintptr_t right_address;
    if (!left || !right || left_size == 0u || right_size == 0u) return 0;
    left_address = (uintptr_t)left;
    right_address = (uintptr_t)right;
    if (left_address <= right_address)
        return right_address - left_address < left_size;
    return left_address - right_address < right_size;
}

int rin_aes_siv_cmac_256_seal(
    const uint8_t key[RIN_AES_SIV_CMAC_256_KEY_BYTES],
    const RinAesSivComponent* associated_data,
    size_t associated_data_count, const uint8_t* plaintext,
    size_t plaintext_size, uint8_t* output, size_t output_capacity,
    size_t* output_size)
{
    aes_ctx cmac_aes;
    aes_ctx ctr_aes;
    uint8_t tag[16];
    int status = -1;

    if (output_size != NULL)
        *output_size = 0u;
    if (!rin_siv_inputs_valid(key, associated_data, associated_data_count) ||
        output == NULL || output_size == NULL ||
        (plaintext_size != 0u && plaintext == NULL) ||
        plaintext_size > SIZE_MAX - RIN_AES_SIV_TAG_BYTES)
        return -1;
    if (output_capacity < plaintext_size + RIN_AES_SIV_TAG_BYTES ||
        rin_siv_ranges_overlap(plaintext, plaintext_size, output,
                               plaintext_size + RIN_AES_SIV_TAG_BYTES))
        return -1;
    if (aes_init(&cmac_aes, key, AES128_KEY_SIZE) != 0 ||
        aes_init(&ctr_aes, key + AES128_KEY_SIZE, AES128_KEY_SIZE) != 0)
        goto cleanup;

    rin_siv_s2v(&cmac_aes, associated_data, associated_data_count,
                plaintext, plaintext_size, tag);
    rin_siv_copy(output, tag, sizeof(tag));
    if (plaintext_size != 0u)
        rin_siv_ctr(&ctr_aes, tag, plaintext, plaintext_size,
                    output + RIN_AES_SIV_TAG_BYTES);
    *output_size = plaintext_size + RIN_AES_SIV_TAG_BYTES;
    status = 0;

cleanup:
    rin_siv_zero(&cmac_aes, sizeof(cmac_aes));
    rin_siv_zero(&ctr_aes, sizeof(ctr_aes));
    rin_siv_zero(tag, sizeof(tag));
    return status;
}

int rin_aes_siv_cmac_256_open(
    const uint8_t key[RIN_AES_SIV_CMAC_256_KEY_BYTES],
    const RinAesSivComponent* associated_data,
    size_t associated_data_count, const uint8_t* ciphertext,
    size_t ciphertext_size, uint8_t* output, size_t output_capacity,
    size_t* output_size)
{
    aes_ctx cmac_aes;
    aes_ctx ctr_aes;
    uint8_t expected[16];
    uint8_t difference = 0u;
    size_t plaintext_size;
    size_t index;
    int status = -1;

    if (output_size != NULL)
        *output_size = 0u;
    if (!rin_siv_inputs_valid(key, associated_data, associated_data_count) ||
        ciphertext == NULL || output == NULL || output_size == NULL ||
        ciphertext_size < RIN_AES_SIV_TAG_BYTES)
        return -1;
    plaintext_size = ciphertext_size - RIN_AES_SIV_TAG_BYTES;
    if (output_capacity < plaintext_size ||
        rin_siv_ranges_overlap(ciphertext, ciphertext_size, output,
                               plaintext_size))
        return -1;
    if (aes_init(&cmac_aes, key, AES128_KEY_SIZE) != 0 ||
        aes_init(&ctr_aes, key + AES128_KEY_SIZE, AES128_KEY_SIZE) != 0)
        goto cleanup;

    if (plaintext_size != 0u)
        rin_siv_ctr(&ctr_aes, ciphertext,
                    ciphertext + RIN_AES_SIV_TAG_BYTES, plaintext_size,
                    output);
    rin_siv_s2v(&cmac_aes, associated_data, associated_data_count,
                output, plaintext_size, expected);
    for (index = 0u; index < sizeof(expected); ++index)
        difference |= expected[index] ^ ciphertext[index];
    if (difference != 0u) {
        rin_siv_zero(output, plaintext_size);
        goto cleanup;
    }
    *output_size = plaintext_size;
    status = 0;

cleanup:
    rin_siv_zero(&cmac_aes, sizeof(cmac_aes));
    rin_siv_zero(&ctr_aes, sizeof(ctr_aes));
    rin_siv_zero(expected, sizeof(expected));
    return status;
}
