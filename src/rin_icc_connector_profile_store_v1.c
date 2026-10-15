/* SPDX-License-Identifier: MIT */
#include "rin_icc_connector_profile_store_v1.h"
#include "rin_icc_display_transform_v1.h"
#include "rin_icc_lut_transform_v1.h"

#include <stdint.h>

static void store_zero(void* pointer, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)pointer;
    if (!pointer) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static void store_copy(uint8_t* destination, const uint8_t* source,
                       uint32_t size)
{
    volatile uint8_t* out = (volatile uint8_t*)destination;
    const volatile uint8_t* in = (const volatile uint8_t*)source;
    while (size-- != 0u) *out++ = *in++;
}

static int store_all_zero(const void* pointer, uint32_t size)
{
    const volatile uint8_t* bytes = (const volatile uint8_t*)pointer;
    uint8_t value = 0u;
    if (!pointer) return 0;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static int store_overlap(const void* first, uint32_t first_size,
                         const void* second, uint32_t second_size)
{
    uintptr_t first_start = (uintptr_t)first;
    uintptr_t second_start = (uintptr_t)second;
    if (first_size == 0u || second_size == 0u) return 0;
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

static void store_lock(RinIccConnectorProfileStoreV1* store)
{
    while (__atomic_exchange_n(&store->lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
#if defined(__i386__) || defined(__x86_64__)
        __asm__ volatile("pause");
#endif
    }
}

static void store_unlock(RinIccConnectorProfileStoreV1* store)
{
    __atomic_store_n(&store->lock, 0u, __ATOMIC_RELEASE);
}

static int store_valid(const RinIccConnectorProfileStoreV1* store)
{
    if (!store || store->magic != RIN_ICC_CONNECTOR_PROFILE_STORE_MAGIC ||
        store->initialized == 0u || !store->scratch ||
        store->scratch_capacity < RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES)
        return 0;
    for (uint32_t index = 0u;
         index < RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS; ++index) {
        const RinIccConnectorProfileStoreSlotV1* slot = &store->slots[index];
        if (slot->occupied > 1u ||
            (slot->occupied != 0u &&
             (slot->connector_id == 0u || slot->profile_id == 0u ||
              slot->generation == 0u ||
              slot->profile_size == 0u ||
              slot->profile_size > RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES ||
              (slot->kind != RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX &&
               slot->kind != RIN_ICC_CONNECTOR_PROFILE_STORE_LUT))))
            return 0;
        for (uint32_t other = 0u; other < index; ++other)
            if (slot->occupied != 0u && store->slots[other].occupied != 0u &&
                slot->connector_id == store->slots[other].connector_id)
                return 0;
    }
    return 1;
}

static int store_find(const RinIccConnectorProfileStoreV1* store,
                      uint64_t connector_id)
{
    for (uint32_t index = 0u;
         index < RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS; ++index)
        if (store->slots[index].occupied != 0u &&
            store->slots[index].connector_id == connector_id)
            return (int)index;
    return -1;
}

static int store_free(const RinIccConnectorProfileStoreV1* store)
{
    for (uint32_t index = 0u;
         index < RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_CONNECTORS; ++index)
        if (store->slots[index].occupied == 0u &&
            store->slots[index].generation != UINT32_MAX)
            return (int)index;
    return -1;
}

static RinIccConnectorProfileStoreResult store_map_result(int result,
                                                          uint32_t kind)
{
    if (kind == RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX) {
        switch ((RinIccDisplayProfileResult)result) {
            case RIN_ICC_DISPLAY_PROFILE_OK:
                return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
            case RIN_ICC_DISPLAY_PROFILE_MALFORMED:
                return RIN_ICC_CONNECTOR_PROFILE_STORE_MALFORMED;
            case RIN_ICC_DISPLAY_PROFILE_UNSUPPORTED:
                return RIN_ICC_CONNECTOR_PROFILE_STORE_UNSUPPORTED;
            case RIN_ICC_DISPLAY_PROFILE_LIMIT_EXCEEDED:
                return RIN_ICC_CONNECTOR_PROFILE_STORE_LIMIT_EXCEEDED;
            default:
                return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
        }
    }
    switch ((RinIccLutProfileResult)result) {
        case RIN_ICC_LUT_PROFILE_OK:
            return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
        case RIN_ICC_LUT_PROFILE_MALFORMED:
            return RIN_ICC_CONNECTOR_PROFILE_STORE_MALFORMED;
        case RIN_ICC_LUT_PROFILE_UNSUPPORTED:
            return RIN_ICC_CONNECTOR_PROFILE_STORE_UNSUPPORTED;
        case RIN_ICC_LUT_PROFILE_LIMIT_EXCEEDED:
            return RIN_ICC_CONNECTOR_PROFILE_STORE_LIMIT_EXCEEDED;
        default:
            return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
}

static RinIccConnectorProfileStoreResult store_map_transform_result(
    int result)
{
    if (result == 0) return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
    if (result == -2) return RIN_ICC_CONNECTOR_PROFILE_STORE_MALFORMED;
    if (result == -3) return RIN_ICC_CONNECTOR_PROFILE_STORE_UNSUPPORTED;
    if (result == -4) return RIN_ICC_CONNECTOR_PROFILE_STORE_LIMIT_EXCEEDED;
    return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
}

static void store_record(const RinIccConnectorProfileStoreSlotV1* slot,
                         RinIccConnectorProfileStoreRecordV1* record)
{
    store_zero(record, sizeof(*record));
    record->abi_version = RIN_ICC_CONNECTOR_PROFILE_STORE_ABI_VERSION;
    record->struct_size = sizeof(*record);
    record->connector_id = slot->connector_id;
    record->profile_id = slot->profile_id;
    record->generation = slot->generation;
    record->kind = slot->kind;
    record->profile_size = slot->profile_size;
}

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_init(
    RinIccConnectorProfileStoreV1* store,
    const RinIccConnectorProfileStoreConfigV1* config)
{
    if (!store || !config || config->abi_version !=
        RIN_ICC_CONNECTOR_PROFILE_STORE_ABI_VERSION ||
        config->struct_size != sizeof(*config) || !config->scratch ||
        config->scratch_capacity < RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES ||
        !store_all_zero(config->reserved, sizeof(config->reserved)) ||
        store_overlap(store, sizeof(*store), config->scratch,
                      config->scratch_capacity))
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    store_zero(store, sizeof(*store));
    store->magic = RIN_ICC_CONNECTOR_PROFILE_STORE_MAGIC;
    store->scratch = config->scratch;
    store->scratch_capacity = config->scratch_capacity;
    store->initialized = 1u;
    store_zero(config->scratch, config->scratch_capacity);
    return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
}

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_install(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t kind, uint32_t expected_generation,
    const uint8_t* profile, uint32_t profile_size,
    RinIccConnectorProfileStoreRecordV1* record_out)
{
    RinIccConnectorProfileStoreResult result;
    int index;
    uint32_t generation;
    if (record_out) store_zero(record_out, sizeof(*record_out));
    if (!store || !profile || !record_out || connector_id == 0u ||
        profile_id == 0u || profile_size == 0u ||
        profile_size > RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES ||
        (kind != RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX &&
         kind != RIN_ICC_CONNECTOR_PROFILE_STORE_LUT) ||
        store_overlap(profile, profile_size, record_out, sizeof(*record_out)))
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    store_lock(store);
    if (!store_valid(store)) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    if (store_overlap(profile, profile_size, store, sizeof(*store)) ||
        store_overlap(profile, profile_size, store->scratch,
                      store->scratch_capacity) ||
        store_overlap(record_out, sizeof(*record_out), store,
                      sizeof(*store))) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    index = store_find(store, connector_id);
    if (index < 0) {
        if (expected_generation != 0u || (index = store_free(store)) < 0) {
            store_unlock(store);
            return expected_generation != 0u
                ? RIN_ICC_CONNECTOR_PROFILE_STORE_STALE
                : RIN_ICC_CONNECTOR_PROFILE_STORE_BUSY;
        }
    } else {
        if (expected_generation == 0u ||
            expected_generation != store->slots[index].generation) {
            store_unlock(store);
            return RIN_ICC_CONNECTOR_PROFILE_STORE_STALE;
        }
        if (store->slots[index].generation == UINT32_MAX) {
            store_unlock(store);
            return RIN_ICC_CONNECTOR_PROFILE_STORE_BUSY;
        }
    }
    if (kind == RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX) {
        RinIccDisplayProfileV1 parsed;
        result = store_map_result(rin_icc_display_profile_admit(
            profile, profile_size, store->scratch, store->scratch_capacity,
            &parsed), kind);
    } else {
        RinIccLutProfileV1 parsed;
        result = store_map_result(rin_icc_lut_profile_admit(
            profile, profile_size, store->scratch, store->scratch_capacity,
            &parsed), kind);
    }
    if (result != RIN_ICC_CONNECTOR_PROFILE_STORE_OK) {
        store_zero(store->scratch, profile_size);
        store_unlock(store);
        return result;
    }
    if (store->slots[index].generation == UINT32_MAX) {
        store_zero(store->scratch, profile_size);
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_BUSY;
    }
    generation = store->slots[index].generation + 1u;
    store_copy(store->profiles[index], store->scratch, profile_size);
    store_zero(store->profiles[index] + profile_size,
               RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES - profile_size);
    store_zero(store->scratch, profile_size);
    store->slots[index].connector_id = connector_id;
    store->slots[index].profile_id = profile_id;
    store->slots[index].generation = generation;
    store->slots[index].kind = kind;
    store->slots[index].profile_size = profile_size;
    store->slots[index].occupied = 1u;
    store_record(&store->slots[index], record_out);
    store_unlock(store);
    return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
}

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_read(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation, uint8_t* profile_out,
    uint32_t profile_capacity, uint32_t* profile_size_out,
    RinIccConnectorProfileStoreRecordV1* record_out)
{
    int index;
    uint32_t size;
    if (profile_size_out) *profile_size_out = 0u;
    if (record_out) store_zero(record_out, sizeof(*record_out));
    if (!store || !profile_out || !profile_size_out || !record_out ||
        connector_id == 0u || profile_id == 0u || expected_generation == 0u)
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    if (store_overlap(profile_out, profile_capacity, store,
                      sizeof(*store)) ||
        store_overlap(record_out, sizeof(*record_out), store,
                      sizeof(*store)) ||
        store_overlap(profile_out, profile_capacity, record_out,
                      sizeof(*record_out)))
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    store_lock(store);
    if (!store_valid(store)) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    index = store_find(store, connector_id);
    if (index < 0) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_NOT_FOUND;
    }
    if (store->slots[index].profile_id != profile_id ||
        store->slots[index].generation != expected_generation) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_STALE;
    }
    size = store->slots[index].profile_size;
    if (profile_capacity < size) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_LIMIT_EXCEEDED;
    }
    store_copy(profile_out, store->profiles[index], size);
    *profile_size_out = size;
    store_record(&store->slots[index], record_out);
    store_unlock(store);
    return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
}

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_apply(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation, const uint16_t input[3],
    uint16_t output[3])
{
    RinIccConnectorProfileStoreResult result;
    RinIccConnectorProfileStoreSlotV1* slot;
    RinIccConnectorProfileStoreKind kind;
    uint32_t profile_size;
    int index;
    if (!output) return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    if (!store || !input || connector_id == 0u || profile_id == 0u ||
        expected_generation == 0u ||
        store_overlap(input, sizeof(uint16_t) * 3u, output,
                      sizeof(uint16_t) * 3u) ||
        store_overlap(output, sizeof(uint16_t) * 3u, store,
                      sizeof(*store)) ||
        (store->scratch &&
         (store_overlap(input, sizeof(uint16_t) * 3u, store->scratch,
                        store->scratch_capacity) ||
          store_overlap(output, sizeof(uint16_t) * 3u, store->scratch,
                        store->scratch_capacity))))
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    store_zero(output, sizeof(uint16_t) * 3u);
    store_lock(store);
    if (!store_valid(store)) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    if (store_overlap(input, sizeof(uint16_t) * 3u, store,
                      sizeof(*store)) ||
        store_overlap(output, sizeof(uint16_t) * 3u, store->scratch,
                      store->scratch_capacity)) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    index = store_find(store, connector_id);
    if (index < 0) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_NOT_FOUND;
    }
    slot = &store->slots[index];
    if (slot->profile_id != profile_id ||
        slot->generation != expected_generation) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_STALE;
    }
    profile_size = slot->profile_size;
    kind = (RinIccConnectorProfileStoreKind)slot->kind;
    if (kind == RIN_ICC_CONNECTOR_PROFILE_STORE_MATRIX) {
        RinIccDisplayProfileV1 parsed;
        result = store_map_result(rin_icc_display_profile_admit(
            store->profiles[index], profile_size, store->scratch,
            store->scratch_capacity, &parsed), kind);
        if (result == RIN_ICC_CONNECTOR_PROFILE_STORE_OK) {
            result = store_map_transform_result(
                rin_icc_display_transform_apply_v1(
                    store->scratch, profile_size, &parsed, input, output));
        }
    } else {
        RinIccLutProfileV1 parsed;
        result = store_map_result(rin_icc_lut_profile_admit(
            store->profiles[index], profile_size, store->scratch,
            store->scratch_capacity, &parsed), kind);
        if (result == RIN_ICC_CONNECTOR_PROFILE_STORE_OK) {
            result = store_map_transform_result(
                rin_icc_lut_transform_apply_v1(
                    store->scratch, profile_size, &parsed, input, output));
        }
    }
    store_zero(store->scratch, profile_size);
    store_unlock(store);
    return result;
}

RinIccConnectorProfileStoreResult
rin_icc_connector_profile_store_remove(
    RinIccConnectorProfileStoreV1* store, uint64_t connector_id,
    uint64_t profile_id, uint32_t expected_generation)
{
    int index;
    if (!store || connector_id == 0u || profile_id == 0u ||
        expected_generation == 0u)
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    store_lock(store);
    if (!store_valid(store)) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_INVALID_ARGUMENT;
    }
    index = store_find(store, connector_id);
    if (index < 0) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_NOT_FOUND;
    }
    if (store->slots[index].profile_id != profile_id ||
        store->slots[index].generation != expected_generation) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_STALE;
    }
    if (store->slots[index].generation == UINT32_MAX) {
        store_unlock(store);
        return RIN_ICC_CONNECTOR_PROFILE_STORE_BUSY;
    }
    store_zero(store->profiles[index],
               RIN_ICC_CONNECTOR_PROFILE_STORE_MAX_PROFILE_BYTES);
    store->slots[index].connector_id = 0u;
    store->slots[index].profile_id = 0u;
    store->slots[index].kind = 0u;
    store->slots[index].profile_size = 0u;
    store->slots[index].generation++;
    store->slots[index].occupied = 0u;
    store_unlock(store);
    return RIN_ICC_CONNECTOR_PROFILE_STORE_OK;
}
