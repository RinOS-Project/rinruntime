/* SPDX-License-Identifier: MIT */

#include <rinruntime/firewall_profile.h>

#include <stddef.h>

static void profile_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (memory == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static void profile_copy(void* destination, const void* source, size_t size)
{
    uint8_t* out = (uint8_t*)destination;
    const uint8_t* in = (const uint8_t*)source;
    size_t index;
    if (destination == NULL || source == NULL) return;
    for (index = 0u; index < size; ++index) out[index] = in[index];
}

static int profile_valid(uint8_t profile)
{
    return profile == RIN_FIREWALL_PROFILE_PUBLIC ||
           profile == RIN_FIREWALL_PROFILE_PRIVATE ||
           profile == RIN_FIREWALL_PROFILE_TRUSTED;
}

static int profile_bytes_zero(const uint8_t* bytes, size_t size)
{
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index)
        if (bytes[index] != 0u) return 0;
    return 1;
}

static int profile_identity_valid(const uint8_t* identity,
                                  uint32_t identity_size)
{
    if (identity == NULL || identity_size == 0u ||
        identity_size > RIN_FIREWALL_PROFILE_IDENTITY_BYTES)
        return 0;
    return !profile_bytes_zero(identity, identity_size);
}

static int profile_find(const RinFirewallProfileTableV1* table,
                        uint32_t interface_id)
{
    uint32_t index;
    for (index = 0u; index < table->entry_count; ++index)
        if (table->entries[index].interface_id == interface_id)
            return (int)index;
    return -1;
}

int rin_firewall_profile_table_init(RinFirewallProfileTableV1* table)
{
    if (table == NULL) return RIN_FIREWALL_INVALID_ARGUMENT;
    profile_zero(table, sizeof(*table));
    table->struct_size = sizeof(*table);
    table->version = RIN_FIREWALL_ABI_VERSION;
    table->generation = 1u;
    return RIN_FIREWALL_OK;
}

int rin_firewall_profile_table_validate(
    const RinFirewallProfileTableV1* table)
{
    uint32_t index;
    if (table == NULL) return RIN_FIREWALL_INVALID_ARGUMENT;
    if (table->struct_size != sizeof(*table) ||
        table->version != RIN_FIREWALL_ABI_VERSION ||
        table->reserved0 != 0u || table->reserved1 != 0u ||
        table->generation == 0u ||
        table->entry_count > RIN_FIREWALL_PROFILE_MAX_INTERFACES)
        return RIN_FIREWALL_MALFORMED;
    for (index = 0u; index < table->entry_count; ++index) {
        uint32_t other;
        const RinFirewallProfileEntryV1* entry = &table->entries[index];
        if (entry->interface_id == 0u || !profile_valid(entry->profile) ||
            entry->generation == 0u ||
            !profile_bytes_zero(entry->reserved0, sizeof(entry->reserved0)) ||
            !profile_identity_valid(entry->identity,
                                     RIN_FIREWALL_PROFILE_IDENTITY_BYTES))
            return RIN_FIREWALL_MALFORMED;
        for (other = 0u; other < index; ++other)
            if (table->entries[other].interface_id == entry->interface_id)
                return RIN_FIREWALL_DUPLICATE;
    }
    for (; index < RIN_FIREWALL_PROFILE_MAX_INTERFACES; ++index)
        if (!profile_bytes_zero((const uint8_t*)&table->entries[index],
                                sizeof(table->entries[index])))
            return RIN_FIREWALL_MALFORMED;
    return RIN_FIREWALL_OK;
}

int rin_firewall_profile_set(
    RinFirewallProfileTableV1* table, uint32_t interface_id, uint8_t profile,
    const uint8_t* identity, uint32_t identity_size,
    uint64_t expected_generation, uint64_t* new_generation)
{
    RinFirewallProfileTableV1 candidate;
    int output_aliases_generation;
    int index;
    int result;
    if (table == NULL || new_generation == NULL || interface_id == 0u)
        return RIN_FIREWALL_INVALID_ARGUMENT;
    output_aliases_generation = new_generation == &table->generation;
    if (!output_aliases_generation) *new_generation = 0u;
    if (!profile_valid(profile) ||
        !profile_identity_valid(identity, identity_size))
        return RIN_FIREWALL_MALFORMED;
    result = rin_firewall_profile_table_validate(table);
    if (result != RIN_FIREWALL_OK) return result;
    if (expected_generation != table->generation)
        return RIN_FIREWALL_NOT_FOUND;
    if (table->generation == UINT64_MAX)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    candidate = *table;
    index = profile_find(&candidate, interface_id);
    if (index < 0) {
        if (candidate.entry_count == RIN_FIREWALL_PROFILE_MAX_INTERFACES)
            return RIN_FIREWALL_CAPACITY;
        index = (int)candidate.entry_count++;
        profile_zero(&candidate.entries[index],
                     sizeof(candidate.entries[index]));
        candidate.entries[index].interface_id = interface_id;
    }
    candidate.generation++;
    candidate.entries[index].profile = profile;
    candidate.entries[index].generation = candidate.generation;
    profile_zero(candidate.entries[index].identity,
                 sizeof(candidate.entries[index].identity));
    profile_copy(candidate.entries[index].identity, identity, identity_size);
    result = rin_firewall_profile_table_validate(&candidate);
    if (result != RIN_FIREWALL_OK) return result;
    *table = candidate;
    if (!output_aliases_generation) *new_generation = candidate.generation;
    return RIN_FIREWALL_OK;
}

int rin_firewall_profile_remove(
    RinFirewallProfileTableV1* table, uint32_t interface_id,
    uint64_t expected_generation, uint64_t* new_generation)
{
    RinFirewallProfileTableV1 candidate;
    int output_aliases_generation;
    int index;
    int result;
    if (table == NULL || new_generation == NULL || interface_id == 0u)
        return RIN_FIREWALL_INVALID_ARGUMENT;
    output_aliases_generation = new_generation == &table->generation;
    if (!output_aliases_generation) *new_generation = 0u;
    result = rin_firewall_profile_table_validate(table);
    if (result != RIN_FIREWALL_OK) return result;
    if (expected_generation != table->generation)
        return RIN_FIREWALL_NOT_FOUND;
    if (table->generation == UINT64_MAX)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    candidate = *table;
    index = profile_find(&candidate, interface_id);
    if (index < 0) return RIN_FIREWALL_NOT_FOUND;
    while ((uint32_t)index + 1u < candidate.entry_count) {
        candidate.entries[index] = candidate.entries[index + 1];
        ++index;
    }
    --candidate.entry_count;
    profile_zero(&candidate.entries[candidate.entry_count],
                 sizeof(candidate.entries[candidate.entry_count]));
    ++candidate.generation;
    result = rin_firewall_profile_table_validate(&candidate);
    if (result != RIN_FIREWALL_OK) return result;
    *table = candidate;
    if (!output_aliases_generation) *new_generation = candidate.generation;
    return RIN_FIREWALL_OK;
}

uint8_t rin_firewall_profile_lookup(
    const RinFirewallProfileTableV1* table, uint32_t interface_id)
{
    int index;
    if (interface_id == 0u ||
        rin_firewall_profile_table_validate(table) != RIN_FIREWALL_OK)
        return RIN_FIREWALL_PROFILE_PUBLIC;
    index = profile_find(table, interface_id);
    if (index < 0) return RIN_FIREWALL_PROFILE_PUBLIC;
    return table->entries[index].profile;
}
