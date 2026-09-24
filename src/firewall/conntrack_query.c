/* SPDX-License-Identifier: MIT */

#include <rinruntime/firewall_conntrack.h>

#include <stddef.h>

static void conntrack_query_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (memory == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int conntrack_query_bytes_zero(const uint8_t* bytes, size_t size)
{
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index)
        if (bytes[index] != 0u) return 0;
    return 1;
}

static int conntrack_query_entry_valid(
    const RinFirewallConntrackEntryV1* entry)
{
    if (entry == NULL || entry->active > 1u) return 0;
    if (entry->active == 0u)
        return conntrack_query_bytes_zero((const uint8_t*)entry,
                                          sizeof(*entry));
    return entry->namespace_id != 0u && entry->interface_id != 0u &&
           (entry->family == RIN_FIREWALL_FAMILY_IPV4 ||
            entry->family == RIN_FIREWALL_FAMILY_IPV6) &&
           (entry->protocol == RIN_FIREWALL_PROTOCOL_TCP ||
            entry->protocol == RIN_FIREWALL_PROTOCOL_UDP ||
            entry->protocol == RIN_FIREWALL_PROTOCOL_ICMP ||
            entry->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) &&
           entry->state != RIN_FIREWALL_STATE_UNTRACKED &&
           (entry->state == RIN_FIREWALL_STATE_NEW ||
            entry->state == RIN_FIREWALL_STATE_ESTABLISHED ||
            entry->state == RIN_FIREWALL_STATE_RELATED) &&
           entry->directions_seen != 0u &&
           (entry->directions_seen & ~UINT32_C(3)) == 0u &&
           entry->tcp_fin_directions <= 3u &&
           conntrack_query_bytes_zero(entry->reserved0,
                                      sizeof(entry->reserved0)) &&
           conntrack_query_bytes_zero(entry->reserved1,
                                      sizeof(entry->reserved1));
}

static int conntrack_query_valid(const RinFirewallConntrackQueryV1* query)
{
    if (query == NULL || query->struct_size != sizeof(*query) ||
        query->version != RIN_FIREWALL_ABI_VERSION || query->reserved0 != 0u ||
        query->reserved2 != 0u ||
        query->cursor > RIN_FIREWALL_CONNTRACK_MAX_ENTRIES)
        return 0;
    if (!conntrack_query_bytes_zero(query->reserved1,
                                    sizeof(query->reserved1)))
        return 0;
    if (query->family != RIN_FIREWALL_FAMILY_ANY &&
        query->family != RIN_FIREWALL_FAMILY_IPV4 &&
        query->family != RIN_FIREWALL_FAMILY_IPV6)
        return 0;
    if (query->protocol != RIN_FIREWALL_PROTOCOL_ANY &&
        query->protocol != RIN_FIREWALL_PROTOCOL_TCP &&
        query->protocol != RIN_FIREWALL_PROTOCOL_UDP &&
        query->protocol != RIN_FIREWALL_PROTOCOL_ICMP &&
        query->protocol != RIN_FIREWALL_PROTOCOL_ICMPV6)
        return 0;
    return 1;
}

static int conntrack_query_snapshot_valid(
    const RinFirewallConntrackEntryV1 entries[
        RIN_FIREWALL_CONNTRACK_MAX_ENTRIES])
{
    uint32_t index;
    if (entries == NULL) return 0;
    for (index = 0u; index < RIN_FIREWALL_CONNTRACK_MAX_ENTRIES; ++index)
        if (!conntrack_query_entry_valid(&entries[index])) return 0;
    return 1;
}

static int conntrack_query_ranges_overlap(
    const void* first, size_t first_size, const void* second,
    size_t second_size)
{
    uintptr_t first_start;
    uintptr_t second_start;
    if (first == NULL || second == NULL || first_size == 0u ||
        second_size == 0u)
        return 0;
    first_start = (uintptr_t)first;
    second_start = (uintptr_t)second;
    if (first_start > UINTPTR_MAX - first_size ||
        second_start > UINTPTR_MAX - second_size)
        return 1;
    return first_start < second_start + second_size &&
           second_start < first_start + first_size;
}

static int conntrack_query_matches(
    const RinFirewallConntrackEntryV1* entry,
    const RinFirewallConntrackQueryV1* query)
{
    return entry != NULL && query != NULL && entry->active != 0u &&
           (query->namespace_id == 0u ||
            query->namespace_id == entry->namespace_id) &&
           (query->interface_id == 0u ||
            query->interface_id == entry->interface_id) &&
           (query->family == RIN_FIREWALL_FAMILY_ANY ||
            query->family == entry->family) &&
           (query->protocol == RIN_FIREWALL_PROTOCOL_ANY ||
            query->protocol == entry->protocol);
}

int rin_firewall_conntrack_snapshot_query(
    const RinFirewallConntrackEntryV1 entries[
        RIN_FIREWALL_CONNTRACK_MAX_ENTRIES],
    uint64_t snapshot_generation,
    const RinFirewallConntrackQueryV1* query,
    RinFirewallConntrackEntryV1* output, uint32_t capacity,
    uint32_t* returned, uint32_t* next_cursor, uint64_t* generation)
{
    uint32_t index;
    uint32_t copied = 0u;

    if (returned != NULL) *returned = 0u;
    if (next_cursor != NULL) *next_cursor = 0u;
    if (generation != NULL) *generation = 0u;
    if (returned == NULL || next_cursor == NULL || generation == NULL ||
        (capacity != 0u && output == NULL))
        return RIN_FIREWALL_INVALID_ARGUMENT;
    if (capacity > RIN_FIREWALL_CONNTRACK_MAX_ENTRIES)
        return RIN_FIREWALL_CAPACITY;
    if (entries != NULL && capacity != 0u &&
        conntrack_query_ranges_overlap(
            entries,
            sizeof(RinFirewallConntrackEntryV1) *
                RIN_FIREWALL_CONNTRACK_MAX_ENTRIES,
            output, sizeof(*output) * capacity))
        return RIN_FIREWALL_INVALID_ARGUMENT;
    if (output != NULL)
        for (index = 0u; index < capacity; ++index)
            conntrack_query_zero(&output[index], sizeof(*output));
    if (snapshot_generation == 0u ||
        !conntrack_query_snapshot_valid(entries))
        return RIN_FIREWALL_MALFORMED;
    if (!conntrack_query_valid(query)) return RIN_FIREWALL_ABI_MISMATCH;

    *generation = snapshot_generation;
    for (index = query->cursor;
         index < RIN_FIREWALL_CONNTRACK_MAX_ENTRIES && copied < capacity;
         ++index) {
        if (!conntrack_query_matches(&entries[index], query)) continue;
        output[copied++] = entries[index];
    }
    *returned = copied;
    *next_cursor = index;
    return RIN_FIREWALL_OK;
}
