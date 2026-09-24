/* SPDX-License-Identifier: MIT */
/* Read-only query helper for caller-owned Firewall connection snapshots. */
#ifndef RINRUNTIME_FIREWALL_CONNTRACK_H
#define RINRUNTIME_FIREWALL_CONNTRACK_H

#include <stdint.h>

#include <rin/firewall/abi.h>
#include <rin/firewall/conntrack_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Filters and paginates an immutable, detached snapshot. This function has no
 * access to kernel connection state; a private service must obtain and
 * authorize the snapshot before calling it. The entries array always has
 * RIN_FIREWALL_CONNTRACK_MAX_ENTRIES elements. The output range must not
 * overlap the snapshot. Output records are cleared on failure when capacity
 * is valid, bounded, and non-overlapping; count/cursor/generation outputs are
 * cleared on every call. */
int rin_firewall_conntrack_snapshot_query(
    const RinFirewallConntrackEntryV1 entries[
        RIN_FIREWALL_CONNTRACK_MAX_ENTRIES],
    uint64_t snapshot_generation,
    const RinFirewallConntrackQueryV1* query,
    RinFirewallConntrackEntryV1* output, uint32_t capacity,
    uint32_t* returned, uint32_t* next_cursor, uint64_t* generation);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FIREWALL_CONNTRACK_H */
