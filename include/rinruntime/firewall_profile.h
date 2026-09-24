/* SPDX-License-Identifier: MIT */
/* Public, bounded network-profile model and value operations. */
#ifndef RIN_FIREWALL_PROFILE_H
#define RIN_FIREWALL_PROFILE_H

#include <stdint.h>

#include <rin/firewall/profile_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_firewall_profile_table_init(RinFirewallProfileTableV1* table);
int rin_firewall_profile_table_validate(
    const RinFirewallProfileTableV1* table);
int rin_firewall_profile_set(
    RinFirewallProfileTableV1* table, uint32_t interface_id, uint8_t profile,
    const uint8_t* identity, uint32_t identity_size,
    uint64_t expected_generation, uint64_t* new_generation);
int rin_firewall_profile_remove(
    RinFirewallProfileTableV1* table, uint32_t interface_id,
    uint64_t expected_generation, uint64_t* new_generation);
uint8_t rin_firewall_profile_lookup(
    const RinFirewallProfileTableV1* table, uint32_t interface_id);

#ifdef __cplusplus
}
#endif

#endif /* RIN_FIREWALL_PROFILE_H */
