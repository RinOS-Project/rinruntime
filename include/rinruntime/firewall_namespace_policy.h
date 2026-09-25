/* SPDX-License-Identifier: MIT */
/* Portable namespace-scoped Firewall policy helpers. */
#ifndef RINRUNTIME_FIREWALL_NAMESPACE_POLICY_H
#define RINRUNTIME_FIREWALL_NAMESPACE_POLICY_H

#include <stdint.h>

#include <rin/firewall/abi.h>

#define RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID UINT64_C(1)
#define RIN_FIREWALL_NAMESPACE_POLICY_DEFAULT_PRIORITY \
    (UINT32_MAX - UINT32_C(1))
#define RIN_FIREWALL_NAMESPACE_POLICY_RULE_ID_BASE \
    UINT64_C(0x4E53000000000000)

/* A default action is represented by a namespace-scoped policy guard at a
 * reserved last priority. Specific NetworkPolicy guard rules therefore win
 * first, and host-owned application rules never become container defaults. */
static inline int rin_firewall_namespace_policy_default_rule_valid(
    const RinFirewallRuleV1* rule)
{
    uint32_t index;
    const uint16_t required_flags =
        RIN_FIREWALL_RULE_FLAG_ENABLED |
        RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE |
        RIN_FIREWALL_RULE_FLAG_POLICY_GUARD;
    if (rule == 0 ||
        rule->id < RIN_FIREWALL_NAMESPACE_POLICY_RULE_ID_BASE ||
        rule->id >= RIN_FIREWALL_NAMESPACE_POLICY_RULE_ID_BASE +
                        RIN_FIREWALL_MAX_RULES ||
        rule->priority != RIN_FIREWALL_NAMESPACE_POLICY_DEFAULT_PRIORITY ||
        rule->rule_class != RIN_FIREWALL_RULE_CLASS_CONTAINER ||
        rule->flags != required_flags ||
        rule->namespace_id <= RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID ||
        rin_firewall_container_rule_owner_id(rule) ==
            RIN_FIREWALL_CONTAINER_OWNER_UNKNOWN ||
        rule->direction < RIN_FIREWALL_DIRECTION_INPUT ||
        rule->direction > RIN_FIREWALL_DIRECTION_FORWARD ||
        (rule->action != RIN_FIREWALL_ACTION_ALLOW &&
         rule->action != RIN_FIREWALL_ACTION_DROP &&
         rule->action != RIN_FIREWALL_ACTION_REJECT) ||
        rule->family != RIN_FIREWALL_FAMILY_ANY ||
        rule->protocol != RIN_FIREWALL_PROTOCOL_ANY ||
        rule->source_prefix_len != 0u ||
        rule->destination_prefix_len != 0u ||
        rule->source_port_first != 0u || rule->source_port_last != 0u ||
        rule->destination_port_first != 0u ||
        rule->destination_port_last != 0u || rule->icmp_type != 0u ||
        rule->icmp_code != 0u || rule->reserved0 != 0u ||
        rule->interface_id != 0u ||
        rule->network_profile != RIN_FIREWALL_PROFILE_ANY ||
        rule->connection_state_mask != 0u)
        return 0;
    for (index = 0u; index < sizeof(rule->source_address); ++index)
        if (rule->source_address[index] != 0u ||
            rule->destination_address[index] != 0u)
            return 0;
    for (index = 0u; index < sizeof(rule->application_id); ++index)
        if (rule->application_id[index] != 0u) return 0;
    return 1;
}

#ifdef __cplusplus
extern "C" {
#endif

/* Add or update one direction's default for a container namespace. The
 * namespace policy is an owned container rule and is failure-atomic. */
int rin_firewall_namespace_policy_set_default_action(
    RinFirewallRuleSetV1* set, uint64_t namespace_id, uint32_t owner_id,
    uint8_t direction, uint8_t action);

/* Remove this owner's namespace default guards. Returns NOT_FOUND when the
 * namespace has no defaults owned by owner_id. */
int rin_firewall_namespace_policy_remove_defaults(
    RinFirewallRuleSetV1* set, uint64_t namespace_id, uint32_t owner_id);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FIREWALL_NAMESPACE_POLICY_H */
