/* SPDX-License-Identifier: MIT */

#include <rinruntime/firewall_namespace_policy.h>

static void namespace_policy_zero(void* memory, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)memory;
    if (bytes == 0) return;
    while (size-- != 0u) *bytes++ = 0u;
}

int rin_firewall_namespace_policy_set_default_action(
    RinFirewallRuleSetV1* set, uint64_t namespace_id, uint32_t owner_id,
    uint8_t direction, uint8_t action)
{
    RinFirewallRuleV1 rule;
    uint32_t index;
    uint32_t id_slot;
    int id_available;
    int result;
    if (set == 0 || namespace_id <= RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID ||
        owner_id == RIN_FIREWALL_CONTAINER_OWNER_UNKNOWN ||
        direction < RIN_FIREWALL_DIRECTION_INPUT ||
        direction > RIN_FIREWALL_DIRECTION_FORWARD ||
        (action != RIN_FIREWALL_ACTION_ALLOW &&
         action != RIN_FIREWALL_ACTION_DROP &&
         action != RIN_FIREWALL_ACTION_REJECT))
        return RIN_FIREWALL_INVALID_ARGUMENT;
    result = rin_firewall_rule_set_validate(set);
    if (result != RIN_FIREWALL_OK) return result;

    for (index = 0u; index < set->rule_count; ++index) {
        RinFirewallRuleV1* current = &set->rules[index];
        if (!rin_firewall_namespace_policy_default_rule_valid(current) ||
            current->namespace_id != namespace_id ||
            current->direction != direction)
            continue;
        if (rin_firewall_container_rule_owner_id(current) != owner_id)
            return RIN_FIREWALL_ACCESS_DENIED;
        if (current->action == action) return RIN_FIREWALL_OK;
        if (set->generation == UINT64_MAX) return RIN_FIREWALL_GENERATION_EXHAUSTED;
        current->action = action;
        ++set->generation;
        return RIN_FIREWALL_OK;
    }

    if (set->rule_count >= RIN_FIREWALL_MAX_RULES)
        return RIN_FIREWALL_CAPACITY;
    id_available = 0;
    for (id_slot = 0u; id_slot < RIN_FIREWALL_MAX_RULES; ++id_slot) {
        uint64_t id = RIN_FIREWALL_NAMESPACE_POLICY_RULE_ID_BASE + id_slot;
        for (index = 0u; index < set->rule_count; ++index)
            if (set->rules[index].id == id) break;
        if (index == set->rule_count) {
            id_available = 1;
            break;
        }
    }
    if (!id_available) return RIN_FIREWALL_CAPACITY;

    namespace_policy_zero(&rule, sizeof(rule));
    rule.struct_size = sizeof(rule);
    rule.version = RIN_FIREWALL_ABI_VERSION;
    rule.flags = RIN_FIREWALL_RULE_FLAG_ENABLED |
                 RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE |
                 RIN_FIREWALL_RULE_FLAG_POLICY_GUARD;
    rule.id = RIN_FIREWALL_NAMESPACE_POLICY_RULE_ID_BASE + id_slot;
    rule.priority = RIN_FIREWALL_NAMESPACE_POLICY_DEFAULT_PRIORITY;
    rule.rule_class = RIN_FIREWALL_RULE_CLASS_CONTAINER;
    rule.direction = direction;
    rule.action = action;
    rule.family = RIN_FIREWALL_FAMILY_ANY;
    rule.protocol = RIN_FIREWALL_PROTOCOL_ANY;
    rule.namespace_id = namespace_id;
    rule.network_profile = RIN_FIREWALL_PROFILE_ANY;
    rule.name[0] = 'n';
    rule.name[1] = 's';
    rule.name[2] = '-';
    rule.name[3] = 'd';
    rule.name[4] = 'e';
    rule.name[5] = 'f';
    rule.name[6] = 'a';
    rule.name[7] = 'u';
    rule.name[8] = 'l';
    rule.name[9] = 't';
    if (!rin_firewall_container_rule_set_owner_id(&rule, owner_id))
        return RIN_FIREWALL_INVALID_ARGUMENT;
    return rin_firewall_rule_set_add(set, &rule);
}

int rin_firewall_namespace_policy_remove_defaults(
    RinFirewallRuleSetV1* set, uint64_t namespace_id, uint32_t owner_id)
{
    uint64_t rule_ids[RIN_FIREWALL_DIRECTION_COUNT];
    uint32_t rule_count = 0u;
    uint32_t index;
    int result;
    if (set == 0 || namespace_id <= RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID ||
        owner_id == RIN_FIREWALL_CONTAINER_OWNER_UNKNOWN)
        return RIN_FIREWALL_INVALID_ARGUMENT;
    result = rin_firewall_rule_set_validate(set);
    if (result != RIN_FIREWALL_OK) return result;
    for (index = 0u; index < set->rule_count; ++index) {
        const RinFirewallRuleV1* rule = &set->rules[index];
        if (!rin_firewall_namespace_policy_default_rule_valid(rule) ||
            rule->namespace_id != namespace_id)
            continue;
        if (rin_firewall_container_rule_owner_id(rule) != owner_id)
            return RIN_FIREWALL_ACCESS_DENIED;
        if (rule_count >= RIN_FIREWALL_DIRECTION_COUNT)
            return RIN_FIREWALL_MALFORMED;
        rule_ids[rule_count++] = rule->id;
    }
    if (rule_count == 0u) return RIN_FIREWALL_NOT_FOUND;
    if (UINT64_MAX - set->generation < rule_count)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    for (index = 0u; index < rule_count; ++index) {
        result = rin_firewall_rule_set_remove(set, rule_ids[index]);
        if (result != RIN_FIREWALL_OK) return result;
    }
    return RIN_FIREWALL_OK;
}
