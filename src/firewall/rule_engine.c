/* SPDX-License-Identifier: MIT */

#include <rin/firewall/abi.h>

#include <stddef.h>

static void firewall_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    while (size-- != 0u) *bytes++ = 0u;
}

static void firewall_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    while (size-- != 0u) *destination++ = *source++;
}

static int firewall_bytes_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static int firewall_bytes_equal(const uint8_t* left, const uint8_t* right,
                               uint32_t size)
{
    uint8_t difference = 0u;
    while (size-- != 0u) difference |= *left++ ^ *right++;
    return difference == 0u;
}

/* Process identity is carried in the ABI's formerly-reserved tail so the
 * fixed v1 wire size remains stable.  Rules use four 32-bit little-endian
 * words; packets use two native fixed-width words. */
static uint64_t firewall_rule_process_id(const RinFirewallRuleV1* rule)
{
    return ((uint64_t)rule->reserved[1] << 32u) |
           (uint64_t)rule->reserved[0];
}

static uint64_t firewall_rule_process_cookie(const RinFirewallRuleV1* rule)
{
    return ((uint64_t)rule->reserved[3] << 32u) |
           (uint64_t)rule->reserved[2];
}

static int firewall_process_identity_valid(uint64_t process_id,
                                           uint64_t process_cookie)
{
    return process_id != 0u && process_cookie != 0u;
}

static int firewall_string_valid(const char* text, uint32_t capacity,
                                 int required)
{
    uint32_t index;
    int terminated = 0;
    for (index = 0u; index < capacity; ++index) {
        if (text[index] == '\0') {
            terminated = 1;
            if (required && index == 0u) return 0;
            ++index;
            break;
        }
    }
    if (!terminated) return 0;
    for (; index < capacity; ++index) {
        if (text[index] != '\0') return 0;
    }
    return 1;
}

static int firewall_action_valid(uint8_t action)
{
    return action == RIN_FIREWALL_ACTION_ALLOW ||
           action == RIN_FIREWALL_ACTION_DROP ||
           action == RIN_FIREWALL_ACTION_REJECT;
}

static int firewall_direction_valid(uint8_t direction)
{
    return direction >= RIN_FIREWALL_DIRECTION_INPUT &&
           direction <= RIN_FIREWALL_DIRECTION_FORWARD;
}

static int firewall_family_valid(uint8_t family)
{
    return family == RIN_FIREWALL_FAMILY_ANY ||
           family == RIN_FIREWALL_FAMILY_IPV4 ||
           family == RIN_FIREWALL_FAMILY_IPV6;
}

static int firewall_protocol_valid(uint8_t protocol)
{
    return protocol == RIN_FIREWALL_PROTOCOL_ANY || protocol != 255u;
}

static int firewall_profile_valid(uint32_t profile)
{
    return profile <= RIN_FIREWALL_PROFILE_TRUSTED;
}

static int firewall_prefix_canonical(const uint8_t address[16],
                                     uint8_t family, uint8_t prefix)
{
    uint32_t bits = family == RIN_FIREWALL_FAMILY_IPV4 ? 32u : 128u;
    uint32_t index;
    if (prefix > bits) return 0;
    if (prefix == 0u) return firewall_bytes_zero(address, 16u);
    if (family == RIN_FIREWALL_FAMILY_IPV4 &&
        !firewall_bytes_zero(address + 4u, 12u)) return 0;
    for (index = prefix; index < bits; ++index) {
        uint32_t byte = index / 8u;
        uint8_t bit = (uint8_t)(1u << (7u - (index % 8u)));
        if ((address[byte] & bit) != 0u) return 0;
    }
    return 1;
}

static int firewall_prefix_match(const uint8_t address[16],
                                 const uint8_t network[16], uint8_t prefix)
{
    uint32_t full_bytes = prefix / 8u;
    uint32_t remaining = prefix % 8u;
    uint8_t mask;
    if (full_bytes != 0u &&
        !firewall_bytes_equal(address, network, full_bytes)) return 0;
    if (remaining == 0u) return 1;
    mask = (uint8_t)(0xffu << (8u - remaining));
    return (address[full_bytes] & mask) == (network[full_bytes] & mask);
}

static int firewall_ports_valid(const RinFirewallRuleV1* rule)
{
    int transport = rule->protocol == RIN_FIREWALL_PROTOCOL_TCP ||
                    rule->protocol == RIN_FIREWALL_PROTOCOL_UDP;
    if (!transport) {
        return rule->source_port_first == 0u &&
               rule->source_port_last == 0u &&
               rule->destination_port_first == 0u &&
               rule->destination_port_last == 0u;
    }
    if ((rule->source_port_first == 0u) !=
        (rule->source_port_last == 0u)) return 0;
    if ((rule->destination_port_first == 0u) !=
        (rule->destination_port_last == 0u)) return 0;
    return (rule->source_port_first == 0u ||
            rule->source_port_first <= rule->source_port_last) &&
           (rule->destination_port_first == 0u ||
            rule->destination_port_first <= rule->destination_port_last);
}

int rin_firewall_rule_validate(const RinFirewallRuleV1* rule)
{
    uint8_t address_family;
    uint32_t index;
    if (!rule) return RIN_FIREWALL_INVALID_ARGUMENT;
    if (rule->struct_size != sizeof(*rule) ||
        rule->version != RIN_FIREWALL_ABI_VERSION)
        return RIN_FIREWALL_ABI_MISMATCH;
    if ((rule->flags & ~RIN_FIREWALL_RULE_KNOWN_FLAGS) != 0u ||
        rule->id == 0u || rule->priority == UINT32_MAX ||
        rule->rule_class < RIN_FIREWALL_RULE_CLASS_SYSTEM ||
        rule->rule_class > RIN_FIREWALL_RULE_CLASS_CONTAINER ||
        (rule->rule_class == RIN_FIREWALL_RULE_CLASS_SYSTEM &&
         rule->priority > RIN_FIREWALL_SYSTEM_PRIORITY_MAX) ||
        (rule->rule_class != RIN_FIREWALL_RULE_CLASS_SYSTEM &&
         rule->priority < RIN_FIREWALL_USER_PRIORITY_MIN) ||
        !firewall_direction_valid(rule->direction) ||
        !firewall_action_valid(rule->action) ||
        !firewall_family_valid(rule->family) ||
        !firewall_protocol_valid(rule->protocol) ||
        (rule->family == RIN_FIREWALL_FAMILY_IPV4 &&
         rule->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) ||
        (rule->family == RIN_FIREWALL_FAMILY_IPV6 &&
         rule->protocol == RIN_FIREWALL_PROTOCOL_ICMP))
        return RIN_FIREWALL_MALFORMED;
    if (rule->reserved0 != 0u) return RIN_FIREWALL_MALFORMED;
    if (rule->connection_state_mask & ~RIN_FIREWALL_STATE_KNOWN_MASK)
        return RIN_FIREWALL_MALFORMED;
    if (!firewall_profile_valid(rule->network_profile))
        return RIN_FIREWALL_MALFORMED;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_INTERFACE) != 0u) {
        if (rule->interface_id == 0u) return RIN_FIREWALL_MALFORMED;
    } else if (rule->interface_id != 0u) {
        return RIN_FIREWALL_MALFORMED;
    }
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE) != 0u) {
        if (rule->namespace_id == 0u) return RIN_FIREWALL_MALFORMED;
    } else if (rule->namespace_id != 0u) {
        return RIN_FIREWALL_MALFORMED;
    }
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_PROFILE) != 0u) {
        if (rule->network_profile == RIN_FIREWALL_PROFILE_ANY)
            return RIN_FIREWALL_MALFORMED;
    } else if (rule->network_profile != RIN_FIREWALL_PROFILE_ANY) {
        return RIN_FIREWALL_MALFORMED;
    }
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) != 0u) {
        if (firewall_bytes_zero(rule->application_id,
                                RIN_FIREWALL_APPLICATION_ID_SIZE))
            return RIN_FIREWALL_MALFORMED;
    } else if (!firewall_bytes_zero(rule->application_id,
                                    RIN_FIREWALL_APPLICATION_ID_SIZE)) {
        return RIN_FIREWALL_MALFORMED;
    }
    if (rule->rule_class == RIN_FIREWALL_RULE_CLASS_APPLICATION &&
        (rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) == 0u)
        return RIN_FIREWALL_MALFORMED;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_ORPHANED) != 0u &&
        (rule->rule_class != RIN_FIREWALL_RULE_CLASS_APPLICATION ||
         (rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) == 0u ||
         (rule->flags & RIN_FIREWALL_RULE_FLAG_ENABLED) != 0u))
        return RIN_FIREWALL_MALFORMED;

    address_family = rule->family == RIN_FIREWALL_FAMILY_ANY ?
                     RIN_FIREWALL_FAMILY_IPV6 : rule->family;
    if (!firewall_prefix_canonical(rule->source_address, address_family,
                                   rule->source_prefix_len) ||
        !firewall_prefix_canonical(rule->destination_address, address_family,
                                   rule->destination_prefix_len))
        return RIN_FIREWALL_MALFORMED;
    if (rule->family == RIN_FIREWALL_FAMILY_ANY &&
        (rule->source_prefix_len != 0u ||
         rule->destination_prefix_len != 0u ||
         !firewall_bytes_zero(rule->source_address, 16u) ||
         !firewall_bytes_zero(rule->destination_address, 16u)))
        return RIN_FIREWALL_MALFORMED;
    if (!firewall_ports_valid(rule)) return RIN_FIREWALL_MALFORMED;
    if (rule->protocol == RIN_FIREWALL_PROTOCOL_ICMP ||
        rule->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) {
        /* 0xff is the explicit type/code wildcard. */
    } else if (rule->icmp_type != 0u || rule->icmp_code != 0u) {
        return RIN_FIREWALL_MALFORMED;
    }
    if (rule->updated_at_ms < rule->created_at_ms)
        return RIN_FIREWALL_MALFORMED;
    if (!firewall_string_valid(rule->name, RIN_FIREWALL_RULE_NAME_MAX, 1) ||
        !firewall_string_valid(rule->description,
                               RIN_FIREWALL_RULE_DESCRIPTION_MAX, 0))
        return RIN_FIREWALL_MALFORMED;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_PROCESS) != 0u) {
        if (!firewall_process_identity_valid(
                firewall_rule_process_id(rule),
                firewall_rule_process_cookie(rule)))
            return RIN_FIREWALL_MALFORMED;
    } else if (rule->rule_class == RIN_FIREWALL_RULE_CLASS_CONTAINER) {
        for (index = 1u; index < 4u; ++index) {
            if (rule->reserved[index] != 0u)
                return RIN_FIREWALL_MALFORMED;
        }
    } else {
        for (index = 0u; index < 4u; ++index) {
            if (rule->reserved[index] != 0u)
                return RIN_FIREWALL_MALFORMED;
        }
    }
    return RIN_FIREWALL_OK;
}

int rin_firewall_rule_set_init(RinFirewallRuleSetV1* set)
{
    if (!set) return RIN_FIREWALL_INVALID_ARGUMENT;
    firewall_zero(set, sizeof(*set));
    set->struct_size = sizeof(*set);
    set->version = RIN_FIREWALL_ABI_VERSION;
    set->generation = 1u;
    set->enabled = 1u;
    set->default_action[RIN_FIREWALL_DIRECTION_INPUT - 1u] =
        RIN_FIREWALL_ACTION_DROP;
    set->default_action[RIN_FIREWALL_DIRECTION_OUTPUT - 1u] =
        RIN_FIREWALL_ACTION_ALLOW;
    set->default_action[RIN_FIREWALL_DIRECTION_FORWARD - 1u] =
        RIN_FIREWALL_ACTION_DROP;
    return RIN_FIREWALL_OK;
}

int rin_firewall_rule_set_validate(const RinFirewallRuleSetV1* set)
{
    uint32_t index;
    if (!set) return RIN_FIREWALL_INVALID_ARGUMENT;
    if (set->struct_size != sizeof(*set) ||
        set->version != RIN_FIREWALL_ABI_VERSION)
        return RIN_FIREWALL_ABI_MISMATCH;
    if (set->flags != 0u || set->generation == 0u || set->enabled > 1u ||
        set->rule_count > RIN_FIREWALL_MAX_RULES)
        return RIN_FIREWALL_MALFORMED;
    for (index = 0u; index < RIN_FIREWALL_DIRECTION_COUNT; ++index) {
        if (!firewall_action_valid(set->default_action[index]))
            return RIN_FIREWALL_MALFORMED;
    }
    if (set->reserved0 != 0u ||
        !firewall_bytes_zero((const uint8_t*)set->reserved,
                             sizeof(set->reserved)))
        return RIN_FIREWALL_MALFORMED;
    for (index = 0u; index < set->rule_count; ++index) {
        uint32_t other;
        int status = rin_firewall_rule_validate(&set->rules[index]);
        if (status != RIN_FIREWALL_OK) return status;
        for (other = 0u; other < index; ++other) {
            if (set->rules[other].id == set->rules[index].id)
                return RIN_FIREWALL_DUPLICATE;
        }
    }
    for (; index < RIN_FIREWALL_MAX_RULES; ++index) {
        if (!firewall_bytes_zero((const uint8_t*)&set->rules[index],
                                 sizeof(set->rules[index])))
            return RIN_FIREWALL_MALFORMED;
    }
    return RIN_FIREWALL_OK;
}

int rin_firewall_packet_validate(const RinFirewallPacketV1* packet)
{
    if (!packet) return RIN_FIREWALL_INVALID_ARGUMENT;
    if (packet->struct_size != sizeof(*packet) ||
        packet->version != RIN_FIREWALL_ABI_VERSION)
        return RIN_FIREWALL_ABI_MISMATCH;
    if ((packet->flags & ~RIN_FIREWALL_PACKET_KNOWN_FLAGS) != 0u ||
        packet->namespace_id == 0u ||
        !firewall_direction_valid(packet->direction) ||
        !firewall_family_valid(packet->family) ||
        packet->family == RIN_FIREWALL_FAMILY_ANY ||
        !firewall_protocol_valid(packet->protocol) || packet->protocol == 0u ||
        (packet->family == RIN_FIREWALL_FAMILY_IPV4 &&
         packet->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) ||
        (packet->family == RIN_FIREWALL_FAMILY_IPV6 &&
         packet->protocol == RIN_FIREWALL_PROTOCOL_ICMP) ||
        !firewall_profile_valid(packet->network_profile) ||
        packet->connection_state > RIN_FIREWALL_STATE_INVALID ||
        (packet->connection_state != RIN_FIREWALL_STATE_UNTRACKED &&
         (packet->connection_state &
          (packet->connection_state - 1u)) != 0u))
        return RIN_FIREWALL_MALFORMED;
    if (packet->family == RIN_FIREWALL_FAMILY_IPV4 &&
        (!firewall_bytes_zero(packet->source_address + 4u, 12u) ||
         !firewall_bytes_zero(packet->destination_address + 4u, 12u)))
        return RIN_FIREWALL_MALFORMED;
    if (packet->protocol == RIN_FIREWALL_PROTOCOL_TCP ||
        packet->protocol == RIN_FIREWALL_PROTOCOL_UDP) {
        if (packet->source_port == 0u || packet->destination_port == 0u ||
            packet->icmp_type != 0u || packet->icmp_code != 0u)
            return RIN_FIREWALL_MALFORMED;
    } else if (packet->protocol == RIN_FIREWALL_PROTOCOL_ICMP ||
               packet->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) {
        if (packet->source_port != 0u || packet->destination_port != 0u)
            return RIN_FIREWALL_MALFORMED;
    } else if (packet->source_port != 0u || packet->destination_port != 0u ||
               packet->icmp_type != 0u || packet->icmp_code != 0u) {
        return RIN_FIREWALL_MALFORMED;
    }
    if (packet->family == RIN_FIREWALL_FAMILY_IPV4 &&
        packet->extension_header_count != 0u)
        return RIN_FIREWALL_MALFORMED;
    if (packet->family == RIN_FIREWALL_FAMILY_IPV6 &&
        packet->extension_header_count > 8u)
        return RIN_FIREWALL_MALFORMED;
    if ((packet->flags & RIN_FIREWALL_PACKET_FLAG_FRAGMENT) == 0u &&
        packet->fragment_offset != 0u)
        return RIN_FIREWALL_MALFORMED;
    if ((packet->flags & RIN_FIREWALL_PACKET_FLAG_PROCESS_IDENTITY) != 0u) {
        if (!firewall_process_identity_valid(packet->reserved[0],
                                             packet->reserved[1]) ||
            (((packet->flags & RIN_FIREWALL_PACKET_FLAG_USER_IDENTITY) != 0u) &&
             (packet->reserved[2] == 0u ||
              packet->reserved[2] > UINT32_MAX)) ||
            (((packet->flags & RIN_FIREWALL_PACKET_FLAG_USER_IDENTITY) == 0u) &&
             packet->reserved[2] != 0u))
            return RIN_FIREWALL_MALFORMED;
    } else if (!firewall_bytes_zero((const uint8_t*)packet->reserved,
                                    sizeof(packet->reserved))) {
        return RIN_FIREWALL_MALFORMED;
    }
    if ((packet->flags & RIN_FIREWALL_PACKET_FLAG_USER_IDENTITY) != 0u &&
        (packet->flags & RIN_FIREWALL_PACKET_FLAG_PROCESS_IDENTITY) == 0u)
        return RIN_FIREWALL_MALFORMED;
    return RIN_FIREWALL_OK;
}

static int firewall_rule_matches(const RinFirewallRuleV1* rule,
                                 const RinFirewallPacketV1* packet)
{
    int transport;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_ENABLED) == 0u ||
        rule->direction != packet->direction ||
        (rule->family != RIN_FIREWALL_FAMILY_ANY &&
         rule->family != packet->family) ||
        (rule->protocol != RIN_FIREWALL_PROTOCOL_ANY &&
         rule->protocol != packet->protocol)) return 0;
    if (rule->source_prefix_len != 0u &&
        !firewall_prefix_match(packet->source_address, rule->source_address,
                               rule->source_prefix_len)) return 0;
    if (rule->destination_prefix_len != 0u &&
        !firewall_prefix_match(packet->destination_address,
                               rule->destination_address,
                               rule->destination_prefix_len)) return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_INTERFACE) != 0u &&
        rule->interface_id != packet->interface_id) return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE) != 0u &&
        rule->namespace_id != packet->namespace_id) return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_PROFILE) != 0u &&
        rule->network_profile != packet->network_profile) return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) != 0u &&
        !firewall_bytes_equal(rule->application_id, packet->application_id,
                              RIN_FIREWALL_APPLICATION_ID_SIZE)) return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_PROCESS) != 0u &&
        (packet->flags & RIN_FIREWALL_PACKET_FLAG_PROCESS_IDENTITY) == 0u)
        return 0;
    if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_PROCESS) != 0u &&
        (firewall_rule_process_id(rule) != packet->reserved[0] ||
         firewall_rule_process_cookie(rule) != packet->reserved[1]))
        return 0;
    if (rule->owner_uid != 0u &&
        ((packet->flags & RIN_FIREWALL_PACKET_FLAG_USER_IDENTITY) == 0u ||
         packet->reserved[2] != rule->owner_uid))
        return 0;
    if (rule->connection_state_mask != 0u &&
        (rule->connection_state_mask & packet->connection_state) == 0u)
        return 0;
    transport = packet->protocol == RIN_FIREWALL_PROTOCOL_TCP ||
                packet->protocol == RIN_FIREWALL_PROTOCOL_UDP;
    if (transport) {
        if (rule->source_port_first != 0u &&
            (packet->source_port < rule->source_port_first ||
             packet->source_port > rule->source_port_last)) return 0;
        if (rule->destination_port_first != 0u &&
            (packet->destination_port < rule->destination_port_first ||
             packet->destination_port > rule->destination_port_last)) return 0;
    }
    if (packet->protocol == RIN_FIREWALL_PROTOCOL_ICMP ||
        packet->protocol == RIN_FIREWALL_PROTOCOL_ICMPV6) {
        if (rule->icmp_type != 0xffu &&
            rule->icmp_type != packet->icmp_type) return 0;
        if (rule->icmp_code != 0xffu &&
            rule->icmp_code != packet->icmp_code) return 0;
    }
    return 1;
}

static void firewall_decision_init(RinFirewallDecisionV1* decision)
{
    firewall_zero(decision, sizeof(*decision));
    decision->struct_size = sizeof(*decision);
    decision->version = RIN_FIREWALL_ABI_VERSION;
    decision->action = RIN_FIREWALL_ACTION_DROP;
}

static void firewall_counter_add(uint64_t* counter, uint64_t value)
{
    if (UINT64_MAX - *counter < value) *counter = UINT64_MAX;
    else *counter += value;
}

/* Rule IDs identify records, not policy.  Treat a second record with the
 * same matching/action contract as a duplicate even when its descriptive
 * metadata or counters differ. */
static int firewall_rule_policy_equal(const RinFirewallRuleV1* left,
                                      const RinFirewallRuleV1* right)
{
    RinFirewallRuleV1 left_policy;
    RinFirewallRuleV1 right_policy;
    if (left == NULL || right == NULL) return 0;
    left_policy = *left;
    right_policy = *right;
    left_policy.id = 0u;
    right_policy.id = 0u;
    firewall_zero(left_policy.name, sizeof(left_policy.name));
    firewall_zero(right_policy.name, sizeof(right_policy.name));
    firewall_zero(left_policy.description, sizeof(left_policy.description));
    firewall_zero(right_policy.description, sizeof(right_policy.description));
    left_policy.created_at_ms = 0u;
    right_policy.created_at_ms = 0u;
    left_policy.updated_at_ms = 0u;
    right_policy.updated_at_ms = 0u;
    left_policy.packet_count = 0u;
    right_policy.packet_count = 0u;
    left_policy.byte_count = 0u;
    right_policy.byte_count = 0u;
    return firewall_bytes_equal((const uint8_t*)&left_policy,
                                (const uint8_t*)&right_policy,
                                sizeof(left_policy));
}

int rin_firewall_rule_set_add(RinFirewallRuleSetV1* set,
                              const RinFirewallRuleV1* rule)
{
    uint32_t index;
    int status;
    if (!set || !rule) return RIN_FIREWALL_INVALID_ARGUMENT;
    status = rin_firewall_rule_set_validate(set);
    if (status != RIN_FIREWALL_OK) return status;
    status = rin_firewall_rule_validate(rule);
    if (status != RIN_FIREWALL_OK) return status;
    if (set->rule_count == RIN_FIREWALL_MAX_RULES)
        return RIN_FIREWALL_CAPACITY;
    for (index = 0u; index < set->rule_count; ++index) {
        if (set->rules[index].id == rule->id) return RIN_FIREWALL_DUPLICATE;
        if (firewall_rule_policy_equal(&set->rules[index], rule))
            return RIN_FIREWALL_DUPLICATE;
    }
    if (set->generation == UINT64_MAX)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    firewall_copy(&set->rules[set->rule_count], rule, sizeof(*rule));
    ++set->rule_count;
    ++set->generation;
    return RIN_FIREWALL_OK;
}

int rin_firewall_rule_set_update(RinFirewallRuleSetV1* set,
                                 uint64_t rule_id,
                                 const RinFirewallRuleV1* rule)
{
    uint32_t index;
    int status;
    if (!set || !rule || rule_id == 0u) return RIN_FIREWALL_INVALID_ARGUMENT;
    status = rin_firewall_rule_set_validate(set);
    if (status != RIN_FIREWALL_OK) return status;
    if (rule->id != rule_id) return RIN_FIREWALL_MALFORMED;
    status = rin_firewall_rule_validate(rule);
    if (status != RIN_FIREWALL_OK) return status;
    if (set->generation == UINT64_MAX)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    for (index = 0u; index < set->rule_count; ++index) {
        if (set->rules[index].id == rule_id) {
            firewall_copy(&set->rules[index], rule, sizeof(*rule));
            ++set->generation;
            return RIN_FIREWALL_OK;
        }
    }
    return RIN_FIREWALL_NOT_FOUND;
}

int rin_firewall_rule_set_remove(RinFirewallRuleSetV1* set,
                                 uint64_t rule_id)
{
    uint32_t index;
    int status;
    if (!set || rule_id == 0u) return RIN_FIREWALL_INVALID_ARGUMENT;
    status = rin_firewall_rule_set_validate(set);
    if (status != RIN_FIREWALL_OK) return status;
    if (set->generation == UINT64_MAX)
        return RIN_FIREWALL_GENERATION_EXHAUSTED;
    for (index = 0u; index < set->rule_count; ++index) {
        if (set->rules[index].id == rule_id) {
            uint32_t remaining = set->rule_count - index - 1u;
            if (remaining != 0u) {
                firewall_copy(&set->rules[index], &set->rules[index + 1u],
                              remaining * sizeof(set->rules[0]));
            }
            firewall_zero(&set->rules[set->rule_count - 1u],
                          sizeof(set->rules[0]));
            --set->rule_count;
            ++set->generation;
            return RIN_FIREWALL_OK;
        }
    }
    return RIN_FIREWALL_NOT_FOUND;
}

int rin_firewall_evaluate(RinFirewallRuleSetV1* set,
                          const RinFirewallPacketV1* packet,
                          RinFirewallDecisionV1* decision)
{
    uint32_t index;
    uint32_t best = RIN_FIREWALL_MAX_RULES;
    int status;
    if (!decision) return RIN_FIREWALL_INVALID_ARGUMENT;
    firewall_decision_init(decision);
    if (!set || !packet) {
        decision->status = RIN_FIREWALL_INVALID_ARGUMENT;
        return RIN_FIREWALL_INVALID_ARGUMENT;
    }
    status = rin_firewall_packet_validate(packet);
    if (status != RIN_FIREWALL_OK) {
        decision->status = status;
        return status;
    }
    status = rin_firewall_rule_set_validate(set);
    if (status != RIN_FIREWALL_OK) {
        decision->status = status;
        return status;
    }
    if (set->enabled == 0u) {
        decision->action = RIN_FIREWALL_ACTION_ALLOW;
        decision->status = RIN_FIREWALL_OK;
        return RIN_FIREWALL_OK;
    }
    for (index = 0u; index < set->rule_count; ++index) {
        const RinFirewallRuleV1* candidate = &set->rules[index];
        const RinFirewallRuleV1* current;
        if (!firewall_rule_matches(candidate, packet)) continue;
        if (best == RIN_FIREWALL_MAX_RULES) {
            best = index;
            continue;
        }
        current = &set->rules[best];
        if (candidate->priority < current->priority ||
            (candidate->priority == current->priority &&
             candidate->id < current->id)) best = index;
    }
    if (best == RIN_FIREWALL_MAX_RULES) {
        decision->action = set->default_action[packet->direction - 1u];
    } else {
        RinFirewallRuleV1* rule = &set->rules[best];
        decision->action = rule->action;
        decision->matched = 1u;
        decision->rule_id = rule->id;
        decision->priority = rule->priority;
        if (rule->packet_count != UINT64_MAX) ++rule->packet_count;
        firewall_counter_add(&rule->byte_count, packet->payload_length);
        decision->packet_count = rule->packet_count;
        decision->byte_count = rule->byte_count;
    }
    decision->status = RIN_FIREWALL_OK;
    return RIN_FIREWALL_OK;
}
