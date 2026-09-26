/* SPDX-License-Identifier: MIT */

#include <rinruntime/firewall_namespace_policy.h>
#include <rinruntime/firewall_rule_index.h>

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
        (rule->priority >=
             RIN_FIREWALL_NAMESPACE_POLICY_DEFAULT_PRIORITY &&
         !rin_firewall_namespace_policy_default_rule_valid(rule)) ||
        rule->rule_class < RIN_FIREWALL_RULE_CLASS_SYSTEM ||
        rule->rule_class > RIN_FIREWALL_RULE_CLASS_CONTAINER ||
        (rule->rule_class == RIN_FIREWALL_RULE_CLASS_SYSTEM &&
         rule->priority > RIN_FIREWALL_SYSTEM_PRIORITY_MAX) ||
        (rule->rule_class != RIN_FIREWALL_RULE_CLASS_SYSTEM &&
         rule->priority < RIN_FIREWALL_USER_PRIORITY_MIN) ||
        ((rule->flags & RIN_FIREWALL_RULE_FLAG_POLICY_GUARD) != 0u &&
         (rule->rule_class != RIN_FIREWALL_RULE_CLASS_CONTAINER ||
          (rule->flags & (RIN_FIREWALL_RULE_FLAG_MATCH_PROCESS |
                          RIN_FIREWALL_RULE_FLAG_SYSTEM_CRITICAL |
                          RIN_FIREWALL_RULE_FLAG_POLICY_BYPASS)) != 0u ||
          (rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE) == 0u ||
          rule->reserved[0] == RIN_FIREWALL_CONTAINER_OWNER_UNKNOWN)) ||
        ((rule->flags & RIN_FIREWALL_RULE_FLAG_POLICY_BYPASS) != 0u &&
         (rule->rule_class != RIN_FIREWALL_RULE_CLASS_SYSTEM ||
          rule->action != RIN_FIREWALL_ACTION_ALLOW ||
          (rule->flags & RIN_FIREWALL_RULE_FLAG_SYSTEM_CRITICAL) == 0u)) ||
        (rule->rule_class == RIN_FIREWALL_RULE_CLASS_CONTAINER &&
         ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE) == 0u ||
          rule->namespace_id <=
              RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID)) ||
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
            if (rin_firewall_namespace_policy_default_rule_valid(
                    &set->rules[index]) &&
                rin_firewall_namespace_policy_default_rule_valid(
                    &set->rules[other]) &&
                set->rules[other].namespace_id ==
                    set->rules[index].namespace_id &&
                set->rules[other].direction == set->rules[index].direction)
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
    if (packet->namespace_id != RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID &&
        rule->rule_class != RIN_FIREWALL_RULE_CLASS_SYSTEM &&
        (rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_NAMESPACE) == 0u)
        return 0;
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

static int firewall_rule_precedes(const RinFirewallRuleV1* candidate,
                                  const RinFirewallRuleV1* current)
{
    return candidate->priority < current->priority ||
           (candidate->priority == current->priority &&
            candidate->id < current->id);
}

static uint32_t firewall_rule_index_protocol(uint8_t protocol)
{
    switch (protocol) {
    case RIN_FIREWALL_PROTOCOL_ICMP: return 0u;
    case RIN_FIREWALL_PROTOCOL_TCP: return 1u;
    case RIN_FIREWALL_PROTOCOL_UDP: return 2u;
    case RIN_FIREWALL_PROTOCOL_ICMPV6: return 3u;
    default: return RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT - 1u;
    }
}

static uint32_t firewall_rule_index_family(uint8_t family)
{
    if (family == RIN_FIREWALL_FAMILY_IPV4) return 0u;
    if (family == RIN_FIREWALL_FAMILY_IPV6) return 1u;
    return RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT;
}

static int firewall_application_id_compare(
    const uint8_t left[RIN_FIREWALL_APPLICATION_ID_SIZE],
    const uint8_t right[RIN_FIREWALL_APPLICATION_ID_SIZE])
{
    uint32_t index;
    for (index = 0u; index < RIN_FIREWALL_APPLICATION_ID_SIZE; ++index) {
        if (left[index] < right[index]) return -1;
        if (left[index] > right[index]) return 1;
    }
    return 0;
}

static int firewall_rule_index_application_find(
    const RinFirewallRuleIndexV2* index,
    const uint8_t application_id[RIN_FIREWALL_APPLICATION_ID_SIZE],
    uint32_t* position_out)
{
    uint32_t low = 0u;
    uint32_t high = index->application_count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2u;
        int comparison = firewall_application_id_compare(
            application_id, index->applications[middle].application_id);
        if (comparison == 0) {
            *position_out = middle;
            return 1;
        }
        if (comparison < 0) high = middle;
        else low = middle + 1u;
    }
    *position_out = low;
    return 0;
}

static int firewall_rule_index_header_valid(
    const RinFirewallRuleSetV1* set, const RinFirewallRuleIndexV2* index)
{
    uint32_t direction;
    const uint32_t direction_mask =
        (UINT32_C(1) << RIN_FIREWALL_DIRECTION_COUNT) - 1u;
    if (set == NULL || index == NULL ||
        set->struct_size != sizeof(*set) ||
        set->version != RIN_FIREWALL_ABI_VERSION ||
        set->rule_count > RIN_FIREWALL_MAX_RULES || set->enabled > 1u ||
        index->struct_size != sizeof(*index) ||
        index->version != RIN_FIREWALL_RULE_INDEX_VERSION ||
        index->reserved0 != 0u || index->reserved1 != 0u ||
        (index->active_guard_direction_mask & ~direction_mask) != 0u ||
        index->generation != set->generation ||
        index->rule_count != set->rule_count ||
        index->application_count > RIN_FIREWALL_MAX_RULES ||
        index->application_rule_count > set->rule_count)
        return 0;
    for (direction = 0u; direction < RIN_FIREWALL_DIRECTION_COUNT;
         ++direction) {
        if (!firewall_action_valid(set->default_action[direction])) return 0;
    }
    return 1;
}

static int firewall_rule_index_insert(
    RinFirewallRuleIndexBucketV2* bucket,
    const RinFirewallRuleSetV1* set, uint16_t rule_index)
{
    uint32_t position;
    if (bucket == NULL || set == NULL || rule_index >= set->rule_count ||
        bucket->count >= RIN_FIREWALL_MAX_RULES)
        return RIN_FIREWALL_MALFORMED;
    position = bucket->count;
    while (position != 0u) {
        uint16_t previous = bucket->rule_indices[position - 1u];
        if (!firewall_rule_precedes(&set->rules[rule_index],
                                    &set->rules[previous]))
            break;
        bucket->rule_indices[position] = previous;
        --position;
    }
    bucket->rule_indices[position] = rule_index;
    ++bucket->count;
    return RIN_FIREWALL_OK;
}

int rin_firewall_rule_index_build(const RinFirewallRuleSetV1* set,
                                  RinFirewallRuleIndexV2* index)
{
    static const uint8_t protocols[RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT - 1u] = {
        RIN_FIREWALL_PROTOCOL_ICMP,
        RIN_FIREWALL_PROTOCOL_TCP,
        RIN_FIREWALL_PROTOCOL_UDP,
        RIN_FIREWALL_PROTOCOL_ICMPV6
    };
    static const uint8_t families[RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT] = {
        RIN_FIREWALL_FAMILY_IPV4,
        RIN_FIREWALL_FAMILY_IPV6
    };
    int status;
    uint32_t rule_index;
    if (index == NULL) return RIN_FIREWALL_INVALID_ARGUMENT;
    firewall_zero((uint8_t*)index, (uint32_t)sizeof(*index));
    if (set == NULL) return RIN_FIREWALL_INVALID_ARGUMENT;
    status = rin_firewall_rule_set_validate(set);
    if (status != RIN_FIREWALL_OK) return status;

    index->struct_size = sizeof(*index);
    index->version = RIN_FIREWALL_RULE_INDEX_VERSION;
    index->generation = set->generation;
    index->rule_count = set->rule_count;
    for (rule_index = 0u; rule_index < set->rule_count; ++rule_index) {
        const RinFirewallRuleV1* rule = &set->rules[rule_index];
        if ((rule->flags & (RIN_FIREWALL_RULE_FLAG_ENABLED |
                            RIN_FIREWALL_RULE_FLAG_POLICY_GUARD)) ==
                (RIN_FIREWALL_RULE_FLAG_ENABLED |
                 RIN_FIREWALL_RULE_FLAG_POLICY_GUARD))
            index->active_guard_direction_mask |=
                UINT32_C(1) << (rule->direction - 1u);
    }
    /* Group the application-specific rules by exact package identity. The
     * table stays sorted so a packet performs a bounded binary search. */
    for (rule_index = 0u; rule_index < set->rule_count; ++rule_index) {
        const RinFirewallRuleV1* rule = &set->rules[rule_index];
        uint32_t position;
        if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) == 0u)
            continue;
        if (firewall_rule_index_application_find(
                index, rule->application_id, &position))
            continue;
        if (index->application_count >= RIN_FIREWALL_MAX_RULES) {
            firewall_zero((uint8_t*)index, (uint32_t)sizeof(*index));
            return RIN_FIREWALL_CAPACITY;
        }
        for (uint32_t shift = index->application_count;
             shift > position; --shift) {
            index->applications[shift] = index->applications[shift - 1u];
        }
        firewall_copy(index->applications[position].application_id,
                      rule->application_id,
                      RIN_FIREWALL_APPLICATION_ID_SIZE);
        ++index->application_count;
    }

    /* Flatten each sorted application group into one bounded vector. */
    index->application_rule_count = 0u;
    for (uint32_t application_index = 0u;
         application_index < index->application_count; ++application_index) {
        RinFirewallRuleIndexApplicationBucketV2* application =
            &index->applications[application_index];
        uint32_t rule_position;
        application->first_rule = index->application_rule_count;
        for (rule_position = 0u; rule_position < set->rule_count;
             ++rule_position) {
            const RinFirewallRuleV1* rule = &set->rules[rule_position];
            uint32_t insert_at;
            if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) == 0u ||
                !firewall_bytes_equal(rule->application_id,
                                      application->application_id,
                                      RIN_FIREWALL_APPLICATION_ID_SIZE))
                continue;
            insert_at = index->application_rule_count;
            while (insert_at > application->first_rule) {
                uint16_t previous =
                    index->application_rule_indices[insert_at - 1u];
                if (!firewall_rule_precedes(rule,
                                            &set->rules[previous]))
                    break;
                index->application_rule_indices[insert_at] = previous;
                --insert_at;
            }
            index->application_rule_indices[insert_at] =
                (uint16_t)rule_position;
            ++index->application_rule_count;
            ++application->rule_count;
        }
    }

    for (rule_index = 0u; rule_index < set->rule_count; ++rule_index) {
        const RinFirewallRuleV1* rule = &set->rules[rule_index];
        uint32_t family_index;
        uint32_t protocol_index;
        uint32_t protocol_first = 0u;
        uint32_t protocol_end = RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT;
        if ((rule->flags & RIN_FIREWALL_RULE_FLAG_MATCH_APPLICATION) != 0u)
            continue;
        if (rule->protocol != RIN_FIREWALL_PROTOCOL_ANY) {
            protocol_first = firewall_rule_index_protocol(rule->protocol);
            protocol_end = protocol_first + 1u;
        }
        for (family_index = 0u;
             family_index < RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT;
             ++family_index) {
            if (rule->family != RIN_FIREWALL_FAMILY_ANY &&
                rule->family != families[family_index])
                continue;
            for (protocol_index = protocol_first;
                 protocol_index < protocol_end; ++protocol_index) {
                RinFirewallRuleIndexBucketV2* bucket;
                if (protocol_index < RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT -
                                         1u &&
                    rule->protocol != RIN_FIREWALL_PROTOCOL_ANY &&
                    rule->protocol != protocols[protocol_index])
                    continue;
                bucket = &index->buckets[rule->direction - 1u]
                                        [family_index][protocol_index];
                status = firewall_rule_index_insert(
                    bucket, set, (uint16_t)rule_index);
                if (status != RIN_FIREWALL_OK) {
                    firewall_zero((uint8_t*)index, (uint32_t)sizeof(*index));
                    return status;
                }
            }
        }
    }
    return RIN_FIREWALL_OK;
}

static int firewall_rule_index_valid_for_packet(
    const RinFirewallRuleSetV1* set, const RinFirewallRuleIndexV2* index,
    const RinFirewallPacketV1* packet,
    const RinFirewallRuleIndexBucketV2** bucket_out,
    const RinFirewallRuleIndexApplicationBucketV2** application_bucket_out)
{
    uint32_t family_index = firewall_rule_index_family(packet->family);
    uint32_t protocol_index = firewall_rule_index_protocol(packet->protocol);
    const RinFirewallRuleIndexBucketV2* bucket;
    const RinFirewallRuleIndexApplicationBucketV2* application_bucket = NULL;
    uint32_t item;
    if (!firewall_rule_index_header_valid(set, index) ||
        family_index >= RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT ||
        protocol_index >= RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT)
        return 0;
    bucket = &index->buckets[packet->direction - 1u]
                             [family_index][protocol_index];
    if (bucket->count > set->rule_count) return 0;
    for (item = 0u; item < bucket->count; ++item) {
        uint16_t current_index = bucket->rule_indices[item];
        if (current_index >= set->rule_count) return 0;
        if (item != 0u) {
            uint16_t previous_index = bucket->rule_indices[item - 1u];
            if (previous_index >= set->rule_count ||
                !firewall_rule_precedes(&set->rules[previous_index],
                                        &set->rules[current_index]))
                return 0;
        }
    }
    if (!firewall_bytes_zero(packet->application_id,
                             RIN_FIREWALL_APPLICATION_ID_SIZE)) {
        uint32_t application_position;
        if (firewall_rule_index_application_find(
                index, packet->application_id, &application_position)) {
            application_bucket = &index->applications[application_position];
            if (application_bucket->first_rule >
                    index->application_rule_count ||
                application_bucket->rule_count >
                    index->application_rule_count -
                        application_bucket->first_rule)
                return 0;
        }
    }
    if (bucket->count +
            (application_bucket != NULL ? application_bucket->rule_count : 0u) >
        set->rule_count)
        return 0;
    *bucket_out = bucket;
    *application_bucket_out = application_bucket;
    return 1;
}

static int firewall_evaluate_internal(
    RinFirewallRuleSetV1* set, const RinFirewallRuleIndexV2* rule_index,
    const RinFirewallPacketV1* packet, RinFirewallDecisionV1* decision)
{
    uint32_t iteration;
    uint32_t best_bypass = RIN_FIREWALL_MAX_RULES;
    uint32_t best_system = RIN_FIREWALL_MAX_RULES;
    uint32_t best_guard = RIN_FIREWALL_MAX_RULES;
    uint32_t best_regular = RIN_FIREWALL_MAX_RULES;
    uint32_t best;
    uint32_t candidate_count;
    const RinFirewallRuleIndexBucketV2* bucket = NULL;
    const RinFirewallRuleIndexApplicationBucketV2* application_bucket = NULL;
    uint32_t generic_cursor = 0u;
    uint32_t application_cursor = 0u;
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
    if (rule_index != NULL) {
        if (!firewall_rule_index_header_valid(set, rule_index)) {
            decision->status = RIN_FIREWALL_MALFORMED;
            return RIN_FIREWALL_MALFORMED;
        }
        if (set->enabled == 0u &&
            (rule_index->active_guard_direction_mask &
             (UINT32_C(1) << (packet->direction - 1u))) == 0u) {
            decision->action = RIN_FIREWALL_ACTION_ALLOW;
            decision->status = RIN_FIREWALL_OK;
            return RIN_FIREWALL_OK;
        }
    }
    if (rule_index == NULL) {
        status = rin_firewall_rule_set_validate(set);
        if (status != RIN_FIREWALL_OK) {
            decision->status = status;
            return status;
        }
        candidate_count = set->rule_count;
    } else {
        if (!firewall_rule_index_valid_for_packet(
                set, rule_index, packet, &bucket, &application_bucket)) {
            decision->status = RIN_FIREWALL_MALFORMED;
            return RIN_FIREWALL_MALFORMED;
        }
        candidate_count = bucket->count +
            (application_bucket != NULL ? application_bucket->rule_count : 0u);
    }
    for (iteration = 0u; iteration < candidate_count; ++iteration) {
        uint32_t candidate_index;
        if (bucket == NULL) {
            candidate_index = iteration;
        } else {
            uint16_t generic_index = RIN_FIREWALL_MAX_RULES;
            uint16_t application_index = RIN_FIREWALL_MAX_RULES;
            if (generic_cursor < bucket->count) {
                generic_index = bucket->rule_indices[generic_cursor];
                if (generic_index >= set->rule_count) {
                    decision->status = RIN_FIREWALL_MALFORMED;
                    return RIN_FIREWALL_MALFORMED;
                }
            }
            if (application_bucket != NULL &&
                application_cursor < application_bucket->rule_count) {
                application_index = rule_index->application_rule_indices[
                    application_bucket->first_rule + application_cursor];
                if (application_index >= set->rule_count) {
                    decision->status = RIN_FIREWALL_MALFORMED;
                    return RIN_FIREWALL_MALFORMED;
                }
            }
            if (generic_index == RIN_FIREWALL_MAX_RULES) {
                candidate_index = application_index;
                ++application_cursor;
            } else if (application_index == RIN_FIREWALL_MAX_RULES) {
                candidate_index = generic_index;
                ++generic_cursor;
            } else if (firewall_rule_precedes(&set->rules[generic_index],
                                              &set->rules[application_index])) {
                candidate_index = generic_index;
                ++generic_cursor;
            } else {
                candidate_index = application_index;
                ++application_cursor;
            }
        }
        const RinFirewallRuleV1* candidate = &set->rules[candidate_index];
        uint32_t* selected;
        const RinFirewallRuleV1* current;
        if (!firewall_rule_matches(candidate, packet)) continue;
        if (candidate->rule_class == RIN_FIREWALL_RULE_CLASS_SYSTEM &&
            (candidate->flags &
             RIN_FIREWALL_RULE_FLAG_POLICY_BYPASS) != 0u)
            selected = &best_bypass;
        else if (candidate->rule_class == RIN_FIREWALL_RULE_CLASS_SYSTEM)
            selected = &best_system;
        else if ((candidate->flags &
                  RIN_FIREWALL_RULE_FLAG_POLICY_GUARD) != 0u)
            selected = &best_guard;
        else
            selected = &best_regular;
        if (*selected == RIN_FIREWALL_MAX_RULES) {
            *selected = candidate_index;
        } else if (bucket == NULL) {
            current = &set->rules[*selected];
            if (firewall_rule_precedes(candidate, current))
                *selected = candidate_index;
        }
        if (best_bypass != RIN_FIREWALL_MAX_RULES &&
            best_system != RIN_FIREWALL_MAX_RULES &&
            best_guard != RIN_FIREWALL_MAX_RULES &&
            best_regular != RIN_FIREWALL_MAX_RULES)
            break;
    }

    /* Authenticated infrastructure exceptions may pass container guards.
     * Otherwise a guard denial wins before any ordinary system, user, or
     * application ALLOW. Guard ALLOW remains subject to ordinary system and
     * user rules, and replaces the direction default only if none match.
     * Guard denials remain active when the desktop Firewall toggle is off. */
    if (set->enabled != 0u && best_bypass != RIN_FIREWALL_MAX_RULES)
        best = best_bypass;
    else if (best_guard != RIN_FIREWALL_MAX_RULES &&
             set->rules[best_guard].action != RIN_FIREWALL_ACTION_ALLOW)
        best = best_guard;
    else if (set->enabled != 0u && best_system != RIN_FIREWALL_MAX_RULES)
        best = best_system;
    else if (set->enabled == 0u) {
        decision->action = RIN_FIREWALL_ACTION_ALLOW;
        decision->status = RIN_FIREWALL_OK;
        return RIN_FIREWALL_OK;
    } else if (best_regular != RIN_FIREWALL_MAX_RULES)
        best = best_regular;
    else if (best_guard != RIN_FIREWALL_MAX_RULES)
        best = best_guard;
    else
        best = RIN_FIREWALL_MAX_RULES;

    if (best == RIN_FIREWALL_MAX_RULES) {
        decision->action =
            packet->namespace_id == RIN_FIREWALL_NAMESPACE_POLICY_HOST_ID
                ? set->default_action[packet->direction - 1u]
                : RIN_FIREWALL_ACTION_DROP;
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

int rin_firewall_evaluate(RinFirewallRuleSetV1* set,
                          const RinFirewallPacketV1* packet,
                          RinFirewallDecisionV1* decision)
{
    return firewall_evaluate_internal(set, NULL, packet, decision);
}

int rin_firewall_evaluate_indexed(RinFirewallRuleSetV1* set,
                                  const RinFirewallRuleIndexV2* index,
                                  const RinFirewallPacketV1* packet,
                                  RinFirewallDecisionV1* decision)
{
    if (index == NULL) {
        if (decision != NULL) {
            firewall_decision_init(decision);
            decision->status = RIN_FIREWALL_INVALID_ARGUMENT;
        }
        return RIN_FIREWALL_INVALID_ARGUMENT;
    }
    return firewall_evaluate_internal(set, index, packet, decision);
}
