/* SPDX-License-Identifier: MIT */
/* Immutable policy index for bounded Firewall rulesets. */
#ifndef RINRUNTIME_FIREWALL_RULE_INDEX_H
#define RINRUNTIME_FIREWALL_RULE_INDEX_H

#include <rin/firewall/abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_FIREWALL_RULE_INDEX_VERSION UINT16_C(2)
#define RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT UINT32_C(2)
#define RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT UINT32_C(5)

typedef struct RinFirewallRuleIndexBucketV2 {
    uint16_t count;
    uint16_t rule_indices[RIN_FIREWALL_MAX_RULES];
} RinFirewallRuleIndexBucketV2;

typedef struct RinFirewallRuleIndexApplicationBucketV2 {
    uint8_t application_id[RIN_FIREWALL_APPLICATION_ID_SIZE];
    uint16_t first_rule;
    uint16_t rule_count;
} RinFirewallRuleIndexApplicationBucketV2;

typedef struct RinFirewallRuleIndexV2 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint64_t generation;
    uint32_t rule_count;
    uint32_t reserved1;
    uint16_t application_count;
    uint16_t application_rule_count;
    uint32_t active_guard_direction_mask;
    /* Application-specific rules are grouped by exact authenticated ID and
     * stored in one compact, sorted index vector. Groups are ID-sorted for
     * bounded binary lookup; generic rules remain in the policy buckets. */
    RinFirewallRuleIndexApplicationBucketV2 applications[
        RIN_FIREWALL_MAX_RULES];
    uint16_t application_rule_indices[RIN_FIREWALL_MAX_RULES];
    /* [direction - INPUT][IPv4/IPv6][ICMP/TCP/UDP/ICMPv6/OTHER]. Each bucket
     * is priority/ID ordered and includes rules whose family or protocol is
     * ANY. Application-specific rules are excluded here; OTHER retains exact
     * matching for uncommon IP protocol numbers. */
    RinFirewallRuleIndexBucketV2 buckets[RIN_FIREWALL_DIRECTION_COUNT]
        [RIN_FIREWALL_RULE_INDEX_FAMILY_COUNT]
        [RIN_FIREWALL_RULE_INDEX_PROTOCOL_COUNT];
} RinFirewallRuleIndexV2;

/* Build from a fully validated ruleset. Rebuild after every policy change.
 * Once built, policy fields in the ruleset must remain unchanged while the
 * index is used; packet/byte counters may change. */
int rin_firewall_rule_index_build(const RinFirewallRuleSetV1* set,
                                  RinFirewallRuleIndexV2* index);

/* Evaluates only the candidate bucket for this packet. The ruleset must be
 * the validated, unchanged policy snapshot used to build index. */
int rin_firewall_evaluate_indexed(RinFirewallRuleSetV1* set,
                                  const RinFirewallRuleIndexV2* index,
                                  const RinFirewallPacketV1* packet,
                                  RinFirewallDecisionV1* decision);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FIREWALL_RULE_INDEX_H */
