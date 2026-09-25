/* SPDX-License-Identifier: MIT */
/* Portable wire validation for the authenticated Firewall service ABI. */
#ifndef RINRUNTIME_FIREWALL_SERVICE_PROTOCOL_H
#define RINRUNTIME_FIREWALL_SERVICE_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include <rin/firewall/service_abi.h>

#define RIN_FIREWALL_SERVICE_PROTOCOL_MAGIC UINT32_C(0x32504657) /* WFP2 */
#define RIN_FIREWALL_SERVICE_SOCKET_PATH "/run/rin/firewalld.sock"

enum {
    RIN_FIREWALL_SERVICE_OP_GET_STATUS = 1u,
    RIN_FIREWALL_SERVICE_OP_GET_RULESET = 2u,
    RIN_FIREWALL_SERVICE_OP_REPLACE = 3u,
    RIN_FIREWALL_SERVICE_OP_SET_ENABLED = 4u,
    RIN_FIREWALL_SERVICE_OP_EVALUATE = 5u,
    RIN_FIREWALL_SERVICE_OP_READ_LOG = 6u,
    RIN_FIREWALL_SERVICE_OP_GET_CONNECTIONS = 7u,
    RIN_FIREWALL_SERVICE_OP_READ_EVENTS = 8u,
    RIN_FIREWALL_SERVICE_OP_RESET = 9u,
    RIN_FIREWALL_SERVICE_OP_ROTATE_LOG = 10u,
    RIN_FIREWALL_SERVICE_OP_PERMISSION_ENQUEUE = 11u,
    RIN_FIREWALL_SERVICE_OP_PERMISSION_DEQUEUE = 12u,
    RIN_FIREWALL_SERVICE_OP_PERMISSION_DECIDE = 13u,
    RIN_FIREWALL_SERVICE_OP_PERMISSION_EXPIRE = 14u,
    RIN_FIREWALL_SERVICE_OP_GET_PROFILES = 15u,
    RIN_FIREWALL_SERVICE_OP_SET_PROFILE = 16u,
    RIN_FIREWALL_SERVICE_OP_NOTIFY_APPLICATION = 17u,
    RIN_FIREWALL_SERVICE_OP_ISSUE_WARNING_ACK = 18u,
    RIN_FIREWALL_SERVICE_OP_SET_LOG_ALLOW = 19u,
    RIN_FIREWALL_SERVICE_OP_REPLACE_CONTAINER_RULES = 20u,
};

#pragma pack(push, 1)
typedef struct RinFirewallServiceMessageHeaderV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t header_size;
    uint32_t payload_size;
    uint32_t reserved0;
    uint64_t request_id;
    uint64_t session_id;
    uint64_t session_cookie;
    int32_t status;
    uint32_t reserved1;
} RinFirewallServiceMessageHeaderV1;

typedef struct RinFirewallServiceRequestV2 {
    RinFirewallServiceMessageHeaderV1 header;
    /* Transport input only: Firewalld replaces this envelope and the header
     * session fields with its kernel-authenticated connection identity before
     * validating or dispatching an operation. */
    RinFirewallServicePeerV1 peer;
    uint64_t expected_generation;
    uint64_t after_sequence;
    uint32_t enabled;
    uint32_t log_capacity;
    uint32_t reserved0;
    RinFirewallRuleSetV1 rule_set;
    RinFirewallPacketV1 packet;
    RinFirewallPermissionRequestV1 permission_request;
    union {
        uint64_t permission_request_id;
        uint64_t warning_ack_token;
    };
    uint16_t permission_action;
    uint16_t reserved_permission;
    RinFirewallConntrackQueryV2 conntrack_query;
    uint32_t connection_capacity;
    uint32_t event_capacity;
    uint32_t reserved2;
    uint32_t profile_interface_id;
    uint32_t profile;
    uint32_t profile_identity_size;
    uint32_t application_installed;
    uint8_t profile_identity[RIN_FIREWALL_PROFILE_IDENTITY_BYTES];
    uint8_t application_id[RIN_FIREWALL_APPLICATION_ID_SIZE];
} RinFirewallServiceRequestV2;
typedef RinFirewallServiceRequestV2 RinFirewallServiceRequestV1;
#pragma pack(pop)

#define RIN_FIREWALL_SERVICE_TRANSPORT_MAX_LOG_ITEMS UINT32_C(16)
#define RIN_FIREWALL_SERVICE_TRANSPORT_MAX_EVENT_ITEMS UINT32_C(16)

#pragma pack(push, 1)
typedef struct RinFirewallServiceLogBatchV1 {
    uint32_t returned;
    uint32_t reserved0;
    uint64_t next_sequence;
    RinFirewallServiceLogEventV1 events[
        RIN_FIREWALL_SERVICE_TRANSPORT_MAX_LOG_ITEMS];
} RinFirewallServiceLogBatchV1;

typedef struct RinFirewallServiceConnectionBatchV2 {
    uint32_t returned;
    uint32_t next_cursor;
    uint64_t generation;
    RinFirewallConntrackEntryV2 entries[RIN_FIREWALL_CONNTRACK_MAX_ENTRIES];
} RinFirewallServiceConnectionBatchV2;
typedef RinFirewallServiceConnectionBatchV2
    RinFirewallServiceConnectionBatchV1;

typedef struct RinFirewallServiceEventBatchV1 {
    uint32_t returned;
    uint32_t reserved0;
    uint64_t next_sequence;
    RinFirewallServiceEventV1 events[
        RIN_FIREWALL_SERVICE_TRANSPORT_MAX_EVENT_ITEMS];
} RinFirewallServiceEventBatchV1;

typedef struct RinFirewallServiceGenerationV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint64_t generation;
} RinFirewallServiceGenerationV1;

typedef union RinFirewallServiceResponseBodyV2 {
    RinFirewallServiceStatusV1 status;
    RinFirewallRuleSetV1 rule_set;
    RinFirewallDecisionV1 decision;
    RinFirewallServicePermissionResultV1 permission_result;
    RinFirewallPermissionRequestV1 permission_request;
    RinFirewallServiceLogBatchV1 log_batch;
    RinFirewallServiceConnectionBatchV2 connection_batch;
    RinFirewallServiceEventBatchV1 event_batch;
    RinFirewallProfileTableV1 profiles;
    RinFirewallServiceWarningAckV1 warning_ack;
    RinFirewallServiceGenerationV1 generation;
} RinFirewallServiceResponseBodyV2;
typedef RinFirewallServiceResponseBodyV2 RinFirewallServiceResponseBodyV1;

typedef struct RinFirewallServiceResponseV2 {
    RinFirewallServiceMessageHeaderV1 header;
    RinFirewallServiceResponseBodyV2 body;
} RinFirewallServiceResponseV2;
typedef RinFirewallServiceResponseV2 RinFirewallServiceResponseV1;
#pragma pack(pop)

#if defined(__cplusplus)
static_assert(sizeof(RinFirewallServiceGenerationV1) == 16u,
              "Firewall generation response ABI drift");
static_assert(sizeof(RinFirewallServiceResponseBodyV1) ==
                  sizeof(RinFirewallRuleSetV1),
              "Firewall service response body ABI drift");
static_assert(sizeof(RinFirewallServiceMessageHeaderV1) == 52u,
              "Firewall service header ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinFirewallServiceGenerationV1) == 16u,
               "Firewall generation response ABI drift");
_Static_assert(sizeof(RinFirewallServiceResponseBodyV1) ==
                   sizeof(RinFirewallRuleSetV1),
               "Firewall service response body ABI drift");
_Static_assert(sizeof(RinFirewallServiceMessageHeaderV1) == 52u,
               "Firewall service header ABI drift");
#endif

static inline int rin_firewall_service_peer_valid(
    const RinFirewallServicePeerV1* peer)
{
    uint32_t index;
    if (peer == NULL || peer->struct_size != sizeof(*peer) ||
        peer->version != RIN_FIREWALL_SERVICE_ABI_VERSION ||
        peer->reserved0 != 0u || peer->capabilities == 0u ||
        (peer->capabilities & ~RIN_FIREWALL_SERVICE_KNOWN_CAPS) != 0u ||
        peer->session_id == 0u || peer->session_cookie == 0u ||
        peer->process_generation == 0u)
        return 0;
    for (index = 0u; index < sizeof(peer->reserved1); ++index)
        if (peer->reserved1[index] != 0u) return 0;
    return 1;
}

static inline int rin_firewall_service_operation_valid(uint16_t operation)
{
    return operation >= RIN_FIREWALL_SERVICE_OP_GET_STATUS &&
           operation <= RIN_FIREWALL_SERVICE_OP_REPLACE_CONTAINER_RULES;
}

static inline void rin_firewall_service_message_initialize(
    RinFirewallServiceMessageHeaderV1* header, uint16_t operation,
    uint64_t request_id, const RinFirewallServicePeerV1* peer,
    uint32_t payload_size)
{
    uint8_t* bytes;
    uint32_t index;
    if (header == NULL) return;
    bytes = (uint8_t*)header;
    for (index = 0u; index < sizeof(*header); ++index) bytes[index] = 0u;
    header->magic = RIN_FIREWALL_SERVICE_PROTOCOL_MAGIC;
    header->version = RIN_FIREWALL_SERVICE_ABI_VERSION;
    header->operation = operation;
    header->header_size = sizeof(*header);
    header->payload_size = payload_size;
    header->request_id = request_id;
    if (peer != NULL) {
        header->session_id = peer->session_id;
        header->session_cookie = peer->session_cookie;
    }
}

static inline int rin_firewall_service_message_valid(
    const RinFirewallServiceMessageHeaderV1* header,
    const RinFirewallServicePeerV1* peer, uint32_t expected_payload_size)
{
    return header != NULL && rin_firewall_service_peer_valid(peer) &&
           header->magic == RIN_FIREWALL_SERVICE_PROTOCOL_MAGIC &&
           header->version == RIN_FIREWALL_SERVICE_ABI_VERSION &&
           rin_firewall_service_operation_valid(header->operation) &&
           header->header_size == sizeof(*header) &&
           header->payload_size == expected_payload_size &&
           header->reserved0 == 0u && header->reserved1 == 0u &&
           header->request_id != 0u &&
           header->session_id == peer->session_id &&
           header->session_cookie == peer->session_cookie &&
           header->status == 0;
}

static inline int rin_firewall_service_request_valid(
    const RinFirewallServiceRequestV1* request)
{
    if (request == NULL ||
        !rin_firewall_service_message_valid(
            &request->header, &request->peer,
            (uint32_t)(sizeof(*request) - sizeof(request->header))) ||
        request->reserved_permission != 0u ||
        (request->header.operation !=
             RIN_FIREWALL_SERVICE_OP_REPLACE_CONTAINER_RULES &&
         request->reserved2 != 0u))
        return 0;
    if (request->header.operation ==
        RIN_FIREWALL_SERVICE_OP_REPLACE_CONTAINER_RULES) {
        uint32_t index;
        if (request->reserved2 == RIN_FIREWALL_CONTAINER_OWNER_UNKNOWN ||
            request->rule_set.rule_count > RIN_FIREWALL_MAX_RULES)
            return 0;
        for (index = 0u; index < request->rule_set.rule_count; ++index) {
            const RinFirewallRuleV1* rule = &request->rule_set.rules[index];
            if (rule->rule_class != RIN_FIREWALL_RULE_CLASS_CONTAINER ||
                rin_firewall_container_rule_owner_id(rule) !=
                    request->reserved2 ||
                (rule->flags & RIN_FIREWALL_RULE_FLAG_SYSTEM_CRITICAL) != 0u)
                return 0;
        }
    }
    if (request->header.operation != RIN_FIREWALL_SERVICE_OP_REPLACE &&
        request->header.operation != RIN_FIREWALL_SERVICE_OP_SET_ENABLED &&
        request->header.operation != RIN_FIREWALL_SERVICE_OP_SET_PROFILE &&
        request->header.operation != RIN_FIREWALL_SERVICE_OP_PERMISSION_DECIDE &&
        request->warning_ack_token != 0u)
        return 0;
    if (request->header.operation == RIN_FIREWALL_SERVICE_OP_READ_LOG &&
        request->log_capacity > RIN_FIREWALL_SERVICE_TRANSPORT_MAX_LOG_ITEMS)
        return 0;
    if (request->header.operation == RIN_FIREWALL_SERVICE_OP_GET_CONNECTIONS &&
        request->connection_capacity > RIN_FIREWALL_CONNTRACK_MAX_ENTRIES)
        return 0;
    if (request->header.operation == RIN_FIREWALL_SERVICE_OP_READ_EVENTS &&
        request->event_capacity > RIN_FIREWALL_SERVICE_TRANSPORT_MAX_EVENT_ITEMS)
        return 0;
    if (request->header.operation == RIN_FIREWALL_SERVICE_OP_SET_PROFILE) {
        uint32_t index;
        if (request->profile_interface_id == 0u ||
            request->profile > RIN_FIREWALL_PROFILE_TRUSTED ||
            request->profile < RIN_FIREWALL_PROFILE_PUBLIC ||
            request->profile_identity_size == 0u ||
            request->profile_identity_size >
                RIN_FIREWALL_PROFILE_IDENTITY_BYTES)
            return 0;
        for (index = request->profile_identity_size;
             index < RIN_FIREWALL_PROFILE_IDENTITY_BYTES; ++index)
            if (request->profile_identity[index] != 0u) return 0;
    }
    if (request->header.operation ==
            RIN_FIREWALL_SERVICE_OP_NOTIFY_APPLICATION) {
        uint32_t index;
        int all_zero = 1;
        if (request->application_installed > 1u) return 0;
        for (index = 0u; index < RIN_FIREWALL_APPLICATION_ID_SIZE; ++index)
            if (request->application_id[index] != 0u) {
                all_zero = 0;
                break;
            }
        if (all_zero) return 0;
    }
    return 1;
}

#endif /* RINRUNTIME_FIREWALL_SERVICE_PROTOCOL_H */
