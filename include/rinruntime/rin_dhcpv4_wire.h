/* SPDX-License-Identifier: MIT */
/* Strict, allocation-free DHCPv4 reply parser shared by kernel and dhcpd. */

#ifndef RIN_SHARED_RIN_DHCPV4_WIRE_H
#define RIN_SHARED_RIN_DHCPV4_WIRE_H

#include <stdint.h>

#define RIN_DHCPV4_WIRE_VERSION UINT32_C(1)
#define RIN_DHCPV4_MAX_PACKET_SIZE UINT32_C(576)
#define RIN_DHCPV4_MAX_DNS_SERVERS UINT32_C(3)

typedef enum RinDhcpv4WireStatus {
    RIN_DHCPV4_WIRE_OK = 0,
    RIN_DHCPV4_WIRE_INVALID_ARGUMENT = -1,
    RIN_DHCPV4_WIRE_MALFORMED = -2,
    RIN_DHCPV4_WIRE_NOT_FOR_US = -3,
    RIN_DHCPV4_WIRE_UNSUPPORTED = -4
} RinDhcpv4WireStatus;

typedef enum RinDhcpv4MessageType {
    RIN_DHCPV4_MESSAGE_OFFER = 2,
    RIN_DHCPV4_MESSAGE_ACK = 5,
    RIN_DHCPV4_MESSAGE_NAK = 6
} RinDhcpv4MessageType;

typedef struct RinDhcpv4ReplyV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t transaction_id;
    uint32_t message_type;
    uint8_t yiaddr[4];
    uint8_t server_identifier[4];
    uint8_t subnet_mask[4];
    uint8_t router[4];
    uint8_t dns_servers[RIN_DHCPV4_MAX_DNS_SERVERS][4];
    uint32_t dns_server_count;
    uint32_t lease_seconds;
    uint32_t renewal_seconds;
    uint32_t rebind_seconds;
    uint32_t options_seen;
    uint32_t reserved;
} RinDhcpv4ReplyV1;

/* expected_transaction_id and client_hardware_address come from the
 * authenticated outstanding request.  A reply is published only after all
 * options have been parsed and validated. */
RinDhcpv4WireStatus rin_dhcpv4_parse_reply(
    const uint8_t* packet, uint32_t packet_size,
    uint32_t expected_transaction_id,
    const uint8_t client_hardware_address[6],
    RinDhcpv4ReplyV1* reply);

#if defined(__cplusplus)
static_assert(sizeof(RinDhcpv4ReplyV1) == 68u,
              "DHCPv4 reply ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinDhcpv4ReplyV1) == 68u,
               "DHCPv4 reply ABI drift");
#endif

#endif /* RIN_SHARED_RIN_DHCPV4_WIRE_H */
