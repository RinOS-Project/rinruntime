/* SPDX-License-Identifier: MIT */
#ifndef RIN_KERNEL_RIN_DHCPV6_TRANSPORT_H
#define RIN_KERNEL_RIN_DHCPV6_TRANSPORT_H

#include <stdint.h>

#include "rin_dhcpv6_client.h"

#define RIN_DHCPV6_TRANSPORT_VERSION 1u
#define RIN_DHCPV6_TRANSPORT_FRAME_SIZE \
    (14u + 40u + 8u + RIN_DHCPV6_MAX_MESSAGE_SIZE)

typedef enum RinDhcpv6TransportStatus {
    RIN_DHCPV6_TRANSPORT_OK = 0,
    RIN_DHCPV6_TRANSPORT_PACKET_READY = 1,
    RIN_DHCPV6_TRANSPORT_RECONFIGURED = 2,
    RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT = -1,
    RIN_DHCPV6_TRANSPORT_INVALID_STATE = -2,
    RIN_DHCPV6_TRANSPORT_MALFORMED_FRAME = -3,
    RIN_DHCPV6_TRANSPORT_CHECKSUM_FAILURE = -4,
    RIN_DHCPV6_TRANSPORT_NOT_FOR_US = -5,
    RIN_DHCPV6_TRANSPORT_RANDOM_FAILURE = -6,
    RIN_DHCPV6_TRANSPORT_RANGE_EXHAUSTED = -7
} RinDhcpv6TransportStatus;

typedef int (*RinDhcpv6TransportRandomFn)(void* context, uint8_t* output,
                                           uint32_t output_size);

typedef struct RinDhcpv6TransportConfigV1 {
    uint32_t version;
    uint32_t struct_size;
    uint64_t interface_generation;
    uint8_t mac[6];
    uint8_t reserved0[2];
    uint8_t source_address[16];
    /* Reuses the v1 reserved storage; the structure size and offsets stay
     * stable for 32- and 64-bit callers. */
    uint32_t client_mode;
    uint8_t reserved1[4];
} RinDhcpv6TransportConfigV1;

typedef struct RinDhcpv6TransportTransmitV1 {
    uint32_t version;
    uint32_t struct_size;
    RinDhcpv6TransmitV1 client_transmit;
    uint16_t source_port;
    uint16_t destination_port;
    uint8_t source_mac[6];
    uint8_t destination_is_multicast;
    uint8_t reserved0;
    uint8_t source_address[16];
    uint8_t destination_address[16];
} RinDhcpv6TransportTransmitV1;

typedef struct RinDhcpv6TransportV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t initialized;
    uint32_t server_address_present;
    uint64_t transport_generation;
    RinDhcpv6TransportConfigV1 config;
    RinDhcpv6ClientV1 client;
    uint8_t server_address[16];
    uint8_t reserved0[8];
} RinDhcpv6TransportV1;

/* Validate a live transport snapshot without changing it. */
int rin_dhcpv6_transport_state_valid(const RinDhcpv6TransportV1* state);

int rin_dhcpv6_transport_init(
    RinDhcpv6TransportV1* state, const RinDhcpv6TransportConfigV1* config,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context);
int rin_dhcpv6_transport_reconfigure(
    RinDhcpv6TransportV1* state, const RinDhcpv6TransportConfigV1* config,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context);
int rin_dhcpv6_transport_prepare(
    RinDhcpv6TransportV1* state, uint64_t now_ms,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context,
    RinDhcpv6TransportTransmitV1* transmit_out);
int rin_dhcpv6_transport_complete_transmit(
    RinDhcpv6TransportV1* state,
    const RinDhcpv6TransportTransmitV1* transmit, int sent_successfully);
int rin_dhcpv6_transport_serialize(
    const RinDhcpv6TransportTransmitV1* transmit,
    const uint8_t destination_mac[6], uint8_t* frame_out,
    uint32_t frame_capacity, uint32_t* frame_size_out);
int rin_dhcpv6_transport_receive_frame(
    RinDhcpv6TransportV1* state, const uint8_t* frame,
    uint32_t frame_size, uint64_t now_ms);
/* The native IPv6 socket has already admitted the local destination and
 * verified the UDP pseudo-header checksum.  This entry point applies the
 * remaining DHCPv6 transport envelope checks to a datagram returned by
 * recvfrom(), then passes only a Reply to the client parser. */
int rin_dhcpv6_transport_receive_datagram(
    RinDhcpv6TransportV1* state, const uint8_t source_address[16],
    uint16_t source_port, const uint8_t destination_address[16],
    uint16_t destination_port, const uint8_t* message,
    uint32_t message_size, uint64_t now_ms);
/* Validate the complete Ethernet/IPv6/UDP envelope of an RKAP Reconfigure
 * without passing it to the Reply-only client parser.  The message pointer is
 * borrowed from frame and remains valid only while frame remains unchanged. */
int rin_dhcpv6_transport_validate_reconfigure_frame(
    const RinDhcpv6TransportV1* state, const uint8_t* frame,
    uint32_t frame_size, const uint8_t** message_out,
    uint32_t* message_size_out);
/* Socket equivalent of the frame validator.  The returned message pointer is
 * borrowed from the caller's datagram buffer.  UDP checksum validation is
 * intentionally owned by rin_ipv6_udp_input before this API is reached. */
int rin_dhcpv6_transport_validate_reconfigure_datagram(
    const RinDhcpv6TransportV1* state, const uint8_t source_address[16],
    uint16_t source_port, const uint8_t destination_address[16],
    uint16_t destination_port, const uint8_t* message,
    uint32_t message_size, const uint8_t** message_out,
    uint32_t* message_size_out);
int rin_dhcpv6_transport_get_lease(
    RinDhcpv6TransportV1* state, uint64_t now_ms,
    RinDhcpv6LeaseV1* lease_out);
int rin_dhcpv6_transport_stop(RinDhcpv6TransportV1* state);
void rin_dhcpv6_transport_destroy(RinDhcpv6TransportV1* state);

#endif /* RIN_KERNEL_RIN_DHCPV6_TRANSPORT_H */
