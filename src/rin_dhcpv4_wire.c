/* SPDX-License-Identifier: MIT */

#include "rin_dhcpv4_wire.h"

#include <stddef.h>

#define DHCPV4_FIXED_HEADER_SIZE UINT32_C(236)
#define DHCPV4_MAGIC_COOKIE UINT32_C(0x63825363)
#define DHCPV4_OP_BOOTREPLY UINT8_C(2)
#define DHCPV4_HTYPE_ETHERNET UINT8_C(1)
#define DHCPV4_HLEN_ETHERNET UINT8_C(6)
#define DHCPV4_OPTION_PAD UINT8_C(0)
#define DHCPV4_OPTION_END UINT8_C(255)
#define DHCPV4_OPTION_SUBNET_MASK UINT8_C(1)
#define DHCPV4_OPTION_ROUTER UINT8_C(3)
#define DHCPV4_OPTION_DNS UINT8_C(6)
#define DHCPV4_OPTION_LEASE_TIME UINT8_C(51)
#define DHCPV4_OPTION_MESSAGE_TYPE UINT8_C(53)
#define DHCPV4_OPTION_SERVER_IDENTIFIER UINT8_C(54)
#define DHCPV4_OPTION_RENEWAL_TIME UINT8_C(58)
#define DHCPV4_OPTION_REBIND_TIME UINT8_C(59)
#define DHCPV4_MAX_OPTIONS UINT32_C(64)

static void zero_bytes(void* destination, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)destination;
    while (bytes != NULL && size-- != 0u) *bytes++ = 0u;
}

static void copy_bytes(void* destination, const void* source, uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *output++ = *input++;
}

static int all_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    if (bytes == NULL) return 0;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static int all_equal(const uint8_t* left, const uint8_t* right,
                     uint32_t size)
{
    uint8_t difference = 0u;
    if (left == NULL || right == NULL) return 0;
    while (size-- != 0u) difference |= (uint8_t)(*left++ ^ *right++);
    return difference == 0u;
}

static uint32_t read_be32(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static int address_valid(const uint8_t address[4])
{
    return address != NULL && !all_zero(address, 4u) &&
           !(address[0] == 255u && address[1] == 255u &&
             address[2] == 255u && address[3] == 255u);
}

static int seconds_order_valid(const RinDhcpv4ReplyV1* reply)
{
    if (reply->message_type == RIN_DHCPV4_MESSAGE_NAK) return 1;
    if (reply->lease_seconds == 0u || reply->lease_seconds == UINT32_MAX)
        return 0;
    if (reply->renewal_seconds == 0u || reply->rebind_seconds == 0u ||
        reply->renewal_seconds >= reply->rebind_seconds ||
        reply->rebind_seconds >= reply->lease_seconds)
        return 0;
    return 1;
}

RinDhcpv4WireStatus rin_dhcpv4_parse_reply(
    const uint8_t* packet, uint32_t packet_size,
    uint32_t expected_transaction_id,
    const uint8_t client_hardware_address[6],
    RinDhcpv4ReplyV1* reply)
{
    uint32_t options_offset;
    uint32_t options_end;
    uint32_t option_count = 0u;
    uint32_t seen_message = 0u;
    uint32_t seen_server = 0u;
    uint32_t seen_lease = 0u;
    uint32_t seen_renewal = 0u;
    uint32_t seen_rebind = 0u;
    uint32_t seen_subnet = 0u;
    uint32_t seen_router = 0u;
    uint32_t seen_dns = 0u;
    uint32_t ended = 0u;
    RinDhcpv4ReplyV1 candidate = {0};
    if (reply != NULL) zero_bytes(reply, (uint32_t)sizeof(*reply));
    if (packet == NULL || client_hardware_address == NULL || reply == NULL ||
        packet_size < DHCPV4_FIXED_HEADER_SIZE + 4u ||
        packet_size > RIN_DHCPV4_MAX_PACKET_SIZE ||
        expected_transaction_id == 0u || all_zero(client_hardware_address, 6u))
        return RIN_DHCPV4_WIRE_INVALID_ARGUMENT;

    if (packet[0] != DHCPV4_OP_BOOTREPLY || packet[1] != DHCPV4_HTYPE_ETHERNET ||
        packet[2] != DHCPV4_HLEN_ETHERNET || packet[3] != 0u ||
        read_be32(packet + 4u) != expected_transaction_id ||
        !all_equal(packet + 28u, client_hardware_address, 6u) ||
        !all_zero(packet + 34u, 10u) ||
        read_be32(packet + DHCPV4_FIXED_HEADER_SIZE) != DHCPV4_MAGIC_COOKIE)
        return RIN_DHCPV4_WIRE_NOT_FOR_US;

    options_offset = DHCPV4_FIXED_HEADER_SIZE + 4u;
    options_end = packet_size;
    while (options_offset < options_end) {
        uint8_t code = packet[options_offset++];
        uint8_t length;
        const uint8_t* value;
        if (code == DHCPV4_OPTION_PAD) continue;
        if (code == DHCPV4_OPTION_END) {
            ended = 1u;
            while (options_offset < options_end) {
                if (packet[options_offset++] != DHCPV4_OPTION_PAD)
                    return RIN_DHCPV4_WIRE_MALFORMED;
            }
            break;
        }
        if (++option_count > DHCPV4_MAX_OPTIONS || options_offset >= options_end)
            return RIN_DHCPV4_WIRE_MALFORMED;
        length = packet[options_offset++];
        if (length > options_end - options_offset) return RIN_DHCPV4_WIRE_MALFORMED;
        value = packet + options_offset;
        switch (code) {
            case DHCPV4_OPTION_MESSAGE_TYPE:
                if (length != 1u || seen_message) return RIN_DHCPV4_WIRE_MALFORMED;
                candidate.message_type = value[0];
                if (candidate.message_type != RIN_DHCPV4_MESSAGE_OFFER &&
                    candidate.message_type != RIN_DHCPV4_MESSAGE_ACK &&
                    candidate.message_type != RIN_DHCPV4_MESSAGE_NAK)
                    return RIN_DHCPV4_WIRE_UNSUPPORTED;
                seen_message = 1u;
                break;
            case DHCPV4_OPTION_SERVER_IDENTIFIER:
                if (length != 4u || seen_server || !address_valid(value))
                    return RIN_DHCPV4_WIRE_MALFORMED;
                copy_bytes(candidate.server_identifier, value, 4u);
                seen_server = 1u;
                break;
            case DHCPV4_OPTION_SUBNET_MASK:
                if (length != 4u || seen_subnet) return RIN_DHCPV4_WIRE_MALFORMED;
                copy_bytes(candidate.subnet_mask, value, 4u);
                seen_subnet = 1u;
                break;
            case DHCPV4_OPTION_ROUTER:
                if (length != 4u || seen_router || !address_valid(value))
                    return RIN_DHCPV4_WIRE_MALFORMED;
                copy_bytes(candidate.router, value, 4u);
                seen_router = 1u;
                break;
            case DHCPV4_OPTION_DNS:
                if (length == 0u || (length % 4u) != 0u || seen_dns ||
                    length > RIN_DHCPV4_MAX_DNS_SERVERS * 4u)
                    return RIN_DHCPV4_WIRE_MALFORMED;
                candidate.dns_server_count = length / 4u;
                for (uint32_t index = 0u;
                     index < candidate.dns_server_count; ++index) {
                    if (!address_valid(value + index * 4u))
                        return RIN_DHCPV4_WIRE_MALFORMED;
                    copy_bytes(candidate.dns_servers[index],
                               value + index * 4u, 4u);
                }
                seen_dns = 1u;
                break;
            case DHCPV4_OPTION_LEASE_TIME:
                if (length != 4u || seen_lease) return RIN_DHCPV4_WIRE_MALFORMED;
                candidate.lease_seconds = read_be32(value);
                seen_lease = 1u;
                break;
            case DHCPV4_OPTION_RENEWAL_TIME:
                if (length != 4u || seen_renewal) return RIN_DHCPV4_WIRE_MALFORMED;
                candidate.renewal_seconds = read_be32(value);
                seen_renewal = 1u;
                break;
            case DHCPV4_OPTION_REBIND_TIME:
                if (length != 4u || seen_rebind) return RIN_DHCPV4_WIRE_MALFORMED;
                candidate.rebind_seconds = read_be32(value);
                seen_rebind = 1u;
                break;
            default:
                break;
        }
        options_offset += length;
    }
    if (!ended || !seen_message || !seen_server)
        return RIN_DHCPV4_WIRE_MALFORMED;
    if (candidate.message_type == RIN_DHCPV4_MESSAGE_NAK) {
        if (!all_zero(packet + 16u, 4u) || seen_lease || seen_renewal ||
            seen_rebind)
            return RIN_DHCPV4_WIRE_MALFORMED;
    } else {
        if (!address_valid(packet + 16u) || !seen_lease || !seen_renewal ||
            !seen_rebind || !seconds_order_valid(&candidate))
            return RIN_DHCPV4_WIRE_MALFORMED;
        copy_bytes(candidate.yiaddr, packet + 16u, 4u);
    }
    candidate.struct_size = (uint32_t)sizeof(candidate);
    candidate.version = RIN_DHCPV4_WIRE_VERSION;
    candidate.transaction_id = expected_transaction_id;
    candidate.options_seen = option_count;
    *reply = candidate;
    return RIN_DHCPV4_WIRE_OK;
}
