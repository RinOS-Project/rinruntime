/* SPDX-License-Identifier: MIT */
#include "rin_dhcpv6_transport.h"

#include <stddef.h>

#define DHCPV6_ETHERNET_HEADER_SIZE 14u
#define DHCPV6_IPV6_HEADER_SIZE 40u
#define DHCPV6_UDP_HEADER_SIZE 8u
#define DHCPV6_ETHERTYPE_IPV6 0x86ddu
#define DHCPV6_NEXT_HEADER_UDP 17u
#define DHCPV6_HOP_LIMIT 1u
#define DHCPV6_CLIENT_PORT 546u
#define DHCPV6_SERVER_PORT 547u
#define DHCPV6_MESSAGE_RECONFIGURE 10u

_Static_assert(sizeof(RinDhcpv6TransportConfigV1) == 48u,
               "DHCPv6 transport config ABI drift");

static void bytes_zero(void* pointer, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)pointer;
    while (size-- != 0u) *bytes++ = 0u;
}

static void bytes_copy(void* destination, const void* source, uint32_t size)
{
    uint8_t* target = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *target++ = *input++;
}

static int bytes_equal(const void* left, const void* right, uint32_t size)
{
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    while (size-- != 0u) difference |= (uint8_t)(*a++ ^ *b++);
    return difference == 0u;
}

static int bytes_all_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static int transport_memory_overlaps(const void* object, size_t object_size,
                                     const void* memory, size_t memory_size)
{
    uintptr_t object_address;
    uintptr_t memory_address;
    if (!object || !memory || object_size == 0u || memory_size == 0u)
        return 0;
    object_address = (uintptr_t)object;
    memory_address = (uintptr_t)memory;
    if (object_address <= memory_address)
        return memory_address - object_address < object_size;
    return object_address - memory_address < memory_size;
}

static uint16_t read_be16(const uint8_t* bytes)
{
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static void write_be16(uint8_t* bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void write_be32(uint8_t* bytes, uint32_t value)
{
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static int mac_valid(const uint8_t mac[6])
{
    return mac != NULL && (mac[0] & 1u) == 0u &&
           !bytes_all_zero(mac, 6u);
}

static int ipv6_unicast_valid(const uint8_t address[16])
{
    return address != NULL && address[0] != 0xffu &&
           !bytes_all_zero(address, 16u);
}

static int ipv6_link_local_valid(const uint8_t address[16])
{
    return ipv6_unicast_valid(address) && address[0] == 0xfeu &&
           (address[1] & 0xc0u) == 0x80u;
}

static int config_valid(const RinDhcpv6TransportConfigV1* config)
{
    return config != NULL &&
           config->version == RIN_DHCPV6_TRANSPORT_VERSION &&
           config->struct_size == sizeof(*config) &&
           config->interface_generation != 0u && mac_valid(config->mac) &&
           ipv6_link_local_valid(config->source_address) &&
           bytes_all_zero(config->reserved0, sizeof(config->reserved0)) &&
           config->client_mode <= RIN_DHCPV6_CLIENT_MODE_INFORMATION &&
           bytes_all_zero(config->reserved1, sizeof(config->reserved1));
}

static int state_valid(const RinDhcpv6TransportV1* state)
{
    return state != NULL && state->version == RIN_DHCPV6_TRANSPORT_VERSION &&
           state->struct_size == sizeof(*state) && state->initialized == 1u &&
           state->transport_generation != 0u && config_valid(&state->config) &&
           state->server_address_present <= 1u &&
           (state->server_address_present == 0u
                ? bytes_all_zero(state->server_address,
                                 sizeof(state->server_address))
                : ipv6_unicast_valid(state->server_address)) &&
           bytes_all_zero(state->reserved0, sizeof(state->reserved0)) &&
           rin_dhcpv6_client_state_valid(&state->client);
}

int rin_dhcpv6_transport_state_valid(const RinDhcpv6TransportV1* state)
{
    return state_valid(state);
}

static int config_equal(const RinDhcpv6TransportConfigV1* left,
                        const RinDhcpv6TransportConfigV1* right)
{
    return bytes_equal(left, right, sizeof(*left));
}

static void clear_server_address(RinDhcpv6TransportV1* state)
{
    state->server_address_present = 0u;
    bytes_zero(state->server_address, sizeof(state->server_address));
}

static int random_iaid(RinDhcpv6TransportRandomFn random_bytes,
                       void* random_context, uint32_t* iaid_out)
{
    uint8_t random[4];
    uint32_t attempt;
    if (!random_bytes || !iaid_out) return 0;
    for (attempt = 0u; attempt < 8u; ++attempt) {
        uint32_t value;
        if (random_bytes(random_context, random, sizeof(random)) != 0) break;
        value = ((uint32_t)random[0] << 24) |
                ((uint32_t)random[1] << 16) |
                ((uint32_t)random[2] << 8) | random[3];
        if (value != 0u) {
            *iaid_out = value;
            bytes_zero(random, sizeof(random));
            return 1;
        }
    }
    bytes_zero(random, sizeof(random));
    return 0;
}

static int random_transaction_id(const RinDhcpv6TransportV1* state,
                                 RinDhcpv6TransportRandomFn random_bytes,
                                 void* random_context,
                                 uint32_t* transaction_id_out)
{
    uint8_t random[3];
    uint32_t attempt;
    if (!state || !random_bytes || !transaction_id_out) return 0;
    for (attempt = 0u; attempt < 8u; ++attempt) {
        uint32_t value;
        if (random_bytes(random_context, random, sizeof(random)) != 0) break;
        value = ((uint32_t)random[0] << 16) |
                ((uint32_t)random[1] << 8) | random[2];
        if (value != 0u && value != state->client.transaction_id) {
            *transaction_id_out = value;
            bytes_zero(random, sizeof(random));
            return 1;
        }
    }
    bytes_zero(random, sizeof(random));
    return 0;
}

static int transmit_needs_new_transaction(const RinDhcpv6ClientV1* client,
                                          uint64_t now_ms)
{
    if (!client) return 0;
    if (client->state == RIN_DHCPV6_STATE_IDLE ||
        client->state == RIN_DHCPV6_STATE_ADVERTISED)
        return 1;
    if (client->state == RIN_DHCPV6_STATE_BOUND)
        return now_ms >= client->renew_at_ms;
    if (client->state == RIN_DHCPV6_STATE_INFORMATION_BOUND)
        return now_ms >= client->renew_at_ms;
    if (client->state ==
            RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
        client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING)
        return now_ms >= client->next_transmit_ms;
    return client->state == RIN_DHCPV6_STATE_RENEWING &&
           now_ms >= client->rebind_at_ms;
}

static int make_transmit(RinDhcpv6TransportV1* state,
                         RinDhcpv6TransportTransmitV1* transmit_out)
{
    uint32_t kind;
    if (!state_valid(state) || !transmit_out ||
        state->client.pending_present != 1u)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    kind = state->client.pending.kind;
    if (kind != RIN_DHCPV6_TRANSMIT_SOLICIT &&
        kind != RIN_DHCPV6_TRANSMIT_REQUEST &&
        kind != RIN_DHCPV6_TRANSMIT_RENEW &&
        kind != RIN_DHCPV6_TRANSMIT_REBIND &&
        kind != RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST)
        return RIN_DHCPV6_TRANSPORT_INVALID_STATE;
    bytes_zero(transmit_out, sizeof(*transmit_out));
    transmit_out->version = RIN_DHCPV6_TRANSPORT_VERSION;
    transmit_out->struct_size = sizeof(*transmit_out);
    transmit_out->client_transmit = state->client.pending;
    transmit_out->source_port = DHCPV6_CLIENT_PORT;
    transmit_out->destination_port = DHCPV6_SERVER_PORT;
    bytes_copy(transmit_out->source_mac, state->config.mac,
               sizeof(transmit_out->source_mac));
    bytes_copy(transmit_out->source_address, state->config.source_address,
               sizeof(transmit_out->source_address));
    if (kind == RIN_DHCPV6_TRANSMIT_SOLICIT ||
        kind == RIN_DHCPV6_TRANSMIT_REBIND ||
        kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        static const uint8_t all_servers_and_relays[16] = {
            0xffu, 0x02u, 0u, 0u, 0u, 0u, 0u, 0u,
            0u, 0u, 0u, 0u, 0u, 0x01u, 0u, 0x02u
        };
        transmit_out->destination_is_multicast = 1u;
        bytes_copy(transmit_out->destination_address,
                   all_servers_and_relays,
                   sizeof(transmit_out->destination_address));
    } else {
        if (state->server_address_present != 1u ||
            !ipv6_unicast_valid(state->server_address)) {
            bytes_zero(transmit_out, sizeof(*transmit_out));
            return RIN_DHCPV6_TRANSPORT_INVALID_STATE;
        }
        bytes_copy(transmit_out->destination_address, state->server_address,
                   sizeof(transmit_out->destination_address));
    }
    return RIN_DHCPV6_TRANSPORT_PACKET_READY;
}

static int transport_transmit_valid(
    const RinDhcpv6TransportTransmitV1* transmit)
{
    return transmit != NULL &&
           transmit->version == RIN_DHCPV6_TRANSPORT_VERSION &&
           transmit->struct_size == sizeof(*transmit) &&
           transmit->source_port == DHCPV6_CLIENT_PORT &&
           transmit->destination_port == DHCPV6_SERVER_PORT &&
           mac_valid(transmit->source_mac) &&
           (transmit->destination_is_multicast == 0u ||
            transmit->destination_is_multicast == 1u) &&
           transmit->reserved0 == 0u &&
           ipv6_link_local_valid(transmit->source_address) &&
           ((transmit->destination_is_multicast == 1u &&
             transmit->destination_address[0] == 0xffu) ||
            (transmit->destination_is_multicast == 0u &&
             ipv6_unicast_valid(transmit->destination_address))) &&
           transmit->client_transmit.version == RIN_DHCPV6_CLIENT_VERSION &&
           transmit->client_transmit.struct_size ==
               sizeof(transmit->client_transmit) &&
           transmit->client_transmit.message_size >= 4u &&
           transmit->client_transmit.message_size <=
               RIN_DHCPV6_MAX_MESSAGE_SIZE;
}

static int datagram_envelope_valid(
    const RinDhcpv6TransportV1* state, const uint8_t source_address[16],
    uint16_t source_port, const uint8_t destination_address[16],
    uint16_t destination_port, const uint8_t* message, uint32_t message_size)
{
    int local_destination;
    if (!state_valid(state) || !source_address || !destination_address ||
        !message)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (message_size < 4u || message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE)
        return RIN_DHCPV6_TRANSPORT_MALFORMED_FRAME;
    if (source_port != DHCPV6_SERVER_PORT ||
        destination_port != DHCPV6_CLIENT_PORT ||
        !ipv6_unicast_valid(source_address))
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    local_destination = bytes_equal(
        destination_address, state->config.source_address,
        sizeof(state->config.source_address)) ||
        (ipv6_unicast_valid(state->client.address) &&
         bytes_equal(destination_address, state->client.address,
                     sizeof(state->client.address)));
    return local_destination ? RIN_DHCPV6_TRANSPORT_OK
                             : RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t* bytes,
                             uint32_t size)
{
    while (size >= 2u) {
        sum += ((uint32_t)bytes[0] << 8) | bytes[1];
        bytes += 2u;
        size -= 2u;
    }
    if (size != 0u) sum += (uint32_t)bytes[0] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while ((sum >> 16) != 0u) sum = (sum & 0xffffu) + (sum >> 16);
    sum = ~sum & 0xffffu;
    return sum == 0u ? 0xffffu : (uint16_t)sum;
}

static uint16_t udp_checksum(const uint8_t source[16],
                             const uint8_t destination[16],
                             const uint8_t* udp, uint32_t udp_size)
{
    uint8_t length[4];
    const uint8_t next_header[4] = {0u, 0u, 0u, DHCPV6_NEXT_HEADER_UDP};
    uint32_t sum = 0u;
    write_be32(length, udp_size);
    sum = checksum_add(sum, source, 16u);
    sum = checksum_add(sum, destination, 16u);
    sum = checksum_add(sum, length, sizeof(length));
    sum = checksum_add(sum, next_header, sizeof(next_header));
    sum = checksum_add(sum, udp, udp_size);
    return checksum_finish(sum);
}

int rin_dhcpv6_transport_init(
    RinDhcpv6TransportV1* state, const RinDhcpv6TransportConfigV1* config,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context)
{
    RinDhcpv6TransportConfigV1 config_snapshot;
    uint8_t duid[10];
    uint32_t iaid;
    if (!state || !config_valid(config) || !random_bytes)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    config_snapshot = *config;
    if (!random_iaid(random_bytes, random_context, &iaid))
        return RIN_DHCPV6_TRANSPORT_RANDOM_FAILURE;
    bytes_zero(duid, sizeof(duid));
    duid[1] = 3u; /* DUID-LL */
    duid[3] = 1u; /* ARPHRD_ETHER */
    bytes_copy(duid + 4u, config_snapshot.mac, 6u);
    bytes_zero(state, sizeof(*state));
    state->version = RIN_DHCPV6_TRANSPORT_VERSION;
    state->struct_size = sizeof(*state);
    state->initialized = 1u;
    state->transport_generation = 1u;
    state->config = config_snapshot;
    if (rin_dhcpv6_client_init(&state->client, duid, sizeof(duid), iaid,
                               state->config.interface_generation) !=
        RIN_DHCPV6_OK) {
        bytes_zero(state, sizeof(*state));
        bytes_zero(duid, sizeof(duid));
        return RIN_DHCPV6_TRANSPORT_INVALID_STATE;
    }
    if (rin_dhcpv6_client_set_mode(
            &state->client,
            (RinDhcpv6ClientMode)state->config.client_mode) !=
        RIN_DHCPV6_OK) {
        bytes_zero(state, sizeof(*state));
        bytes_zero(duid, sizeof(duid));
        return RIN_DHCPV6_TRANSPORT_INVALID_STATE;
    }
    bytes_zero(duid, sizeof(duid));
    return RIN_DHCPV6_TRANSPORT_OK;
}

int rin_dhcpv6_transport_reconfigure(
    RinDhcpv6TransportV1* state, const RinDhcpv6TransportConfigV1* config,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context)
{
    int result;
    if (!state || !config_valid(config) || !random_bytes)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (state_valid(state) && config_equal(&state->config, config))
        return RIN_DHCPV6_TRANSPORT_OK;
    result = rin_dhcpv6_transport_init(state, config, random_bytes,
                                       random_context);
    return result == RIN_DHCPV6_TRANSPORT_OK
        ? RIN_DHCPV6_TRANSPORT_RECONFIGURED : result;
}

int rin_dhcpv6_transport_prepare(
    RinDhcpv6TransportV1* state, uint64_t now_ms,
    RinDhcpv6TransportRandomFn random_bytes, void* random_context,
    RinDhcpv6TransportTransmitV1* transmit_out)
{
    uint32_t transaction_id = 1u;
    RinDhcpv6TransmitV1 client_transmit;
    int status;
    if (transmit_out) bytes_zero(transmit_out, sizeof(*transmit_out));
    if (!state_valid(state) || !transmit_out || !random_bytes)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (state->client.pending_present == 1u)
        return make_transmit(state, transmit_out);
    if (transmit_needs_new_transaction(&state->client, now_ms) &&
        !random_transaction_id(state, random_bytes, random_context,
                               &transaction_id))
        return RIN_DHCPV6_TRANSPORT_RANDOM_FAILURE;
    bytes_zero(&client_transmit, sizeof(client_transmit));
    status = rin_dhcpv6_client_prepare(&state->client, transaction_id, now_ms,
                                        &client_transmit);
    bytes_zero(&client_transmit, sizeof(client_transmit));
    if (status == RIN_DHCPV6_LEASE_EXPIRED) clear_server_address(state);
    if (status != RIN_DHCPV6_PACKET_READY) return status;
    return make_transmit(state, transmit_out);
}

int rin_dhcpv6_transport_complete_transmit(
    RinDhcpv6TransportV1* state,
    const RinDhcpv6TransportTransmitV1* transmit, int sent_successfully)
{
    if (!state_valid(state) || !transport_transmit_valid(transmit) ||
        (sent_successfully != 0 && sent_successfully != 1) ||
        !bytes_equal(transmit->source_address, state->config.source_address,
                     sizeof(state->config.source_address)) ||
        !bytes_equal(transmit->source_mac, state->config.mac,
                     sizeof(state->config.mac)))
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    return rin_dhcpv6_client_complete_transmit(&state->client,
                                               &transmit->client_transmit,
                                               sent_successfully);
}

int rin_dhcpv6_transport_serialize(
    const RinDhcpv6TransportTransmitV1* transmit,
    const uint8_t destination_mac[6], uint8_t* frame_out,
    uint32_t frame_capacity, uint32_t* frame_size_out)
{
    const uint32_t payload_size = transmit
        ? transmit->client_transmit.message_size : 0u;
    const uint32_t udp_size = DHCPV6_UDP_HEADER_SIZE + payload_size;
    const uint32_t frame_size = DHCPV6_ETHERNET_HEADER_SIZE +
        DHCPV6_IPV6_HEADER_SIZE + udp_size;
    uint8_t* ipv6;
    uint8_t* udp;
    uint16_t checksum;
    if (frame_size_out) *frame_size_out = 0u;
    if (!transport_transmit_valid(transmit) || !destination_mac ||
        bytes_all_zero(destination_mac, 6u) || !frame_out ||
        frame_capacity < frame_size || frame_size > RIN_DHCPV6_TRANSPORT_FRAME_SIZE)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    bytes_zero(frame_out, frame_size);
    bytes_copy(frame_out, destination_mac, 6u);
    bytes_copy(frame_out + 6u, transmit->source_mac, 6u);
    write_be16(frame_out + 12u, DHCPV6_ETHERTYPE_IPV6);
    ipv6 = frame_out + DHCPV6_ETHERNET_HEADER_SIZE;
    ipv6[0] = 0x60u;
    write_be16(ipv6 + 4u, (uint16_t)udp_size);
    ipv6[6] = DHCPV6_NEXT_HEADER_UDP;
    ipv6[7] = DHCPV6_HOP_LIMIT;
    bytes_copy(ipv6 + 8u, transmit->source_address, 16u);
    bytes_copy(ipv6 + 24u, transmit->destination_address, 16u);
    udp = ipv6 + DHCPV6_IPV6_HEADER_SIZE;
    write_be16(udp, transmit->source_port);
    write_be16(udp + 2u, transmit->destination_port);
    write_be16(udp + 4u, (uint16_t)udp_size);
    bytes_copy(udp + DHCPV6_UDP_HEADER_SIZE, transmit->client_transmit.message,
               payload_size);
    checksum = udp_checksum(transmit->source_address,
                            transmit->destination_address, udp, udp_size);
    write_be16(udp + 6u, checksum);
    if (frame_size_out) *frame_size_out = frame_size;
    return RIN_DHCPV6_TRANSPORT_OK;
}

int rin_dhcpv6_transport_receive_frame(
    RinDhcpv6TransportV1* state, const uint8_t* frame,
    uint32_t frame_size, uint64_t now_ms)
{
    const uint8_t* ipv6;
    const uint8_t* udp;
    uint32_t payload_size;
    uint32_t udp_size;
    int status;
    if (!state_valid(state) || !frame ||
        frame_size < DHCPV6_ETHERNET_HEADER_SIZE + DHCPV6_IPV6_HEADER_SIZE +
                         DHCPV6_UDP_HEADER_SIZE + 4u)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (!bytes_equal(frame, state->config.mac, 6u) ||
        read_be16(frame + 12u) != DHCPV6_ETHERTYPE_IPV6)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    ipv6 = frame + DHCPV6_ETHERNET_HEADER_SIZE;
    if ((ipv6[0] >> 4) != 6u || ipv6[6] != DHCPV6_NEXT_HEADER_UDP ||
        ipv6[7] != DHCPV6_HOP_LIMIT ||
        !ipv6_unicast_valid(ipv6 + 8u) ||
        !bytes_equal(ipv6 + 24u, state->config.source_address, 16u))
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    payload_size = read_be16(ipv6 + 4u);
    if (payload_size < DHCPV6_UDP_HEADER_SIZE + 4u ||
        payload_size != frame_size - DHCPV6_ETHERNET_HEADER_SIZE -
                            DHCPV6_IPV6_HEADER_SIZE)
        return RIN_DHCPV6_TRANSPORT_MALFORMED_FRAME;
    udp = ipv6 + DHCPV6_IPV6_HEADER_SIZE;
    udp_size = read_be16(udp + 4u);
    if (udp_size != payload_size || read_be16(udp) != DHCPV6_SERVER_PORT ||
        read_be16(udp + 2u) != DHCPV6_CLIENT_PORT)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    if (read_be16(udp + 6u) == 0u)
        return RIN_DHCPV6_TRANSPORT_CHECKSUM_FAILURE;
    if (udp_checksum(ipv6 + 8u, ipv6 + 24u, udp, udp_size) != 0xffffu)
        return RIN_DHCPV6_TRANSPORT_CHECKSUM_FAILURE;
    status = rin_dhcpv6_client_receive(
        &state->client, udp + DHCPV6_UDP_HEADER_SIZE,
        udp_size - DHCPV6_UDP_HEADER_SIZE, now_ms);
    if (status == RIN_DHCPV6_OFFER_READY || status == RIN_DHCPV6_LEASE_READY) {
        bytes_copy(state->server_address, ipv6 + 8u,
                   sizeof(state->server_address));
        state->server_address_present = 1u;
    }
    return status;
}

int rin_dhcpv6_transport_receive_datagram(
    RinDhcpv6TransportV1* state, const uint8_t source_address[16],
    uint16_t source_port, const uint8_t destination_address[16],
    uint16_t destination_port, const uint8_t* message,
    uint32_t message_size, uint64_t now_ms)
{
    int status;
    status = datagram_envelope_valid(
        state, source_address, source_port, destination_address,
        destination_port, message, message_size);
    if (status != RIN_DHCPV6_TRANSPORT_OK) return status;
    if (message[0] == DHCPV6_MESSAGE_RECONFIGURE)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    status = rin_dhcpv6_client_receive(&state->client, message, message_size,
                                       now_ms);
    if (status == RIN_DHCPV6_OFFER_READY || status == RIN_DHCPV6_LEASE_READY) {
        bytes_copy(state->server_address, source_address,
                   sizeof(state->server_address));
        state->server_address_present = 1u;
    }
    return status;
}

int rin_dhcpv6_transport_validate_reconfigure_frame(
    const RinDhcpv6TransportV1* state, const uint8_t* frame,
    uint32_t frame_size, const uint8_t** message_out,
    uint32_t* message_size_out)
{
    const uint8_t* ipv6;
    const uint8_t* udp;
    uint32_t payload_size;
    uint32_t udp_size;
    int local_destination;
    if (message_out) *message_out = NULL;
    if (message_size_out) *message_size_out = 0u;
    if (!state_valid(state) || !frame || !message_out || !message_size_out ||
        frame_size < DHCPV6_ETHERNET_HEADER_SIZE + DHCPV6_IPV6_HEADER_SIZE +
                         DHCPV6_UDP_HEADER_SIZE + 4u)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (!bytes_equal(frame, state->config.mac, 6u) ||
        read_be16(frame + 12u) != DHCPV6_ETHERTYPE_IPV6)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    ipv6 = frame + DHCPV6_ETHERNET_HEADER_SIZE;
    if ((ipv6[0] >> 4) != 6u || ipv6[6] != DHCPV6_NEXT_HEADER_UDP ||
        ipv6[7] != DHCPV6_HOP_LIMIT || !ipv6_unicast_valid(ipv6 + 8u))
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    local_destination = bytes_equal(ipv6 + 24u, state->config.source_address,
                                    sizeof(state->config.source_address)) ||
        (ipv6_unicast_valid(state->client.address) &&
         bytes_equal(ipv6 + 24u, state->client.address,
                     sizeof(state->client.address)));
    if (!local_destination) return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    payload_size = read_be16(ipv6 + 4u);
    if (payload_size < DHCPV6_UDP_HEADER_SIZE + 4u ||
        payload_size != frame_size - DHCPV6_ETHERNET_HEADER_SIZE -
                            DHCPV6_IPV6_HEADER_SIZE)
        return RIN_DHCPV6_TRANSPORT_MALFORMED_FRAME;
    udp = ipv6 + DHCPV6_IPV6_HEADER_SIZE;
    udp_size = read_be16(udp + 4u);
    if (udp_size != payload_size || read_be16(udp) != DHCPV6_SERVER_PORT ||
        read_be16(udp + 2u) != DHCPV6_CLIENT_PORT)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    if (read_be16(udp + 6u) == 0u ||
        udp_checksum(ipv6 + 8u, ipv6 + 24u, udp, udp_size) != 0xffffu)
        return RIN_DHCPV6_TRANSPORT_CHECKSUM_FAILURE;
    if (udp[DHCPV6_UDP_HEADER_SIZE] != DHCPV6_MESSAGE_RECONFIGURE)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    *message_out = udp + DHCPV6_UDP_HEADER_SIZE;
    *message_size_out = udp_size - DHCPV6_UDP_HEADER_SIZE;
    return RIN_DHCPV6_TRANSPORT_OK;
}

int rin_dhcpv6_transport_validate_reconfigure_datagram(
    const RinDhcpv6TransportV1* state, const uint8_t source_address[16],
    uint16_t source_port, const uint8_t destination_address[16],
    uint16_t destination_port, const uint8_t* message,
    uint32_t message_size, const uint8_t** message_out,
    uint32_t* message_size_out)
{
    int status;
    if (message_out) *message_out = NULL;
    if (message_size_out) *message_size_out = 0u;
    if (!message_out || !message_size_out)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    status = datagram_envelope_valid(
        state, source_address, source_port, destination_address,
        destination_port, message, message_size);
    if (status != RIN_DHCPV6_TRANSPORT_OK) return status;
    if (message[0] != DHCPV6_MESSAGE_RECONFIGURE)
        return RIN_DHCPV6_TRANSPORT_NOT_FOR_US;
    *message_out = message;
    *message_size_out = message_size;
    return RIN_DHCPV6_TRANSPORT_OK;
}

int rin_dhcpv6_transport_get_lease(
    RinDhcpv6TransportV1* state, uint64_t now_ms,
    RinDhcpv6LeaseV1* lease_out)
{
    int status;
    if (transport_memory_overlaps(state, sizeof(*state), lease_out,
                                  sizeof(*lease_out)))
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    if (lease_out) bytes_zero(lease_out, sizeof(*lease_out));
    if (!state_valid(state) || !lease_out)
        return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    status = rin_dhcpv6_client_get_lease(&state->client, now_ms, lease_out);
    if (status == RIN_DHCPV6_LEASE_EXPIRED) clear_server_address(state);
    return status;
}

int rin_dhcpv6_transport_stop(RinDhcpv6TransportV1* state)
{
    int status;
    if (!state_valid(state)) return RIN_DHCPV6_TRANSPORT_INVALID_ARGUMENT;
    status = rin_dhcpv6_client_stop(&state->client);
    if (status == RIN_DHCPV6_OK) clear_server_address(state);
    return status;
}

void rin_dhcpv6_transport_destroy(RinDhcpv6TransportV1* state)
{
    if (state) bytes_zero(state, sizeof(*state));
}
