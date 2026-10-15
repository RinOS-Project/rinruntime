/* SPDX-License-Identifier: MIT */
#include "rin_dhcpv6_client.h"

#include <limits.h>
#include <stddef.h>

#define DHCPV6_MESSAGE_ADVERTISE 2u
#define DHCPV6_MESSAGE_REPLY 7u

#define DHCPV6_OPTION_CLIENT_ID 1u
#define DHCPV6_OPTION_SERVER_ID 2u
#define DHCPV6_OPTION_IA_NA 3u
#define DHCPV6_OPTION_IA_ADDRESS 5u
#define DHCPV6_OPTION_ORO 6u
#define DHCPV6_OPTION_PREFERENCE 7u
#define DHCPV6_OPTION_ELAPSED_TIME 8u
#define DHCPV6_OPTION_STATUS_CODE 13u
#define DHCPV6_OPTION_RECONFIGURE_ACCEPT 20u
#define DHCPV6_OPTION_DNS_SERVERS 23u
#define DHCPV6_OPTION_INFORMATION_REFRESH_TIME 32u

#define DHCPV6_DNS_OPTION_CODE 23u
#define DHCPV6_MIN_VALID_SECONDS 60u
#define DHCPV6_MAX_VALID_SECONDS (30u * 24u * 60u * 60u)
#define DHCPV6_INITIAL_RETRY_MS UINT64_C(1000)
#define DHCPV6_MAX_RETRY_MS UINT64_C(120000)
#define DHCPV6_MAX_OPTIONS 32u
#define DHCPV6_MAX_NESTED_OPTIONS 16u
#define DHCPV6_INFORMATION_REFRESH_DEFAULT_SECONDS (24u * 60u * 60u)
#define DHCPV6_INFORMATION_REFRESH_MIN_SECONDS 600u
#define DHCPV6_INFORMATION_REFRESH_MAX_SECONDS \
    (24u * 60u * 60u)

_Static_assert(sizeof(RinDhcpv6TransmitV1) == 552u,
               "DHCPv6 transmit ABI drift");
_Static_assert(sizeof(RinDhcpv6LeaseV1) == 128u,
               "DHCPv6 lease ABI drift");
_Static_assert(sizeof(RinDhcpv6ClientV1) == 840u,
               "DHCPv6 client ABI drift");

typedef struct MessageWriter {
    uint8_t* bytes;
    uint32_t size;
    uint32_t capacity;
} MessageWriter;

typedef struct ParsedMessage {
    const uint8_t* client_duid;
    uint32_t client_duid_size;
    const uint8_t* server_duid;
    uint32_t server_duid_size;
    uint8_t address[16];
    uint8_t dns_servers[RIN_DHCPV6_MAX_DNS_SERVERS][16];
    uint32_t dns_server_count;
    uint32_t preferred_seconds;
    uint32_t valid_seconds;
    uint32_t t1_seconds;
    uint32_t t2_seconds;
    uint32_t status_code;
    uint32_t iaid;
    uint32_t client_seen;
    uint32_t server_seen;
    uint32_t ia_seen;
    uint32_t address_seen;
    uint32_t dns_seen;
    uint32_t status_seen;
    uint32_t preference_seen;
    uint32_t information_refresh_seconds;
    uint32_t information_refresh_seen;
} ParsedMessage;

static void byte_zero(void* value, size_t size) {
    volatile uint8_t* output = (volatile uint8_t*)value;
    while (size != 0u) {
        *output++ = 0u;
        --size;
    }
}

static void byte_copy(void* destination, const void* source, size_t size) {
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size != 0u) {
        *output++ = *input++;
        --size;
    }
}

static int byte_equal(const void* left, const void* right, size_t size) {
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    while (size != 0u) {
        difference |= (uint8_t)(*a++ ^ *b++);
        --size;
    }
    return difference == 0u;
}

static int byte_tail_zero(const uint8_t* bytes, uint32_t offset,
                          uint32_t capacity) {
    while (offset < capacity) {
        if (bytes[offset++] != 0u) return 0;
    }
    return 1;
}

static int byte_all_zero(const void* value, size_t size) {
    const uint8_t* bytes = (const uint8_t*)value;
    while (size != 0u) {
        if (*bytes++ != 0u) return 0;
        --size;
    }
    return 1;
}

static int memory_overlaps(const void* object, size_t object_size,
                           const void* memory, size_t memory_size) {
    uintptr_t object_address;
    uintptr_t memory_address;
    if (!object || !memory || object_size == 0u || memory_size == 0u) return 0;
    object_address = (uintptr_t)object;
    memory_address = (uintptr_t)memory;
    if (object_address <= memory_address)
        return memory_address - object_address < object_size;
    return object_address - memory_address < memory_size;
}

static uint16_t load_be16(const uint8_t* bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
}

static uint32_t load_be32(const uint8_t* bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[2] << 8) | bytes[3];
}

static void store_be16(uint8_t* bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static void store_be32(uint8_t* bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static int duid_valid(const uint8_t* duid, uint32_t size) {
    uint16_t type;
    uint32_t index;
    uint8_t any_payload = 0u;
    if (!duid || size < 5u || size > RIN_DHCPV6_MAX_DUID_SIZE) return 0;
    type = load_be16(duid);
    if ((type == 1u && size < 9u) || (type == 2u && size < 7u) ||
        (type == 3u && size < 5u) || (type == 4u && size != 18u) ||
        type == 0u || type > 4u)
        return 0;
    for (index = 2u; index < size; ++index) any_payload |= duid[index];
    return any_payload != 0u;
}

static int address_usable(const uint8_t address[16]) {
    uint32_t index;
    uint8_t any = 0u;
    if (!address || address[0] == 0xffu ||
        (address[0] == 0xfeu && (address[1] & 0xc0u) == 0x80u))
        return 0;
    for (index = 0u; index < 16u; ++index) any |= address[index];
    return any != 0u;
}

static int dns_address_usable(const uint8_t address[16]) {
    return address_usable(address);
}

static int lifetimes_normalize(uint32_t valid, uint32_t preferred,
                               uint32_t* t1, uint32_t* t2) {
    if (!t1 || !t2 || valid < DHCPV6_MIN_VALID_SECONDS ||
        valid > DHCPV6_MAX_VALID_SECONDS || preferred > valid)
        return 0;
    if (*t1 == 0u && *t2 == 0u) {
        *t1 = valid / 2u;
        *t2 = (valid / 5u) * 4u;
        if (*t2 >= valid) *t2 = valid - 1u;
    } else if (*t1 == 0u || *t2 == 0u) {
        return 0;
    }
    return *t1 != 0u && *t1 < *t2 && *t2 < valid;
}

static int information_refresh_normalize(uint32_t refresh_seconds,
                                         uint32_t* normalized_out) {
    if (!normalized_out) return 0;
    if (refresh_seconds == 0u)
        refresh_seconds = DHCPV6_INFORMATION_REFRESH_DEFAULT_SECONDS;
    if (refresh_seconds < DHCPV6_INFORMATION_REFRESH_MIN_SECONDS)
        refresh_seconds = DHCPV6_INFORMATION_REFRESH_MIN_SECONDS;
    if (refresh_seconds > DHCPV6_INFORMATION_REFRESH_MAX_SECONDS)
        refresh_seconds = DHCPV6_INFORMATION_REFRESH_MAX_SECONDS;
    *normalized_out = refresh_seconds;
    return 1;
}

static int deadline_from_seconds(uint64_t now_ms, uint32_t seconds,
                                 uint64_t* deadline_out) {
    uint64_t duration;
    if (!deadline_out) return 0;
    duration = (uint64_t)seconds * UINT64_C(1000);
    if (now_ms > UINT64_MAX - duration) return 0;
    *deadline_out = now_ms + duration;
    return 1;
}

static int append_bytes(MessageWriter* writer, const void* bytes,
                        uint32_t size) {
    if (!writer || writer->size > writer->capacity ||
        (size != 0u && !bytes) || size > writer->capacity - writer->size)
        return 0;
    byte_copy(writer->bytes + writer->size, bytes, size);
    writer->size += size;
    return 1;
}

static int append_option(MessageWriter* writer, uint16_t code,
                         const void* value, uint16_t size) {
    uint8_t header[4];
    store_be16(header, code);
    store_be16(header + 2u, size);
    return append_bytes(writer, header, sizeof(header)) &&
           append_bytes(writer, value, size);
}

static int append_ia_na(MessageWriter* writer, const RinDhcpv6ClientV1* client,
                        int include_address) {
    uint8_t option[40];
    uint16_t size = 12u;
    byte_zero(option, sizeof(option));
    store_be32(option, client->iaid);
    if (include_address) {
        store_be32(option + 4u, client->offer_t1_seconds);
        store_be32(option + 8u, client->offer_t2_seconds);
        store_be16(option + 12u, DHCPV6_OPTION_IA_ADDRESS);
        store_be16(option + 14u, 24u);
        byte_copy(option + 16u, client->address, 16u);
        store_be32(option + 32u, client->offer_preferred_seconds);
        store_be32(option + 36u, client->offer_valid_seconds);
        size = 40u;
    }
    return append_option(writer, DHCPV6_OPTION_IA_NA, option, size);
}

static int build_message(const RinDhcpv6ClientV1* client, uint32_t kind,
                         uint32_t transaction_id, uint64_t now_ms,
                         RinDhcpv6TransmitV1* transmit) {
    uint8_t elapsed[2];
    uint8_t oro[2];
    uint64_t elapsed_centiseconds;
    MessageWriter writer;
    int include_server;
    int include_address;
    if (!client || !transmit || transaction_id == 0u ||
        transaction_id > UINT32_C(0x00ffffff))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    byte_zero(transmit, sizeof(*transmit));
    transmit->version = RIN_DHCPV6_CLIENT_VERSION;
    transmit->struct_size = sizeof(*transmit);
    transmit->owner_generation = client->generation;
    transmit->prepared_at_ms = now_ms;
    transmit->kind = kind;
    writer.bytes = transmit->message;
    writer.size = 0u;
    writer.capacity = sizeof(transmit->message);
    transmit->message[0] = (uint8_t)kind;
    transmit->message[1] = (uint8_t)(transaction_id >> 16);
    transmit->message[2] = (uint8_t)(transaction_id >> 8);
    transmit->message[3] = (uint8_t)transaction_id;
    writer.size = 4u;
    if (!append_option(&writer, DHCPV6_OPTION_CLIENT_ID,
                       client->duid, (uint16_t)client->duid_size))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    include_server = kind == RIN_DHCPV6_TRANSMIT_REQUEST ||
                     kind == RIN_DHCPV6_TRANSMIT_RENEW;
    if (include_server &&
        !append_option(&writer, DHCPV6_OPTION_SERVER_ID,
                       client->server_duid,
                       (uint16_t)client->server_duid_size))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    elapsed_centiseconds = transaction_id == client->transaction_id &&
            now_ms >= client->transaction_started_ms
        ? (now_ms - client->transaction_started_ms) / UINT64_C(10) : 0u;
    if (elapsed_centiseconds > UINT16_MAX) elapsed_centiseconds = UINT16_MAX;
    store_be16(elapsed, (uint16_t)elapsed_centiseconds);
    if (!append_option(&writer, DHCPV6_OPTION_ELAPSED_TIME,
                       elapsed, sizeof(elapsed)))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    include_address = kind != RIN_DHCPV6_TRANSMIT_SOLICIT &&
                      kind != RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST;
    if (kind != RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
        !append_ia_na(&writer, client, include_address))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    store_be16(oro, DHCPV6_DNS_OPTION_CODE);
    if (!append_option(&writer, DHCPV6_OPTION_ORO, oro, sizeof(oro)))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    /* RFC 8415 defaults a client to unwilling to receive Reconfigure.  We
     * advertise acceptance only because the product owner validates RKAP
     * before it can request a follow-up exchange. */
    if (!append_option(&writer, DHCPV6_OPTION_RECONFIGURE_ACCEPT, NULL, 0u))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    transmit->message_size = writer.size;
    return RIN_DHCPV6_OK;
}

static int parse_ia_na(const uint8_t* value, uint32_t size,
                       ParsedMessage* parsed) {
    uint32_t offset = 12u;
    uint32_t option_count = 0u;
    uint32_t nested_status_seen = 0u;
    if (!value || !parsed || size < 12u) return RIN_DHCPV6_MALFORMED_PACKET;
    parsed->iaid = load_be32(value);
    parsed->t1_seconds = load_be32(value + 4u);
    parsed->t2_seconds = load_be32(value + 8u);
    while (offset < size) {
        uint16_t code;
        uint16_t length;
        const uint8_t* option;
        if (++option_count > DHCPV6_MAX_NESTED_OPTIONS || size - offset < 4u)
            return RIN_DHCPV6_MALFORMED_PACKET;
        code = load_be16(value + offset);
        length = load_be16(value + offset + 2u);
        offset += 4u;
        if ((uint32_t)length > size - offset)
            return RIN_DHCPV6_MALFORMED_PACKET;
        option = value + offset;
        if (code == DHCPV6_OPTION_IA_ADDRESS) {
            if (parsed->address_seen || length != 24u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            byte_copy(parsed->address, option, 16u);
            parsed->preferred_seconds = load_be32(option + 16u);
            parsed->valid_seconds = load_be32(option + 20u);
            parsed->address_seen = 1u;
        } else if (code == DHCPV6_OPTION_STATUS_CODE) {
            if (nested_status_seen || length < 2u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            nested_status_seen = 1u;
            if (load_be16(option) != 0u)
                parsed->status_code = load_be16(option);
        }
        offset += length;
    }
    return offset == size ? RIN_DHCPV6_OK : RIN_DHCPV6_MALFORMED_PACKET;
}

static int parse_message(const uint8_t* message, uint32_t size,
                         uint8_t expected_type, int require_ia,
                         ParsedMessage* parsed) {
    uint32_t offset = 4u;
    uint32_t option_count = 0u;
    if (!message || !parsed || size < 4u || size > RIN_DHCPV6_MAX_MESSAGE_SIZE ||
        message[0] != expected_type)
        return RIN_DHCPV6_MALFORMED_PACKET;
    byte_zero(parsed, sizeof(*parsed));
    while (offset < size) {
        uint16_t code;
        uint16_t length;
        const uint8_t* value;
        int status;
        if (++option_count > DHCPV6_MAX_OPTIONS || size - offset < 4u)
            return RIN_DHCPV6_MALFORMED_PACKET;
        code = load_be16(message + offset);
        length = load_be16(message + offset + 2u);
        offset += 4u;
        if ((uint32_t)length > size - offset)
            return RIN_DHCPV6_MALFORMED_PACKET;
        value = message + offset;
        if (code == DHCPV6_OPTION_CLIENT_ID) {
            if (parsed->client_seen || !duid_valid(value, length))
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->client_seen = 1u;
            parsed->client_duid = value;
            parsed->client_duid_size = length;
        } else if (code == DHCPV6_OPTION_SERVER_ID) {
            if (parsed->server_seen || !duid_valid(value, length))
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->server_seen = 1u;
            parsed->server_duid = value;
            parsed->server_duid_size = length;
        } else if (code == DHCPV6_OPTION_IA_NA) {
            if (parsed->ia_seen) return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->ia_seen = 1u;
            status = parse_ia_na(value, length, parsed);
            if (status != RIN_DHCPV6_OK) return status;
        } else if (code == DHCPV6_OPTION_DNS_SERVERS) {
            uint32_t index;
            if (parsed->dns_seen || length == 0u || length % 16u != 0u ||
                length / 16u > RIN_DHCPV6_MAX_DNS_SERVERS)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->dns_seen = 1u;
            parsed->dns_server_count = length / 16u;
            for (index = 0u; index < parsed->dns_server_count; ++index) {
                uint32_t previous;
                if (!dns_address_usable(value + index * 16u))
                    return RIN_DHCPV6_MALFORMED_PACKET;
                for (previous = 0u; previous < index; ++previous) {
                    if (byte_equal(value + index * 16u,
                                   value + previous * 16u, 16u))
                        return RIN_DHCPV6_MALFORMED_PACKET;
                }
                byte_copy(parsed->dns_servers[index],
                          value + index * 16u, 16u);
            }
        } else if (code == DHCPV6_OPTION_STATUS_CODE) {
            if (parsed->status_seen || length < 2u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->status_seen = 1u;
            if (load_be16(value) != 0u)
                parsed->status_code = load_be16(value);
        } else if (code == DHCPV6_OPTION_PREFERENCE) {
            if (parsed->preference_seen || length != 1u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->preference_seen = 1u;
        } else if (code == DHCPV6_OPTION_INFORMATION_REFRESH_TIME) {
            if (parsed->information_refresh_seen || length != 4u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->information_refresh_seen = 1u;
            parsed->information_refresh_seconds = load_be32(value);
        }
        offset += length;
    }
    if (offset != size || !parsed->client_seen || !parsed->server_seen ||
        (require_ia && (!parsed->ia_seen || !parsed->address_seen)) ||
        (!require_ia && (parsed->ia_seen || parsed->address_seen)))
        return RIN_DHCPV6_MALFORMED_PACKET;
    return parsed->status_code == 0u ? RIN_DHCPV6_OK
                                     : RIN_DHCPV6_SERVER_REJECTED;
}

static void clear_pending(RinDhcpv6ClientV1* client) {
    client->pending_present = 0u;
    byte_zero(&client->pending, sizeof(client->pending));
}

static void clear_dynamic(RinDhcpv6ClientV1* client) {
    client->state = RIN_DHCPV6_STATE_IDLE;
    client->transaction_started_ms = 0u;
    client->next_transmit_ms = 0u;
    client->retry_ms = 0u;
    client->lease_generation = 0u;
    client->preferred_until_ms = 0u;
    client->renew_at_ms = 0u;
    client->rebind_at_ms = 0u;
    client->expires_at_ms = 0u;
    client->transaction_id = 0u;
    client->server_duid_size = 0u;
    client->dns_server_count = 0u;
    client->offer_preferred_seconds = 0u;
    client->offer_valid_seconds = 0u;
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
    byte_zero(client->server_duid, sizeof(client->server_duid));
    byte_zero(client->address, sizeof(client->address));
    byte_zero(client->dns_servers, sizeof(client->dns_servers));
    clear_pending(client);
}

static int client_information_mode(const RinDhcpv6ClientV1* client) {
    return client->reserved == RIN_DHCPV6_CLIENT_MODE_INFORMATION;
}

static int client_state_has_server(uint32_t state) {
    return state == RIN_DHCPV6_STATE_ADVERTISED ||
           state == RIN_DHCPV6_STATE_REQUESTING ||
           state == RIN_DHCPV6_STATE_BOUND ||
           state == RIN_DHCPV6_STATE_RENEWING ||
           state == RIN_DHCPV6_STATE_REBINDING ||
           state == RIN_DHCPV6_STATE_INFORMATION_BOUND ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
}

static int client_state_has_address(uint32_t state) {
    return state == RIN_DHCPV6_STATE_ADVERTISED ||
           state == RIN_DHCPV6_STATE_REQUESTING ||
           state == RIN_DHCPV6_STATE_BOUND ||
           state == RIN_DHCPV6_STATE_RENEWING ||
           state == RIN_DHCPV6_STATE_REBINDING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
}

static int client_state_has_lease(uint32_t state) {
    return state == RIN_DHCPV6_STATE_BOUND ||
           state == RIN_DHCPV6_STATE_RENEWING ||
           state == RIN_DHCPV6_STATE_REBINDING ||
           state == RIN_DHCPV6_STATE_INFORMATION_BOUND ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
}

static int client_has_lease(const RinDhcpv6ClientV1* client) {
    return client_state_has_lease(client->state) ||
           (client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING &&
            client->lease_generation != 0u);
}

static int client_state_retransmits(uint32_t state) {
    return state == RIN_DHCPV6_STATE_SOLICITING ||
           state == RIN_DHCPV6_STATE_REQUESTING ||
           state == RIN_DHCPV6_STATE_RENEWING ||
           state == RIN_DHCPV6_STATE_REBINDING ||
           state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
           state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
}

static int pending_valid(const RinDhcpv6ClientV1* client) {
    const RinDhcpv6TransmitV1* pending = &client->pending;
    uint32_t transaction_id;
    if (!client->pending_present)
        return byte_all_zero(pending, sizeof(*pending));
    if (pending->version != RIN_DHCPV6_CLIENT_VERSION ||
        pending->struct_size != sizeof(*pending) ||
        pending->owner_generation != client->generation ||
        pending->sequence == 0u || pending->reserved != 0u ||
        pending->message_size < 4u ||
        pending->message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE ||
        pending->message[0] != (uint8_t)pending->kind ||
        !byte_tail_zero(pending->message, pending->message_size,
                        sizeof(pending->message)))
        return 0;
    if (pending->kind != RIN_DHCPV6_TRANSMIT_SOLICIT &&
        pending->kind != RIN_DHCPV6_TRANSMIT_REQUEST &&
        pending->kind != RIN_DHCPV6_TRANSMIT_RENEW &&
        pending->kind != RIN_DHCPV6_TRANSMIT_REBIND &&
        pending->kind != RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST)
        return 0;
    transaction_id = ((uint32_t)pending->message[1] << 16) |
                     ((uint32_t)pending->message[2] << 8) |
                     pending->message[3];
    return transaction_id != 0u;
}

static int client_valid(const RinDhcpv6ClientV1* client) {
    uint32_t t1;
    uint32_t t2;
    uint32_t index;
    int has_server;
    int has_address;
    int has_lease;
    if (!client || client->version != RIN_DHCPV6_CLIENT_VERSION ||
        client->struct_size != sizeof(*client) || client->initialized != 1u ||
        client->state > RIN_DHCPV6_STATE_RECONFIGURE_REBINDING ||
        client->interface_generation == 0u || client->generation == 0u ||
        client->iaid == 0u || !duid_valid(client->duid, client->duid_size) ||
        !byte_tail_zero(client->duid, client->duid_size,
                        sizeof(client->duid)) ||
        client->transaction_id > UINT32_C(0x00ffffff) ||
        client->dns_server_count > RIN_DHCPV6_MAX_DNS_SERVERS ||
        client->pending_present > 1u ||
        client->reserved > RIN_DHCPV6_CLIENT_MODE_INFORMATION ||
        !pending_valid(client))
        return 0;
    if ((client_information_mode(client) &&
         (client->state == RIN_DHCPV6_STATE_SOLICITING ||
          client->state == RIN_DHCPV6_STATE_ADVERTISED ||
          client->state == RIN_DHCPV6_STATE_REQUESTING ||
          client->state == RIN_DHCPV6_STATE_RENEWING ||
          client->state == RIN_DHCPV6_STATE_REBINDING ||
          client->state ==
              RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
          client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING)) ||
        (!client_information_mode(client) &&
         (client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING ||
          client->state == RIN_DHCPV6_STATE_INFORMATION_BOUND)))
        return 0;
    has_server = client_state_has_server(client->state) ||
        (client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING &&
         client->server_duid_size != 0u);
    has_address = client_state_has_address(client->state);
    has_lease = client_has_lease(client);
    if (has_server != (client->server_duid_size != 0u) ||
        (has_server && !duid_valid(client->server_duid,
                                   client->server_duid_size)) ||
        !byte_tail_zero(client->server_duid, client->server_duid_size,
                        sizeof(client->server_duid)) ||
        has_address != address_usable(client->address))
        return 0;
    if ((client->state == RIN_DHCPV6_STATE_IDLE) !=
        (client->transaction_id == 0u))
        return 0;
    t1 = client->offer_t1_seconds;
    t2 = client->offer_t2_seconds;
    if (has_address &&
        !lifetimes_normalize(client->offer_valid_seconds,
                             client->offer_preferred_seconds, &t1, &t2))
        return 0;
    if (!has_address && (client->offer_valid_seconds != 0u ||
                         client->offer_preferred_seconds != 0u ||
                         client->offer_t1_seconds != 0u ||
                         client->offer_t2_seconds != 0u))
        return 0;
    if (has_lease) {
        if (client->lease_generation == 0u ||
            client->preferred_until_ms > client->expires_at_ms ||
            (client_information_mode(client) && !has_address
                ? (client->renew_at_ms >= client->expires_at_ms ||
                   client->rebind_at_ms != client->expires_at_ms)
                : (client->renew_at_ms >= client->rebind_at_ms ||
                   client->rebind_at_ms >= client->expires_at_ms)))
            return 0;
    } else if (client->lease_generation != 0u ||
               client->preferred_until_ms != 0u ||
               client->renew_at_ms != 0u || client->rebind_at_ms != 0u ||
               client->expires_at_ms != 0u || client->dns_server_count != 0u) {
        return 0;
    }
    for (index = 0u; index < RIN_DHCPV6_MAX_DNS_SERVERS; ++index) {
        if (index < client->dns_server_count) {
            if (!dns_address_usable(client->dns_servers[index])) return 0;
        } else if (!byte_tail_zero(client->dns_servers[index], 0u, 16u)) {
            return 0;
        }
    }
    if (client_state_retransmits(client->state)) {
        if (client->next_transmit_ms < client->transaction_started_ms ||
            client->retry_ms < DHCPV6_INITIAL_RETRY_MS ||
            client->retry_ms > DHCPV6_MAX_RETRY_MS)
            return 0;
    } else if (client->transaction_started_ms != 0u ||
               client->next_transmit_ms != 0u || client->retry_ms != 0u) {
        return 0;
    }
    return 1;
}

int rin_dhcpv6_client_state_valid(const RinDhcpv6ClientV1* client) {
    return client_valid(client);
}

static int time_valid(const RinDhcpv6ClientV1* client, uint64_t now_ms) {
    return now_ms >= client->last_now_ms;
}

static int advance_generation(RinDhcpv6ClientV1* client) {
    if (client->generation == UINT64_MAX) return 0;
    client->generation++;
    return 1;
}

static uint64_t earlier_deadline(uint64_t deadline, uint64_t phase_end) {
    return phase_end != 0u && phase_end < deadline ? phase_end : deadline;
}

static void schedule_initial_retry(RinDhcpv6ClientV1* client,
                                   uint64_t now_ms, uint64_t phase_end) {
    client->transaction_started_ms = now_ms;
    client->next_transmit_ms = earlier_deadline(
        now_ms + DHCPV6_INITIAL_RETRY_MS, phase_end);
    client->retry_ms = DHCPV6_INITIAL_RETRY_MS * UINT64_C(2);
}

static void schedule_later_retry(RinDhcpv6ClientV1* client,
                                 uint64_t now_ms, uint64_t phase_end) {
    uint64_t delay = client->retry_ms;
    client->next_transmit_ms = earlier_deadline(now_ms + delay, phase_end);
    if (delay < DHCPV6_MAX_RETRY_MS) {
        delay *= 2u;
        if (delay > DHCPV6_MAX_RETRY_MS) delay = DHCPV6_MAX_RETRY_MS;
        client->retry_ms = delay;
    }
}

static int expire_lease(RinDhcpv6ClientV1* client) {
    if (!advance_generation(client)) return RIN_DHCPV6_RANGE_EXHAUSTED;
    clear_dynamic(client);
    return RIN_DHCPV6_LEASE_EXPIRED;
}

int rin_dhcpv6_client_init(
    RinDhcpv6ClientV1* client, const uint8_t* duid, uint32_t duid_size,
    uint32_t iaid, uint64_t interface_generation) {
    uint8_t snapshot[RIN_DHCPV6_MAX_DUID_SIZE];
    if (!client || !duid_valid(duid, duid_size) || iaid == 0u ||
        interface_generation == 0u ||
        memory_overlaps(client, sizeof(*client), duid, duid_size))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    byte_zero(snapshot, sizeof(snapshot));
    byte_copy(snapshot, duid, duid_size);
    byte_zero(client, sizeof(*client));
    client->version = RIN_DHCPV6_CLIENT_VERSION;
    client->struct_size = sizeof(*client);
    client->initialized = 1u;
    client->state = RIN_DHCPV6_STATE_IDLE;
    client->interface_generation = interface_generation;
    client->generation = 1u;
    client->next_lease_generation = 1u;
    client->next_transmit_sequence = 1u;
    client->iaid = iaid;
    client->duid_size = duid_size;
    byte_copy(client->duid, snapshot, duid_size);
    byte_zero(snapshot, sizeof(snapshot));
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_set_mode(RinDhcpv6ClientV1* client,
                               RinDhcpv6ClientMode mode) {
    if (!client_valid(client) ||
        (mode != RIN_DHCPV6_CLIENT_MODE_STATEFUL &&
         mode != RIN_DHCPV6_CLIENT_MODE_INFORMATION) ||
        client->state != RIN_DHCPV6_STATE_IDLE || client->pending_present)
        return RIN_DHCPV6_INVALID_ARGUMENT;
    client->reserved = (uint32_t)mode;
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_request_reconfigure(
    RinDhcpv6ClientV1* client, RinDhcpv6TransmitKind requested_kind,
    uint64_t now_ms) {
    if (!client_valid(client)) return RIN_DHCPV6_INVALID_ARGUMENT;
    if (now_ms < client->last_now_ms) return RIN_DHCPV6_CLOCK_ROLLBACK;
    if (client->pending_present) return RIN_DHCPV6_BUSY;
    if ((requested_kind == RIN_DHCPV6_TRANSMIT_RENEW &&
         client->state == RIN_DHCPV6_STATE_BOUND &&
         !client_information_mode(client)) ||
        (requested_kind == RIN_DHCPV6_TRANSMIT_REBIND &&
         client->state == RIN_DHCPV6_STATE_BOUND &&
         !client_information_mode(client)) ||
        (requested_kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
         client->state == RIN_DHCPV6_STATE_BOUND &&
         !client_information_mode(client)) ||
        (requested_kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
         client->state == RIN_DHCPV6_STATE_INFORMATION_BOUND &&
         client_information_mode(client))) {
        if (client->generation == UINT64_MAX ||
            ((requested_kind == RIN_DHCPV6_TRANSMIT_REBIND ||
              (requested_kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
               !client_information_mode(client))) &&
             now_ms > UINT64_MAX - DHCPV6_INITIAL_RETRY_MS))
            return RIN_DHCPV6_RANGE_EXHAUSTED;
        if (now_ms >= client->expires_at_ms) {
            client->last_now_ms = now_ms;
            return expire_lease(client);
        }
        /* Keep the currently accepted lease published until the normal
         * renewal transaction succeeds or it expires.  Setting only its
         * deadline makes transport_prepare allocate a fresh XID and retains
         * the immutable prepare/complete send rule. */
        if (requested_kind == RIN_DHCPV6_TRANSMIT_REBIND) {
            client->state = RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
            /* Force a new Rebind XID even before a successful send moves the
             * normal state machine; failed sends leave this exact retryable
             * state intact. */
            schedule_initial_retry(client, now_ms, client->expires_at_ms);
            client->next_transmit_ms = now_ms;
        } else if (requested_kind ==
                   RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
                   !client_information_mode(client)) {
            client->state =
                RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING;
            schedule_initial_retry(client, now_ms, client->expires_at_ms);
            client->next_transmit_ms = now_ms;
        } else {
            client->renew_at_ms = now_ms;
        }
        client->last_now_ms = now_ms;
        client->generation++;
        return RIN_DHCPV6_OK;
    }
    return RIN_DHCPV6_INVALID_STATE;
}

int rin_dhcpv6_client_prepare(
    RinDhcpv6ClientV1* client, uint32_t new_transaction_id,
    uint64_t now_ms, RinDhcpv6TransmitV1* transmit_out) {
    RinDhcpv6TransmitV1 transmit;
    uint32_t transaction_id;
    uint32_t kind = RIN_DHCPV6_TRANSMIT_NONE;
    int needs_new_transaction = 0;
    int status;
    if (memory_overlaps(client, sizeof(*client), transmit_out,
                        sizeof(*transmit_out)))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (transmit_out) byte_zero(transmit_out, sizeof(*transmit_out));
    if (!client_valid(client) || !transmit_out)
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (!time_valid(client, now_ms)) return RIN_DHCPV6_CLOCK_ROLLBACK;
    if (client_has_lease(client) &&
        now_ms >= client->expires_at_ms) {
        client->last_now_ms = now_ms;
        return expire_lease(client);
    }
    if (client->pending_present) return RIN_DHCPV6_BUSY;
    switch (client->state) {
        case RIN_DHCPV6_STATE_IDLE:
            kind = client_information_mode(client)
                ? RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST
                : RIN_DHCPV6_TRANSMIT_SOLICIT;
            needs_new_transaction = 1;
            break;
        case RIN_DHCPV6_STATE_SOLICITING:
            if (now_ms >= client->next_transmit_ms)
                kind = RIN_DHCPV6_TRANSMIT_SOLICIT;
            break;
        case RIN_DHCPV6_STATE_ADVERTISED:
            kind = RIN_DHCPV6_TRANSMIT_REQUEST;
            needs_new_transaction = 1;
            break;
        case RIN_DHCPV6_STATE_REQUESTING:
            if (now_ms >= client->next_transmit_ms)
                kind = RIN_DHCPV6_TRANSMIT_REQUEST;
            break;
        case RIN_DHCPV6_STATE_BOUND:
            if (now_ms >= client->rebind_at_ms) {
                kind = RIN_DHCPV6_TRANSMIT_REBIND;
                needs_new_transaction = 1;
            } else if (now_ms >= client->renew_at_ms) {
                kind = RIN_DHCPV6_TRANSMIT_RENEW;
                needs_new_transaction = 1;
            }
            break;
        case RIN_DHCPV6_STATE_RENEWING:
            if (now_ms >= client->rebind_at_ms) {
                kind = RIN_DHCPV6_TRANSMIT_REBIND;
                needs_new_transaction = 1;
            } else if (now_ms >= client->next_transmit_ms) {
                kind = RIN_DHCPV6_TRANSMIT_RENEW;
            }
            break;
        case RIN_DHCPV6_STATE_REBINDING:
            if (now_ms >= client->next_transmit_ms)
                kind = RIN_DHCPV6_TRANSMIT_REBIND;
            break;
        case RIN_DHCPV6_STATE_INFORMATION_REQUESTING:
            if (now_ms >= client->next_transmit_ms)
                kind = RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST;
            break;
        case RIN_DHCPV6_STATE_INFORMATION_BOUND:
            if (now_ms >= client->renew_at_ms) {
                kind = RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST;
                needs_new_transaction = 1;
            }
            break;
        case RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING:
            if (now_ms >= client->next_transmit_ms) {
                kind = RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST;
                needs_new_transaction = 1;
            }
            break;
        case RIN_DHCPV6_STATE_RECONFIGURE_REBINDING:
            if (now_ms >= client->next_transmit_ms) {
                kind = RIN_DHCPV6_TRANSMIT_REBIND;
                needs_new_transaction = 1;
            }
            break;
        default:
            return RIN_DHCPV6_INVALID_STATE;
    }
    if (kind == RIN_DHCPV6_TRANSMIT_NONE) {
        client->last_now_ms = now_ms;
        return RIN_DHCPV6_OK;
    }
    if (now_ms > UINT64_MAX - DHCPV6_MAX_RETRY_MS ||
        client->next_transmit_sequence == 0u ||
        (needs_new_transaction && client->generation == UINT64_MAX))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    transaction_id = needs_new_transaction ? new_transaction_id
                                           : client->transaction_id;
    if (transaction_id == 0u || transaction_id > UINT32_C(0x00ffffff) ||
        (needs_new_transaction && transaction_id == client->transaction_id))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    status = build_message(client, kind, transaction_id, now_ms, &transmit);
    if (status != RIN_DHCPV6_OK) return status;
    transmit.sequence = client->next_transmit_sequence;
    client->next_transmit_sequence = transmit.sequence == UINT32_MAX
        ? 0u : transmit.sequence + 1u;
    client->pending = transmit;
    client->pending_present = 1u;
    client->last_now_ms = now_ms;
    *transmit_out = transmit;
    return RIN_DHCPV6_PACKET_READY;
}

int rin_dhcpv6_client_complete_transmit(
    RinDhcpv6ClientV1* client, const RinDhcpv6TransmitV1* transmit,
    int sent_successfully) {
    uint32_t transaction_id;
    uint64_t phase_end = 0u;
    int transition = 0;
    int initial_retry = 0;
    if (!client_valid(client) || !transmit ||
        memory_overlaps(client, sizeof(*client), transmit, sizeof(*transmit)) ||
        !client->pending_present ||
        !byte_equal(transmit, &client->pending, sizeof(*transmit)) ||
        (sent_successfully != 0 && sent_successfully != 1))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (!sent_successfully) {
        clear_pending(client);
        return RIN_DHCPV6_OK;
    }
    transaction_id = ((uint32_t)transmit->message[1] << 16) |
                     ((uint32_t)transmit->message[2] << 8) |
                     transmit->message[3];
    if (client->state == RIN_DHCPV6_STATE_IDLE &&
        transmit->kind == RIN_DHCPV6_TRANSMIT_SOLICIT) {
        client->state = RIN_DHCPV6_STATE_SOLICITING;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_IDLE &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        client->state = RIN_DHCPV6_STATE_INFORMATION_REQUESTING;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_SOLICITING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_SOLICIT) {
        if (transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
    } else if (client->state == RIN_DHCPV6_STATE_ADVERTISED &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REQUEST) {
        client->state = RIN_DHCPV6_STATE_REQUESTING;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_REQUESTING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REQUEST) {
        if (transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
    } else if (client->state == RIN_DHCPV6_STATE_BOUND &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_RENEW) {
        client->state = RIN_DHCPV6_STATE_RENEWING;
        phase_end = client->rebind_at_ms;
        transition = 1;
    } else if ((client->state == RIN_DHCPV6_STATE_BOUND ||
                client->state == RIN_DHCPV6_STATE_RENEWING) &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REBIND) {
        client->state = RIN_DHCPV6_STATE_REBINDING;
        phase_end = client->expires_at_ms;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_RENEWING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_RENEW) {
        if (transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
        phase_end = client->rebind_at_ms;
    } else if (client->state == RIN_DHCPV6_STATE_REBINDING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REBIND) {
        if (transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
        phase_end = client->expires_at_ms;
    } else if (client->state == RIN_DHCPV6_STATE_INFORMATION_BOUND &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        client->state = RIN_DHCPV6_STATE_INFORMATION_REQUESTING;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        if (transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
    } else if (client->state ==
                   RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        phase_end = client->expires_at_ms;
        initial_retry = 1;
    } else if (client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REBIND) {
        phase_end = client->expires_at_ms;
        initial_retry = 1;
    } else {
        return RIN_DHCPV6_INVALID_STATE;
    }
    if (transition && !advance_generation(client))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    client->transaction_id = transaction_id;
    if (transition || initial_retry) {
        schedule_initial_retry(client, transmit->prepared_at_ms, phase_end);
    } else {
        schedule_later_retry(client, transmit->prepared_at_ms, phase_end);
    }
    clear_pending(client);
    return RIN_DHCPV6_OK;
}

static int parsed_identity_matches(const RinDhcpv6ClientV1* client,
                                   const ParsedMessage* parsed) {
    return parsed->client_duid_size == client->duid_size &&
           byte_equal(parsed->client_duid, client->duid,
                      client->duid_size) && parsed->iaid == client->iaid;
}

static int parsed_client_identity_matches(const RinDhcpv6ClientV1* client,
                                          const ParsedMessage* parsed) {
    return parsed->client_duid_size == client->duid_size &&
           byte_equal(parsed->client_duid, client->duid,
                      client->duid_size);
}

static int commit_offer(RinDhcpv6ClientV1* client,
                        const ParsedMessage* parsed) {
    uint32_t t1 = parsed->t1_seconds;
    uint32_t t2 = parsed->t2_seconds;
    if (!parsed_identity_matches(client, parsed) ||
        !address_usable(parsed->address) ||
        !lifetimes_normalize(parsed->valid_seconds,
                             parsed->preferred_seconds, &t1, &t2))
        return RIN_DHCPV6_MALFORMED_PACKET;
    if (client->generation == UINT64_MAX)
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    byte_zero(client->server_duid, sizeof(client->server_duid));
    byte_copy(client->server_duid, parsed->server_duid,
              parsed->server_duid_size);
    client->server_duid_size = parsed->server_duid_size;
    byte_copy(client->address, parsed->address, sizeof(client->address));
    client->offer_preferred_seconds = parsed->preferred_seconds;
    client->offer_valid_seconds = parsed->valid_seconds;
    client->offer_t1_seconds = t1;
    client->offer_t2_seconds = t2;
    client->transaction_started_ms = 0u;
    client->next_transmit_ms = 0u;
    client->retry_ms = 0u;
    client->state = RIN_DHCPV6_STATE_ADVERTISED;
    client->generation++;
    return RIN_DHCPV6_OFFER_READY;
}

static int commit_lease(RinDhcpv6ClientV1* client,
                        const ParsedMessage* parsed, uint64_t now_ms) {
    uint64_t renew_at;
    uint64_t rebind_at;
    uint64_t expires_at;
    uint64_t preferred_until;
    uint32_t t1 = parsed->t1_seconds;
    uint32_t t2 = parsed->t2_seconds;
    uint32_t index;
    int allow_server_change = client->state == RIN_DHCPV6_STATE_REBINDING ||
        client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
    if (!parsed_identity_matches(client, parsed) ||
        !address_usable(parsed->address) ||
        !lifetimes_normalize(parsed->valid_seconds,
                             parsed->preferred_seconds, &t1, &t2))
        return RIN_DHCPV6_MALFORMED_PACKET;
    if (!allow_server_change &&
        (parsed->server_duid_size != client->server_duid_size ||
         !byte_equal(parsed->server_duid, client->server_duid,
                     client->server_duid_size)))
        return RIN_DHCPV6_NOT_FOR_US;
    if (!allow_server_change &&
        !byte_equal(parsed->address, client->address, sizeof(client->address)))
        return RIN_DHCPV6_NOT_FOR_US;
    if (!deadline_from_seconds(now_ms, t1, &renew_at) ||
        !deadline_from_seconds(now_ms, t2, &rebind_at) ||
        !deadline_from_seconds(now_ms, parsed->preferred_seconds,
                               &preferred_until) ||
        !deadline_from_seconds(now_ms, parsed->valid_seconds, &expires_at) ||
        client->next_lease_generation == 0u ||
        client->generation == UINT64_MAX)
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    if (allow_server_change) {
        byte_zero(client->server_duid, sizeof(client->server_duid));
        byte_copy(client->server_duid, parsed->server_duid,
                  parsed->server_duid_size);
        client->server_duid_size = parsed->server_duid_size;
    }
    byte_copy(client->address, parsed->address, sizeof(client->address));
    byte_zero(client->dns_servers, sizeof(client->dns_servers));
    for (index = 0u; index < parsed->dns_server_count; ++index)
        byte_copy(client->dns_servers[index], parsed->dns_servers[index], 16u);
    client->dns_server_count = parsed->dns_server_count;
    client->offer_preferred_seconds = parsed->preferred_seconds;
    client->offer_valid_seconds = parsed->valid_seconds;
    client->offer_t1_seconds = t1;
    client->offer_t2_seconds = t2;
    client->preferred_until_ms = preferred_until;
    client->renew_at_ms = renew_at;
    client->rebind_at_ms = rebind_at;
    client->expires_at_ms = expires_at;
    client->lease_generation = client->next_lease_generation;
    client->next_lease_generation = client->lease_generation == UINT64_MAX
        ? 0u : client->lease_generation + 1u;
    client->transaction_started_ms = 0u;
    client->next_transmit_ms = 0u;
    client->retry_ms = 0u;
    client->state = RIN_DHCPV6_STATE_BOUND;
    client->generation++;
    return RIN_DHCPV6_LEASE_READY;
}

static int commit_information(RinDhcpv6ClientV1* client,
                              const ParsedMessage* parsed,
                              uint64_t now_ms) {
    uint32_t refresh_seconds;
    uint64_t refresh_at;
    uint64_t expires_at;
    uint32_t index;
    if (!client_information_mode(client) ||
        !parsed_client_identity_matches(client, parsed) ||
        !parsed->server_seen || parsed->ia_seen || parsed->address_seen ||
        !information_refresh_normalize(parsed->information_refresh_seen
                                        ? parsed->information_refresh_seconds
                                        : 0u, &refresh_seconds) ||
        !deadline_from_seconds(now_ms, refresh_seconds, &refresh_at) ||
        !deadline_from_seconds(now_ms, refresh_seconds * 2u, &expires_at))
        return RIN_DHCPV6_MALFORMED_PACKET;
    if (client->next_lease_generation == 0u ||
        client->generation == UINT64_MAX)
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    byte_zero(client->server_duid, sizeof(client->server_duid));
    byte_copy(client->server_duid, parsed->server_duid,
              parsed->server_duid_size);
    client->server_duid_size = parsed->server_duid_size;
    byte_zero(client->address, sizeof(client->address));
    byte_zero(client->dns_servers, sizeof(client->dns_servers));
    for (index = 0u; index < parsed->dns_server_count; ++index)
        byte_copy(client->dns_servers[index], parsed->dns_servers[index], 16u);
    client->dns_server_count = parsed->dns_server_count;
    client->offer_preferred_seconds = 0u;
    client->offer_valid_seconds = 0u;
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
    client->preferred_until_ms = expires_at;
    client->renew_at_ms = refresh_at;
    client->rebind_at_ms = expires_at;
    client->expires_at_ms = expires_at;
    client->lease_generation = client->next_lease_generation;
    client->next_lease_generation = client->lease_generation == UINT64_MAX
        ? 0u : client->lease_generation + 1u;
    client->transaction_started_ms = 0u;
    client->next_transmit_ms = 0u;
    client->retry_ms = 0u;
    client->state = RIN_DHCPV6_STATE_INFORMATION_BOUND;
    client->generation++;
    return RIN_DHCPV6_LEASE_READY;
}

/* A stateful Reconfigure can request an Information-request.  RFC 8415
 * permits that exchange without discarding the valid IA_NA that caused the
 * client to be reachable in the first place.  Only configuration options
 * owned by this client (currently DNS) change here; address lifetimes and
 * server identity remain exact. */
static int commit_reconfigure_information(RinDhcpv6ClientV1* client,
                                          const ParsedMessage* parsed) {
    uint32_t index;
    if (client_information_mode(client) ||
        !parsed_client_identity_matches(client, parsed) ||
        !parsed->server_seen || parsed->ia_seen || parsed->address_seen ||
        parsed->server_duid_size != client->server_duid_size ||
        !byte_equal(parsed->server_duid, client->server_duid,
                    client->server_duid_size) ||
        client->next_lease_generation == 0u ||
        client->generation == UINT64_MAX)
        return RIN_DHCPV6_MALFORMED_PACKET;
    byte_zero(client->dns_servers, sizeof(client->dns_servers));
    for (index = 0u; index < parsed->dns_server_count; ++index)
        byte_copy(client->dns_servers[index], parsed->dns_servers[index], 16u);
    client->dns_server_count = parsed->dns_server_count;
    client->lease_generation = client->next_lease_generation;
    client->next_lease_generation = client->lease_generation == UINT64_MAX
        ? 0u : client->lease_generation + 1u;
    client->transaction_started_ms = 0u;
    client->next_transmit_ms = 0u;
    client->retry_ms = 0u;
    client->state = RIN_DHCPV6_STATE_BOUND;
    client->generation++;
    return RIN_DHCPV6_LEASE_READY;
}

int rin_dhcpv6_client_receive(
    RinDhcpv6ClientV1* client, const uint8_t* message,
    uint32_t message_size, uint64_t now_ms) {
    uint8_t snapshot[RIN_DHCPV6_MAX_MESSAGE_SIZE];
    ParsedMessage parsed;
    uint32_t transaction_id;
    uint8_t expected_type;
    int status;
    if (!client_valid(client) || !message || message_size < 4u ||
        message_size > sizeof(snapshot) ||
        memory_overlaps(client, sizeof(*client), message, message_size))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (now_ms < client->last_now_ms) return RIN_DHCPV6_CLOCK_ROLLBACK;
    if (client->pending_present) return RIN_DHCPV6_BUSY;
    if (client->state == RIN_DHCPV6_STATE_SOLICITING) {
        expected_type = DHCPV6_MESSAGE_ADVERTISE;
    } else if (client->state == RIN_DHCPV6_STATE_REQUESTING ||
               client->state == RIN_DHCPV6_STATE_RENEWING ||
               client->state == RIN_DHCPV6_STATE_REBINDING) {
        expected_type = DHCPV6_MESSAGE_REPLY;
    } else if (client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING) {
        expected_type = DHCPV6_MESSAGE_REPLY;
    } else if (client->state ==
               RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING) {
        expected_type = DHCPV6_MESSAGE_REPLY;
    } else if (client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING) {
        expected_type = DHCPV6_MESSAGE_REPLY;
    } else {
        return RIN_DHCPV6_INVALID_STATE;
    }
    byte_copy(snapshot, message, message_size);
    transaction_id = ((uint32_t)snapshot[1] << 16) |
                     ((uint32_t)snapshot[2] << 8) | snapshot[3];
    if (transaction_id != client->transaction_id)
        return RIN_DHCPV6_NOT_FOR_US;
    status = parse_message(
        snapshot, message_size, expected_type,
        client->state != RIN_DHCPV6_STATE_INFORMATION_REQUESTING &&
            client->state !=
                RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING,
        &parsed);
    if (status != RIN_DHCPV6_OK) {
        byte_zero(snapshot, sizeof(snapshot));
        byte_zero(&parsed, sizeof(parsed));
        return status;
    }
    status = expected_type == DHCPV6_MESSAGE_ADVERTISE
        ? commit_offer(client, &parsed)
        : client->state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING
            ? commit_information(client, &parsed, now_ms)
            : client->state ==
                  RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING
                ? commit_reconfigure_information(client, &parsed)
            : commit_lease(client, &parsed, now_ms);
    if (status > 0) client->last_now_ms = now_ms;
    byte_zero(snapshot, sizeof(snapshot));
    byte_zero(&parsed, sizeof(parsed));
    return status;
}

int rin_dhcpv6_client_get_lease(
    RinDhcpv6ClientV1* client, uint64_t now_ms,
    RinDhcpv6LeaseV1* lease_out) {
    uint32_t index;
    if (memory_overlaps(client, sizeof(*client), lease_out,
                        sizeof(*lease_out)))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (lease_out) byte_zero(lease_out, sizeof(*lease_out));
    if (!client_valid(client) || !lease_out)
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (!time_valid(client, now_ms)) return RIN_DHCPV6_CLOCK_ROLLBACK;
    if (client_has_lease(client) &&
        now_ms >= client->expires_at_ms) {
        client->last_now_ms = now_ms;
        return expire_lease(client);
    }
    if (!client_has_lease(client))
        return RIN_DHCPV6_NOT_FOUND;
    client->last_now_ms = now_ms;
    lease_out->version = RIN_DHCPV6_CLIENT_VERSION;
    lease_out->struct_size = sizeof(*lease_out);
    lease_out->interface_generation = client->interface_generation;
    lease_out->lease_generation = client->lease_generation;
    lease_out->preferred_until_ms = client->preferred_until_ms;
    lease_out->renew_at_ms = client->renew_at_ms;
    lease_out->rebind_at_ms = client->rebind_at_ms;
    lease_out->expires_at_ms = client->expires_at_ms;
    lease_out->dns_server_count = client->dns_server_count;
    lease_out->state = client->state;
    byte_copy(lease_out->address, client->address, sizeof(lease_out->address));
    for (index = 0u; index < client->dns_server_count; ++index)
        byte_copy(lease_out->dns_servers[index], client->dns_servers[index], 16u);
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_stop(RinDhcpv6ClientV1* client) {
    if (!client_valid(client)) return RIN_DHCPV6_INVALID_ARGUMENT;
    if (client->state == RIN_DHCPV6_STATE_IDLE && !client->pending_present)
        return RIN_DHCPV6_OK;
    if (!advance_generation(client)) return RIN_DHCPV6_RANGE_EXHAUSTED;
    clear_dynamic(client);
    return RIN_DHCPV6_OK;
}

void rin_dhcpv6_client_destroy(RinDhcpv6ClientV1* client) {
    if (client) byte_zero(client, sizeof(*client));
}
