/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_dhcpv6_client.h>

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
#define DHCPV6_OPTION_SOL_MAX_RT 82u
#define DHCPV6_OPTION_INF_MAX_RT 83u

#define DHCPV6_DNS_OPTION_CODE 23u
#define DHCPV6_MIN_VALID_SECONDS 60u
#define DHCPV6_MAX_VALID_SECONDS (30u * 24u * 60u * 60u)
#define DHCPV6_SOL_TIMEOUT_MS UINT64_C(1000)
#define DHCPV6_SOL_MAX_RT_DEFAULT_SECONDS 3600u
#define DHCPV6_INF_MAX_RT_DEFAULT_SECONDS 3600u
#define DHCPV6_REQUEST_TIMEOUT_MS UINT64_C(1000)
#define DHCPV6_REQUEST_MAX_RT_MS UINT64_C(30000)
#define DHCPV6_REQUEST_MAX_RETRANSMISSIONS 10u
#define DHCPV6_RENEW_TIMEOUT_MS UINT64_C(10000)
#define DHCPV6_RENEW_MAX_RT_MS UINT64_C(600000)
#define DHCPV6_REBIND_TIMEOUT_MS UINT64_C(10000)
#define DHCPV6_REBIND_MAX_RT_MS UINT64_C(600000)
#define DHCPV6_INFORMATION_TIMEOUT_MS UINT64_C(1000)
#define DHCPV6_MAX_RT_OPTION_MIN_SECONDS 60u
#define DHCPV6_MAX_RT_OPTION_MAX_SECONDS 86400u
#define DHCPV6_MAX_RANDOMIZED_RT_MS UINT64_C(95040000)
#define DHCPV6_STARTUP_DELAY_MAX_MS UINT64_C(1000)
#define DHCPV6_RETRANSMISSION_NOT_STARTED UINT32_MAX
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
_Static_assert(sizeof(RinDhcpv6AddressBindingV2) == 48u,
               "DHCPv6 address binding ABI drift");
_Static_assert(sizeof(RinDhcpv6ClientV2) == 1056u,
               "DHCPv6 client V2 ABI drift");
_Static_assert(sizeof(RinDhcpv6LeaseV2) == 304u,
               "DHCPv6 lease V2 ABI drift");

typedef struct MessageWriter {
    uint8_t* bytes;
    uint32_t size;
    uint32_t capacity;
} MessageWriter;

typedef struct ParsedIaAddress {
    uint8_t address[16];
    uint32_t preferred_seconds;
    uint32_t valid_seconds;
    uint32_t status_code;
} ParsedIaAddress;

typedef struct ParsedMessage {
    const uint8_t* client_duid;
    uint32_t client_duid_size;
    const uint8_t* server_duid;
    uint32_t server_duid_size;
    uint8_t address[16];
    ParsedIaAddress ia_addresses[RIN_DHCPV6_MAX_IA_ADDRESSES];
    uint32_t ia_address_count;
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
    uint32_t sol_max_rt_seconds;
    uint32_t sol_max_rt_seen;
    uint32_t inf_max_rt_seconds;
    uint32_t inf_max_rt_seen;
    uint32_t structural_valid;
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
        store_be16(option + 12u, DHCPV6_OPTION_IA_ADDRESS);
        store_be16(option + 14u, 24u);
        byte_copy(option + 16u, client->address, 16u);
        /* RFC 9915 §21.4 and §21.6 recommend zero in client-sent lifetime
         * hints; the server must ignore these fields. */
        size = 40u;
    }
    return append_option(writer, DHCPV6_OPTION_IA_NA, option, size);
}

static int build_message(const RinDhcpv6ClientV1* client, uint32_t kind,
                         uint32_t transaction_id, uint64_t now_ms,
                         RinDhcpv6TransmitV1* transmit) {
    uint8_t elapsed[2];
    uint8_t oro[6];
    uint32_t oro_count = 1u;
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
            client->offer_t1_seconds !=
                DHCPV6_RETRANSMISSION_NOT_STARTED &&
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
    if (kind == RIN_DHCPV6_TRANSMIT_SOLICIT ||
        kind == RIN_DHCPV6_TRANSMIT_REQUEST ||
        kind == RIN_DHCPV6_TRANSMIT_RENEW ||
        kind == RIN_DHCPV6_TRANSMIT_REBIND) {
        store_be16(oro + oro_count * 2u, DHCPV6_OPTION_SOL_MAX_RT);
        oro_count++;
    } else if (kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST) {
        store_be16(oro + oro_count * 2u,
                   DHCPV6_OPTION_INFORMATION_REFRESH_TIME);
        oro_count++;
        store_be16(oro + oro_count * 2u, DHCPV6_OPTION_INF_MAX_RT);
        oro_count++;
    }
    if (!append_option(&writer, DHCPV6_OPTION_ORO, oro,
                       (uint16_t)(oro_count * 2u)))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    /* RFC 9915 defaults a client to unwilling to receive Reconfigure.  We
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
            uint32_t nested_offset = 24u;
            uint32_t nested_count = 0u;
            uint32_t address_status_seen = 0u;
            ParsedIaAddress candidate;
            uint32_t prior;
            if (parsed->ia_address_count >= RIN_DHCPV6_MAX_IA_ADDRESSES ||
                length < 24u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            byte_zero(&candidate, sizeof(candidate));
            byte_copy(candidate.address, option, sizeof(candidate.address));
            candidate.preferred_seconds = load_be32(option + 16u);
            candidate.valid_seconds = load_be32(option + 20u);
            if (!address_usable(candidate.address) ||
                candidate.valid_seconds > DHCPV6_MAX_VALID_SECONDS ||
                candidate.preferred_seconds > candidate.valid_seconds ||
                (candidate.valid_seconds == 0u &&
                 candidate.preferred_seconds != 0u))
                return RIN_DHCPV6_MALFORMED_PACKET;
            for (prior = 0u; prior < parsed->ia_address_count; ++prior) {
                if (byte_equal(parsed->ia_addresses[prior].address,
                               candidate.address,
                               sizeof(candidate.address)))
                    return RIN_DHCPV6_MALFORMED_PACKET;
            }
            parsed->address_seen = 1u;
            while (nested_offset < length) {
                uint16_t nested_code;
                uint16_t nested_length;
                const uint8_t* nested_option;
                if (++nested_count > DHCPV6_MAX_NESTED_OPTIONS ||
                    (uint32_t)length - nested_offset < 4u)
                    return RIN_DHCPV6_MALFORMED_PACKET;
                nested_code = load_be16(option + nested_offset);
                nested_length = load_be16(option + nested_offset + 2u);
                nested_offset += 4u;
                if ((uint32_t)nested_length >
                    (uint32_t)length - nested_offset)
                    return RIN_DHCPV6_MALFORMED_PACKET;
                nested_option = option + nested_offset;
                if (nested_code == DHCPV6_OPTION_STATUS_CODE) {
                    uint32_t address_status;
                    if (address_status_seen || nested_length < 2u)
                        return RIN_DHCPV6_MALFORMED_PACKET;
                    address_status_seen = 1u;
                    address_status = load_be16(nested_option);
                    candidate.status_code = address_status;
                }
                /* Unknown IAaddr suboptions are optional to this client and
                 * were already bounded by the enclosing option length. */
                nested_offset += nested_length;
            }
            if (nested_offset != length)
                return RIN_DHCPV6_MALFORMED_PACKET;
            {
                ParsedIaAddress* stored =
                    &parsed->ia_addresses[parsed->ia_address_count++];
                *stored = candidate;
                /* V1 callers expose one address. Prefer the first successful
                 * nonzero binding, retaining the first IAADDR as a fallback
                 * for V2 withdrawal-only replies. */
                if (candidate.status_code == 0u &&
                    (!address_usable(parsed->address) ||
                     (candidate.valid_seconds != 0u &&
                      parsed->valid_seconds == 0u))) {
                    byte_copy(parsed->address, candidate.address, 16u);
                    parsed->preferred_seconds =
                        candidate.preferred_seconds;
                    parsed->valid_seconds = candidate.valid_seconds;
                }
            }
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
        } else if (code == DHCPV6_OPTION_SOL_MAX_RT) {
            if (parsed->sol_max_rt_seen || length != 4u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->sol_max_rt_seen = 1u;
            parsed->sol_max_rt_seconds = load_be32(value);
        } else if (code == DHCPV6_OPTION_INF_MAX_RT) {
            if (parsed->inf_max_rt_seen || length != 4u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            parsed->inf_max_rt_seen = 1u;
            parsed->inf_max_rt_seconds = load_be32(value);
        }
        offset += length;
    }
    if (offset != size || !parsed->client_seen || !parsed->server_seen)
        return RIN_DHCPV6_MALFORMED_PACKET;
    parsed->structural_valid = 1u;
    if ((require_ia && !parsed->ia_seen) ||
        (require_ia && !parsed->address_seen && parsed->status_code == 0u) ||
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
    uint32_t sol_max_rt = client->offer_preferred_seconds;
    uint32_t inf_max_rt = client->offer_valid_seconds;
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
    client->offer_preferred_seconds = sol_max_rt;
    client->offer_valid_seconds = inf_max_rt;
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

static int client_startup_delayed(const RinDhcpv6ClientV1* client) {
    return client->state == RIN_DHCPV6_STATE_IDLE &&
           client->transaction_id != 0u &&
           client->offer_t1_seconds == DHCPV6_RETRANSMISSION_NOT_STARTED;
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

static uint64_t retransmission_irt_ms(uint32_t kind);
static uint64_t retransmission_mrt_ms(const RinDhcpv6ClientV1* client,
                                      uint32_t kind);

static uint32_t retransmission_kind_for_state(uint32_t state) {
    switch (state) {
        case RIN_DHCPV6_STATE_SOLICITING:
            return RIN_DHCPV6_TRANSMIT_SOLICIT;
        case RIN_DHCPV6_STATE_REQUESTING:
            return RIN_DHCPV6_TRANSMIT_REQUEST;
        case RIN_DHCPV6_STATE_RENEWING:
            return RIN_DHCPV6_TRANSMIT_RENEW;
        case RIN_DHCPV6_STATE_REBINDING:
        case RIN_DHCPV6_STATE_RECONFIGURE_REBINDING:
            return RIN_DHCPV6_TRANSMIT_REBIND;
        case RIN_DHCPV6_STATE_INFORMATION_REQUESTING:
        case RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING:
            return RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST;
        default:
            return RIN_DHCPV6_TRANSMIT_NONE;
    }
}

static int client_valid(const RinDhcpv6ClientV1* client) {
    uint32_t index;
    int has_server;
    int has_address;
    int has_lease;
    int retransmitting;
    int first_send_pending;
    uint32_t retransmission_kind;
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
        client->offer_preferred_seconds <
            DHCPV6_MAX_RT_OPTION_MIN_SECONDS ||
        client->offer_preferred_seconds >
            DHCPV6_MAX_RT_OPTION_MAX_SECONDS ||
        client->offer_valid_seconds < DHCPV6_MAX_RT_OPTION_MIN_SECONDS ||
        client->offer_valid_seconds > DHCPV6_MAX_RT_OPTION_MAX_SECONDS ||
        client->offer_t2_seconds != 0u ||
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
    if ((client->state == RIN_DHCPV6_STATE_IDLE &&
         client->transaction_id == 0u && client->offer_t1_seconds != 0u) ||
        (client->state != RIN_DHCPV6_STATE_IDLE &&
         client->transaction_id == 0u) ||
        (client->state == RIN_DHCPV6_STATE_IDLE &&
         client->transaction_id != 0u && !client_startup_delayed(client)))
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
    retransmitting = client_state_retransmits(client->state);
    retransmission_kind = retransmission_kind_for_state(client->state);
    first_send_pending = client_startup_delayed(client) ||
        ((client->state ==
              RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING ||
          client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING) &&
         client->offer_t1_seconds == DHCPV6_RETRANSMISSION_NOT_STARTED);
    if (retransmitting || first_send_pending) {
        if (client->offer_t1_seconds ==
            DHCPV6_RETRANSMISSION_NOT_STARTED) {
            if (!first_send_pending || client->transaction_started_ms != 0u ||
                client->retry_ms != 0u)
                return 0;
        } else {
            uint64_t minimum_rt;
            uint64_t maximum_rt;
            if (retransmission_kind == RIN_DHCPV6_TRANSMIT_NONE ||
                client->next_transmit_ms < client->transaction_started_ms)
                return 0;
            minimum_rt = retransmission_irt_ms(retransmission_kind);
            minimum_rt -= minimum_rt / 10u;
            maximum_rt = retransmission_mrt_ms(client, retransmission_kind);
            maximum_rt += maximum_rt / 10u;
            if (client->retry_ms < minimum_rt ||
                client->retry_ms > maximum_rt)
                return 0;
        }
        if (client->state == RIN_DHCPV6_STATE_REQUESTING &&
            client->offer_t1_seconds >=
                DHCPV6_REQUEST_MAX_RETRANSMISSIONS)
            return 0;
    } else if (client->transaction_started_ms != 0u ||
               client->next_transmit_ms != 0u || client->retry_ms != 0u ||
               client->offer_t1_seconds != 0u) {
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

static uint32_t random_next(uint32_t* state) {
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    if (value == 0u) value = UINT32_C(0x6d2b79f5);
    *state = value;
    return value;
}

static uint32_t random_bounded(uint32_t* state, uint32_t bound) {
    return (uint32_t)(((uint64_t)random_next(state) * bound) >> 32);
}

static uint32_t random_event_seed(const RinDhcpv6ClientV1* client,
                                  uint32_t transaction_id,
                                  uint32_t sequence, uint32_t purpose) {
    uint32_t value = UINT32_C(2166136261) ^ transaction_id ^
                     (sequence * UINT32_C(0x9e3779b9)) ^ client->iaid ^
                     (uint32_t)client->interface_generation ^
                     (uint32_t)(client->interface_generation >> 32) ^
                     (uint32_t)client->generation ^
                     (uint32_t)(client->generation >> 32) ^ purpose;
    uint32_t index;
    for (index = 0u; index < client->duid_size; ++index)
        value = (value ^ client->duid[index]) * UINT32_C(16777619);
    if (value == 0u) value = UINT32_C(0x6d2b79f5);
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    return value != 0u ? value : UINT32_C(0x6d2b79f5);
}

static uint64_t retransmission_irt_ms(uint32_t kind) {
    switch (kind) {
        case RIN_DHCPV6_TRANSMIT_RENEW:
            return DHCPV6_RENEW_TIMEOUT_MS;
        case RIN_DHCPV6_TRANSMIT_REBIND:
            return DHCPV6_REBIND_TIMEOUT_MS;
        case RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST:
            return DHCPV6_INFORMATION_TIMEOUT_MS;
        case RIN_DHCPV6_TRANSMIT_SOLICIT:
            return DHCPV6_SOL_TIMEOUT_MS;
        case RIN_DHCPV6_TRANSMIT_REQUEST:
        default:
            return DHCPV6_REQUEST_TIMEOUT_MS;
    }
}

static uint64_t retransmission_mrt_ms(const RinDhcpv6ClientV1* client,
                                      uint32_t kind) {
    switch (kind) {
        case RIN_DHCPV6_TRANSMIT_SOLICIT:
            return (uint64_t)client->offer_preferred_seconds * UINT64_C(1000);
        case RIN_DHCPV6_TRANSMIT_REQUEST:
            return DHCPV6_REQUEST_MAX_RT_MS;
        case RIN_DHCPV6_TRANSMIT_RENEW:
            return DHCPV6_RENEW_MAX_RT_MS;
        case RIN_DHCPV6_TRANSMIT_REBIND:
            return DHCPV6_REBIND_MAX_RT_MS;
        case RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST:
            return (uint64_t)client->offer_valid_seconds * UINT64_C(1000);
        default:
            return retransmission_irt_ms(kind);
    }
}

static uint32_t retransmission_mrc(uint32_t kind) {
    return kind == RIN_DHCPV6_TRANSMIT_REQUEST
        ? DHCPV6_REQUEST_MAX_RETRANSMISSIONS : 0u;
}

static uint64_t randomized_rt(RinDhcpv6ClientV1* client, uint64_t base_ms,
                              int first_solicit_rt, uint32_t kind,
                              uint32_t transaction_id,
                              uint32_t sequence) {
    uint32_t random_state = random_event_seed(client, transaction_id,
                                               sequence,
                                               UINT32_C(0x52540000) ^ kind);
    int32_t signed_factor;
    uint64_t magnitude;
    if (first_solicit_rt) {
        signed_factor = (int32_t)(random_bounded(&random_state, 1000u) + 1u);
    } else {
        signed_factor = (int32_t)random_bounded(&random_state, 2001u) - 1000;
    }
    magnitude = (base_ms * (uint32_t)(signed_factor < 0
                    ? -signed_factor : signed_factor)) / UINT64_C(10000);
    return signed_factor < 0 ? base_ms - magnitude : base_ms + magnitude;
}

static void schedule_initial_retry(RinDhcpv6ClientV1* client,
                                   uint32_t kind, uint32_t transaction_id,
                                   uint32_t sequence, uint64_t now_ms,
                                   uint64_t phase_end) {
    uint64_t retry_ms = randomized_rt(
        client, retransmission_irt_ms(kind),
        kind == RIN_DHCPV6_TRANSMIT_SOLICIT,
        kind, transaction_id, sequence);
    client->transaction_started_ms = now_ms;
    client->next_transmit_ms = earlier_deadline(now_ms + retry_ms, phase_end);
    client->retry_ms = retry_ms;
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
}

static void schedule_later_retry(RinDhcpv6ClientV1* client, uint32_t kind,
                                 uint32_t transaction_id, uint32_t sequence,
                                 uint64_t now_ms, uint64_t phase_end) {
    uint64_t mrt_ms = retransmission_mrt_ms(client, kind);
    uint64_t base_ms = client->retry_ms > UINT64_MAX / 2u
        ? mrt_ms : client->retry_ms * UINT64_C(2);
    uint64_t retry_ms;
    if (base_ms > mrt_ms) base_ms = mrt_ms;
    retry_ms = randomized_rt(client, base_ms, 0, kind,
                             transaction_id, sequence);
    client->next_transmit_ms = earlier_deadline(now_ms + retry_ms, phase_end);
    client->retry_ms = retry_ms;
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
    client->offer_preferred_seconds = DHCPV6_SOL_MAX_RT_DEFAULT_SECONDS;
    client->offer_valid_seconds = DHCPV6_INF_MAX_RT_DEFAULT_SECONDS;
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
        client->state != RIN_DHCPV6_STATE_IDLE ||
        client->transaction_id != 0u || client->pending_present)
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
        if (client->generation >= UINT64_MAX - 3u ||
            ((requested_kind == RIN_DHCPV6_TRANSMIT_REBIND ||
              (requested_kind == RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
               !client_information_mode(client))) &&
             now_ms > UINT64_MAX - DHCPV6_MAX_RANDOMIZED_RT_MS))
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
            /* The authenticated instruction starts one normal Rebind
             * transaction.  Its first XID is allocated by prepare; later
             * retransmissions retain that XID. */
            client->transaction_started_ms = 0u;
            client->next_transmit_ms = now_ms;
            client->retry_ms = 0u;
            client->offer_t1_seconds =
                DHCPV6_RETRANSMISSION_NOT_STARTED;
        } else if (requested_kind ==
                   RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST &&
                   !client_information_mode(client)) {
            client->state =
                RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING;
            client->transaction_started_ms = 0u;
            client->next_transmit_ms = now_ms;
            client->retry_ms = 0u;
            client->offer_t1_seconds =
                DHCPV6_RETRANSMISSION_NOT_STARTED;
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
            if (client_startup_delayed(client)) {
                if (now_ms >= client->next_transmit_ms)
                    kind = client_information_mode(client)
                        ? RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST
                        : RIN_DHCPV6_TRANSMIT_SOLICIT;
            } else {
                kind = client_information_mode(client)
                    ? RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST
                    : RIN_DHCPV6_TRANSMIT_SOLICIT;
                needs_new_transaction = 1;
            }
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
                needs_new_transaction = client->offer_t1_seconds ==
                    DHCPV6_RETRANSMISSION_NOT_STARTED;
            }
            break;
        case RIN_DHCPV6_STATE_RECONFIGURE_REBINDING:
            if (now_ms >= client->next_transmit_ms) {
                kind = RIN_DHCPV6_TRANSMIT_REBIND;
                needs_new_transaction = client->offer_t1_seconds ==
                    DHCPV6_RETRANSMISSION_NOT_STARTED;
            }
            break;
        default:
            return RIN_DHCPV6_INVALID_STATE;
    }
    if (kind == RIN_DHCPV6_TRANSMIT_NONE) {
        client->last_now_ms = now_ms;
        return RIN_DHCPV6_OK;
    }
    if (now_ms > UINT64_MAX - DHCPV6_MAX_RANDOMIZED_RT_MS ||
        client->next_transmit_sequence == 0u ||
        (needs_new_transaction && client->generation == UINT64_MAX) ||
        (client->state == RIN_DHCPV6_STATE_IDLE &&
         client->transaction_id == 0u &&
         client->generation >= UINT64_MAX - 1u))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    transaction_id = needs_new_transaction ? new_transaction_id
                                           : client->transaction_id;
    if (transaction_id == 0u || transaction_id > UINT32_C(0x00ffffff) ||
        (needs_new_transaction && transaction_id == client->transaction_id))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (client->state == RIN_DHCPV6_STATE_IDLE &&
        client->transaction_id == 0u) {
        uint64_t startup_delay_ms;
        client->transaction_id = transaction_id;
        client->offer_t1_seconds = DHCPV6_RETRANSMISSION_NOT_STARTED;
        {
            uint32_t random_state = random_event_seed(
                client, transaction_id, client->next_transmit_sequence,
                UINT32_C(0x53544152));
            startup_delay_ms = random_bounded(
                &random_state,
                (uint32_t)DHCPV6_STARTUP_DELAY_MAX_MS + 1u);
        }
        client->next_transmit_ms = now_ms + startup_delay_ms;
        client->generation++;
        needs_new_transaction = 0;
        if (startup_delay_ms != 0u) {
            client->last_now_ms = now_ms;
            return RIN_DHCPV6_OK;
        }
    }
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
        client->offer_t1_seconds == DHCPV6_RETRANSMISSION_NOT_STARTED &&
        transmit->kind == RIN_DHCPV6_TRANSMIT_SOLICIT) {
        client->state = RIN_DHCPV6_STATE_SOLICITING;
        transition = 1;
    } else if (client->state == RIN_DHCPV6_STATE_IDLE &&
               client->offer_t1_seconds ==
                   DHCPV6_RETRANSMISSION_NOT_STARTED &&
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
        if (client->offer_t1_seconds !=
                DHCPV6_RETRANSMISSION_NOT_STARTED &&
            transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
        phase_end = client->expires_at_ms;
        transition = client->offer_t1_seconds ==
                     DHCPV6_RETRANSMISSION_NOT_STARTED;
    } else if (client->state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING &&
               transmit->kind == RIN_DHCPV6_TRANSMIT_REBIND) {
        if (client->offer_t1_seconds !=
                DHCPV6_RETRANSMISSION_NOT_STARTED &&
            transaction_id != client->transaction_id)
            return RIN_DHCPV6_INVALID_STATE;
        phase_end = client->expires_at_ms;
        transition = client->offer_t1_seconds ==
                     DHCPV6_RETRANSMISSION_NOT_STARTED;
    } else {
        return RIN_DHCPV6_INVALID_STATE;
    }
    if (transition && !advance_generation(client))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    client->transaction_id = transaction_id;
    if (transition) {
        schedule_initial_retry(client, transmit->kind,
                               transaction_id, transmit->sequence,
                               transmit->prepared_at_ms, phase_end);
    } else {
        uint32_t retransmissions = retransmission_mrc(transmit->kind);
        if (retransmissions != 0u &&
            client->offer_t1_seconds < retransmissions &&
            client->offer_t1_seconds + 1u >= retransmissions) {
            if (client->generation != UINT64_MAX)
                (void)advance_generation(client);
            clear_dynamic(client);
            return RIN_DHCPV6_OK;
        }
        if (client->offer_t1_seconds < UINT32_MAX - 1u)
            client->offer_t1_seconds++;
        schedule_later_retry(client, transmit->kind, transaction_id,
                             transmit->sequence,
                             transmit->prepared_at_ms, phase_end);
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

static int parsed_server_identity_matches(const RinDhcpv6ClientV1* client,
                                          const ParsedMessage* parsed) {
    return parsed->server_duid_size == client->server_duid_size &&
           byte_equal(parsed->server_duid, client->server_duid,
                      client->server_duid_size);
}

static int apply_retransmission_overrides(RinDhcpv6ClientV1* client,
                                          const ParsedMessage* parsed,
                                          uint64_t now_ms) {
    uint32_t sol_max_rt = client->offer_preferred_seconds;
    uint32_t inf_max_rt = client->offer_valid_seconds;
    int requires_selected_server =
        client->state == RIN_DHCPV6_STATE_REQUESTING ||
        client->state == RIN_DHCPV6_STATE_RENEWING ||
        client->state ==
            RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING;
    int allows_information_reply = client_information_mode(client) ||
        client->state ==
            RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING;
    if (!parsed->structural_valid || !parsed->server_seen ||
        !parsed_client_identity_matches(client, parsed))
        return RIN_DHCPV6_OK;
    if ((parsed->ia_seen && parsed->iaid != client->iaid) ||
        (!parsed->ia_seen && !allows_information_reply) ||
        (requires_selected_server &&
         !parsed_server_identity_matches(client, parsed)))
        return RIN_DHCPV6_OK;
    if (parsed->sol_max_rt_seen &&
        parsed->sol_max_rt_seconds >= DHCPV6_MAX_RT_OPTION_MIN_SECONDS &&
        parsed->sol_max_rt_seconds <= DHCPV6_MAX_RT_OPTION_MAX_SECONDS)
        sol_max_rt = parsed->sol_max_rt_seconds;
    if (parsed->inf_max_rt_seen &&
        parsed->inf_max_rt_seconds >= DHCPV6_MAX_RT_OPTION_MIN_SECONDS &&
        parsed->inf_max_rt_seconds <= DHCPV6_MAX_RT_OPTION_MAX_SECONDS)
        inf_max_rt = parsed->inf_max_rt_seconds;
    if (sol_max_rt == client->offer_preferred_seconds &&
        inf_max_rt == client->offer_valid_seconds)
        return RIN_DHCPV6_OK;
    if (!advance_generation(client)) return RIN_DHCPV6_RANGE_EXHAUSTED;
    client->offer_preferred_seconds = sol_max_rt;
    client->offer_valid_seconds = inf_max_rt;
    client->last_now_ms = now_ms;
    return RIN_DHCPV6_OK;
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
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
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
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
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
    client->offer_t1_seconds = 0u;
    client->offer_t2_seconds = 0u;
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
    int override_status;
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
    byte_zero(&parsed, sizeof(parsed));
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
    override_status = status == RIN_DHCPV6_OK ||
            status == RIN_DHCPV6_SERVER_REJECTED
        ? apply_retransmission_overrides(client, &parsed, now_ms)
        : RIN_DHCPV6_OK;
    if (override_status != RIN_DHCPV6_OK) status = override_status;
    else if (status == RIN_DHCPV6_SERVER_REJECTED &&
             parsed.structural_valid &&
             parsed_client_identity_matches(client, &parsed))
        client->last_now_ms = now_ms;
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
    if (client->state == RIN_DHCPV6_STATE_IDLE &&
        client->transaction_id == 0u && !client->pending_present)
        return RIN_DHCPV6_OK;
    if (!advance_generation(client)) return RIN_DHCPV6_RANGE_EXHAUSTED;
    clear_dynamic(client);
    return RIN_DHCPV6_OK;
}

void rin_dhcpv6_client_destroy(RinDhcpv6ClientV1* client) {
    if (client) byte_zero(client, sizeof(*client));
}

static int client_v2_binding_index(
    const RinDhcpv6AddressBindingV2* addresses, uint32_t count,
    const uint8_t address[16])
{
    uint32_t index;
    for (index = 0u; index < count; ++index)
        if (byte_equal(addresses[index].address, address, 16u))
            return (int)index;
    return -1;
}

int rin_dhcpv6_client_v2_state_valid(const RinDhcpv6ClientV2* client)
{
    uint32_t index;
    if (client == NULL ||
        client->version != RIN_DHCPV6_CLIENT_V2_VERSION ||
        client->struct_size != sizeof(*client) || client->reserved != 0u ||
        client->address_count > RIN_DHCPV6_MAX_IA_ADDRESSES ||
        client->next_address_generation == 0u ||
        !client_valid(&client->exchange))
        return 0;
    for (index = 0u; index < RIN_DHCPV6_MAX_IA_ADDRESSES; ++index) {
        const RinDhcpv6AddressBindingV2* binding = &client->addresses[index];
        uint32_t prior;
        if (index >= client->address_count) {
            if (!byte_all_zero(binding, sizeof(*binding))) return 0;
            continue;
        }
        if (!address_usable(binding->address) || binding->reserved != 0u ||
            binding->reserved_alignment != 0u ||
            binding->generation == 0u ||
            binding->preferred_until_ms > binding->valid_until_ms ||
            binding->generation >= client->next_address_generation)
            return 0;
        for (prior = 0u; prior < index; ++prior)
            if (byte_equal(client->addresses[prior].address,
                           binding->address, 16u))
                return 0;
    }
    if (client->address_count != 0u &&
        !client_state_has_lease(client->exchange.state) &&
        client->exchange.state != RIN_DHCPV6_STATE_ADVERTISED &&
        client->exchange.state != RIN_DHCPV6_STATE_REQUESTING)
        return 0;
    return 1;
}

int rin_dhcpv6_client_v2_init(
    RinDhcpv6ClientV2* client, const uint8_t* duid, uint32_t duid_size,
    uint32_t iaid, uint64_t interface_generation)
{
    int status;
    if (client == NULL) return RIN_DHCPV6_INVALID_ARGUMENT;
    byte_zero(client, sizeof(*client));
    status = rin_dhcpv6_client_init(&client->exchange, duid, duid_size,
                                    iaid, interface_generation);
    if (status != RIN_DHCPV6_OK) {
        byte_zero(client, sizeof(*client));
        return status;
    }
    client->version = RIN_DHCPV6_CLIENT_V2_VERSION;
    client->struct_size = sizeof(*client);
    client->next_address_generation = 1u;
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_v2_set_mode(
    RinDhcpv6ClientV2* client, RinDhcpv6ClientMode mode)
{
    if (!rin_dhcpv6_client_v2_state_valid(client))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    return rin_dhcpv6_client_set_mode(&client->exchange, mode);
}

int rin_dhcpv6_client_v2_request_reconfigure(
    RinDhcpv6ClientV2* client, RinDhcpv6TransmitKind requested_kind,
    uint64_t now_ms)
{
    if (!rin_dhcpv6_client_v2_state_valid(client))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    return rin_dhcpv6_client_request_reconfigure(
        &client->exchange, requested_kind, now_ms);
}

static uint32_t client_v2_remaining_seconds(uint64_t deadline,
                                            uint64_t now_ms)
{
    uint64_t seconds;
    if (deadline <= now_ms) return 0u;
    seconds = (deadline - now_ms) / UINT64_C(1000);
    if ((deadline - now_ms) % UINT64_C(1000) != 0u) ++seconds;
    return seconds > UINT32_MAX ? UINT32_MAX : (uint32_t)seconds;
}

static int client_v2_rewrite_renew_ia(
    RinDhcpv6ClientV2* client, uint64_t now_ms,
    RinDhcpv6TransmitV1* transmit)
{
    uint8_t rewritten[RIN_DHCPV6_MAX_MESSAGE_SIZE];
    uint32_t input_offset = 4u;
    uint32_t output_offset = 0u;
    uint32_t index;
    int found = 0;
    if (!client || !transmit ||
        (transmit->kind != RIN_DHCPV6_TRANSMIT_REQUEST &&
         transmit->kind != RIN_DHCPV6_TRANSMIT_RENEW &&
         transmit->kind != RIN_DHCPV6_TRANSMIT_REBIND))
        return RIN_DHCPV6_OK;
    if (transmit->message_size < 4u ||
        transmit->message_size > sizeof(transmit->message))
        return RIN_DHCPV6_INVALID_STATE;
    byte_copy(rewritten, transmit->message, 4u);
    output_offset = 4u;
    while (input_offset < transmit->message_size) {
        uint16_t code;
        uint16_t length;
        const uint8_t* value;
        uint32_t option_start = input_offset;
        uint32_t option_end;
        if (transmit->message_size - input_offset < 4u) return
            RIN_DHCPV6_INVALID_STATE;
        code = load_be16(transmit->message + input_offset);
        length = load_be16(transmit->message + input_offset + 2u);
        input_offset += 4u;
        if ((uint32_t)length > transmit->message_size - input_offset)
            return RIN_DHCPV6_INVALID_STATE;
        value = transmit->message + input_offset;
        option_end = input_offset + length;
        if (code != DHCPV6_OPTION_IA_NA) {
            uint32_t option_size = option_end - option_start;
            if (option_size > sizeof(rewritten) - output_offset)
                return RIN_DHCPV6_RANGE_EXHAUSTED;
            byte_copy(rewritten + output_offset,
                      transmit->message + option_start, option_size);
            output_offset += option_size;
        } else {
            uint32_t ia_payload_size = 12u;
            if (found || length < 12u) return RIN_DHCPV6_INVALID_STATE;
            found = 1;
            for (index = 0u; index < client->address_count; ++index) {
                if (client->addresses[index].valid_until_ms > now_ms)
                    ia_payload_size += 28u;
            }
            if (ia_payload_size > UINT16_MAX ||
                ia_payload_size + 4u > sizeof(rewritten) - output_offset)
                return RIN_DHCPV6_RANGE_EXHAUSTED;
            store_be16(rewritten + output_offset, DHCPV6_OPTION_IA_NA);
            store_be16(rewritten + output_offset + 2u,
                       (uint16_t)ia_payload_size);
            byte_copy(rewritten + output_offset + 4u, value, 12u);
            output_offset += 16u;
            for (index = 0u; index < client->address_count; ++index) {
                const RinDhcpv6AddressBindingV2* binding =
                    &client->addresses[index];
                uint8_t* option;
                if (binding->valid_until_ms <= now_ms) continue;
                option = rewritten + output_offset;
                store_be16(option, DHCPV6_OPTION_IA_ADDRESS);
                store_be16(option + 2u, 24u);
                byte_copy(option + 4u, binding->address, 16u);
                store_be32(option + 20u, client_v2_remaining_seconds(
                    binding->preferred_until_ms, now_ms));
                store_be32(option + 24u, client_v2_remaining_seconds(
                    binding->valid_until_ms, now_ms));
                output_offset += 28u;
            }
        }
        input_offset = option_end;
    }
    if (!found) return RIN_DHCPV6_INVALID_STATE;
    if (output_offset > sizeof(transmit->message))
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    byte_zero(transmit->message, sizeof(transmit->message));
    byte_copy(transmit->message, rewritten, output_offset);
    transmit->message_size = output_offset;
    client->exchange.pending.message_size = output_offset;
    byte_zero(client->exchange.pending.message,
              sizeof(client->exchange.pending.message));
    byte_copy(client->exchange.pending.message, rewritten, output_offset);
    byte_zero(rewritten, sizeof(rewritten));
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_v2_prepare(
    RinDhcpv6ClientV2* client, uint32_t new_transaction_id,
    uint64_t now_ms, RinDhcpv6TransmitV1* transmit_out)
{
    int status;
    if (!rin_dhcpv6_client_v2_state_valid(client))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    status = rin_dhcpv6_client_prepare(&client->exchange,
                                      new_transaction_id, now_ms,
                                      transmit_out);
    if (status != RIN_DHCPV6_PACKET_READY) return status;
    status = client_v2_rewrite_renew_ia(client, now_ms, transmit_out);
    if (status != RIN_DHCPV6_OK) {
        /* Do not leave a reserved transmit behind when its expanded IA_NA
         * cannot fit the bounded wire message. */
        (void)rin_dhcpv6_client_complete_transmit(
            &client->exchange, transmit_out, 0);
        byte_zero(transmit_out, sizeof(*transmit_out));
    }
    return status == RIN_DHCPV6_OK ? RIN_DHCPV6_PACKET_READY : status;
}

int rin_dhcpv6_client_v2_complete_transmit(
    RinDhcpv6ClientV2* client, const RinDhcpv6TransmitV1* transmit,
    int sent_successfully)
{
    if (!rin_dhcpv6_client_v2_state_valid(client))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    return rin_dhcpv6_client_complete_transmit(
        &client->exchange, transmit, sent_successfully);
}

static int client_v2_prepare_bindings(
    RinDhcpv6ClientV2* client, const ParsedMessage* parsed, uint64_t now_ms,
    uint32_t old_state,
    RinDhcpv6AddressBindingV2 candidate[RIN_DHCPV6_MAX_IA_ADDRESSES],
    uint32_t* candidate_count_out, uint64_t* next_generation_out)
{
    uint32_t count = 0u;
    uint32_t index;
    uint64_t next_generation = client->next_address_generation;
    int preserve_omitted = old_state == RIN_DHCPV6_STATE_RENEWING ||
        old_state == RIN_DHCPV6_STATE_REBINDING ||
        old_state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING;
    byte_zero(candidate, sizeof(RinDhcpv6AddressBindingV2) *
                          RIN_DHCPV6_MAX_IA_ADDRESSES);
    if (preserve_omitted) {
        count = client->address_count;
        byte_copy(candidate, client->addresses,
                  count * sizeof(candidate[0]));
    }
    for (index = 0u; index < parsed->ia_address_count; ++index) {
        const ParsedIaAddress* parsed_address = &parsed->ia_addresses[index];
        int found = client_v2_binding_index(candidate, count,
                                            parsed_address->address);
        if (parsed_address->status_code != 0u ||
            parsed_address->valid_seconds == 0u) {
            if (found >= 0) {
                uint32_t remove_index = (uint32_t)found;
                if (remove_index + 1u < count)
                    byte_copy(&candidate[remove_index],
                              &candidate[remove_index + 1u],
                              (count - remove_index - 1u) *
                                  sizeof(candidate[0]));
                --count;
                byte_zero(&candidate[count], sizeof(candidate[count]));
            }
            continue;
        }
        {
            RinDhcpv6AddressBindingV2 binding;
            uint64_t preferred_until;
            uint64_t valid_until;
            if (!deadline_from_seconds(now_ms,
                                       parsed_address->preferred_seconds,
                                       &preferred_until) ||
                !deadline_from_seconds(now_ms,
                                       parsed_address->valid_seconds,
                                       &valid_until))
                return RIN_DHCPV6_RANGE_EXHAUSTED;
            byte_zero(&binding, sizeof(binding));
            byte_copy(binding.address, parsed_address->address, 16u);
            binding.preferred_until_ms = preferred_until;
            binding.valid_until_ms = valid_until;
            if (found >= 0) {
                const RinDhcpv6AddressBindingV2* previous =
                    &candidate[(uint32_t)found];
                binding.generation = previous->generation;
                if (previous->preferred_until_ms != preferred_until ||
                    previous->valid_until_ms != valid_until) {
                    if (next_generation == UINT64_MAX)
                        return RIN_DHCPV6_RANGE_EXHAUSTED;
                    binding.generation = next_generation++;
                }
                candidate[(uint32_t)found] = binding;
            } else {
                if (count >= RIN_DHCPV6_MAX_IA_ADDRESSES ||
                    next_generation == UINT64_MAX)
                    return RIN_DHCPV6_RANGE_EXHAUSTED;
                binding.generation = next_generation++;
                candidate[count++] = binding;
            }
        }
    }
    *candidate_count_out = count;
    *next_generation_out = next_generation;
    return RIN_DHCPV6_OK;
}

/* The v1 exchange engine accepts one IAADDR.  Feed it a bounded synthetic
 * IA_NA containing one harmless address while the v2 binding set is built
 * from the original packet above.  The exchange engine still validates the
 * transaction, DUIDs, IAID, server selection, and every non-address option;
 * the synthetic address is replaced by the complete v2 set immediately
 * after commit. */
static int client_v2_single_address_reply(
    const uint8_t* message, uint32_t message_size,
    const ParsedMessage* parsed, const uint8_t address[16],
    uint8_t output[RIN_DHCPV6_MAX_MESSAGE_SIZE], uint32_t* output_size)
{
    uint32_t input_offset = 4u;
    uint32_t output_offset = 4u;
    int found_ia = 0;
    if (!message || !parsed || !address || !output || !output_size ||
        message_size < 4u || message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE)
        return RIN_DHCPV6_INVALID_ARGUMENT;
    byte_zero(output, RIN_DHCPV6_MAX_MESSAGE_SIZE);
    byte_copy(output, message, 4u);
    while (input_offset < message_size) {
        uint32_t option_start = input_offset;
        uint32_t value_start;
        uint32_t option_end;
        uint16_t code;
        uint16_t length;
        if (message_size - input_offset < 4u) return
            RIN_DHCPV6_MALFORMED_PACKET;
        code = load_be16(message + input_offset);
        length = load_be16(message + input_offset + 2u);
        value_start = input_offset + 4u;
        if ((uint32_t)length > message_size - value_start)
            return RIN_DHCPV6_MALFORMED_PACKET;
        option_end = value_start + length;
        if (code != DHCPV6_OPTION_IA_NA) {
            uint32_t option_size = option_end - option_start;
            if (option_size > RIN_DHCPV6_MAX_MESSAGE_SIZE - output_offset)
                return RIN_DHCPV6_RANGE_EXHAUSTED;
            byte_copy(output + output_offset, message + option_start,
                      option_size);
            output_offset += option_size;
        } else {
            uint32_t nested_offset = value_start + 12u;
            uint32_t ia_start = output_offset;
            uint32_t ia_length_offset;
            if (found_ia || length < 12u ||
                RIN_DHCPV6_MAX_MESSAGE_SIZE - output_offset < 32u)
                return RIN_DHCPV6_MALFORMED_PACKET;
            found_ia = 1;
            store_be16(output + output_offset, DHCPV6_OPTION_IA_NA);
            ia_length_offset = output_offset + 2u;
            byte_copy(output + output_offset + 4u, message + value_start,
                      12u);
            /* Keep the shared IA_NA T1/T2 values intact; the v1 exchange
             * engine validates them against this bounded synthetic address. */
            store_be32(output + output_offset + 8u, parsed->t1_seconds);
            store_be32(output + output_offset + 12u, parsed->t2_seconds);
            output_offset += 16u;
            store_be16(output + output_offset, DHCPV6_OPTION_IA_ADDRESS);
            store_be16(output + output_offset + 2u, 24u);
            byte_copy(output + output_offset + 4u, address, 16u);
            store_be32(output + output_offset + 20u,
                       DHCPV6_MAX_VALID_SECONDS);
            store_be32(output + output_offset + 24u,
                       DHCPV6_MAX_VALID_SECONDS);
            output_offset += 28u;
            while (nested_offset < option_end) {
                uint16_t nested_code;
                uint16_t nested_length;
                uint32_t nested_start = nested_offset;
                uint32_t nested_end;
                if (option_end - nested_offset < 4u)
                    return RIN_DHCPV6_MALFORMED_PACKET;
                nested_code = load_be16(message + nested_offset);
                nested_length = load_be16(message + nested_offset + 2u);
                nested_offset += 4u;
                if ((uint32_t)nested_length > option_end - nested_offset)
                    return RIN_DHCPV6_MALFORMED_PACKET;
                nested_end = nested_offset + nested_length;
                if (nested_code != DHCPV6_OPTION_IA_ADDRESS) {
                    uint32_t nested_size = nested_end - nested_start;
                    if (nested_size >
                        RIN_DHCPV6_MAX_MESSAGE_SIZE - output_offset)
                        return RIN_DHCPV6_RANGE_EXHAUSTED;
                    byte_copy(output + output_offset,
                              message + nested_start, nested_size);
                    output_offset += nested_size;
                }
                nested_offset = nested_end;
            }
            if (nested_offset != option_end ||
                output_offset < ia_start + 4u ||
                output_offset - ia_start - 4u > UINT16_MAX)
                return RIN_DHCPV6_MALFORMED_PACKET;
            store_be16(output + ia_length_offset,
                       (uint16_t)(output_offset - ia_start - 4u));
        }
        input_offset = option_end;
    }
    if (!found_ia || output_offset > RIN_DHCPV6_MAX_MESSAGE_SIZE)
        return RIN_DHCPV6_MALFORMED_PACKET;
    *output_size = output_offset;
    return RIN_DHCPV6_OK;
}

static int client_v2_expected_reply(uint32_t state, uint8_t* type_out,
                                    int* require_ia_out)
{
    if (!type_out || !require_ia_out) return 0;
    if (state == RIN_DHCPV6_STATE_SOLICITING) {
        *type_out = DHCPV6_MESSAGE_ADVERTISE;
        *require_ia_out = 1;
        return 1;
    }
    if (state == RIN_DHCPV6_STATE_REQUESTING ||
        state == RIN_DHCPV6_STATE_RENEWING ||
        state == RIN_DHCPV6_STATE_REBINDING ||
        state == RIN_DHCPV6_STATE_RECONFIGURE_REBINDING) {
        *type_out = DHCPV6_MESSAGE_REPLY;
        *require_ia_out = 1;
        return 1;
    }
    if (state == RIN_DHCPV6_STATE_INFORMATION_REQUESTING ||
        state == RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING) {
        *type_out = DHCPV6_MESSAGE_REPLY;
        *require_ia_out = 0;
        return 1;
    }
    return 0;
}

int rin_dhcpv6_client_v2_receive(
    RinDhcpv6ClientV2* client, const uint8_t* message,
    uint32_t message_size, uint64_t now_ms)
{
    ParsedMessage parsed;
    RinDhcpv6AddressBindingV2 candidate[RIN_DHCPV6_MAX_IA_ADDRESSES];
    RinDhcpv6ClientV1 exchange_before;
    uint8_t normalized_message[RIN_DHCPV6_MAX_MESSAGE_SIZE];
    uint32_t normalized_size = 0u;
    uint32_t candidate_count = 0u;
    uint32_t old_state;
    uint8_t expected_type;
    int require_ia;
    int parsed_status;
    int status;
    uint64_t next_generation = client != NULL
        ? client->next_address_generation : 0u;
    uint64_t maximum_valid = 0u;
    uint32_t index;
    if (!rin_dhcpv6_client_v2_state_valid(client) || !message ||
        message_size < 4u || message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE ||
        memory_overlaps(client, sizeof(*client), message, message_size))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (now_ms < client->exchange.last_now_ms)
        return RIN_DHCPV6_CLOCK_ROLLBACK;
    old_state = client->exchange.state;
    if (!client_v2_expected_reply(old_state, &expected_type, &require_ia))
        return RIN_DHCPV6_INVALID_STATE;
    byte_zero(&parsed, sizeof(parsed));
    parsed_status = parse_message(message, message_size, expected_type,
                                  require_ia, &parsed);
    if (parsed_status != RIN_DHCPV6_OK) {
        status = rin_dhcpv6_client_receive(
            &client->exchange, message, message_size, now_ms);
        byte_zero(&parsed, sizeof(parsed));
        return status;
    }
    if (require_ia &&
        client_v2_prepare_bindings(client, &parsed, now_ms, old_state,
                                   candidate, &candidate_count,
                                   &next_generation) != RIN_DHCPV6_OK) {
        byte_zero(&parsed, sizeof(parsed));
        byte_zero(candidate, sizeof(candidate));
        return RIN_DHCPV6_RANGE_EXHAUSTED;
    }
    exchange_before = client->exchange;
    if (require_ia &&
        (candidate_count != 0u || parsed.ia_address_count != 0u)) {
        const uint8_t* exchange_address = exchange_before.address;
        if (!address_usable(exchange_address))
            exchange_address = candidate[0].address;
        parsed_status = client_v2_single_address_reply(
            message, message_size, &parsed, exchange_address,
            normalized_message, &normalized_size);
        if (parsed_status != RIN_DHCPV6_OK) {
            byte_zero(&parsed, sizeof(parsed));
            byte_zero(candidate, sizeof(candidate));
            byte_zero(normalized_message, sizeof(normalized_message));
            return parsed_status;
        }
        status = rin_dhcpv6_client_receive(
            &client->exchange, normalized_message, normalized_size, now_ms);
    } else {
        status = rin_dhcpv6_client_receive(
            &client->exchange, message, message_size, now_ms);
    }
    if (status == RIN_DHCPV6_OFFER_READY && require_ia) {
        client->address_count = candidate_count;
        client->next_address_generation = next_generation;
        byte_zero(client->addresses, sizeof(client->addresses));
        if (candidate_count != 0u)
            byte_copy(client->addresses, candidate,
                      candidate_count * sizeof(candidate[0]));
    } else if (status == RIN_DHCPV6_LEASE_READY && require_ia) {
        client->address_count = candidate_count;
        client->next_address_generation = next_generation;
        byte_zero(client->addresses, sizeof(client->addresses));
        if (candidate_count != 0u) {
            byte_copy(client->addresses, candidate,
                      candidate_count * sizeof(candidate[0]));
            byte_copy(client->exchange.address, candidate[0].address, 16u);
            client->exchange.preferred_until_ms =
                candidate[0].preferred_until_ms;
            for (index = 0u; index < candidate_count; ++index)
                if (client->addresses[index].valid_until_ms > maximum_valid)
                    maximum_valid = client->addresses[index].valid_until_ms;
            if (maximum_valid < client->exchange.rebind_at_ms) {
                uint64_t floor = client->exchange.rebind_at_ms;
                if (floor != UINT64_MAX) ++floor;
                if (floor > maximum_valid) maximum_valid = floor;
            }
            client->exchange.expires_at_ms = maximum_valid;
        } else if (client_state_has_lease(old_state)) {
            /* An IA_NA can withdraw its final IAADDR. Keep the association
             * transaction alive while dhcpd clears the published addresses. */
            byte_copy(client->exchange.address, exchange_before.address, 16u);
            client->exchange.renew_at_ms = exchange_before.renew_at_ms;
            client->exchange.rebind_at_ms = exchange_before.rebind_at_ms;
            client->exchange.expires_at_ms = exchange_before.expires_at_ms;
        } else if (parsed.ia_address_count != 0u) {
            /* A first Reply may contain only zero-lifetime IAADDRs. Keep the
             * accepted IA_NA transaction so a later Renew can acquire an
             * address while the empty set remains unpublished. */
            byte_copy(client->exchange.address, exchange_before.address, 16u);
        }
    }
    byte_zero(&parsed, sizeof(parsed));
    byte_zero(candidate, sizeof(candidate));
    byte_zero(normalized_message, sizeof(normalized_message));
    return status;
}

int rin_dhcpv6_client_v2_get_lease(
    RinDhcpv6ClientV2* client, uint64_t now_ms,
    RinDhcpv6LeaseV2* lease_out)
{
    RinDhcpv6AddressBindingV2 live[RIN_DHCPV6_MAX_IA_ADDRESSES];
    uint32_t live_count = 0u;
    uint32_t index;
    uint64_t maximum_valid = 0u;
    if (memory_overlaps(client, sizeof(*client), lease_out,
                        sizeof(*lease_out)))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (lease_out) byte_zero(lease_out, sizeof(*lease_out));
    if (!rin_dhcpv6_client_v2_state_valid(client) || !lease_out)
        return RIN_DHCPV6_INVALID_ARGUMENT;
    if (!time_valid(&client->exchange, now_ms))
        return RIN_DHCPV6_CLOCK_ROLLBACK;
    if (!client_has_lease(&client->exchange)) return RIN_DHCPV6_NOT_FOUND;
    byte_zero(live, sizeof(live));
    for (index = 0u; index < client->address_count; ++index) {
        const RinDhcpv6AddressBindingV2* binding = &client->addresses[index];
        if (now_ms >= binding->valid_until_ms) continue;
        live[live_count++] = *binding;
        if (binding->valid_until_ms > maximum_valid)
            maximum_valid = binding->valid_until_ms;
    }
    if (now_ms >= client->exchange.expires_at_ms) {
        client->exchange.last_now_ms = now_ms;
        (void)expire_lease(&client->exchange);
        client->address_count = 0u;
        byte_zero(client->addresses, sizeof(client->addresses));
        byte_zero(live, sizeof(live));
        return RIN_DHCPV6_LEASE_EXPIRED;
    }
    if (live_count != client->address_count) {
        client->address_count = live_count;
        byte_zero(client->addresses, sizeof(client->addresses));
        if (live_count != 0u)
            byte_copy(client->addresses, live,
                      live_count * sizeof(live[0]));
    }
    if (live_count != 0u) {
        byte_copy(client->exchange.address, live[0].address, 16u);
        client->exchange.preferred_until_ms =
            live[0].preferred_until_ms;
    }
    client->exchange.last_now_ms = now_ms;
    lease_out->version = RIN_DHCPV6_CLIENT_V2_VERSION;
    lease_out->struct_size = sizeof(*lease_out);
    lease_out->interface_generation = client->exchange.interface_generation;
    lease_out->lease_generation = client->exchange.lease_generation;
    lease_out->renew_at_ms = client->exchange.renew_at_ms;
    lease_out->rebind_at_ms = client->exchange.rebind_at_ms;
    lease_out->expires_at_ms = live_count != 0u
        ? maximum_valid : client->exchange.expires_at_ms;
    lease_out->address_count = live_count;
    lease_out->dns_server_count = client->exchange.dns_server_count;
    lease_out->state = client->exchange.state;
    if (live_count != 0u)
        byte_copy(lease_out->addresses, live,
                  live_count * sizeof(live[0]));
    for (index = 0u; index < lease_out->dns_server_count; ++index)
        byte_copy(lease_out->dns_servers[index],
                  client->exchange.dns_servers[index], 16u);
    byte_zero(live, sizeof(live));
    return RIN_DHCPV6_OK;
}

int rin_dhcpv6_client_v2_stop(RinDhcpv6ClientV2* client)
{
    int status;
    if (!rin_dhcpv6_client_v2_state_valid(client))
        return RIN_DHCPV6_INVALID_ARGUMENT;
    status = rin_dhcpv6_client_stop(&client->exchange);
    if (status == RIN_DHCPV6_OK) {
        client->address_count = 0u;
        byte_zero(client->addresses, sizeof(client->addresses));
    }
    return status;
}

void rin_dhcpv6_client_v2_destroy(RinDhcpv6ClientV2* client)
{
    if (client) byte_zero(client, sizeof(*client));
}
