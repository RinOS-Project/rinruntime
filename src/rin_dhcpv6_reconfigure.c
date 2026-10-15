/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_dhcpv6_reconfigure.h>

#include <limits.h>
#include <stddef.h>

#define DHCPV6_MESSAGE_REPLY 7u
#define DHCPV6_MESSAGE_RECONFIGURE 10u
#define DHCPV6_OPTION_CLIENT_ID 1u
#define DHCPV6_OPTION_SERVER_ID 2u
#define DHCPV6_OPTION_AUTHENTICATION 11u
#define DHCPV6_OPTION_RECONFIGURE_MESSAGE 19u
#define DHCPV6_RKAP_PROTOCOL 3u
#define DHCPV6_RKAP_ALGORITHM_HMAC_MD5 1u
#define DHCPV6_RKAP_RDM_MONOTONIC 0u
#define DHCPV6_RKAP_AUTH_SIZE 28u
#define DHCPV6_RKAP_KEY_TYPE 1u
#define DHCPV6_RKAP_DIGEST_TYPE 2u
#define DHCPV6_MAX_OPTIONS 32u

typedef struct Md5Context {
    uint32_t state[4];
    uint64_t byte_count;
    uint32_t used;
    uint8_t block[64];
} Md5Context;

typedef struct ReconfigureOptions {
    const uint8_t* client_duid;
    const uint8_t* server_duid;
    const uint8_t* authentication;
    uint32_t client_duid_size;
    uint32_t server_duid_size;
    uint32_t authentication_offset;
    uint64_t replay;
    uint8_t requested_kind;
    uint8_t client_seen;
    uint8_t server_seen;
    uint8_t authentication_seen;
    uint8_t requested_kind_seen;
} ReconfigureOptions;

static void bytes_zero(void* pointer, uint32_t size) {
    uint8_t* bytes = (uint8_t*)pointer;
    while (size-- != 0u) *bytes++ = 0u;
}

static void bytes_copy(void* destination, const void* source, uint32_t size) {
    uint8_t* out = (uint8_t*)destination;
    const uint8_t* in = (const uint8_t*)source;
    while (size-- != 0u) *out++ = *in++;
}

static int bytes_equal(const void* left, const void* right, uint32_t size) {
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    while (size-- != 0u) difference |= (uint8_t)(*a++ ^ *b++);
    return difference == 0u;
}

static int bytes_all_zero(const uint8_t* bytes, uint32_t size) {
    uint8_t value = 0u;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static uint16_t load_be16(const uint8_t* bytes) {
    return (uint16_t)(((uint16_t)bytes[0] << 8) | bytes[1]);
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

static uint64_t load_be64(const uint8_t* bytes) {
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        value = (value << 8) | bytes[index];
    return value;
}

static uint32_t load_le32(const uint8_t* bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static void store_le32(uint8_t* bytes, uint32_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static uint32_t md5_rotate_left(uint32_t value, uint32_t bits) {
    return (value << bits) | (value >> (32u - bits));
}

static void md5_transform(Md5Context* context, const uint8_t block[64]) {
    static const uint32_t shift[64] = {
        7u,12u,17u,22u, 7u,12u,17u,22u, 7u,12u,17u,22u, 7u,12u,17u,22u,
        5u, 9u,14u,20u, 5u, 9u,14u,20u, 5u, 9u,14u,20u, 5u, 9u,14u,20u,
        4u,11u,16u,23u, 4u,11u,16u,23u, 4u,11u,16u,23u, 4u,11u,16u,23u,
        6u,10u,15u,21u, 6u,10u,15u,21u, 6u,10u,15u,21u, 6u,10u,15u,21u
    };
    static const uint32_t constants[64] = {
        0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,
        0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
        0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,
        0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
        0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,
        0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
        0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,
        0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
        0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,
        0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
        0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,
        0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
        0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,
        0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
        0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,
        0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
    };
    uint32_t words[16];
    uint32_t a = context->state[0];
    uint32_t b = context->state[1];
    uint32_t c = context->state[2];
    uint32_t d = context->state[3];
    uint32_t index;
    for (index = 0u; index < 16u; ++index)
        words[index] = load_le32(block + index * 4u);
    for (index = 0u; index < 64u; ++index) {
        uint32_t f;
        uint32_t g;
        uint32_t temporary;
        if (index < 16u) {
            f = (b & c) | ((~b) & d);
            g = index;
        } else if (index < 32u) {
            f = (d & b) | ((~d) & c);
            g = (5u * index + 1u) & 15u;
        } else if (index < 48u) {
            f = b ^ c ^ d;
            g = (3u * index + 5u) & 15u;
        } else {
            f = c ^ (b | (~d));
            g = (7u * index) & 15u;
        }
        temporary = d;
        d = c;
        c = b;
        b += md5_rotate_left(a + f + constants[index] + words[g],
                             shift[index]);
        a = temporary;
    }
    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;
    bytes_zero(words, sizeof(words));
}

static void md5_init(Md5Context* context) {
    bytes_zero(context, sizeof(*context));
    context->state[0] = 0x67452301u;
    context->state[1] = 0xefcdab89u;
    context->state[2] = 0x98badcfeu;
    context->state[3] = 0x10325476u;
}

static void md5_update(Md5Context* context, const uint8_t* bytes,
                       uint32_t size) {
    uint32_t take;
    if (size == 0u) return;
    context->byte_count += size;
    while (size != 0u) {
        take = 64u - context->used;
        if (take > size) take = size;
        bytes_copy(context->block + context->used, bytes, take);
        context->used += take;
        bytes += take;
        size -= take;
        if (context->used == 64u) {
            md5_transform(context, context->block);
            context->used = 0u;
        }
    }
}

static void md5_finish(Md5Context* context, uint8_t output[16]) {
    uint8_t length[8];
    uint8_t pad = 0x80u;
    uint8_t zero = 0u;
    uint64_t bit_count = context->byte_count << 3;
    uint32_t index;
    for (index = 0u; index < sizeof(length); ++index)
        length[index] = (uint8_t)(bit_count >> (index * 8u));
    md5_update(context, &pad, 1u);
    while (context->used != 56u)
        md5_update(context, &zero, 1u);
    md5_update(context, length, sizeof(length));
    for (index = 0u; index < 4u; ++index)
        store_le32(output + index * 4u, context->state[index]);
    bytes_zero(context, sizeof(*context));
    bytes_zero(length, sizeof(length));
}

static void hmac_md5(const uint8_t key[RIN_DHCPV6_RECONFIGURE_KEY_SIZE],
                     const uint8_t* message, uint32_t message_size,
                     uint8_t output[16]) {
    Md5Context context;
    uint8_t inner[16];
    uint8_t pad[64];
    uint32_t index;
    for (index = 0u; index < sizeof(pad); ++index)
        pad[index] = index < RIN_DHCPV6_RECONFIGURE_KEY_SIZE
            ? (uint8_t)(key[index] ^ 0x36u) : 0x36u;
    md5_init(&context);
    md5_update(&context, pad, sizeof(pad));
    md5_update(&context, message, message_size);
    md5_finish(&context, inner);
    for (index = 0u; index < sizeof(pad); ++index)
        pad[index] = index < RIN_DHCPV6_RECONFIGURE_KEY_SIZE
            ? (uint8_t)(key[index] ^ 0x5cu) : 0x5cu;
    md5_init(&context);
    md5_update(&context, pad, sizeof(pad));
    md5_update(&context, inner, sizeof(inner));
    md5_finish(&context, output);
    bytes_zero(inner, sizeof(inner));
    bytes_zero(pad, sizeof(pad));
}

static int client_snapshot_valid(const RinDhcpv6ClientV1* client) {
    return client != NULL && client->version == RIN_DHCPV6_CLIENT_VERSION &&
           client->struct_size == sizeof(*client) && client->initialized == 1u &&
           client->interface_generation != 0u && client->lease_generation != 0u &&
           client->duid_size >= 5u && client->duid_size <= RIN_DHCPV6_MAX_DUID_SIZE &&
           client->server_duid_size >= 5u &&
           client->server_duid_size <= RIN_DHCPV6_MAX_DUID_SIZE;
}

static int state_valid(const RinDhcpv6ReconfigureStateV1* state) {
    if (!state || state->version != RIN_DHCPV6_RECONFIGURE_VERSION ||
        state->struct_size != sizeof(*state) || state->initialized != 1u ||
        state->key_present > 1u || state->reserved0 != 0u)
        return 0;
    if (state->key_present == 0u)
        return state->interface_generation == 0u &&
               state->lease_generation == 0u && state->highest_replay == 0u &&
               state->server_duid_size == 0u &&
               bytes_all_zero(state->server_duid, sizeof(state->server_duid)) &&
               bytes_all_zero(state->key, sizeof(state->key));
    return state->interface_generation != 0u &&
           state->lease_generation != 0u && state->server_duid_size >= 5u &&
           state->server_duid_size <= RIN_DHCPV6_MAX_DUID_SIZE &&
           duid_valid(state->server_duid, state->server_duid_size) &&
           bytes_all_zero(state->server_duid + state->server_duid_size,
                          sizeof(state->server_duid) - state->server_duid_size) &&
           !bytes_all_zero(state->key, sizeof(state->key));
}

int rin_dhcpv6_reconfigure_state_valid(
    const RinDhcpv6ReconfigureStateV1* state) {
    return state_valid(state);
}

static void clear_key(RinDhcpv6ReconfigureStateV1* state) {
    state->key_present = 0u;
    state->interface_generation = 0u;
    state->lease_generation = 0u;
    state->highest_replay = 0u;
    state->server_duid_size = 0u;
    bytes_zero(state->server_duid, sizeof(state->server_duid));
    bytes_zero(state->key, sizeof(state->key));
}

static int parse_options(const uint8_t* message, uint32_t message_size,
                         ReconfigureOptions* parsed) {
    uint32_t offset = 4u;
    uint32_t count = 0u;
    if (!message || !parsed || message_size < 4u ||
        message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE)
        return 0;
    bytes_zero(parsed, sizeof(*parsed));
    while (offset < message_size) {
        uint16_t code;
        uint16_t length;
        const uint8_t* value;
        if (message_size - offset < 4u || count++ == DHCPV6_MAX_OPTIONS)
            return 0;
        code = load_be16(message + offset);
        length = load_be16(message + offset + 2u);
        offset += 4u;
        if ((uint32_t)length > message_size - offset) return 0;
        value = message + offset;
        if (code == DHCPV6_OPTION_CLIENT_ID) {
            if (parsed->client_seen || length < 5u ||
                length > RIN_DHCPV6_MAX_DUID_SIZE) return 0;
            parsed->client_seen = 1u;
            parsed->client_duid = value;
            parsed->client_duid_size = length;
        } else if (code == DHCPV6_OPTION_SERVER_ID) {
            if (parsed->server_seen || length < 5u ||
                length > RIN_DHCPV6_MAX_DUID_SIZE) return 0;
            parsed->server_seen = 1u;
            parsed->server_duid = value;
            parsed->server_duid_size = length;
        } else if (code == DHCPV6_OPTION_AUTHENTICATION) {
            if (parsed->authentication_seen || length != DHCPV6_RKAP_AUTH_SIZE ||
                value[0] != DHCPV6_RKAP_PROTOCOL ||
                value[1] != DHCPV6_RKAP_ALGORITHM_HMAC_MD5 ||
                value[2] != DHCPV6_RKAP_RDM_MONOTONIC)
                return 0;
            parsed->authentication_seen = 1u;
            parsed->authentication = value;
            parsed->authentication_offset = offset;
            parsed->replay = load_be64(value + 3u);
        } else if (code == DHCPV6_OPTION_RECONFIGURE_MESSAGE) {
            if (parsed->requested_kind_seen || length != 1u ||
                (value[0] != RIN_DHCPV6_TRANSMIT_RENEW &&
                 value[0] != RIN_DHCPV6_TRANSMIT_REBIND &&
                 value[0] != RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST))
                return 0;
            parsed->requested_kind_seen = 1u;
            parsed->requested_kind = value[0];
        }
        offset += length;
    }
    return offset == message_size;
}

int rin_dhcpv6_reconfigure_init(RinDhcpv6ReconfigureStateV1* state) {
    if (!state) return RIN_DHCPV6_RECONFIGURE_INVALID_ARGUMENT;
    bytes_zero(state, sizeof(*state));
    state->version = RIN_DHCPV6_RECONFIGURE_VERSION;
    state->struct_size = sizeof(*state);
    state->initialized = 1u;
    return RIN_DHCPV6_RECONFIGURE_OK;
}

int rin_dhcpv6_reconfigure_capture_reply(
    RinDhcpv6ReconfigureStateV1* state, const RinDhcpv6ClientV1* client,
    const uint8_t* message, uint32_t message_size) {
    ReconfigureOptions parsed;
    uint8_t key[RIN_DHCPV6_RECONFIGURE_KEY_SIZE];
    if (!state_valid(state) || !client_snapshot_valid(client) || !message ||
        message_size < 4u || message_size > RIN_DHCPV6_MAX_MESSAGE_SIZE)
        return RIN_DHCPV6_RECONFIGURE_INVALID_ARGUMENT;
    /* A new accepted Reply is authoritative.  Never keep a key that did not
     * accompany its lease generation. */
    clear_key(state);
    if (message[0] != DHCPV6_MESSAGE_REPLY ||
        !parse_options(message, message_size, &parsed) ||
        !parsed.client_seen || !parsed.server_seen ||
        !parsed.authentication_seen || parsed.authentication[11] !=
            DHCPV6_RKAP_KEY_TYPE ||
        parsed.client_duid_size != client->duid_size ||
        parsed.server_duid_size != client->server_duid_size ||
        !bytes_equal(parsed.client_duid, client->duid, client->duid_size) ||
        !bytes_equal(parsed.server_duid, client->server_duid,
                     client->server_duid_size) ||
        bytes_all_zero(parsed.authentication + 12u,
                       RIN_DHCPV6_RECONFIGURE_KEY_SIZE)) {
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_NOT_FOR_US;
    }
    bytes_copy(key, parsed.authentication + 12u, sizeof(key));
    state->interface_generation = client->interface_generation;
    state->lease_generation = client->lease_generation;
    state->highest_replay = parsed.replay; /* First accepted value seeds RDM. */
    state->server_duid_size = client->server_duid_size;
    bytes_copy(state->server_duid, client->server_duid,
               client->server_duid_size);
    bytes_copy(state->key, key, sizeof(key));
    state->key_present = 1u;
    bytes_zero(key, sizeof(key));
    bytes_zero(&parsed, sizeof(parsed));
    return RIN_DHCPV6_RECONFIGURE_KEY_CAPTURED;
}

int rin_dhcpv6_reconfigure_receive(
    RinDhcpv6ReconfigureStateV1* state, RinDhcpv6ClientV1* client,
    const uint8_t* message, uint32_t message_size, uint64_t now_ms) {
    ReconfigureOptions parsed;
    uint8_t snapshot[RIN_DHCPV6_MAX_MESSAGE_SIZE];
    uint8_t digest[16];
    int result;
    if (!state_valid(state) || !client_snapshot_valid(client) || !message ||
        message_size < 4u || message_size > sizeof(snapshot))
        return RIN_DHCPV6_RECONFIGURE_INVALID_ARGUMENT;
    if (state->key_present != 1u ||
        state->interface_generation != client->interface_generation ||
        state->lease_generation != client->lease_generation ||
        state->server_duid_size != client->server_duid_size ||
        !bytes_equal(state->server_duid, client->server_duid,
                     client->server_duid_size))
        return RIN_DHCPV6_RECONFIGURE_NOT_FOR_US;
    if (client->pending_present ||
        (client->state != RIN_DHCPV6_STATE_BOUND &&
         client->state != RIN_DHCPV6_STATE_INFORMATION_BOUND))
        return RIN_DHCPV6_RECONFIGURE_BUSY;
    if (message[0] != DHCPV6_MESSAGE_RECONFIGURE ||
        !parse_options(message, message_size, &parsed) ||
        !parsed.client_seen || !parsed.server_seen ||
        !parsed.authentication_seen || !parsed.requested_kind_seen ||
        parsed.authentication[11] != DHCPV6_RKAP_DIGEST_TYPE ||
        parsed.client_duid_size != client->duid_size ||
        parsed.server_duid_size != state->server_duid_size ||
        !bytes_equal(parsed.client_duid, client->duid, client->duid_size) ||
        !bytes_equal(parsed.server_duid, state->server_duid,
                     state->server_duid_size)) {
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_NOT_FOR_US;
    }
    if (parsed.replay <= state->highest_replay) {
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_REPLAY;
    }
    bytes_copy(snapshot, message, message_size);
    bytes_zero(snapshot + parsed.authentication_offset + 12u,
               RIN_DHCPV6_RECONFIGURE_KEY_SIZE);
    hmac_md5(state->key, snapshot, message_size, digest);
    if (!bytes_equal(digest, parsed.authentication + 12u, sizeof(digest))) {
        bytes_zero(snapshot, sizeof(snapshot));
        bytes_zero(digest, sizeof(digest));
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_AUTH_FAILED;
    }
    result = rin_dhcpv6_client_request_reconfigure(
        client, (RinDhcpv6TransmitKind)parsed.requested_kind, now_ms);
    if (result == RIN_DHCPV6_BUSY) {
        bytes_zero(snapshot, sizeof(snapshot));
        bytes_zero(digest, sizeof(digest));
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_BUSY;
    }
    if (result != RIN_DHCPV6_OK) {
        bytes_zero(snapshot, sizeof(snapshot));
        bytes_zero(digest, sizeof(digest));
        bytes_zero(&parsed, sizeof(parsed));
        return RIN_DHCPV6_RECONFIGURE_NOT_FOR_US;
    }
    state->highest_replay = parsed.replay;
    bytes_zero(snapshot, sizeof(snapshot));
    bytes_zero(digest, sizeof(digest));
    bytes_zero(&parsed, sizeof(parsed));
    return RIN_DHCPV6_RECONFIGURE_ACCEPTED;
}

void rin_dhcpv6_reconfigure_destroy(RinDhcpv6ReconfigureStateV1* state) {
    if (state) bytes_zero(state, sizeof(*state));
}
