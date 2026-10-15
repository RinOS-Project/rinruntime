/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_DNS_WIRE_H
#define RIN_SHARED_DNS_WIRE_H

#include <stddef.h>
#include <stdint.h>

#define RIN_DNS_WIRE_MAX_NAME_SIZE 255u
#define RIN_DNS_WIRE_MAX_POINTERS 32u
#define RIN_DNS_WIRE_MAX_ANSWERS 32u
#define RIN_DNS_WIRE_MAX_AUTHORITY 32u
#define RIN_DNS_WIRE_MAX_ADDITIONAL 32u
#define RIN_DNS_WIRE_MAX_EDNS_OPTIONS 32u
#define RIN_DNS_WIRE_MAX_CNAME_HOPS 8u
/* A response can carry more records, but publishing a partial answer list is
 * unsafe.  The resolver admits at most this many same-family addresses as one
 * atomic result. */
#define RIN_DNS_WIRE_MAX_RESULT_ADDRESSES 8u

#define RIN_DNS_WIRE_TYPE_A 1u
#define RIN_DNS_WIRE_TYPE_CNAME 5u
#define RIN_DNS_WIRE_TYPE_PTR 12u
#define RIN_DNS_WIRE_TYPE_AAAA 28u
#define RIN_DNS_WIRE_TYPE_OPT 41u
#define RIN_DNS_WIRE_CLASS_IN 1u

#define RIN_DNS_WIRE_EDNS_OPTION_ECS 8u
#define RIN_DNS_WIRE_EDNS_OPTION_COOKIE 10u
#define RIN_DNS_WIRE_EDNS_OPTION_PADDING 12u
#define RIN_DNS_WIRE_EDNS_OPTION_EDE 15u

typedef struct RinDnsWireAnswer {
    uint16_t type;
    uint32_t ttl;
    uint8_t address[16];
    char name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u];
    uint16_t edns_udp_payload_size;
    uint16_t edns_extended_error_code;
    uint8_t edns_present;
    uint8_t edns_dnssec_ok;
    uint8_t edns_extended_error_present;
    uint8_t edns_cookie_present;
    uint8_t edns_client_subnet_present;
    uint8_t edns_padding_present;
} RinDnsWireAnswer;

typedef struct RinDnsWireAnswerSet {
    RinDnsWireAnswer primary;
    uint32_t address_count;
    uint8_t addresses[RIN_DNS_WIRE_MAX_RESULT_ADDRESSES][16];
} RinDnsWireAnswerSet;

/* ``parse_response_ex`` keeps a CNAME-only or negative response private until
 * every DNS section has passed the same bounded admission rules as a positive
 * answer.  The legacy success-only wrapper below deliberately maps these
 * states back to failure so existing callers cannot accidentally publish a
 * partial result. */
#define RIN_DNS_WIRE_PARSE_SUCCESS 0
#define RIN_DNS_WIRE_PARSE_CNAME_REFERRAL 1
#define RIN_DNS_WIRE_PARSE_NAME_ERROR 2
#define RIN_DNS_WIRE_PARSE_NO_DATA 3
#define RIN_DNS_WIRE_PARSE_NOT_IMPLEMENTED 4

static inline uint16_t rin_dns_wire_read_u16(const uint8_t* input)
{
    return (uint16_t)(((uint16_t)input[0] << 8) | (uint16_t)input[1]);
}

static inline uint32_t rin_dns_wire_read_u32(const uint8_t* input)
{
    return ((uint32_t)input[0] << 24) | ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] << 8) | (uint32_t)input[3];
}

static inline uint8_t rin_dns_wire_fold_ascii(uint8_t character)
{
    if (character >= (uint8_t)'A' && character <= (uint8_t)'Z') {
        return (uint8_t)(character + ((uint8_t)'a' - (uint8_t)'A'));
    }
    return character;
}

static inline int rin_dns_wire_names_equal(const char* left,
                                           const char* right)
{
    size_t index = 0u;
    if (!left || !right) return 0;
    while (index <= RIN_DNS_WIRE_MAX_NAME_SIZE) {
        uint8_t left_character = (uint8_t)left[index];
        uint8_t right_character = (uint8_t)right[index];
        if (index < RIN_DNS_WIRE_MAX_NAME_SIZE &&
            left_character == (uint8_t)'.' && left[index + 1u] == '\0') {
            left_character = 0u;
        }
        if (index < RIN_DNS_WIRE_MAX_NAME_SIZE &&
            right_character == (uint8_t)'.' && right[index + 1u] == '\0') {
            right_character = 0u;
        }
        if (rin_dns_wire_fold_ascii(left_character) !=
            rin_dns_wire_fold_ascii(right_character)) {
            return 0;
        }
        if (left_character == 0u) return 1;
        ++index;
    }
    return 0;
}

static inline int rin_dns_wire_copy_name(char* destination,
                                         size_t capacity,
                                         const char* source)
{
    size_t index;
    if (!destination || capacity == 0u || !source) return -1;
    for (index = 0u; index < capacity; ++index) {
        destination[index] = source[index];
        if (source[index] == '\0') return 0;
    }
    destination[0] = '\0';
    return -1;
}

/* Encode a presentation name into RFC 1035 label form. Empty labels,
 * oversized labels, ambiguous label bytes, and names above the 255-byte wire
 * limit are rejected before output length is published. One terminal dot is
 * accepted as the absolute-name spelling. */
static inline int rin_dns_wire_encode_name(const char* name,
                                           uint8_t* output,
                                           size_t output_capacity,
                                           size_t* output_size)
{
    size_t input_position = 0u;
    size_t output_position = 0u;
    if (output_size) *output_size = 0u;
    if (!name || !output || !output_size || output_capacity == 0u ||
        name[0] == '\0') {
        return -1;
    }

    for (;;) {
        size_t label_start = input_position;
        size_t label_length = 0u;
        while (input_position <= RIN_DNS_WIRE_MAX_NAME_SIZE &&
               name[input_position] != '\0' &&
               name[input_position] != '.') {
            uint8_t character = (uint8_t)name[input_position];
            if (character < UINT8_C(0x21) || character > UINT8_C(0x7e) ||
                character == (uint8_t)'\\') {
                return -1;
            }
            ++input_position;
            ++label_length;
        }
        if (input_position > RIN_DNS_WIRE_MAX_NAME_SIZE ||
            label_length == 0u || label_length > 63u ||
            output_position >= output_capacity ||
            label_length > output_capacity - output_position - 1u ||
            output_position + 1u + label_length >=
                RIN_DNS_WIRE_MAX_NAME_SIZE) {
            return -1;
        }
        output[output_position++] = (uint8_t)label_length;
        for (size_t index = 0u; index < label_length; ++index) {
            output[output_position++] =
                (uint8_t)name[label_start + index];
        }
        if (name[input_position] == '\0') break;
        ++input_position;
        if (name[input_position] == '\0') break;
    }

    if (output_position >= output_capacity ||
        output_position >= RIN_DNS_WIRE_MAX_NAME_SIZE) {
        return -1;
    }
    output[output_position++] = 0u;
    *output_size = output_position;
    return 0;
}

/* Decode one RFC 1035 presentation name without allocation. Compression
 * pointers must refer backwards to a previously encoded suffix. Requiring a
 * strict decrease rejects self/forward pointers and makes cycles impossible;
 * the pointer count remains bounded as a second CPU-exhaustion guard.
 *
 * Output is the ASCII/punycode presentation form used by RinResolver. Raw
 * binary labels, embedded dots and backslashes are rejected because they
 * cannot be represented unambiguously by this interface. */
static inline int rin_dns_wire_decode_name(const uint8_t* packet,
                                           size_t packet_size,
                                           size_t start_offset,
                                           char* output,
                                           size_t output_capacity,
                                           size_t* next_offset)
{
    size_t position = start_offset;
    size_t output_size = 0u;
    size_t expanded_wire_size = 1u;
    size_t final_offset = 0u;
    unsigned int pointers = 0u;
    int jumped = 0;

    if (next_offset) *next_offset = 0u;
    if (output && output_capacity != 0u) output[0] = '\0';
    if (!packet || !output || output_capacity == 0u || !next_offset ||
        start_offset >= packet_size) {
        return -1;
    }

    for (;;) {
        uint8_t length;
        size_t label_end;
        size_t index;
        if (position >= packet_size) goto fail;
        length = packet[position];
        if (length == 0u) {
            if (!jumped) final_offset = position + 1u;
            output[output_size] = '\0';
            *next_offset = final_offset;
            return 0;
        }
        if ((length & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
            size_t target;
            if (position + 1u >= packet_size ||
                ++pointers > RIN_DNS_WIRE_MAX_POINTERS) {
                goto fail;
            }
            target = ((size_t)(length & UINT8_C(0x3f)) << 8) |
                     packet[position + 1u];
            if (target >= position || target >= packet_size) goto fail;
            if (!jumped) final_offset = position + 2u;
            position = target;
            jumped = 1;
            continue;
        }
        if ((length & UINT8_C(0xc0)) != 0u || length > 63u) goto fail;
        label_end = position + 1u + (size_t)length;
        if (label_end < position || label_end > packet_size ||
            expanded_wire_size > RIN_DNS_WIRE_MAX_NAME_SIZE -
                                     (1u + (size_t)length)) {
            goto fail;
        }
        if (output_size != 0u) {
            if (output_size + 1u >= output_capacity) goto fail;
            output[output_size++] = '.';
        }
        if ((size_t)length >= output_capacity - output_size) goto fail;
        for (index = 0u; index < (size_t)length; ++index) {
            uint8_t character = packet[position + 1u + index];
            if (character < UINT8_C(0x21) || character > UINT8_C(0x7e) ||
                character == (uint8_t)'.' || character == (uint8_t)'\\') {
                goto fail;
            }
            output[output_size++] = (char)character;
        }
        expanded_wire_size += 1u + (size_t)length;
        position = label_end;
    }

fail:
    output[0] = '\0';
    *next_offset = 0u;
    return -1;
}

static inline void rin_dns_wire_clear_answer(RinDnsWireAnswer* answer)
{
    size_t index;
    if (!answer) return;
    answer->type = 0u;
    answer->ttl = 0u;
    answer->edns_udp_payload_size = 0u;
    answer->edns_extended_error_code = 0u;
    answer->edns_present = 0u;
    answer->edns_dnssec_ok = 0u;
    answer->edns_extended_error_present = 0u;
    answer->edns_cookie_present = 0u;
    answer->edns_client_subnet_present = 0u;
    answer->edns_padding_present = 0u;
    for (index = 0u; index < sizeof(answer->address); ++index) {
        answer->address[index] = 0u;
    }
    answer->name[0] = '\0';
}

static inline void rin_dns_wire_clear_answer_set(RinDnsWireAnswerSet* set)
{
    size_t index;
    if (!set) return;
    rin_dns_wire_clear_answer(&set->primary);
    set->address_count = 0u;
    for (index = 0u; index < sizeof(set->addresses); ++index) {
        ((uint8_t*)set->addresses)[index] = 0u;
    }
}

/* Admit only a truncated response that belongs to the exact outstanding
 * question. This is intentionally separate from the complete-response parser:
 * TC permits the remaining UDP sections to be incomplete, but must not let an
 * unrelated datagram trigger a TCP connection. */
static inline int rin_dns_wire_is_truncated_response(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type)
{
    uint16_t flags;
    size_t next_offset = 0u;
    char decoded_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};
    if (!packet || packet_size < 12u || !expected_name ||
        (expected_type != RIN_DNS_WIRE_TYPE_A &&
         expected_type != RIN_DNS_WIRE_TYPE_AAAA &&
         expected_type != RIN_DNS_WIRE_TYPE_PTR) ||
        rin_dns_wire_read_u16(packet) != expected_id) {
        return 0;
    }
    flags = rin_dns_wire_read_u16(packet + 2u);
    if ((flags & UINT16_C(0x8000)) == 0u ||
        (flags & UINT16_C(0x7800)) != 0u ||
        (flags & UINT16_C(0x0200)) == 0u ||
        (flags & UINT16_C(0x000f)) != 0u ||
        rin_dns_wire_read_u16(packet + 4u) != 1u ||
        rin_dns_wire_decode_name(packet, packet_size, 12u, decoded_name,
                                 sizeof(decoded_name), &next_offset) != 0 ||
        !rin_dns_wire_names_equal(decoded_name, expected_name) ||
        next_offset > packet_size || packet_size - next_offset < 4u ||
        rin_dns_wire_read_u16(packet + next_offset) != expected_type ||
        rin_dns_wire_read_u16(packet + next_offset + 2u) !=
            RIN_DNS_WIRE_CLASS_IN) {
        return 0;
    }
    return 1;
}

/* EDNS negotiation failures are not normal DNS answers.  Admit a downgrade
 * trigger only after the same exact question checks used by the complete
 * parser, and only for the two bounded responses an EDNS0 version-zero query
 * can safely retry without OPT: an empty FORMERR, or an empty BADVERS carried
 * by one well-formed root OPT record.  In particular, an arbitrary parse
 * failure, NXDOMAIN, NOTIMP, an answer-bearing error, or an OPT with unknown
 * version/Z bits must never make a caller silently change wire mode. */
static inline int rin_dns_wire_utf8_valid(const uint8_t* text, size_t size)
{
    size_t position = 0u;
    if (!text && size != 0u) return 0;
    while (position < size) {
        uint8_t first = text[position++];
        uint32_t code_point;
        unsigned int continuation_count;
        uint32_t minimum;
        if (first < UINT8_C(0x80)) continue;
        if (first >= UINT8_C(0xc2) && first <= UINT8_C(0xdf)) {
            code_point = first & UINT8_C(0x1f);
            continuation_count = 1u;
            minimum = UINT32_C(0x80);
        } else if (first >= UINT8_C(0xe0) && first <= UINT8_C(0xef)) {
            code_point = first & UINT8_C(0x0f);
            continuation_count = 2u;
            minimum = UINT32_C(0x800);
        } else if (first >= UINT8_C(0xf0) && first <= UINT8_C(0xf4)) {
            code_point = first & UINT8_C(0x07);
            continuation_count = 3u;
            minimum = UINT32_C(0x10000);
        } else {
            return 0;
        }
        if (continuation_count > size - position) return 0;
        while (continuation_count-- != 0u) {
            uint8_t continuation = text[position++];
            if ((continuation & UINT8_C(0xc0)) != UINT8_C(0x80)) return 0;
            code_point = (code_point << 6u) | (continuation & UINT8_C(0x3f));
        }
        if (code_point < minimum ||
            (code_point >= UINT32_C(0xd800) &&
             code_point <= UINT32_C(0xdfff)) ||
            code_point > UINT32_C(0x10ffff)) {
            return 0;
        }
    }
    return 1;
}

static inline int rin_dns_wire_edns_ecs_valid(const uint8_t* data,
                                              size_t size)
{
    uint16_t family;
    uint8_t source_prefix;
    uint8_t scope_prefix;
    uint8_t maximum_prefix;
    size_t address_size;
    if (!data || size < 4u) return 0;
    family = rin_dns_wire_read_u16(data);
    source_prefix = data[2u];
    scope_prefix = data[3u];
    address_size = size - 4u;
    if (family == 1u) {
        maximum_prefix = 32u;
    } else if (family == 2u) {
        maximum_prefix = 128u;
    } else {
        /* Unknown address families retain the EDNS forward-compatibility
         * rule: their bounded TLV has already been structurally admitted. */
        return 1;
    }
    if (source_prefix > maximum_prefix || scope_prefix > maximum_prefix ||
        address_size != ((size_t)source_prefix + 7u) / 8u) {
        return 0;
    }
    if ((source_prefix & 7u) != 0u && address_size != 0u &&
        (data[size - 1u] & ((UINT8_C(1) <<
                              (8u - (source_prefix & 7u))) - 1u)) != 0u) {
        return 0;
    }
    return 1;
}

/* A response must distinguish the standard options it understands from a
 * merely length-valid opaque blob.  COOKIE and ECS have canonical wire
 * bounds, Padding is deliberately opaque, and EDE carries a UTF-8 diagnostic
 * after its 16-bit information code.  Client emission is owned by
 * rin_dns_client_policy.h; unknown response option codes remain accepted
 * after the same bounded TLV walk. */
static inline int rin_dns_wire_edns_options_valid(const uint8_t* packet,
                                                  size_t position,
                                                  size_t data_end,
                                                  RinDnsWireAnswer* answer)
{
    unsigned int option_count = 0u;
    uint8_t saw_cookie = 0u;
    uint8_t saw_ecs = 0u;
    uint8_t saw_padding = 0u;
    if (!packet || position > data_end) return 0;
    while (position < data_end) {
        uint16_t option_code;
        uint16_t option_length;
        const uint8_t* option_data;
        if (++option_count > RIN_DNS_WIRE_MAX_EDNS_OPTIONS ||
            data_end - position < 4u) {
            return 0;
        }
        option_code = rin_dns_wire_read_u16(packet + position);
        option_length = rin_dns_wire_read_u16(packet + position + 2u);
        position += 4u;
        if ((size_t)option_length > data_end - position) return 0;
        option_data = packet + position;
        switch (option_code) {
            case RIN_DNS_WIRE_EDNS_OPTION_COOKIE:
                if (saw_cookie ||
                    !(option_length == 8u ||
                      (option_length >= 16u && option_length <= 40u))) {
                    return 0;
                }
                saw_cookie = 1u;
                break;
            case RIN_DNS_WIRE_EDNS_OPTION_ECS:
                if (saw_ecs || !rin_dns_wire_edns_ecs_valid(
                                   option_data, (size_t)option_length)) {
                    return 0;
                }
                saw_ecs = 1u;
                break;
            case RIN_DNS_WIRE_EDNS_OPTION_PADDING:
                if (saw_padding) return 0;
                saw_padding = 1u;
                break;
            case RIN_DNS_WIRE_EDNS_OPTION_EDE:
                if (option_length < 2u ||
                    !rin_dns_wire_utf8_valid(option_data + 2u,
                                              (size_t)option_length - 2u)) {
                    return 0;
                }
                /* RFC 8914 permits multiple EDE options. Preserve the first
                 * code for this bounded private metadata while validating all
                 * later diagnostics instead of rejecting a legal response. */
                if (answer && !answer->edns_extended_error_present) {
                    answer->edns_extended_error_code =
                        rin_dns_wire_read_u16(option_data);
                    answer->edns_extended_error_present = 1u;
                }
                break;
            default:
                break;
        }
        position += (size_t)option_length;
    }
    if (position != data_end) return 0;
    if (answer) {
        answer->edns_cookie_present = saw_cookie;
        answer->edns_client_subnet_present = saw_ecs;
        answer->edns_padding_present = saw_padding;
    }
    return 1;
}

static inline int rin_dns_wire_is_edns_downgrade_response(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type)
{
    uint16_t flags;
    uint16_t rcode;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    size_t position = 12u;
    size_t next_offset = 0u;
    char decoded_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};

    if (!packet || packet_size < 12u || !expected_name ||
        (expected_type != RIN_DNS_WIRE_TYPE_A &&
         expected_type != RIN_DNS_WIRE_TYPE_AAAA &&
         expected_type != RIN_DNS_WIRE_TYPE_PTR) ||
        rin_dns_wire_read_u16(packet) != expected_id) {
        return 0;
    }
    flags = rin_dns_wire_read_u16(packet + 2u);
    rcode = (uint16_t)(flags & UINT16_C(0x000f));
    answer_count = rin_dns_wire_read_u16(packet + 6u);
    authority_count = rin_dns_wire_read_u16(packet + 8u);
    additional_count = rin_dns_wire_read_u16(packet + 10u);
    if ((flags & UINT16_C(0x8000)) == 0u ||
        (flags & UINT16_C(0x7800)) != 0u ||
        (flags & UINT16_C(0x0200)) != 0u ||
        (rcode != 0u && rcode != 1u) ||
        rin_dns_wire_read_u16(packet + 4u) != 1u ||
        answer_count != 0u || authority_count != 0u || additional_count > 1u ||
        rin_dns_wire_decode_name(packet, packet_size, position, decoded_name,
                                 sizeof(decoded_name), &next_offset) != 0 ||
        !rin_dns_wire_names_equal(decoded_name, expected_name) ||
        next_offset > packet_size || packet_size - next_offset < 4u ||
        rin_dns_wire_read_u16(packet + next_offset) != expected_type ||
        rin_dns_wire_read_u16(packet + next_offset + 2u) !=
            RIN_DNS_WIRE_CLASS_IN) {
        return 0;
    }
    position = next_offset + 4u;
    if (additional_count == 0u) return rcode == 1u && position == packet_size;

    {
        uint16_t record_type;
        uint16_t data_length;
        uint32_t ttl;
        size_t data_end;
        if (rin_dns_wire_decode_name(packet, packet_size, position,
                                     decoded_name, sizeof(decoded_name),
                                     &next_offset) != 0 ||
            decoded_name[0] != '\0' || next_offset > packet_size ||
            packet_size - next_offset < 10u) {
            return 0;
        }
        record_type = rin_dns_wire_read_u16(packet + next_offset);
        ttl = rin_dns_wire_read_u32(packet + next_offset + 4u);
        data_length = rin_dns_wire_read_u16(packet + next_offset + 8u);
        position = next_offset + 10u;
        if (record_type != RIN_DNS_WIRE_TYPE_OPT ||
            (size_t)data_length > packet_size - position) {
            return 0;
        }
        data_end = position + (size_t)data_length;
        if (!rin_dns_wire_edns_options_valid(packet, position, data_end,
                                             NULL) ||
            data_end != packet_size ||
            ((ttl >> 16) & UINT32_C(0xff)) != 0u ||
            (ttl & UINT32_C(0x7fff)) != 0u) {
            return 0;
        }
        return rcode == 0u && (ttl >> 24) == 1u;
    }
}

/* NOTIMP is a terminal response to the outstanding standard query, not an
 * EDNS negotiation signal.  Do not trust its RCODE alone: a peer has to echo
 * the exact question and every declared record must be bounded and complete
 * before callers are allowed to stop retrying.  The strict no-answer shape
 * avoids treating an answer-bearing error as either a negative result or a
 * resolver capability statement. */
static inline int rin_dns_wire_is_notimp_response(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type)
{
    uint16_t flags;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    size_t position = 12u;
    size_t next_offset = 0u;
    unsigned int opt_count = 0u;
    char decoded_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};

    if (!packet || packet_size < 12u || !expected_name ||
        (expected_type != RIN_DNS_WIRE_TYPE_A &&
         expected_type != RIN_DNS_WIRE_TYPE_AAAA &&
         expected_type != RIN_DNS_WIRE_TYPE_PTR) ||
        rin_dns_wire_read_u16(packet) != expected_id) {
        return 0;
    }
    flags = rin_dns_wire_read_u16(packet + 2u);
    answer_count = rin_dns_wire_read_u16(packet + 6u);
    authority_count = rin_dns_wire_read_u16(packet + 8u);
    additional_count = rin_dns_wire_read_u16(packet + 10u);
    if ((flags & UINT16_C(0x8000)) == 0u ||
        (flags & UINT16_C(0x7800)) != 0u ||
        (flags & UINT16_C(0x0200)) != 0u ||
        (flags & UINT16_C(0x000f)) != 4u ||
        rin_dns_wire_read_u16(packet + 4u) != 1u || answer_count != 0u ||
        authority_count > RIN_DNS_WIRE_MAX_AUTHORITY ||
        additional_count > RIN_DNS_WIRE_MAX_ADDITIONAL ||
        rin_dns_wire_decode_name(packet, packet_size, position, decoded_name,
                                 sizeof(decoded_name), &next_offset) != 0 ||
        !rin_dns_wire_names_equal(decoded_name, expected_name) ||
        next_offset > packet_size || packet_size - next_offset < 4u ||
        rin_dns_wire_read_u16(packet + next_offset) != expected_type ||
        rin_dns_wire_read_u16(packet + next_offset + 2u) !=
            RIN_DNS_WIRE_CLASS_IN) {
        return 0;
    }
    position = next_offset + 4u;
    for (uint16_t section = 0u; section < 2u; ++section) {
        uint16_t record_count = section == 0u ? authority_count :
                                                  additional_count;
        for (uint16_t index = 0u; index < record_count; ++index) {
            uint16_t record_type;
            uint16_t data_length;
            uint32_t ttl;
            size_t data_end;
            if (rin_dns_wire_decode_name(packet, packet_size, position,
                                         decoded_name, sizeof(decoded_name),
                                         &next_offset) != 0 ||
                next_offset > packet_size || packet_size - next_offset < 10u) {
                return 0;
            }
            record_type = rin_dns_wire_read_u16(packet + next_offset);
            ttl = rin_dns_wire_read_u32(packet + next_offset + 4u);
            data_length = rin_dns_wire_read_u16(packet + next_offset + 8u);
            position = next_offset + 10u;
            if ((size_t)data_length > packet_size - position) return 0;
            data_end = position + (size_t)data_length;
            if (record_type == RIN_DNS_WIRE_TYPE_OPT) {
                if (section == 0u || ++opt_count != 1u ||
                    decoded_name[0] != '\0' ||
                    ((ttl >> 24) & UINT32_C(0xff)) != 0u ||
                    ((ttl >> 16) & UINT32_C(0xff)) != 0u ||
                    (ttl & UINT32_C(0x7fff)) != 0u ||
                    !rin_dns_wire_edns_options_valid(packet, position,
                                                     data_end, NULL)) {
                    return 0;
                }
            }
            position = data_end;
        }
    }
    return position == packet_size;
}

/* Parse one bounded DNS/EDNS0 response. The echoed question must match the
 * exact requested name/type/class, and accepted A/AAAA records must belong to
 * that name or to an in-order, bounded CNAME chain.  Their wire order is
 * retained as one all-or-nothing answer set; a set that exceeds the public
 * bounded result capacity is rejected rather than truncated.  CNAME-only,
 * NXDOMAIN, and NODATA responses are returned only after every DNS section
 * has been admitted. */
static inline int rin_dns_wire_parse_response_answers_ex(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type,
    RinDnsWireAnswerSet* answer_set,
    char* cname_referral,
    size_t cname_referral_capacity)
{
    size_t position = 12u;
    size_t next_offset = 0u;
    uint16_t flags;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
    uint16_t rcode;
    uint32_t cname_ttl = UINT32_MAX;
    unsigned int cname_hops = 0u;
    unsigned int seen_name_count = 0u;
    int result_found = 0;
    RinDnsWireAnswer* answer;
    char decoded_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};
    char current_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};
    char record_data_name[RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {0};
    char seen_names[RIN_DNS_WIRE_MAX_CNAME_HOPS + 1u]
                   [RIN_DNS_WIRE_MAX_NAME_SIZE + 1u] = {{0}};

    rin_dns_wire_clear_answer_set(answer_set);
    if (cname_referral && cname_referral_capacity > 0u) {
        cname_referral[0] = '\0';
    }
    if (!packet || packet_size < 12u || !expected_name || !answer_set ||
        (expected_type != RIN_DNS_WIRE_TYPE_A &&
         expected_type != RIN_DNS_WIRE_TYPE_AAAA &&
         expected_type != RIN_DNS_WIRE_TYPE_PTR) ||
        rin_dns_wire_read_u16(packet) != expected_id) {
        goto fail;
    }
    answer = &answer_set->primary;
    flags = rin_dns_wire_read_u16(packet + 2u);
    rcode = (uint16_t)(flags & UINT16_C(0x000f));
    if ((flags & UINT16_C(0x8000)) == 0u ||
        (flags & UINT16_C(0x7800)) != 0u ||
        (flags & UINT16_C(0x0200)) != 0u ||
        rin_dns_wire_read_u16(packet + 4u) != 1u) {
        goto fail;
    }
    if (rcode == 4u) {
        return rin_dns_wire_is_notimp_response(
                   packet, packet_size, expected_id, expected_name,
                   expected_type)
                   ? RIN_DNS_WIRE_PARSE_NOT_IMPLEMENTED
                   : -1;
    }
    if (rcode != 0u && rcode != 3u) goto fail;
    answer_count = rin_dns_wire_read_u16(packet + 6u);
    authority_count = rin_dns_wire_read_u16(packet + 8u);
    additional_count = rin_dns_wire_read_u16(packet + 10u);
    if (answer_count > RIN_DNS_WIRE_MAX_ANSWERS ||
        authority_count > RIN_DNS_WIRE_MAX_AUTHORITY ||
        additional_count > RIN_DNS_WIRE_MAX_ADDITIONAL ||
        (rcode == 3u && answer_count != 0u) ||
        rin_dns_wire_copy_name(current_name, sizeof(current_name),
                               expected_name) != 0 ||
        rin_dns_wire_copy_name(seen_names[0], sizeof(seen_names[0]),
                               expected_name) != 0 ||
        rin_dns_wire_decode_name(packet, packet_size, position, decoded_name,
                                 sizeof(decoded_name), &next_offset) != 0 ||
        !rin_dns_wire_names_equal(decoded_name, expected_name) ||
        next_offset > packet_size || packet_size - next_offset < 4u ||
        rin_dns_wire_read_u16(packet + next_offset) != expected_type ||
        rin_dns_wire_read_u16(packet + next_offset + 2u) !=
            RIN_DNS_WIRE_CLASS_IN) {
        goto fail;
    }
    position = next_offset + 4u;
    seen_name_count = 1u;

    for (uint16_t index = 0u; index < answer_count; ++index) {
        uint16_t record_type;
        uint16_t record_class;
        uint16_t data_length;
        uint32_t ttl;
        size_t data_end;

        if (rin_dns_wire_decode_name(packet, packet_size, position,
                                     decoded_name, sizeof(decoded_name),
                                     &next_offset) != 0 ||
            next_offset > packet_size || packet_size - next_offset < 10u) {
            goto fail;
        }
        record_type = rin_dns_wire_read_u16(packet + next_offset);
        record_class = rin_dns_wire_read_u16(packet + next_offset + 2u);
        ttl = rin_dns_wire_read_u32(packet + next_offset + 4u);
        data_length = rin_dns_wire_read_u16(packet + next_offset + 8u);
        position = next_offset + 10u;
        if ((size_t)data_length > packet_size - position) goto fail;
        data_end = position + (size_t)data_length;

        if (record_type == RIN_DNS_WIRE_TYPE_OPT) goto fail;

        if (rin_dns_wire_names_equal(decoded_name, current_name)) {
            if ((record_type == RIN_DNS_WIRE_TYPE_CNAME ||
                 record_type == expected_type) &&
                record_class != RIN_DNS_WIRE_CLASS_IN) {
                goto fail;
            }
            if (record_type == RIN_DNS_WIRE_TYPE_CNAME) {
                if (result_found ||
                    cname_hops >= RIN_DNS_WIRE_MAX_CNAME_HOPS ||
                    rin_dns_wire_decode_name(packet, packet_size, position,
                                             record_data_name,
                                             sizeof(record_data_name),
                                             &next_offset) != 0 ||
                    next_offset != data_end || record_data_name[0] == '\0' ||
                    rin_dns_wire_copy_name(current_name,
                                           sizeof(current_name),
                                           record_data_name) != 0) {
                    goto fail;
                }
                for (unsigned int seen_index = 0u;
                     seen_index < seen_name_count; ++seen_index) {
                    if (rin_dns_wire_names_equal(record_data_name,
                                                 seen_names[seen_index])) {
                        goto fail;
                    }
                }
                if (rin_dns_wire_copy_name(seen_names[seen_name_count],
                                           sizeof(seen_names[seen_name_count]),
                                           record_data_name) != 0) {
                    goto fail;
                }
                ++seen_name_count;
                ++cname_hops;
                record_data_name[0] = '\0';
                if (ttl < cname_ttl) cname_ttl = ttl;
            } else if (record_type == expected_type) {
                if (expected_type == RIN_DNS_WIRE_TYPE_A) {
                    if (data_length != 4u) goto fail;
                    if (answer_set->address_count >=
                        RIN_DNS_WIRE_MAX_RESULT_ADDRESSES) goto fail;
                    for (size_t byte = 0u; byte < 4u; ++byte) {
                        answer_set->addresses[answer_set->address_count][byte] =
                            packet[position + byte];
                    }
                    ++answer_set->address_count;
                    if (!result_found) {
                        for (size_t byte = 0u; byte < 4u; ++byte) {
                            answer->address[byte] = packet[position + byte];
                        }
                    }
                } else if (expected_type == RIN_DNS_WIRE_TYPE_AAAA) {
                    if (data_length != 16u) goto fail;
                    if (answer_set->address_count >=
                        RIN_DNS_WIRE_MAX_RESULT_ADDRESSES) goto fail;
                    for (size_t byte = 0u; byte < 16u; ++byte) {
                        answer_set->addresses[answer_set->address_count][byte] =
                            packet[position + byte];
                    }
                    ++answer_set->address_count;
                    if (!result_found) {
                        for (size_t byte = 0u; byte < 16u; ++byte) {
                            answer->address[byte] = packet[position + byte];
                        }
                    }
                } else if (rin_dns_wire_decode_name(
                               packet, packet_size, position,
                               record_data_name, sizeof(record_data_name),
                               &next_offset) != 0 ||
                           next_offset != data_end ||
                           record_data_name[0] == '\0') {
                    goto fail;
                }
                if (!result_found) {
                    answer->type = expected_type;
                    answer->ttl = ttl < cname_ttl ? ttl : cname_ttl;
                    if (expected_type == RIN_DNS_WIRE_TYPE_PTR &&
                        rin_dns_wire_copy_name(answer->name,
                                               sizeof(answer->name),
                                               record_data_name) != 0) {
                        goto fail;
                    }
                    if (expected_type == RIN_DNS_WIRE_TYPE_PTR) {
                        answer_set->address_count = 1u;
                    }
                    result_found = 1;
                }
                record_data_name[0] = '\0';
            }
        }
        position = data_end;
    }

    for (uint16_t index = 0u; index < authority_count; ++index) {
        uint16_t record_type;
        uint16_t data_length;
        if (rin_dns_wire_decode_name(packet, packet_size, position,
                                     decoded_name, sizeof(decoded_name),
                                     &next_offset) != 0 ||
            next_offset > packet_size || packet_size - next_offset < 10u) {
            goto fail;
        }
        record_type = rin_dns_wire_read_u16(packet + next_offset);
        data_length = rin_dns_wire_read_u16(packet + next_offset + 8u);
        position = next_offset + 10u;
        if (record_type == RIN_DNS_WIRE_TYPE_OPT ||
            (size_t)data_length > packet_size - position) {
            goto fail;
        }
        position += (size_t)data_length;
    }

    for (uint16_t index = 0u; index < additional_count; ++index) {
        uint16_t record_type;
        uint16_t record_class;
        uint16_t data_length;
        uint32_t ttl;
        size_t data_end;
        if (rin_dns_wire_decode_name(packet, packet_size, position,
                                     decoded_name, sizeof(decoded_name),
                                     &next_offset) != 0 ||
            next_offset > packet_size || packet_size - next_offset < 10u) {
            goto fail;
        }
        record_type = rin_dns_wire_read_u16(packet + next_offset);
        record_class = rin_dns_wire_read_u16(packet + next_offset + 2u);
        ttl = rin_dns_wire_read_u32(packet + next_offset + 4u);
        data_length = rin_dns_wire_read_u16(packet + next_offset + 8u);
        position = next_offset + 10u;
        if ((size_t)data_length > packet_size - position) goto fail;
        data_end = position + (size_t)data_length;

        if (record_type == RIN_DNS_WIRE_TYPE_OPT) {
            if (answer->edns_present || decoded_name[0] != '\0' ||
                ((ttl >> 24) & UINT32_C(0xff)) != 0u ||
                ((ttl >> 16) & UINT32_C(0xff)) != 0u ||
                (ttl & UINT32_C(0x7fff)) != 0u) {
                goto fail;
            }
            if (!rin_dns_wire_edns_options_valid(packet, position, data_end,
                                                 answer)) {
                goto fail;
            }
            answer->edns_udp_payload_size =
                record_class < 512u ? 512u : record_class;
            answer->edns_present = 1u;
            answer->edns_dnssec_ok =
                (ttl & UINT32_C(0x8000)) != 0u ? 1u : 0u;
        }
        position = data_end;
    }

    if (position != packet_size) goto fail;
    if (result_found) return RIN_DNS_WIRE_PARSE_SUCCESS;
    if (rcode == 3u) return RIN_DNS_WIRE_PARSE_NAME_ERROR;
    if (cname_hops != 0u && cname_referral &&
        cname_referral_capacity > 0u &&
        rin_dns_wire_copy_name(cname_referral, cname_referral_capacity,
                               current_name) == 0) {
        return RIN_DNS_WIRE_PARSE_CNAME_REFERRAL;
    }
    if (cname_hops == 0u) return RIN_DNS_WIRE_PARSE_NO_DATA;

fail:
    rin_dns_wire_clear_answer_set(answer_set);
    if (cname_referral && cname_referral_capacity > 0u) {
        cname_referral[0] = '\0';
    }
    return -1;
}

/* Preserve the single-record contract for existing synchronous consumers.
 * Multi-answer users call the answer-set form above and never receive a
 * silently truncated response. */
static inline int rin_dns_wire_parse_response_ex(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type,
    RinDnsWireAnswer* answer,
    char* cname_referral,
    size_t cname_referral_capacity)
{
    RinDnsWireAnswerSet answers;
    int status;
    if (!answer) return -1;
    status = rin_dns_wire_parse_response_answers_ex(
        packet, packet_size, expected_id, expected_name, expected_type,
        &answers, cname_referral, cname_referral_capacity);
    if (status == RIN_DNS_WIRE_PARSE_SUCCESS) {
        *answer = answers.primary;
    } else {
        rin_dns_wire_clear_answer(answer);
    }
    return status;
}

/* Legacy callers expose only a complete positive answer. */
static inline int rin_dns_wire_parse_response(
    const uint8_t* packet,
    size_t packet_size,
    uint16_t expected_id,
    const char* expected_name,
    uint16_t expected_type,
    RinDnsWireAnswer* answer)
{
    return rin_dns_wire_parse_response_ex(packet, packet_size, expected_id,
                                          expected_name, expected_type,
                                          answer, NULL, 0u) ==
                   RIN_DNS_WIRE_PARSE_SUCCESS
               ? 0
               : -1;
}

#endif /* RIN_SHARED_DNS_WIRE_H */
