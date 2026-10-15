/* SPDX-License-Identifier: MIT */

#include "rin_midi_policy.h"

#include <stddef.h>

static int midi_utility_word_is_valid(uint32_t word)
{
    uint32_t group = (word >> 24u) & UINT32_C(0x0f);
    uint32_t status = (word >> 20u) & UINT32_C(0x0f);
    uint32_t reserved = (word >> 16u) & UINT32_C(0x0f);
    uint32_t data16 = word & UINT32_C(0x0000ffff);

    if (group != 0u) return 0;
    switch (status) {
        case RIN_MIDI_UMP_UTILITY_NOOP:
            return (word & UINT32_C(0x000fffff)) == 0u;
        case RIN_MIDI_UMP_UTILITY_JR_CLOCK:
        case RIN_MIDI_UMP_UTILITY_JR_TIMESTAMP:
            return reserved == 0u;
        case RIN_MIDI_UMP_UTILITY_DELTA_CLOCKSTAMP_TPQ:
            return reserved == 0u && data16 != 0u;
        case RIN_MIDI_UMP_UTILITY_DELTA_CLOCKSTAMP:
            return 1;
        default:
            return 0;
    }
}

static int midi_system_word_is_valid(uint32_t word)
{
    uint32_t status = (word >> 16u) & UINT32_C(0xff);
    uint32_t data1 = (word >> 8u) & UINT32_C(0xff);
    uint32_t data2 = word & UINT32_C(0xff);

    if (data1 > 0x7fu || data2 > 0x7fu) return 0;
    switch (status) {
        case 0xf1u:
        case 0xf3u:
            return data2 == 0u;
        case 0xf2u:
            return 1;
        case 0xf6u:
        case 0xf8u:
        case 0xfau:
        case 0xfbu:
        case 0xfcu:
        case 0xfeu:
        case 0xffu:
            return data1 == 0u && data2 == 0u;
        default:
            return 0;
    }
}

static uint32_t midi_ump_byte(const RinMidiPacketV1* packet, uint32_t index)
{
    uint32_t word = packet->words[index / 4u];
    uint32_t shift = (3u - (index & 3u)) * 8u;
    return (word >> shift) & UINT32_C(0xff);
}

static uint16_t midi_ump_u16(const RinMidiPacketV1* packet, uint32_t index)
{
    return (uint16_t)((midi_ump_byte(packet, index) << 8u) |
                      midi_ump_byte(packet, index + 1u));
}

static int midi_manufacturer_id_is_valid(uint16_t manufacturer_id)
{
    if (manufacturer_id == 0u) return 0;
    if ((manufacturer_id & UINT16_C(0x8000)) == 0u) {
        return (manufacturer_id & UINT16_C(0xff80)) == 0u;
    }
    return (manufacturer_id & UINT16_C(0x0080)) == 0u;
}

static int midi_sysex7_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t status = (packet->words[0] >> 20u) & UINT32_C(0x0f);
    uint32_t byte_count = (packet->words[0] >> 16u) & UINT32_C(0x0f);
    uint32_t index;

    if (status > RIN_MIDI_UMP_SYSEX_END || byte_count > 6u) return 0;
    for (index = 0u; index < 6u; ++index) {
        uint32_t value = midi_ump_byte(packet, index + 2u);
        if (index < byte_count) {
            if (value > UINT32_C(0x7f)) return 0;
        } else if (value != 0u) {
            return 0;
        }
    }
    return 1;
}

static int midi_sysex8_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t status = (packet->words[0] >> 20u) & UINT32_C(0x0f);
    uint32_t byte_count = (packet->words[0] >> 16u) & UINT32_C(0x0f);
    uint32_t index;

    if (status > RIN_MIDI_UMP_SYSEX_END) return 0;
    if (byte_count == 15u) {
        if (status != RIN_MIDI_UMP_SYSEX_END) return 0;
        for (index = 3u; index < 16u; ++index) {
            if (midi_ump_byte(packet, index) != 0u) return 0;
        }
        return 1;
    }
    if (byte_count == 0u || byte_count > 14u) return 0;
    for (index = 2u + byte_count; index < 16u; ++index) {
        if (midi_ump_byte(packet, index) != 0u) return 0;
    }
    return 1;
}

static int midi_mds_header_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t valid_bytes = midi_ump_u16(packet, 2u);
    uint32_t total_chunks = midi_ump_u16(packet, 4u);
    uint32_t chunk = midi_ump_u16(packet, 6u);
    uint16_t manufacturer_id = midi_ump_u16(packet, 8u);

    if (valid_bytes < 16u ||
        !midi_manufacturer_id_is_valid(manufacturer_id)) {
        return 0;
    }
    return chunk == 0u || total_chunks == 0u || chunk <= total_chunks;
}

static int midi_data128_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t status = (packet->words[0] >> 20u) & UINT32_C(0x0f);

    if (status <= RIN_MIDI_UMP_SYSEX_END) {
        return midi_sysex8_packet_is_valid(packet);
    }
    if (status == RIN_MIDI_UMP_MDS_HEADER) {
        return midi_mds_header_packet_is_valid(packet);
    }
    return status == RIN_MIDI_UMP_MDS_PAYLOAD;
}

static int midi_ump_bytes_are_zero(
    const RinMidiPacketV1* packet,
    uint32_t begin,
    uint32_t end)
{
    uint32_t index;

    for (index = begin; index < end; ++index) {
        if (midi_ump_byte(packet, index) != 0u) return 0;
    }
    return 1;
}

static int midi_text_payload_is_valid(
    const RinMidiPacketV1* packet,
    uint32_t begin,
    uint32_t format,
    int ascii_only,
    int continue_zero_allowed)
{
    uint32_t index;
    int terminated = 0;

    for (index = begin; index < 16u; ++index) {
        uint32_t value = midi_ump_byte(packet, index);
        if (value == 0u) {
            if (format == RIN_MIDI_UMP_FORMAT_START ||
                (format == RIN_MIDI_UMP_FORMAT_CONTINUE &&
                 !continue_zero_allowed)) {
                return 0;
            }
            terminated = 1;
        } else {
            if (terminated) return 0;
            if (ascii_only && (value < 32u || value > 126u)) return 0;
        }
    }
    return 1;
}

static int midi_utf8_byte_advance(
    uint32_t value,
    uint8_t* remaining,
    uint8_t* first_min,
    uint8_t* first_max)
{
    if (*remaining != 0u) {
        if (value < *first_min || value > *first_max) return 0;
        --*remaining;
        if (*remaining == 0u) {
            *first_min = 0u;
            *first_max = 0u;
        } else {
            *first_min = 0x80u;
            *first_max = 0xbfu;
        }
        return 1;
    }
    if (value <= 0x7fu) return value != 0u;
    if (value >= 0xc2u && value <= 0xdfu) {
        *remaining = 1u;
        *first_min = 0x80u;
        *first_max = 0xbfu;
        return 1;
    }
    if (value >= 0xe0u && value <= 0xefu) {
        *remaining = 2u;
        *first_min = value == 0xe0u ? 0xa0u : 0x80u;
        *first_max = value == 0xedu ? 0x9fu : 0xbfu;
        return 1;
    }
    if (value >= 0xf0u && value <= 0xf4u) {
        *remaining = 3u;
        *first_min = value == 0xf0u ? 0x90u : 0x80u;
        *first_max = value == 0xf4u ? 0x8fu : 0xbfu;
        return 1;
    }
    return 0;
}

static int midi_utf8_payload_advance(
    const RinMidiPacketV1* packet,
    uint32_t begin,
    uint32_t format,
    int continue_zero_allowed,
    uint8_t* remaining,
    uint8_t* first_min,
    uint8_t* first_max)
{
    uint32_t index;

    for (index = begin; index < 16u; ++index) {
        uint32_t value = midi_ump_byte(packet, index);
        if (value == 0u) {
            if (format == RIN_MIDI_UMP_FORMAT_START) return 0;
            if (format == RIN_MIDI_UMP_FORMAT_CONTINUE &&
                !continue_zero_allowed) return 0;
            return *remaining == 0u;
        }
        if (!midi_utf8_byte_advance(
                value, remaining, first_min, first_max)) {
            return 0;
        }
    }
    if (format == RIN_MIDI_UMP_FORMAT_COMPLETE ||
        format == RIN_MIDI_UMP_FORMAT_END) {
        return *remaining == 0u;
    }
    return 1;
}

static int midi_utf8_payload_may_be_valid(
    const RinMidiPacketV1* packet,
    uint32_t begin,
    uint32_t format,
    int continue_zero_allowed)
{
    uint32_t assumed_remaining;
    uint32_t max_assumed =
        format == RIN_MIDI_UMP_FORMAT_START ||
        format == RIN_MIDI_UMP_FORMAT_COMPLETE ? 0u : 3u;

    for (assumed_remaining = 0u; assumed_remaining <= max_assumed;
         ++assumed_remaining) {
        uint8_t remaining = (uint8_t)assumed_remaining;
        uint8_t first_min = remaining == 0u ? 0u : 0x80u;
        uint8_t first_max = remaining == 0u ? 0u : 0xbfu;

        if (midi_utf8_payload_advance(
                packet, begin, format, continue_zero_allowed, &remaining,
                &first_min, &first_max)) {
            return 1;
        }
    }
    return 0;
}

static int midi_chord_accidental_is_valid(uint32_t value)
{
    return value <= 2u || value == 0xeu || value == 0xfu;
}

static int midi_chord_alteration_is_valid(uint32_t value)
{
    uint32_t type = value >> 4u;
    uint32_t degree = value & UINT32_C(0x0f);

    return type <= 4u && (type != 0u || degree == 0u);
}

static int midi_flex_setup_packet_is_valid(
    const RinMidiPacketV1* packet,
    uint32_t address,
    uint32_t status)
{
    uint32_t byte4;
    uint32_t byte12;

    if (((packet->words[0] >> 22u) & UINT32_C(0x03)) !=
        RIN_MIDI_UMP_FORMAT_COMPLETE) {
        return 0;
    }
    switch (status) {
        case RIN_MIDI_UMP_FLEX_SETUP_SET_TEMPO:
            return address == RIN_MIDI_UMP_FLEX_ADDRESS_GROUP &&
                   packet->words[1] != 0u && packet->words[2] == 0u &&
                   packet->words[3] == 0u;
        case RIN_MIDI_UMP_FLEX_SETUP_SET_TIME_SIGNATURE:
            return address == RIN_MIDI_UMP_FLEX_ADDRESS_GROUP &&
                   midi_ump_byte(packet, 7u) == 0u &&
                   packet->words[2] == 0u && packet->words[3] == 0u;
        case RIN_MIDI_UMP_FLEX_SETUP_SET_METRONOME:
            return address == RIN_MIDI_UMP_FLEX_ADDRESS_GROUP &&
                   (packet->words[2] & UINT32_C(0x0000ffff)) == 0u &&
                   packet->words[3] == 0u;
        case RIN_MIDI_UMP_FLEX_SETUP_SET_KEY_SIGNATURE:
            byte4 = midi_ump_byte(packet, 4u);
            return (byte4 & UINT32_C(0x0f)) <= 7u &&
                   midi_ump_bytes_are_zero(packet, 5u, 16u);
        case RIN_MIDI_UMP_FLEX_SETUP_SET_CHORD_NAME:
            byte4 = midi_ump_byte(packet, 4u);
            byte12 = midi_ump_byte(packet, 12u);
            if (!midi_chord_accidental_is_valid(byte4 >> 4u) ||
                (byte4 & UINT32_C(0x0f)) > 7u ||
                midi_ump_byte(packet, 5u) > 0x1bu ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 6u)) ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 7u)) ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 8u)) ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 9u)) ||
                !midi_ump_bytes_are_zero(packet, 10u, 12u) ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 14u)) ||
                !midi_chord_alteration_is_valid(
                    midi_ump_byte(packet, 15u)) ||
                midi_ump_byte(packet, 13u) > 0x1bu) {
                return 0;
            }
            if ((byte12 >> 4u) == 8u) {
                return (byte12 & UINT32_C(0x0f)) == 0u;
            }
            return midi_chord_accidental_is_valid(byte12 >> 4u) &&
                   (byte12 & UINT32_C(0x0f)) != 0u &&
                   (byte12 & UINT32_C(0x0f)) <= 7u;
        default:
            return 0;
    }
}

static int midi_flex_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t format =
        (packet->words[0] >> 22u) & UINT32_C(0x03);
    uint32_t address =
        (packet->words[0] >> 20u) & UINT32_C(0x03);
    uint32_t channel =
        (packet->words[0] >> 16u) & UINT32_C(0x0f);
    uint32_t status_bank =
        (packet->words[0] >> 8u) & UINT32_C(0xff);
    uint32_t status = packet->words[0] & UINT32_C(0xff);

    if (address > RIN_MIDI_UMP_FLEX_ADDRESS_GROUP ||
        (address == RIN_MIDI_UMP_FLEX_ADDRESS_GROUP && channel != 0u)) {
        return 0;
    }
    if (status_bank == RIN_MIDI_UMP_FLEX_BANK_SETUP) {
        return midi_flex_setup_packet_is_valid(packet, address, status);
    }
    if (status_bank == RIN_MIDI_UMP_FLEX_BANK_METADATA_TEXT) {
        if (status > 0x0cu) return 0;
        return midi_text_payload_is_valid(packet, 4u, format, 0, 0) &&
               midi_utf8_payload_may_be_valid(packet, 4u, format, 0);
    }
    if (status_bank == RIN_MIDI_UMP_FLEX_BANK_PERFORMANCE_TEXT) {
        int continue_zero_allowed = status == 1u || status == 3u;
        if (status > 0x04u) return 0;
        return midi_text_payload_is_valid(
                   packet, 4u, format, 0, continue_zero_allowed) &&
               midi_utf8_payload_may_be_valid(
                   packet, 4u, format, continue_zero_allowed);
    }
    return 0;
}

static int midi_stream_device_identity_is_valid(
    const RinMidiPacketV1* packet)
{
    uint32_t id1;
    uint32_t id2;
    uint32_t id3;
    uint32_t index;

    if (!midi_ump_bytes_are_zero(packet, 2u, 5u)) return 0;
    id1 = midi_ump_byte(packet, 5u);
    id2 = midi_ump_byte(packet, 6u);
    id3 = midi_ump_byte(packet, 7u);
    for (index = 5u; index < 16u; ++index) {
        if (midi_ump_byte(packet, index) > 0x7fu) return 0;
    }
    if (id1 == 0u) return id2 != 0u || id3 != 0u;
    return id2 == 0u && id3 == 0u;
}

static int midi_stream_function_block_info_is_valid(
    const RinMidiPacketV1* packet)
{
    uint32_t function_block = midi_ump_byte(packet, 2u);
    uint32_t attributes = midi_ump_byte(packet, 3u);
    uint32_t ui_hint = (attributes >> 4u) & UINT32_C(0x03);
    uint32_t midi1 = (attributes >> 2u) & UINT32_C(0x03);
    uint32_t direction = attributes & UINT32_C(0x03);
    uint32_t first_group = midi_ump_byte(packet, 4u);
    uint32_t group_count = midi_ump_byte(packet, 5u);

    if ((function_block & UINT32_C(0x7f)) > 31u ||
        (attributes & UINT32_C(0xc0)) != 0u || direction == 0u ||
        midi1 == 3u || first_group > 15u || group_count == 0u ||
        group_count > 16u || first_group + group_count > 16u ||
        (midi1 != 0u && group_count != 1u) ||
        (direction == 1u && ui_hint == 2u) ||
        (direction == 2u && ui_hint == 1u)) {
        return 0;
    }
    return packet->words[2] == 0u && packet->words[3] == 0u;
}

static int midi_stream_packet_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t format =
        (packet->words[0] >> 26u) & UINT32_C(0x03);
    uint32_t status =
        (packet->words[0] >> 16u) & UINT32_C(0x03ff);
    uint32_t function_block;

    if (status == RIN_MIDI_UMP_STREAM_ENDPOINT_NAME) {
        return midi_text_payload_is_valid(packet, 2u, format, 0, 0) &&
               midi_utf8_payload_may_be_valid(packet, 2u, format, 0);
    }
    if (status == RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID) {
        return midi_text_payload_is_valid(packet, 2u, format, 1, 0);
    }
    if (status == RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_NAME) {
        function_block = midi_ump_byte(packet, 2u);
        return function_block <= 31u &&
               midi_text_payload_is_valid(packet, 3u, format, 0, 0) &&
               midi_utf8_payload_may_be_valid(packet, 3u, format, 0);
    }
    if (format != RIN_MIDI_UMP_FORMAT_COMPLETE) return 0;

    switch (status) {
        case RIN_MIDI_UMP_STREAM_ENDPOINT_DISCOVERY:
            return (midi_ump_byte(packet, 7u) & ~UINT32_C(0x1f)) == 0u &&
                   midi_ump_bytes_are_zero(packet, 4u, 7u) &&
                   packet->words[2] == 0u && packet->words[3] == 0u;
        case RIN_MIDI_UMP_STREAM_ENDPOINT_INFO:
            return (midi_ump_byte(packet, 4u) & UINT32_C(0x7f)) <= 32u &&
                   midi_ump_byte(packet, 5u) == 0u &&
                   (midi_ump_byte(packet, 6u) & ~UINT32_C(0x03)) == 0u &&
                   (midi_ump_byte(packet, 7u) & ~UINT32_C(0x03)) == 0u &&
                   packet->words[2] == 0u && packet->words[3] == 0u;
        case RIN_MIDI_UMP_STREAM_DEVICE_IDENTITY:
            return midi_stream_device_identity_is_valid(packet);
        case RIN_MIDI_UMP_STREAM_CONFIGURATION_REQUEST:
        case RIN_MIDI_UMP_STREAM_CONFIGURATION_NOTIFICATION:
            return (midi_ump_byte(packet, 2u) ==
                        RIN_MIDI_STREAM_PROTOCOL_MIDI1 ||
                    midi_ump_byte(packet, 2u) ==
                        RIN_MIDI_STREAM_PROTOCOL_MIDI2) &&
                   (midi_ump_byte(packet, 3u) &
                    ~RIN_MIDI_STREAM_CONFIG_KNOWN_FLAGS) == 0u &&
                   packet->words[1] == 0u && packet->words[2] == 0u &&
                   packet->words[3] == 0u;
        case RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_DISCOVERY:
            function_block = midi_ump_byte(packet, 2u);
            return (function_block <= 31u || function_block == 0xffu) &&
                   (midi_ump_byte(packet, 3u) & ~UINT32_C(0x03)) == 0u &&
                   packet->words[1] == 0u && packet->words[2] == 0u &&
                   packet->words[3] == 0u;
        case RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_INFO:
            return midi_stream_function_block_info_is_valid(packet);
        case RIN_MIDI_UMP_STREAM_START_OF_CLIP:
        case RIN_MIDI_UMP_STREAM_END_OF_CLIP:
            return midi_ump_bytes_are_zero(packet, 2u, 16u);
        default:
            return 0;
    }
}

int rin_midi_packet_v1_is_valid(const RinMidiPacketV1* packet)
{
    uint32_t message_type;
    uint32_t expected_words;
    uint32_t status;
    uint32_t data1;
    uint32_t data2;
    uint32_t index;

    if (packet == NULL || packet->struct_size != sizeof(*packet) ||
        packet->version != RIN_MIDI_PACKET_VERSION ||
        packet->word_count == 0u || packet->word_count > 4u ||
        (packet->flags & ~RIN_MIDI_PACKET_KNOWN_FLAGS) != 0u) {
        return 0;
    }
    if ((packet->flags & RIN_MIDI_PACKET_TIMESTAMP_VALID) == 0u) {
        if (packet->monotonic_time_ns != 0u) return 0;
    } else if (packet->monotonic_time_ns == 0u) {
        return 0;
    }

    message_type = packet->words[0] >> 28u;
    switch (message_type) {
        case RIN_MIDI_UMP_TYPE_UTILITY:
        case RIN_MIDI_UMP_TYPE_SYSTEM:
        case RIN_MIDI_UMP_TYPE_MIDI1_CHANNEL_VOICE:
            expected_words = 1u;
            break;
        case RIN_MIDI_UMP_TYPE_DATA64:
            expected_words = 2u;
            break;
        case RIN_MIDI_UMP_TYPE_MIDI2_CHANNEL_VOICE:
            expected_words = 2u;
            break;
        case RIN_MIDI_UMP_TYPE_DATA128:
        case RIN_MIDI_UMP_TYPE_FLEX_DATA:
        case RIN_MIDI_UMP_TYPE_STREAM:
            expected_words = 4u;
            break;
        default:
            return 0;
    }
    if (packet->word_count != expected_words) return 0;
    for (index = expected_words; index < 4u; ++index) {
        if (packet->words[index] != 0u) return 0;
    }

    if (message_type == RIN_MIDI_UMP_TYPE_UTILITY) {
        return midi_utility_word_is_valid(packet->words[0]);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_SYSTEM) {
        return midi_system_word_is_valid(packet->words[0]);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_DATA64) {
        return midi_sysex7_packet_is_valid(packet);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_DATA128) {
        return midi_data128_packet_is_valid(packet);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_FLEX_DATA) {
        return midi_flex_packet_is_valid(packet);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_STREAM) {
        return midi_stream_packet_is_valid(packet);
    }
    status = (packet->words[0] >> 20u) & UINT32_C(0x0f);
    if (status < 0x8u || status > 0xeu) return 0;
    if (message_type == RIN_MIDI_UMP_TYPE_MIDI2_CHANNEL_VOICE) return 1;

    data1 = (packet->words[0] >> 8u) & UINT32_C(0xff);
    data2 = packet->words[0] & UINT32_C(0xff);
    if (data1 > 0x7fu || data2 > 0x7fu) return 0;
    if ((status == 0xcu || status == 0xdu) && data2 != 0u) return 0;
    return 1;
}

uint32_t rin_midi_packet_v1_group(const RinMidiPacketV1* packet)
{
    return (packet->words[0] >> 24u) & UINT32_C(0x0f);
}

int rin_midi_packet_v1_is_group_addressed(const RinMidiPacketV1* packet)
{
    uint32_t message_type = packet->words[0] >> 28u;
    return message_type != RIN_MIDI_UMP_TYPE_UTILITY &&
           message_type != RIN_MIDI_UMP_TYPE_STREAM;
}

static int midi_packet_is_system_realtime(const RinMidiPacketV1* packet)
{
    uint32_t status;

    if ((packet->words[0] >> 28u) != RIN_MIDI_UMP_TYPE_SYSTEM) return 0;
    status = (packet->words[0] >> 16u) & UINT32_C(0xff);
    return status == UINT32_C(0xf8) || status == UINT32_C(0xfa) ||
           status == UINT32_C(0xfb) || status == UINT32_C(0xfc) ||
           status == UINT32_C(0xfe) || status == UINT32_C(0xff);
}

static RinMidiSysEx8StreamStateV1* midi_sysex8_find(
    RinMidiFramingStateV1* state,
    uint32_t group,
    uint32_t stream_id)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_SYSEX8_TRACKED_STREAMS; ++index) {
        RinMidiSysEx8StreamStateV1* stream = &state->sysex8[index];
        if (stream->active && stream->group == group &&
            stream->stream_id == stream_id) {
            return stream;
        }
    }
    return NULL;
}

static RinMidiSysEx8StreamStateV1* midi_sysex8_allocate(
    RinMidiFramingStateV1* state)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_SYSEX8_TRACKED_STREAMS; ++index) {
        if (!state->sysex8[index].active) return &state->sysex8[index];
    }
    return NULL;
}

static RinMidiMixedDataSetStateV1* midi_mds_find(
    RinMidiFramingStateV1* state,
    uint32_t group,
    uint32_t mds_id)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_MDS_TRACKED_DATA_SETS; ++index) {
        RinMidiMixedDataSetStateV1* data_set = &state->mds[index];
        if (data_set->active && data_set->group == group &&
            data_set->mds_id == mds_id) {
            return data_set;
        }
    }
    return NULL;
}

static RinMidiMixedDataSetStateV1* midi_mds_allocate(
    RinMidiFramingStateV1* state)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_MDS_TRACKED_DATA_SETS; ++index) {
        if (!state->mds[index].active) return &state->mds[index];
    }
    return NULL;
}

static void midi_mds_clear(RinMidiMixedDataSetStateV1* data_set)
{
    data_set->total_chunks = 0u;
    data_set->next_chunk = 0u;
    data_set->payload_umps_remaining = 0u;
    data_set->manufacturer_id = 0u;
    data_set->device_id = 0u;
    data_set->sub_id1 = 0u;
    data_set->sub_id2 = 0u;
    data_set->group = 0u;
    data_set->mds_id = 0u;
    data_set->last_payload_bytes = 0u;
    data_set->close_after_payload = 0u;
    data_set->active = 0u;
    data_set->reserved0 = 0u;
}

static int midi_mds_header_matches(
    const RinMidiMixedDataSetStateV1* data_set,
    const RinMidiPacketV1* packet)
{
    return data_set->manufacturer_id == midi_ump_u16(packet, 8u) &&
           data_set->device_id == midi_ump_u16(packet, 10u) &&
           data_set->sub_id1 == midi_ump_u16(packet, 12u) &&
           data_set->sub_id2 == midi_ump_u16(packet, 14u);
}

static int midi_mds_header_advance(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    uint32_t group = rin_midi_packet_v1_group(packet);
    uint32_t mds_id = (packet->words[0] >> 16u) & UINT32_C(0x0f);
    uint32_t valid_bytes = midi_ump_u16(packet, 2u);
    uint32_t total_chunks = midi_ump_u16(packet, 4u);
    uint32_t chunk = midi_ump_u16(packet, 6u);
    uint32_t payload_bytes = valid_bytes - 16u;
    uint32_t payload_umps = (payload_bytes + 13u) / 14u;
    uint32_t last_payload_bytes = payload_bytes % 14u;
    int close_after_payload;
    RinMidiMixedDataSetStateV1* data_set =
        midi_mds_find(state, group, mds_id);

    if (chunk == 0u) {
        if (data_set == NULL || data_set->payload_umps_remaining != 0u ||
            total_chunks != data_set->total_chunks ||
            !midi_mds_header_matches(data_set, packet)) {
            return 0;
        }
        close_after_payload = 1;
    } else if (data_set == NULL) {
        if (chunk != 1u) return 0;
        data_set = midi_mds_allocate(state);
        if (data_set == NULL) return 0;
        midi_mds_clear(data_set);
        data_set->active = 1u;
        data_set->group = (uint8_t)group;
        data_set->mds_id = (uint8_t)mds_id;
        data_set->manufacturer_id = midi_ump_u16(packet, 8u);
        data_set->device_id = midi_ump_u16(packet, 10u);
        data_set->sub_id1 = midi_ump_u16(packet, 12u);
        data_set->sub_id2 = midi_ump_u16(packet, 14u);
        data_set->total_chunks = (uint16_t)total_chunks;
        close_after_payload = total_chunks == chunk;
    } else {
        if (data_set->payload_umps_remaining != 0u ||
            chunk != data_set->next_chunk ||
            !midi_mds_header_matches(data_set, packet)) {
            return 0;
        }
        if (data_set->total_chunks == 0u) {
            if (total_chunks != 0u && total_chunks != chunk) return 0;
        } else if (total_chunks != data_set->total_chunks &&
                   total_chunks != chunk) {
            return 0;
        }
        if (total_chunks != 0u) {
            data_set->total_chunks = (uint16_t)total_chunks;
        }
        close_after_payload = total_chunks == chunk;
    }

    if (!close_after_payload && chunk == UINT16_MAX) return 0;
    data_set->next_chunk = chunk == 0u
        ? data_set->next_chunk
        : (uint16_t)(chunk + 1u);
    data_set->payload_umps_remaining = (uint16_t)payload_umps;
    data_set->last_payload_bytes = payload_umps == 0u
        ? 0u
        : (uint8_t)(last_payload_bytes == 0u ? 14u : last_payload_bytes);
    data_set->close_after_payload = (uint8_t)close_after_payload;
    if (payload_umps == 0u) {
        if (close_after_payload) {
            midi_mds_clear(data_set);
        } else {
            data_set->close_after_payload = 0u;
        }
    }
    return 1;
}

static int midi_mds_payload_advance(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    uint32_t group = rin_midi_packet_v1_group(packet);
    uint32_t mds_id = (packet->words[0] >> 16u) & UINT32_C(0x0f);
    RinMidiMixedDataSetStateV1* data_set =
        midi_mds_find(state, group, mds_id);
    uint32_t index;

    if (data_set == NULL || data_set->payload_umps_remaining == 0u) return 0;
    if (data_set->payload_umps_remaining == 1u) {
        for (index = 2u + data_set->last_payload_bytes; index < 16u;
             ++index) {
            if (midi_ump_byte(packet, index) != 0u) return 0;
        }
    }
    --data_set->payload_umps_remaining;
    if (data_set->payload_umps_remaining == 0u) {
        if (data_set->close_after_payload) {
            midi_mds_clear(data_set);
        } else {
            data_set->last_payload_bytes = 0u;
            data_set->close_after_payload = 0u;
        }
    }
    return 1;
}

static void midi_flex_clear(RinMidiFlexDataStateV1* flex)
{
    flex->address = 0u;
    flex->channel = 0u;
    flex->status_bank = 0u;
    flex->status = 0u;
    flex->ump_count = 0u;
    flex->active = 0u;
    flex->utf8_remaining = 0u;
    flex->utf8_first_min = 0u;
    flex->utf8_first_max = 0u;
    flex->reserved0 = 0u;
}

static int midi_flex_header_matches(
    const RinMidiFlexDataStateV1* flex,
    const RinMidiPacketV1* packet)
{
    return flex->address ==
               ((packet->words[0] >> 20u) & UINT32_C(0x03)) &&
           flex->channel ==
               ((packet->words[0] >> 16u) & UINT32_C(0x0f)) &&
           flex->status_bank ==
               ((packet->words[0] >> 8u) & UINT32_C(0xff)) &&
           flex->status == (packet->words[0] & UINT32_C(0xff));
}

static int midi_flex_advance(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    uint32_t group = rin_midi_packet_v1_group(packet);
    uint32_t format =
        (packet->words[0] >> 22u) & UINT32_C(0x03);
    RinMidiFlexDataStateV1* flex = &state->flex[group];
    uint8_t utf8_remaining = 0u;
    uint8_t utf8_first_min = 0u;
    uint8_t utf8_first_max = 0u;
    uint32_t status_bank =
        (packet->words[0] >> 8u) & UINT32_C(0xff);
    uint32_t status = packet->words[0] & UINT32_C(0xff);
    int text_message =
        status_bank == RIN_MIDI_UMP_FLEX_BANK_METADATA_TEXT ||
        status_bank == RIN_MIDI_UMP_FLEX_BANK_PERFORMANCE_TEXT;
    int continue_zero_allowed =
        status_bank == RIN_MIDI_UMP_FLEX_BANK_PERFORMANCE_TEXT &&
        (status == 1u || status == 3u);

    if (format == RIN_MIDI_UMP_FORMAT_COMPLETE) {
        return !flex->active &&
               (!text_message || midi_utf8_payload_advance(
                    packet, 4u, format, continue_zero_allowed,
                    &utf8_remaining, &utf8_first_min, &utf8_first_max));
    }
    if (format == RIN_MIDI_UMP_FORMAT_START) {
        if (flex->active) return 0;
        if (text_message && !midi_utf8_payload_advance(
                packet, 4u, format, continue_zero_allowed,
                &utf8_remaining, &utf8_first_min, &utf8_first_max)) {
            return 0;
        }
        flex->address = (uint8_t)((packet->words[0] >> 20u) & 0x03u);
        flex->channel = (uint8_t)((packet->words[0] >> 16u) & 0x0fu);
        flex->status_bank =
            (uint8_t)((packet->words[0] >> 8u) & 0xffu);
        flex->status = (uint8_t)(packet->words[0] & 0xffu);
        flex->ump_count = 1u;
        flex->active = 1u;
        flex->utf8_remaining = utf8_remaining;
        flex->utf8_first_min = utf8_first_min;
        flex->utf8_first_max = utf8_first_max;
        flex->reserved0 = 0u;
        return 1;
    }
    if (!flex->active || !midi_flex_header_matches(flex, packet)) return 0;
    utf8_remaining = flex->utf8_remaining;
    utf8_first_min = flex->utf8_first_min;
    utf8_first_max = flex->utf8_first_max;
    if (text_message && !midi_utf8_payload_advance(
            packet, 4u, format, continue_zero_allowed, &utf8_remaining,
            &utf8_first_min, &utf8_first_max)) {
        return 0;
    }
    if (format == RIN_MIDI_UMP_FORMAT_CONTINUE) {
        if (flex->ump_count >= RIN_MIDI_FLEX_MAX_UMPS - 1u) return 0;
        ++flex->ump_count;
        flex->utf8_remaining = utf8_remaining;
        flex->utf8_first_min = utf8_first_min;
        flex->utf8_first_max = utf8_first_max;
        return 1;
    }
    if (format != RIN_MIDI_UMP_FORMAT_END ||
        flex->ump_count >= RIN_MIDI_FLEX_MAX_UMPS) {
        return 0;
    }
    midi_flex_clear(flex);
    return 1;
}

static uint32_t midi_stream_max_umps(uint32_t status)
{
    if (status == RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID) return 3u;
    if (status == RIN_MIDI_UMP_STREAM_ENDPOINT_NAME ||
        status == RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_NAME) {
        return 7u;
    }
    return 0u;
}

static uint32_t midi_stream_function_block(
    const RinMidiPacketV1* packet,
    uint32_t status)
{
    return status == RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_NAME
        ? midi_ump_byte(packet, 2u)
        : 0u;
}

static RinMidiStreamSequenceStateV1* midi_stream_find(
    RinMidiFramingStateV1* state,
    uint32_t status,
    uint32_t function_block)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_STREAM_TRACKED_SEQUENCES; ++index) {
        RinMidiStreamSequenceStateV1* stream = &state->stream[index];
        if (stream->active && stream->status == status &&
            stream->function_block == function_block) {
            return stream;
        }
    }
    return NULL;
}

static RinMidiStreamSequenceStateV1* midi_stream_allocate(
    RinMidiFramingStateV1* state)
{
    uint32_t index;

    for (index = 0u; index < RIN_MIDI_STREAM_TRACKED_SEQUENCES; ++index) {
        if (!state->stream[index].active) return &state->stream[index];
    }
    return NULL;
}

static void midi_stream_clear(RinMidiStreamSequenceStateV1* stream)
{
    stream->status = 0u;
    stream->function_block = 0u;
    stream->ump_count = 0u;
    stream->active = 0u;
    stream->utf8_remaining = 0u;
    stream->utf8_first_min = 0u;
    stream->utf8_first_max = 0u;
}

static int midi_stream_advance(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    uint32_t format =
        (packet->words[0] >> 26u) & UINT32_C(0x03);
    uint32_t status =
        (packet->words[0] >> 16u) & UINT32_C(0x03ff);
    uint32_t function_block = midi_stream_function_block(packet, status);
    uint32_t max_umps = midi_stream_max_umps(status);
    RinMidiStreamSequenceStateV1* stream =
        midi_stream_find(state, status, function_block);
    uint32_t payload_begin =
        status == RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_NAME ? 3u : 2u;
    uint8_t utf8_remaining = 0u;
    uint8_t utf8_first_min = 0u;
    uint8_t utf8_first_max = 0u;

    if (max_umps == 0u) return format == RIN_MIDI_UMP_FORMAT_COMPLETE;
    if (format == RIN_MIDI_UMP_FORMAT_COMPLETE) {
        return stream == NULL &&
               (status == RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID ||
                midi_utf8_payload_advance(
                    packet, payload_begin, format, 0, &utf8_remaining,
                    &utf8_first_min, &utf8_first_max));
    }
    if (format == RIN_MIDI_UMP_FORMAT_START) {
        if (stream != NULL) return 0;
        if (status != RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID &&
            !midi_utf8_payload_advance(
                packet, payload_begin, format, 0, &utf8_remaining,
                &utf8_first_min, &utf8_first_max)) {
            return 0;
        }
        stream = midi_stream_allocate(state);
        if (stream == NULL) return 0;
        stream->status = (uint16_t)status;
        stream->function_block = (uint8_t)function_block;
        stream->ump_count = 1u;
        stream->active = 1u;
        stream->utf8_remaining = utf8_remaining;
        stream->utf8_first_min = utf8_first_min;
        stream->utf8_first_max = utf8_first_max;
        return 1;
    }
    if (stream == NULL) return 0;
    utf8_remaining = stream->utf8_remaining;
    utf8_first_min = stream->utf8_first_min;
    utf8_first_max = stream->utf8_first_max;
    if (status != RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID &&
        !midi_utf8_payload_advance(
            packet, payload_begin, format, 0, &utf8_remaining,
            &utf8_first_min, &utf8_first_max)) {
        return 0;
    }
    if (format == RIN_MIDI_UMP_FORMAT_CONTINUE) {
        if (stream->ump_count >= max_umps - 1u) return 0;
        ++stream->ump_count;
        stream->utf8_remaining = utf8_remaining;
        stream->utf8_first_min = utf8_first_min;
        stream->utf8_first_max = utf8_first_max;
        return 1;
    }
    if (format != RIN_MIDI_UMP_FORMAT_END ||
        stream->ump_count >= max_umps) {
        return 0;
    }
    midi_stream_clear(stream);
    return 1;
}

static int midi_framing_state_v1_advance(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    uint32_t message_type;
    uint32_t group;
    uint32_t status;
    uint32_t index;

    if (state == NULL || !rin_midi_packet_v1_is_valid(packet) ||
        state->reserved0 != 0u || state->reserved1 != 0u) {
        return 0;
    }
    for (index = 0u; index < RIN_MIDI_SYSEX8_TRACKED_STREAMS; ++index) {
        const RinMidiSysEx8StreamStateV1* stream = &state->sysex8[index];
        if (stream->reserved0 != 0u || stream->active > 1u ||
            (stream->active && stream->group > 15u) ||
            (!stream->active &&
             (stream->group != 0u || stream->stream_id != 0u))) {
            return 0;
        }
    }
    for (index = 0u; index < RIN_MIDI_MDS_TRACKED_DATA_SETS; ++index) {
        const RinMidiMixedDataSetStateV1* data_set = &state->mds[index];
        if (data_set->reserved0 != 0u || data_set->active > 1u ||
            data_set->close_after_payload > 1u ||
            (data_set->active &&
             (data_set->group > 15u || data_set->mds_id > 15u ||
              data_set->next_chunk == 0u ||
              !midi_manufacturer_id_is_valid(data_set->manufacturer_id) ||
              (data_set->payload_umps_remaining == 0u &&
               (data_set->last_payload_bytes != 0u ||
                data_set->close_after_payload != 0u)) ||
              (data_set->payload_umps_remaining != 0u &&
               (data_set->last_payload_bytes == 0u ||
                data_set->last_payload_bytes > 14u)))) ||
            (!data_set->active &&
             (data_set->total_chunks != 0u || data_set->next_chunk != 0u ||
              data_set->payload_umps_remaining != 0u ||
              data_set->manufacturer_id != 0u || data_set->device_id != 0u ||
              data_set->sub_id1 != 0u || data_set->sub_id2 != 0u ||
              data_set->group != 0u || data_set->mds_id != 0u ||
              data_set->last_payload_bytes != 0u ||
              data_set->close_after_payload != 0u))) {
            return 0;
        }
    }
    for (index = 0u; index < RIN_MIDI_FLEX_TRACKED_GROUPS; ++index) {
        const RinMidiFlexDataStateV1* flex = &state->flex[index];
        if (flex->reserved0 != 0u || flex->active > 1u ||
            (flex->active &&
             (flex->address > RIN_MIDI_UMP_FLEX_ADDRESS_GROUP ||
              (flex->address == RIN_MIDI_UMP_FLEX_ADDRESS_GROUP &&
               flex->channel != 0u) ||
              (flex->status_bank !=
                   RIN_MIDI_UMP_FLEX_BANK_METADATA_TEXT &&
               flex->status_bank !=
                   RIN_MIDI_UMP_FLEX_BANK_PERFORMANCE_TEXT) ||
              (flex->status_bank ==
                   RIN_MIDI_UMP_FLEX_BANK_METADATA_TEXT &&
               flex->status > 0x0cu) ||
              (flex->status_bank ==
                   RIN_MIDI_UMP_FLEX_BANK_PERFORMANCE_TEXT &&
               flex->status > 0x04u) ||
              flex->ump_count == 0u ||
              flex->ump_count >= RIN_MIDI_FLEX_MAX_UMPS ||
              flex->utf8_remaining > 3u ||
              (flex->utf8_remaining == 0u &&
               (flex->utf8_first_min != 0u ||
                flex->utf8_first_max != 0u)) ||
              (flex->utf8_remaining != 0u &&
               (flex->utf8_first_min < 0x80u ||
                flex->utf8_first_min > flex->utf8_first_max ||
                flex->utf8_first_max > 0xbfu)))) ||
            (!flex->active &&
             (flex->address != 0u || flex->channel != 0u ||
              flex->status_bank != 0u || flex->status != 0u ||
              flex->ump_count != 0u || flex->utf8_remaining != 0u ||
              flex->utf8_first_min != 0u ||
              flex->utf8_first_max != 0u))) {
            return 0;
        }
    }
    for (index = 0u; index < RIN_MIDI_STREAM_TRACKED_SEQUENCES; ++index) {
        const RinMidiStreamSequenceStateV1* stream = &state->stream[index];
        uint32_t max_umps = midi_stream_max_umps(stream->status);
        if (stream->active > 1u ||
            (stream->active &&
             (max_umps == 0u || stream->ump_count == 0u ||
              stream->ump_count >= max_umps ||
              (stream->status ==
                   RIN_MIDI_UMP_STREAM_FUNCTION_BLOCK_NAME
                   ? stream->function_block > 31u
                   : stream->function_block != 0u) ||
              stream->utf8_remaining > 3u ||
              (stream->utf8_remaining == 0u &&
               (stream->utf8_first_min != 0u ||
                stream->utf8_first_max != 0u)) ||
              (stream->utf8_remaining != 0u &&
               (stream->utf8_first_min < 0x80u ||
                stream->utf8_first_min > stream->utf8_first_max ||
                stream->utf8_first_max > 0xbfu)) ||
              (stream->status ==
                   RIN_MIDI_UMP_STREAM_PRODUCT_INSTANCE_ID &&
               stream->utf8_remaining != 0u))) ||
            (!stream->active &&
             (stream->status != 0u || stream->function_block != 0u ||
              stream->ump_count != 0u ||
              stream->utf8_remaining != 0u ||
              stream->utf8_first_min != 0u ||
              stream->utf8_first_max != 0u))) {
            return 0;
        }
    }
    message_type = packet->words[0] >> 28u;
    group = rin_midi_packet_v1_group(packet);

    if (rin_midi_packet_v1_is_group_addressed(packet) &&
        message_type != RIN_MIDI_UMP_TYPE_DATA64 &&
        !midi_packet_is_system_realtime(packet)) {
        state->sysex7_active_groups &=
            (uint16_t)~(UINT16_C(1) << group);
    }
    if (rin_midi_packet_v1_is_group_addressed(packet) &&
        message_type != RIN_MIDI_UMP_TYPE_FLEX_DATA &&
        !midi_packet_is_system_realtime(packet)) {
        midi_flex_clear(&state->flex[group]);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_DATA64) {
        uint16_t group_bit = (uint16_t)(UINT16_C(1) << group);
        int active = (state->sysex7_active_groups & group_bit) != 0u;
        status = (packet->words[0] >> 20u) & UINT32_C(0x0f);

        if (status == RIN_MIDI_UMP_SYSEX_CONTINUE ||
            status == RIN_MIDI_UMP_SYSEX_END) {
            if (!active) return 0;
        } else {
            state->sysex7_active_groups &= (uint16_t)~group_bit;
        }
        if (status == RIN_MIDI_UMP_SYSEX_START) {
            state->sysex7_active_groups |= group_bit;
        } else if (status == RIN_MIDI_UMP_SYSEX_END) {
            state->sysex7_active_groups &= (uint16_t)~group_bit;
        }
        return 1;
    }

    if (message_type == RIN_MIDI_UMP_TYPE_DATA128) {
        status = (packet->words[0] >> 20u) & UINT32_C(0x0f);
        if (status == RIN_MIDI_UMP_MDS_HEADER) {
            return midi_mds_header_advance(state, packet);
        }
        if (status == RIN_MIDI_UMP_MDS_PAYLOAD) {
            return midi_mds_payload_advance(state, packet);
        }
        uint32_t stream_id = midi_ump_byte(packet, 2u);
        RinMidiSysEx8StreamStateV1* stream =
            midi_sysex8_find(state, group, stream_id);

        if (status == RIN_MIDI_UMP_SYSEX_COMPLETE) return stream == NULL;
        if (status == RIN_MIDI_UMP_SYSEX_START) {
            if (stream != NULL) return 0;
            stream = midi_sysex8_allocate(state);
            if (stream == NULL) return 0;
            stream->group = (uint8_t)group;
            stream->stream_id = (uint8_t)stream_id;
            stream->active = 1u;
            stream->reserved0 = 0u;
            return 1;
        }
        if (stream == NULL) return 0;
        if (status == RIN_MIDI_UMP_SYSEX_END) {
            stream->group = 0u;
            stream->stream_id = 0u;
            stream->active = 0u;
            stream->reserved0 = 0u;
        }
    }
    if (message_type == RIN_MIDI_UMP_TYPE_FLEX_DATA) {
        return midi_flex_advance(state, packet);
    }
    if (message_type == RIN_MIDI_UMP_TYPE_STREAM) {
        return midi_stream_advance(state, packet);
    }
    return 1;
}

int rin_midi_framing_state_v1_accept(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet)
{
    RinMidiFramingStateV1 next;

    if (state == NULL) return 0;
    next = *state;
    if (!midi_framing_state_v1_advance(&next, packet)) return 0;
    *state = next;
    return 1;
}
