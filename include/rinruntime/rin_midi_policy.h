/* SPDX-License-Identifier: MIT */
/* Shared validator for the fixed privacy-gated MIDI UMP packet ABI. */

#ifndef RIN_SHARED_RIN_MIDI_POLICY_H
#define RIN_SHARED_RIN_MIDI_POLICY_H

#include <stdint.h>

#include <rin/audio/midi.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_midi_packet_v1_is_valid(const RinMidiPacketV1* packet);

/* Call both addressing helpers only after rin_midi_packet_v1_is_valid
 * succeeds. */
uint32_t rin_midi_packet_v1_group(const RinMidiPacketV1* packet);

/* Utility and UMP Stream packets are endpoint-scoped rather than addressed
 * to one of the sixteen Groups. */
int rin_midi_packet_v1_is_group_addressed(const RinMidiPacketV1* packet);

#define RIN_MIDI_SYSEX8_TRACKED_STREAMS 8u
#define RIN_MIDI_MDS_TRACKED_DATA_SETS 16u
#define RIN_MIDI_FLEX_TRACKED_GROUPS 16u
#define RIN_MIDI_STREAM_TRACKED_SEQUENCES 8u
#define RIN_MIDI_FLEX_MAX_UMPS 32u

typedef struct RinMidiSysEx8StreamStateV1 {
    uint8_t group;
    uint8_t stream_id;
    uint8_t active;
    uint8_t reserved0;
} RinMidiSysEx8StreamStateV1;

typedef struct RinMidiMixedDataSetStateV1 {
    uint16_t total_chunks;
    uint16_t next_chunk;
    uint16_t payload_umps_remaining;
    uint16_t manufacturer_id;
    uint16_t device_id;
    uint16_t sub_id1;
    uint16_t sub_id2;
    uint8_t group;
    uint8_t mds_id;
    uint8_t last_payload_bytes;
    uint8_t close_after_payload;
    uint8_t active;
    uint8_t reserved0;
} RinMidiMixedDataSetStateV1;

typedef struct RinMidiFlexDataStateV1 {
    uint8_t address;
    uint8_t channel;
    uint8_t status_bank;
    uint8_t status;
    uint8_t ump_count;
    uint8_t active;
    uint8_t utf8_remaining;
    uint8_t utf8_first_min;
    uint8_t utf8_first_max;
    uint8_t reserved0;
} RinMidiFlexDataStateV1;

typedef struct RinMidiStreamSequenceStateV1 {
    uint16_t status;
    uint8_t function_block;
    uint8_t ump_count;
    uint8_t active;
    uint8_t utf8_remaining;
    uint8_t utf8_first_min;
    uint8_t utf8_first_max;
} RinMidiStreamSequenceStateV1;

/* Direction-local state. Use independent instances for receive and send. */
typedef struct RinMidiFramingStateV1 {
    uint16_t sysex7_active_groups;
    uint16_t reserved0;
    uint32_t reserved1;
    RinMidiSysEx8StreamStateV1
        sysex8[RIN_MIDI_SYSEX8_TRACKED_STREAMS];
    RinMidiMixedDataSetStateV1
        mds[RIN_MIDI_MDS_TRACKED_DATA_SETS];
    RinMidiFlexDataStateV1 flex[RIN_MIDI_FLEX_TRACKED_GROUPS];
    RinMidiStreamSequenceStateV1
        stream[RIN_MIDI_STREAM_TRACKED_SEQUENCES];
} RinMidiFramingStateV1;

/* Mutates state only when the packet is a valid continuation of the current
 * SysEx7/SysEx8, Mixed Data Set, Flex Data and UMP Stream framing. The packet
 * must first pass the stateless validator. */
int rin_midi_framing_state_v1_accept(
    RinMidiFramingStateV1* state,
    const RinMidiPacketV1* packet);

#if defined(__cplusplus)
static_assert(sizeof(RinMidiMixedDataSetStateV1) == 20u,
              "RinMidiMixedDataSetStateV1 layout drift");
static_assert(sizeof(RinMidiFlexDataStateV1) == 10u,
              "RinMidiFlexDataStateV1 layout drift");
static_assert(sizeof(RinMidiStreamSequenceStateV1) == 8u,
              "RinMidiStreamSequenceStateV1 layout drift");
static_assert(sizeof(RinMidiFramingStateV1) == 584u,
              "RinMidiFramingStateV1 layout drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinMidiMixedDataSetStateV1) == 20u,
               "RinMidiMixedDataSetStateV1 layout drift");
_Static_assert(sizeof(RinMidiFlexDataStateV1) == 10u,
               "RinMidiFlexDataStateV1 layout drift");
_Static_assert(sizeof(RinMidiStreamSequenceStateV1) == 8u,
               "RinMidiStreamSequenceStateV1 layout drift");
_Static_assert(sizeof(RinMidiFramingStateV1) == 584u,
               "RinMidiFramingStateV1 layout drift");
#endif

#ifdef __cplusplus
}
#endif

#endif /* RIN_SHARED_RIN_MIDI_POLICY_H */
