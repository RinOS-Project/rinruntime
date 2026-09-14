/* SPDX-License-Identifier: MIT */
/* Public, backend-independent provenance for Settings values. */

#ifndef RINRUNTIME_SETTING_PROVENANCE_H
#define RINRUNTIME_SETTING_PROVENANCE_H

#include <stdint.h>

#define RINRUNTIME_SETTING_PROVENANCE_VERSION UINT32_C(1)

#define RINRUNTIME_SETTING_SOURCE_USER_BIT UINT32_C(0x00000001)
#define RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR_BIT UINT32_C(0x00000002)
#define RINRUNTIME_SETTING_SOURCE_HARDWARE_BIT UINT32_C(0x00000004)
#define RINRUNTIME_SETTING_SOURCE_MASK                                      \
    (RINRUNTIME_SETTING_SOURCE_USER_BIT |                                   \
     RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR_BIT |                          \
     RINRUNTIME_SETTING_SOURCE_HARDWARE_BIT)

typedef enum RinRuntimeSettingSource {
    RINRUNTIME_SETTING_SOURCE_NONE = 0,
    RINRUNTIME_SETTING_SOURCE_USER = 1,
    RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR = 2,
    RINRUNTIME_SETTING_SOURCE_HARDWARE = 3
} RinRuntimeSettingSource;

typedef struct RinRuntimeSettingProvenanceV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t generation;
    uint32_t source_mask;
    uint32_t mutable_mask;
    RinRuntimeSettingSource effective_source;
    uint32_t reserved;
} RinRuntimeSettingProvenanceV1;

static inline RinRuntimeSettingSource rinruntime_setting_source_from_mask(
    uint32_t source_mask)
{
    if ((source_mask & RINRUNTIME_SETTING_SOURCE_HARDWARE_BIT) != 0u)
        return RINRUNTIME_SETTING_SOURCE_HARDWARE;
    if ((source_mask & RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR_BIT) != 0u)
        return RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR;
    if ((source_mask & RINRUNTIME_SETTING_SOURCE_USER_BIT) != 0u)
        return RINRUNTIME_SETTING_SOURCE_USER;
    return RINRUNTIME_SETTING_SOURCE_NONE;
}

static inline int rinruntime_setting_provenance_init(
    RinRuntimeSettingProvenanceV1* output, uint32_t source_mask,
    uint32_t mutable_mask, uint64_t generation)
{
    if (output == NULL || source_mask == 0u ||
        (source_mask & ~RINRUNTIME_SETTING_SOURCE_MASK) != 0u ||
        (mutable_mask & ~source_mask) != 0u || generation == 0u)
        return 0;
    output->struct_size = (uint32_t)sizeof(*output);
    output->version = RINRUNTIME_SETTING_PROVENANCE_VERSION;
    output->generation = generation;
    output->source_mask = source_mask;
    output->mutable_mask = mutable_mask;
    output->effective_source = rinruntime_setting_source_from_mask(source_mask);
    output->reserved = 0u;
    return 1;
}

static inline int rinruntime_setting_provenance_valid(
    const RinRuntimeSettingProvenanceV1* value)
{
    return value != NULL && value->struct_size >= sizeof(*value) &&
           value->version == RINRUNTIME_SETTING_PROVENANCE_VERSION &&
           value->generation != 0u && value->source_mask != 0u &&
           (value->source_mask & ~RINRUNTIME_SETTING_SOURCE_MASK) == 0u &&
           (value->mutable_mask & ~value->source_mask) == 0u &&
           value->effective_source ==
               rinruntime_setting_source_from_mask(value->source_mask) &&
           value->reserved == 0u;
}

static inline int rinruntime_setting_provenance_user_editable(
    const RinRuntimeSettingProvenanceV1* value)
{
    return rinruntime_setting_provenance_valid(value) &&
           value->effective_source == RINRUNTIME_SETTING_SOURCE_USER &&
           (value->mutable_mask & RINRUNTIME_SETTING_SOURCE_USER_BIT) != 0u;
}

static inline int rinruntime_setting_provenance_merge_layers(
    RinRuntimeSettingProvenanceV1* output,
    const RinRuntimeSettingProvenanceV1* user,
    const RinRuntimeSettingProvenanceV1* administrator,
    const RinRuntimeSettingProvenanceV1* hardware)
{
    const RinRuntimeSettingProvenanceV1* layers[3] = {
        user, administrator, hardware
    };
    const uint32_t expected_bits[3] = {
        RINRUNTIME_SETTING_SOURCE_USER_BIT,
        RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR_BIT,
        RINRUNTIME_SETTING_SOURCE_HARDWARE_BIT
    };
    uint32_t source_mask = 0u;
    uint32_t mutable_mask = 0u;
    uint64_t generation = 0u;
    RinRuntimeSettingProvenanceV1 candidate;
    unsigned int index;

    if (output == NULL) return 0;
    for (index = 0u; index < 3u; ++index) {
        const RinRuntimeSettingProvenanceV1* layer = layers[index];
        if (layer == NULL) continue;
        if (!rinruntime_setting_provenance_valid(layer) ||
            layer->source_mask != expected_bits[index] ||
            (index != 0u && layer->mutable_mask != 0u) ||
            (index == 0u &&
             (layer->mutable_mask & ~RINRUNTIME_SETTING_SOURCE_USER_BIT) !=
                 0u))
            return 0;
        if (generation == 0u) generation = layer->generation;
        if (layer->generation != generation) return 0;
        source_mask |= layer->source_mask;
        mutable_mask |= layer->mutable_mask;
    }
    if (source_mask == 0u ||
        !rinruntime_setting_provenance_init(&candidate, source_mask,
                                            mutable_mask, generation))
        return 0;
    *output = candidate;
    return 1;
}

static inline const char* rinruntime_setting_source_name(
    RinRuntimeSettingSource source)
{
    switch (source) {
    case RINRUNTIME_SETTING_SOURCE_USER: return "user preference";
    case RINRUNTIME_SETTING_SOURCE_ADMINISTRATOR: return "administrator policy";
    case RINRUNTIME_SETTING_SOURCE_HARDWARE: return "hardware enforced";
    default: return "unknown";
    }
}

#endif /* RINRUNTIME_SETTING_PROVENANCE_H */
