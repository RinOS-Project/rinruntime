/* SPDX-License-Identifier: MIT */
/* Transport-aware, pointer-free storage health values for public consumers. */
#ifndef RINRUNTIME_STORAGE_HEALTH_SNAPSHOT_V1_H
#define RINRUNTIME_STORAGE_HEALTH_SNAPSHOT_V1_H

#include <stdint.h>

#include "rin_nvme_health_snapshot_v1.h"

#define RIN_STORAGE_HEALTH_SNAPSHOT_V1_VERSION UINT32_C(0x00010000)
#define RIN_STORAGE_HEALTH_MAX_METRIC_COUNT UINT32_C(8)

/* Transport is retained because similarly named SMART values do not always
 * have equivalent meaning or thresholds across protocols. */
#define RIN_STORAGE_HEALTH_TRANSPORT_NVME UINT32_C(1)
#define RIN_STORAGE_HEALTH_TRANSPORT_ATA UINT32_C(2)
#define RIN_STORAGE_HEALTH_TRANSPORT_SCSI UINT32_C(3)
#define RIN_STORAGE_HEALTH_TRANSPORT_SD UINT32_C(4)

/* Metric IDs are transport-scoped. These NVMe IDs preserve the source log's
 * names and semantics; they are not normalized pass/fail health scores. */
#define RIN_STORAGE_HEALTH_NVME_CRITICAL_WARNING UINT32_C(1)
#define RIN_STORAGE_HEALTH_NVME_COMPOSITE_TEMPERATURE UINT32_C(2)
#define RIN_STORAGE_HEALTH_NVME_AVAILABLE_SPARE UINT32_C(3)
#define RIN_STORAGE_HEALTH_NVME_AVAILABLE_SPARE_THRESHOLD UINT32_C(4)
#define RIN_STORAGE_HEALTH_NVME_PERCENTAGE_USED UINT32_C(5)
#define RIN_STORAGE_HEALTH_NVME_MEDIA_DATA_INTEGRITY_ERRORS UINT32_C(6)

#define RIN_STORAGE_HEALTH_UNIT_COUNT UINT16_C(1)
#define RIN_STORAGE_HEALTH_UNIT_PERCENT UINT16_C(2)
#define RIN_STORAGE_HEALTH_UNIT_KELVIN UINT16_C(3)
#define RIN_STORAGE_HEALTH_UNIT_BITMASK UINT16_C(4)

/* Only metrics carrying VALID appear in metric_count. A saturated value is a
 * lower bound: NVMe Percentage Used 255 means 255% or more. */
#define RIN_STORAGE_HEALTH_METRIC_FLAG_VALID UINT16_C(0x0001)
#define RIN_STORAGE_HEALTH_METRIC_FLAG_SATURATED UINT16_C(0x0002)
#define RIN_STORAGE_HEALTH_METRIC_FLAG_KNOWN \
    (RIN_STORAGE_HEALTH_METRIC_FLAG_VALID | \
     RIN_STORAGE_HEALTH_METRIC_FLAG_SATURATED)

typedef struct RinStorageHealthMetricV1 {
    uint32_t metric_id;
    uint16_t unit;
    uint16_t flags;
    uint64_t value_low;
    uint64_t value_high;
} RinStorageHealthMetricV1;

/* metric_count contains only values that were valid in this sample. An absent
 * metric means unavailable, unsupported, or not collected; it is never an
 * implicit zero. Values are bound to transport + device_generation. */
typedef struct RinStorageHealthSnapshotV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t transport;
    uint32_t metric_count;
    uint64_t device_generation;
    uint32_t reserved[2];
    RinStorageHealthMetricV1 metrics[RIN_STORAGE_HEALTH_MAX_METRIC_COUNT];
} RinStorageHealthSnapshotV1;

/* Convert one native NVMe SMART/Health snapshot. The output is fully zeroed
 * on failure. This adapter validates native validity flags and publishes only
 * present metrics; it performs no I/O and grants no access to the source. */
static inline int rin_storage_health_from_nvme_v1(
    const RinNvmeHealthSnapshotV1* source,
    RinStorageHealthSnapshotV1* output)
{
#ifdef __cplusplus
    RinNvmeHealthSnapshotV1 health = {};
#else
    RinNvmeHealthSnapshotV1 health = {0};
#endif
    uint8_t* healthBytes = (uint8_t*)&health;
    uint8_t* outputBytes;
    uint32_t index;
    uint32_t logValid;
    uint32_t temperatureValid;
    uint32_t spareValid;
    uint32_t mediaErrorsValid;

    if (output == 0) return 0;
    outputBytes = (uint8_t*)output;
    if (source != 0) {
        const uint8_t* sourceBytes = (const uint8_t*)source;
        for (index = 0u; index < sizeof(health); ++index)
            healthBytes[index] = sourceBytes[index];
    }
    for (index = 0u; index < sizeof(*output); ++index)
        outputBytes[index] = 0u;
    if (source == 0) return 0;

    logValid =
        (health.flags & RIN_NVME_HEALTH_FLAG_LOG_VALID) != 0u;
    temperatureValid =
        (health.flags & RIN_NVME_HEALTH_FLAG_TEMPERATURE_VALID) != 0u;
    spareValid =
        (health.flags & RIN_NVME_HEALTH_FLAG_SPARE_VALID) != 0u;
    mediaErrorsValid =
        (health.flags & RIN_NVME_HEALTH_FLAG_MEDIA_ERRORS_VALID) != 0u;
    if (health.struct_size != sizeof(health) ||
        health.version != RIN_NVME_HEALTH_SNAPSHOT_V1_VERSION ||
        (health.flags & ~RIN_NVME_HEALTH_FLAG_KNOWN) != 0u ||
        health.critical_warning > UINT32_C(0x1f) ||
        health.device_generation == 0u || health.reserved0 != 0u ||
        health.reserved_alignment != 0u || health.reserved[0] != 0u ||
        health.reserved[1] != 0u || (logValid && !mediaErrorsValid) ||
        (!logValid &&
         (health.flags != 0u || health.critical_warning != 0u ||
          health.percentage_used != 0u ||
          health.composite_temperature_kelvin != 0u ||
          health.available_spare_percent != 0u ||
          health.available_spare_threshold_percent != 0u ||
          health.media_data_integrity_errors_low != 0u ||
          health.media_data_integrity_errors_high != 0u)) ||
        (temperatureValid &&
         (health.composite_temperature_kelvin == 0u ||
          health.composite_temperature_kelvin > 1000u)) ||
        (!temperatureValid && health.composite_temperature_kelvin != 0u) ||
        (spareValid &&
         (health.available_spare_percent > 100u ||
          health.available_spare_threshold_percent > 100u)) ||
        (!spareValid &&
         (health.available_spare_percent != 0u ||
          health.available_spare_threshold_percent != 0u)) ||
        (!mediaErrorsValid &&
         (health.media_data_integrity_errors_low != 0u ||
          health.media_data_integrity_errors_high != 0u)))
        return 0;

    output->struct_size = sizeof(*output);
    output->version = RIN_STORAGE_HEALTH_SNAPSHOT_V1_VERSION;
    output->transport = RIN_STORAGE_HEALTH_TRANSPORT_NVME;
    output->device_generation = health.device_generation;
    if (!logValid) return 1;

    output->metrics[output->metric_count].metric_id =
        RIN_STORAGE_HEALTH_NVME_CRITICAL_WARNING;
    output->metrics[output->metric_count].unit =
        RIN_STORAGE_HEALTH_UNIT_BITMASK;
    output->metrics[output->metric_count].flags =
        RIN_STORAGE_HEALTH_METRIC_FLAG_VALID;
    output->metrics[output->metric_count].value_low =
        health.critical_warning;
    ++output->metric_count;
    if (temperatureValid) {
        output->metrics[output->metric_count].metric_id =
            RIN_STORAGE_HEALTH_NVME_COMPOSITE_TEMPERATURE;
        output->metrics[output->metric_count].unit =
            RIN_STORAGE_HEALTH_UNIT_KELVIN;
        output->metrics[output->metric_count].flags =
            RIN_STORAGE_HEALTH_METRIC_FLAG_VALID;
        output->metrics[output->metric_count].value_low =
            health.composite_temperature_kelvin;
        ++output->metric_count;
    }
    if (spareValid) {
        output->metrics[output->metric_count].metric_id =
            RIN_STORAGE_HEALTH_NVME_AVAILABLE_SPARE;
        output->metrics[output->metric_count].unit =
            RIN_STORAGE_HEALTH_UNIT_PERCENT;
        output->metrics[output->metric_count].flags =
            RIN_STORAGE_HEALTH_METRIC_FLAG_VALID;
        output->metrics[output->metric_count].value_low =
            health.available_spare_percent;
        ++output->metric_count;
        output->metrics[output->metric_count].metric_id =
            RIN_STORAGE_HEALTH_NVME_AVAILABLE_SPARE_THRESHOLD;
        output->metrics[output->metric_count].unit =
            RIN_STORAGE_HEALTH_UNIT_PERCENT;
        output->metrics[output->metric_count].flags =
            RIN_STORAGE_HEALTH_METRIC_FLAG_VALID;
        output->metrics[output->metric_count].value_low =
            health.available_spare_threshold_percent;
        ++output->metric_count;
    }
    output->metrics[output->metric_count].metric_id =
        RIN_STORAGE_HEALTH_NVME_PERCENTAGE_USED;
    output->metrics[output->metric_count].unit =
        RIN_STORAGE_HEALTH_UNIT_PERCENT;
    output->metrics[output->metric_count].flags =
        RIN_STORAGE_HEALTH_METRIC_FLAG_VALID |
        (health.percentage_used == UINT8_MAX
             ? RIN_STORAGE_HEALTH_METRIC_FLAG_SATURATED : 0u);
    output->metrics[output->metric_count].value_low =
        health.percentage_used;
    ++output->metric_count;
    output->metrics[output->metric_count].metric_id =
        RIN_STORAGE_HEALTH_NVME_MEDIA_DATA_INTEGRITY_ERRORS;
    output->metrics[output->metric_count].unit = RIN_STORAGE_HEALTH_UNIT_COUNT;
    output->metrics[output->metric_count].flags =
        RIN_STORAGE_HEALTH_METRIC_FLAG_VALID;
    output->metrics[output->metric_count].value_low =
        health.media_data_integrity_errors_low;
    output->metrics[output->metric_count].value_high =
        health.media_data_integrity_errors_high;
    ++output->metric_count;
    return 1;
}

#if defined(__cplusplus)
static_assert(sizeof(RinStorageHealthMetricV1) == 24u,
              "storage health metric ABI drift");
static_assert(sizeof(RinStorageHealthSnapshotV1) == 224u,
              "storage health snapshot ABI drift");
#else
_Static_assert(sizeof(RinStorageHealthMetricV1) == 24u,
               "storage health metric ABI drift");
_Static_assert(sizeof(RinStorageHealthSnapshotV1) == 224u,
               "storage health snapshot ABI drift");
#endif

#endif /* RINRUNTIME_STORAGE_HEALTH_SNAPSHOT_V1_H */
