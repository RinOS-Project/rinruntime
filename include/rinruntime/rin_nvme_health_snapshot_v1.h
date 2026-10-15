/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Public, pointer-free NVMe SMART/Health summary carried by device diagnostics. */
#ifndef RIN_SHARED_RIN_NVME_HEALTH_SNAPSHOT_V1_H
#define RIN_SHARED_RIN_NVME_HEALTH_SNAPSHOT_V1_H

#include <stdint.h>

#define RIN_NVME_QEMU_VENDOR_ID UINT32_C(0x1b36)
#define RIN_NVME_QEMU_DEVICE_ID UINT32_C(0x0010)
#define RIN_NVME_HEALTH_SNAPSHOT_V1_VERSION UINT32_C(0x00010000)
#define RIN_NVME_HEALTH_FLAG_LOG_VALID UINT32_C(0x00000001)
#define RIN_NVME_HEALTH_FLAG_TEMPERATURE_VALID UINT32_C(0x00000002)
#define RIN_NVME_HEALTH_FLAG_SPARE_VALID UINT32_C(0x00000004)
#define RIN_NVME_HEALTH_FLAG_MEDIA_ERRORS_VALID UINT32_C(0x00000008)
#define RIN_NVME_HEALTH_FLAG_KNOWN \
    (RIN_NVME_HEALTH_FLAG_LOG_VALID | \
     RIN_NVME_HEALTH_FLAG_TEMPERATURE_VALID | \
     RIN_NVME_HEALTH_FLAG_SPARE_VALID | \
     RIN_NVME_HEALTH_FLAG_MEDIA_ERRORS_VALID)

#define RIN_NVME_DIAGNOSTIC_SNAPSHOT_V2_VERSION UINT32_C(0x00020000)
#define RIN_NVME_DIAGNOSTIC_SNAPSHOT_V2_MAGIC UINT32_C(0x3244564e) /* NVD2 */
#define RIN_NVME_DIAGNOSTIC_SNAPSHOT_V3_VERSION UINT32_C(0x00030000)
#define RIN_NVME_DIAGNOSTIC_SNAPSHOT_V3_MAGIC UINT32_C(0x3344564e) /* NVD3 */
#define RIN_NVME_DIAGNOSTIC_FLAG_MMIO_PRESENT UINT32_C(0x00000001)
#define RIN_NVME_DIAGNOSTIC_FLAG_CONTROLLER_READY UINT32_C(0x00000002)
#define RIN_NVME_DIAGNOSTIC_FLAG_ACTIVE_DMA UINT32_C(0x00000004)
#define RIN_NVME_DIAGNOSTIC_FLAG_KNOWN \
    (RIN_NVME_DIAGNOSTIC_FLAG_MMIO_PRESENT | \
     RIN_NVME_DIAGNOSTIC_FLAG_CONTROLLER_READY | \
     RIN_NVME_DIAGNOSTIC_FLAG_ACTIVE_DMA)

/* Counts are the NVMe log's full 128-bit little-endian value, split into two
 * words so 32-bit and 64-bit Management clients decode it identically. */
typedef struct RinNvmeHealthSnapshotV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t critical_warning;
    uint16_t composite_temperature_kelvin;
    uint8_t available_spare_percent;
    uint8_t available_spare_threshold_percent;
    uint8_t percentage_used;
    uint8_t reserved0;
    uint16_t reserved_alignment;
    uint64_t media_data_integrity_errors_low;
    uint64_t media_data_integrity_errors_high;
    uint64_t device_generation;
    uint64_t reserved[2];
} RinNvmeHealthSnapshotV1;

/* Stable diagnostic payload for the currently supported native NVMe owner.
 * Hardware addresses and DMA handles are deliberately absent. */
typedef struct RinNvmeDiagnosticSnapshotV2 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t magic;
    uint32_t active;
    uint32_t active_operation;
    uint32_t active_block_count;
    uint32_t active_dma_completed;
    uint32_t removed;
    uint32_t quarantined;
    uint32_t controller_stopped;
    uint32_t admin_phase;
    uint64_t active_request_id;
    uint64_t active_dma_length;
    uint64_t block_count;
    uint32_t logical_block_size;
    uint32_t physical_block_size;
    uint32_t optimal_transfer_blocks;
    uint32_t maximum_transfer_blocks;
    uint64_t register_length;
    uint32_t doorbell_stride;
    uint32_t maximum_transfer_bytes;
    uint32_t admin_sq_tail;
    uint32_t io_sq_tail;
    uint32_t admin_cq_head;
    uint32_t io_cq_head;
    uint32_t next_command_id;
    uint32_t active_command_id;
    RinNvmeHealthSnapshotV1 health;
} RinNvmeDiagnosticSnapshotV2;

#define RIN_NVME_ERROR_LOG_SNAPSHOT_V1_VERSION UINT32_C(0x00010000)
#define RIN_NVME_ERROR_LOG_FLAG_LOG_VALID UINT32_C(0x00000001)
#define RIN_NVME_ERROR_LOG_FLAG_ENTRY_VALID UINT32_C(0x00000002)
#define RIN_NVME_ERROR_LOG_FLAG_MEDIA_ERROR UINT32_C(0x00000004)
#define RIN_NVME_ERROR_LOG_FLAG_KNOWN \
    (RIN_NVME_ERROR_LOG_FLAG_LOG_VALID | \
     RIN_NVME_ERROR_LOG_FLAG_ENTRY_VALID | \
     RIN_NVME_ERROR_LOG_FLAG_MEDIA_ERROR)

/* The most recent NVMe Error Information log entry. It contains only the
 * standard bounded error fields; controller addresses and DMA handles never
 * cross the diagnostic boundary. */
typedef struct RinNvmeErrorLogSnapshotV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t status_code;
    uint32_t status_code_type;
    uint32_t namespace_id;
    uint32_t submission_queue_id;
    uint32_t command_id;
    uint16_t parameter_error_location;
    uint16_t reserved0;
    uint32_t reserved_alignment;
    uint64_t error_count;
    uint64_t lba;
    uint64_t device_generation;
} RinNvmeErrorLogSnapshotV1;

/* V3 preserves the complete V2 prefix and appends one bounded error record.
 * Its size exactly matches the existing Management diagnostic data limit. */
typedef struct RinNvmeDiagnosticSnapshotV3 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t magic;
    uint32_t active;
    uint32_t active_operation;
    uint32_t active_block_count;
    uint32_t active_dma_completed;
    uint32_t removed;
    uint32_t quarantined;
    uint32_t controller_stopped;
    uint32_t admin_phase;
    uint64_t active_request_id;
    uint64_t active_dma_length;
    uint64_t block_count;
    uint32_t logical_block_size;
    uint32_t physical_block_size;
    uint32_t optimal_transfer_blocks;
    uint32_t maximum_transfer_blocks;
    uint64_t register_length;
    uint32_t doorbell_stride;
    uint32_t maximum_transfer_bytes;
    uint32_t admin_sq_tail;
    uint32_t io_sq_tail;
    uint32_t admin_cq_head;
    uint32_t io_cq_head;
    uint32_t next_command_id;
    uint32_t active_command_id;
    RinNvmeHealthSnapshotV1 health;
    RinNvmeErrorLogSnapshotV1 latest_error;
} RinNvmeDiagnosticSnapshotV3;

#if defined(__cplusplus)
static_assert(sizeof(RinNvmeHealthSnapshotV1) == 64u,
              "NVMe health snapshot ABI drift");
static_assert(sizeof(RinNvmeDiagnosticSnapshotV2) == 192u,
              "NVMe diagnostic v2 ABI drift");
static_assert(sizeof(RinNvmeErrorLogSnapshotV1) == 64u,
              "NVMe error-log snapshot ABI drift");
static_assert(sizeof(RinNvmeDiagnosticSnapshotV3) == 256u,
              "NVMe diagnostic v3 ABI drift");
#else
_Static_assert(sizeof(RinNvmeHealthSnapshotV1) == 64u,
               "NVMe health snapshot ABI drift");
_Static_assert(sizeof(RinNvmeDiagnosticSnapshotV2) == 192u,
               "NVMe diagnostic v2 ABI drift");
_Static_assert(sizeof(RinNvmeErrorLogSnapshotV1) == 64u,
               "NVMe error-log snapshot ABI drift");
_Static_assert(sizeof(RinNvmeDiagnosticSnapshotV3) == 256u,
               "NVMe diagnostic v3 ABI drift");
#endif

#endif /* RIN_SHARED_RIN_NVME_HEALTH_SNAPSHOT_V1_H */
