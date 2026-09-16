/* SPDX-License-Identifier: MIT */
/* Public, bounded application backup and restore policy contract. */

#ifndef RINRUNTIME_BACKUP_RESTORE_H
#define RINRUNTIME_BACKUP_RESTORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_BACKUP_VERSION UINT16_C(1)
#define RINRUNTIME_BACKUP_APPLICATION_ID_SIZE 32u
#define RINRUNTIME_BACKUP_PACKAGE_DIGEST_SIZE 32u
#define RINRUNTIME_BACKUP_ITEM_ID_SIZE 48u
#define RINRUNTIME_BACKUP_MAX_ITEMS 64u
/* Maximum bytes in the canonical RBK1 declaration manifest, not payload data. */
#define RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX \
    (112u + RINRUNTIME_BACKUP_MAX_ITEMS * 64u)

typedef enum RinRuntimeBackupStorageClass {
    RINRUNTIME_BACKUP_STORAGE_CONFIG = 1,
    RINRUNTIME_BACKUP_STORAGE_DATA = 2,
    RINRUNTIME_BACKUP_STORAGE_STATE = 3,
    RINRUNTIME_BACKUP_STORAGE_CACHE = 4,
    RINRUNTIME_BACKUP_STORAGE_BACKUP_DATA = 5,
    /* Recent-document MRU data is state-like, but is deliberately never
     * portable backup material because it can grant unwanted file context. */
    RINRUNTIME_BACKUP_STORAGE_RECENT_ITEMS = 6,
    /* Key material remains behind the keyring capability; a manifest may
     * describe it only as excluded metadata, never as archive input. */
    RINRUNTIME_BACKUP_STORAGE_SECRET_KEYRING = 7
} RinRuntimeBackupStorageClass;

typedef enum RinRuntimeBackupItemFlags {
    /* Exactly one of INCLUDE and EXCLUDE is required for every declaration. */
    RINRUNTIME_BACKUP_ITEM_INCLUDE = UINT16_C(1) << 0,
    RINRUNTIME_BACKUP_ITEM_EXCLUDE = UINT16_C(1) << 1
} RinRuntimeBackupItemFlags;

typedef enum RinRuntimeBackupStatusFlags {
    RINRUNTIME_BACKUP_STATUS_FRAMEWORK_AVAILABLE = UINT16_C(1) << 0,
    RINRUNTIME_BACKUP_STATUS_MANIFEST_DECLARED = UINT16_C(1) << 1,
    RINRUNTIME_BACKUP_STATUS_RESTORE_REQUIRES_APP_CONFIRMATION = UINT16_C(1) << 2,
    RINRUNTIME_BACKUP_STATUS_SENSITIVE_DATA_EXCLUDED = UINT16_C(1) << 3
} RinRuntimeBackupStatusFlags;

typedef enum RinRuntimeBackupResult {
    RINRUNTIME_BACKUP_OK = 0,
    RINRUNTIME_BACKUP_INVALID_ARGUMENT = -1,
    RINRUNTIME_BACKUP_LIMIT = -2,
    RINRUNTIME_BACKUP_MALFORMED = -3,
    RINRUNTIME_BACKUP_INTEGRITY_FAILED = -4,
    /* cache, recent-item, and keyring input cannot be made eligible. */
    RINRUNTIME_BACKUP_INELIGIBLE = -5,
    /* Package identity must exactly match unless the launch authority says
     * that this is an authorized package/application handoff. */
    RINRUNTIME_BACKUP_IDENTITY_MISMATCH = -6,
    RINRUNTIME_BACKUP_IDENTITY_NOT_AUTHORIZED = -7,
    RINRUNTIME_BACKUP_MIGRATION_REQUIRED = -8,
    RINRUNTIME_BACKUP_MIGRATION_FAILED = -9,
    /* The kernel File Portal rejected or malformed a payload exchange. */
    RINRUNTIME_BACKUP_TRANSPORT_FAILED = -10
} RinRuntimeBackupResult;

/* This value is supplied by the authenticated package launcher, not an app
 * display name or a path.  It intentionally mirrors the identity properties
 * required by session recovery while keeping this library link-independent. */
typedef struct RinRuntimeBackupIdentityV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint8_t application_id[RINRUNTIME_BACKUP_APPLICATION_ID_SIZE];
    uint8_t package_digest[RINRUNTIME_BACKUP_PACKAGE_DIGEST_SIZE];
    uint64_t package_generation;
    uint64_t reserved[2];
} RinRuntimeBackupIdentityV1;

/* item_id is a bounded logical identifier, never a filesystem path. */
typedef struct RinRuntimeBackupItemV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t storage_class;
    uint8_t item_id[RINRUNTIME_BACKUP_ITEM_ID_SIZE];
    uint64_t schema_version;
    uint16_t flags;
    uint16_t reserved0;
    uint64_t reserved[2];
} RinRuntimeBackupItemV1;

typedef struct RinRuntimeBackupManifestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    RinRuntimeBackupIdentityV1 identity;
    uint64_t manifest_generation;
    uint64_t created_at_ns;
    const RinRuntimeBackupItemV1* items;
    uint32_t item_count;
    uint32_t reserved1;
    uint64_t reserved[2];
} RinRuntimeBackupManifestV1;

typedef struct RinRuntimeBackupManifestInfoV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    RinRuntimeBackupIdentityV1 identity;
    uint64_t manifest_generation;
    uint64_t created_at_ns;
    uint32_t item_count;
    uint32_t eligible_item_count;
    uint32_t excluded_item_count;
    uint32_t manifest_size;
    uint32_t integrity;
    uint32_t reserved1;
    uint64_t reserved[2];
} RinRuntimeBackupManifestInfoV1;

/* A Settings UI can render this without receiving payload paths or bytes. */
typedef struct RinRuntimeBackupStatusV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    RinRuntimeBackupManifestInfoV1 manifest;
    uint64_t reserved[2];
} RinRuntimeBackupStatusV1;

/* The launcher must implement this against its signed package handoff policy.
 * Returning 1 is the only authorization; 0/negative values deny restoration.
 * Apps must not use a self-authored callback to bypass identity checks. */
typedef int (*RinRuntimeBackupIdentityAuthorizerFn)(
    void* context, const RinRuntimeBackupIdentityV1* source_identity,
    const RinRuntimeBackupIdentityV1* target_identity);

/* A migration is called only after identity admission and only for an eligible
 * declaration. It receives isolated input/output buffers and must return 0
 * with an exact `output_size`; a failed migration never falls back to copying
 * the old schema bytes. */
typedef int (*RinRuntimeBackupMigrationFn)(
    void* context, const RinRuntimeBackupItemV1* item,
    uint64_t source_schema_version, uint64_t target_schema_version,
    const uint8_t* input, uint32_t input_size, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size);

int rinruntime_backup_identity_valid(const RinRuntimeBackupIdentityV1* identity);
int rinruntime_backup_item_is_eligible(const RinRuntimeBackupItemV1* item);

/* The canonical encoder accepts a sorted declaration list only. This makes
 * manifests deterministic, bounds item count, and rejects path-like IDs. */
RinRuntimeBackupResult rinruntime_backup_manifest_encode(
    const RinRuntimeBackupManifestV1* manifest, uint8_t* bytes_out,
    size_t bytes_capacity, size_t* bytes_size_out);
RinRuntimeBackupResult rinruntime_backup_manifest_inspect(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeBackupManifestInfoV1* info_out);
RinRuntimeBackupResult rinruntime_backup_manifest_entry_at(
    const uint8_t* bytes, size_t bytes_size, uint32_t entry_index,
    RinRuntimeBackupItemV1* item_out);

/* No backup transport is assumed by the runtime. These helpers expose only
 * policy/declaration state so Settings never needs secret or payload access. */
RinRuntimeBackupResult rinruntime_backup_status_unconfigured(
    RinRuntimeBackupStatusV1* status_out);
RinRuntimeBackupResult rinruntime_backup_status_from_manifest(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeBackupStatusV1* status_out);

/* Restore exact-schema bytes or run the one explicit app migration. A package
 * change is deny-by-default and requires the authenticated launcher callback.
 * Cache, recent items, and keyring entries always return INELIGIBLE. On every
 * failure, restored_size_out is zeroed and the caller-owned restored_out span
 * is cleared when supplied. */
RinRuntimeBackupResult rinruntime_backup_restore_item(
    const uint8_t* source_manifest_bytes, size_t source_manifest_size,
    uint32_t item_index, const RinRuntimeBackupIdentityV1* target_identity,
    uint64_t target_schema_version,
    RinRuntimeBackupIdentityAuthorizerFn authorize_identity,
    void* authorize_context, RinRuntimeBackupMigrationFn migrate,
    void* migrate_context, const uint8_t* archived_bytes,
    uint32_t archived_size, uint8_t* restored_out,
    uint32_t restored_capacity, uint32_t* restored_size_out);

/* Payload transport is descriptor-based only after the caller has obtained a
 * current-process descriptor through the File Portal OPEN/DURABLE_OPEN ABI.
 * Each call is bounded by RIN_FILE_PORTAL_PAYLOAD_DATA_SIZE and larger data
 * must be streamed by increasing offset. */
RinRuntimeBackupResult rinruntime_backup_payload_read(
    int32_t descriptor, uint64_t offset, uint8_t* bytes, uint32_t capacity,
    uint32_t* bytes_read);
RinRuntimeBackupResult rinruntime_backup_payload_write(
    int32_t descriptor, uint64_t offset, const uint8_t* bytes, uint32_t size,
    uint32_t* bytes_written);
RinRuntimeBackupResult rinruntime_backup_payload_sync(int32_t descriptor);
RinRuntimeBackupResult rinruntime_backup_payload_truncate(
    int32_t descriptor, uint64_t size);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_BACKUP_RESTORE_H */
