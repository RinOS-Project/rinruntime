/* SPDX-License-Identifier: MIT */
/* Public, bounded session persistence and document recovery contract. */

#ifndef RINRUNTIME_SESSION_RECOVERY_H
#define RINRUNTIME_SESSION_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "safe_save.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_SESSION_RECOVERY_VERSION UINT16_C(1)
#define RINRUNTIME_SESSION_RECOVERY_APPLICATION_ID_SIZE 32u
#define RINRUNTIME_SESSION_RECOVERY_PACKAGE_DIGEST_SIZE 32u
#define RINRUNTIME_SESSION_RECOVERY_DOCUMENT_ID_SIZE 32u
#define RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX (64u * 1024u)
/* This is an upper bound for caller-owned serialization storage. */
#define RINRUNTIME_SESSION_RECOVERY_STORAGE_MAX \
    (144u + RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX)

typedef enum RinRuntimeSessionRecoveryReason {
    /* A running application saved data that must be reviewed after a crash. */
    RINRUNTIME_SESSION_RECOVERY_AFTER_CRASH = 1,
    /* A normal logout/reboot session snapshot.  It is still never restored
     * implicitly: the application presents the same Restore/Discard choice. */
    RINRUNTIME_SESSION_RECOVERY_AFTER_LOGOUT_OR_REBOOT = 2
} RinRuntimeSessionRecoveryReason;

typedef enum RinRuntimeSessionRecoveryDecision {
    RINRUNTIME_SESSION_RECOVERY_DECISION_NONE = 0,
    RINRUNTIME_SESSION_RECOVERY_DECISION_RESTORE = 1,
    RINRUNTIME_SESSION_RECOVERY_DECISION_DISCARD = 2
} RinRuntimeSessionRecoveryDecision;

typedef enum RinRuntimeSessionRecoveryResult {
    RINRUNTIME_SESSION_RECOVERY_OK = 0,
    /* The caller has not explicitly selected Restore or Discard. */
    RINRUNTIME_SESSION_RECOVERY_DECISION_REQUIRED = 1,
    /* A discard decision is successful without exposing the snapshot bytes. */
    RINRUNTIME_SESSION_RECOVERY_DISCARDED = 2,
    RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT = -1,
    RINRUNTIME_SESSION_RECOVERY_LIMIT = -2,
    RINRUNTIME_SESSION_RECOVERY_MALFORMED = -3,
    RINRUNTIME_SESSION_RECOVERY_INTEGRITY_FAILED = -4,
    /* Recovery data belongs to another signed application/package image. */
    RINRUNTIME_SESSION_RECOVERY_IDENTITY_MISMATCH = -5,
    /* The caller already has a newer document generation. */
    RINRUNTIME_SESSION_RECOVERY_STALE = -6,
    RINRUNTIME_SESSION_RECOVERY_STORAGE_FAILED = -7,
    /* The snapshot is visible but directory durability is not yet known. */
    RINRUNTIME_SESSION_RECOVERY_COMMITTED_UNSYNCED = -8,
    /* A post-commit crashd notification could not be delivered. */
    RINRUNTIME_SESSION_RECOVERY_CRASHD_UNAVAILABLE = -9
} RinRuntimeSessionRecoveryResult;

/* application_id and package_digest come from the authenticated launch
 * identity, never from a document path or a caller-controlled display name. */
typedef struct RinRuntimeSessionRecoveryIdentityV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint8_t application_id[RINRUNTIME_SESSION_RECOVERY_APPLICATION_ID_SIZE];
    uint8_t package_digest[RINRUNTIME_SESSION_RECOVERY_PACKAGE_DIGEST_SIZE];
    uint64_t package_generation;
    uint64_t reserved[2];
} RinRuntimeSessionRecoveryIdentityV1;

typedef struct RinRuntimeSessionRecoverySnapshotV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reason;
    RinRuntimeSessionRecoveryIdentityV1 identity;
    /* Opaque stable identity supplied by the application. It is not a path. */
    uint8_t document_id[RINRUNTIME_SESSION_RECOVERY_DOCUMENT_ID_SIZE];
    uint64_t document_generation;
    uint64_t snapshot_generation;
    uint64_t saved_at_ns;
    const uint8_t* payload;
    uint32_t payload_size;
    uint32_t reserved0;
    uint64_t reserved[2];
} RinRuntimeSessionRecoverySnapshotV1;

typedef struct RinRuntimeSessionRecoveryMetadataV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reason;
    RinRuntimeSessionRecoveryIdentityV1 identity;
    uint8_t document_id[RINRUNTIME_SESSION_RECOVERY_DOCUMENT_ID_SIZE];
    uint64_t document_generation;
    uint64_t snapshot_generation;
    uint64_t saved_at_ns;
    uint32_t payload_size;
    uint32_t reserved0;
    uint64_t reserved[2];
} RinRuntimeSessionRecoveryMetadataV1;

/* The application supplies this adapter after an atomic snapshot commit. The
 * registration contains no document path or plaintext; crashd merely records
 * that a signed application owns a recoverable document. */
typedef int (*RinRuntimeSessionRecoveryCrashdRegisterFn)(
    void* context, const RinRuntimeSessionRecoveryMetadataV1* metadata);

int rinruntime_session_recovery_identity_valid(
    const RinRuntimeSessionRecoveryIdentityV1* identity);

/* Resolve the identity captured by the authenticated RinOS socket ABI.  The
 * result is never synthesized from caller-provided application data.  On
 * every failure identity_out is cleared. */
int rinruntime_session_recovery_get_authenticated_identity(
    RinRuntimeSessionRecoveryIdentityV1* identity_out);

/* Serialize/parse one self-contained snapshot. Parsing rejects trailing data,
 * malformed reserved fields, bound violations, and checksum mismatches. */
RinRuntimeSessionRecoveryResult rinruntime_session_recovery_encode(
    const RinRuntimeSessionRecoverySnapshotV1* snapshot, uint8_t* bytes_out,
    size_t bytes_capacity, size_t* bytes_size_out);
RinRuntimeSessionRecoveryResult rinruntime_session_recovery_inspect(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out);

/* Atomically replace the prior snapshot for the same document. Replacing one
 * bounded target is the GC operation: no old recovery version remains visible
 * after a completed durable commit. */
RinRuntimeSessionRecoveryResult rinruntime_session_recovery_save_atomic(
    const RinRuntimeSafeSaveBackendV1* backend, const char* target_path,
    const RinRuntimeSessionRecoverySnapshotV1* snapshot,
    uint8_t* serialization_buffer, size_t serialization_capacity,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out);

/* A caller must first inspect the record and render a choice in its own UI.
 * This routine deliberately refuses automatic restoration when `decision` is
 * NONE; DISCARDED does not copy payload bytes. `current_document_generation`
 * is zero only for a new/untitled document. */
RinRuntimeSessionRecoveryResult rinruntime_session_recovery_resolve(
    const uint8_t* bytes, size_t bytes_size,
    const RinRuntimeSessionRecoveryIdentityV1* expected_identity,
    uint64_t current_document_generation,
    RinRuntimeSessionRecoveryDecision decision,
    uint8_t* payload_out, size_t payload_capacity,
    size_t* payload_size_out,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out);

/* Notify crashd only after a completed atomic snapshot. A notification failure
 * never invalidates the already durable local recovery data, so callers can
 * retry this operation without re-saving plaintext. */
RinRuntimeSessionRecoveryResult rinruntime_session_recovery_register_crashd(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    RinRuntimeSessionRecoveryCrashdRegisterFn register_fn, void* context);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_SESSION_RECOVERY_H */

