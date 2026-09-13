/* SPDX-License-Identifier: MIT */

#include <rinruntime/session_recovery.h>

#include <string.h>

/* Legacy hosts may not provide the authenticated launcher adapter.  Keep the
 * optional hook weak so the runtime library remains linkable on those hosts. */
#if defined(__GNUC__)
extern int rin_runtime_get_authenticated_session_identity(
    RinRuntimeSessionRecoveryIdentityV1* identity_out) __attribute__((weak));
#else
extern int rin_runtime_get_authenticated_session_identity(
    RinRuntimeSessionRecoveryIdentityV1* identity_out);
#endif

#define RINRUNTIME_SESSION_RECOVERY_MAGIC UINT32_C(0x31525352) /* RSR1 */

typedef struct __attribute__((packed)) RinRuntimeSessionRecoveryWireV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t reason;
    uint32_t payload_size;
    uint64_t package_generation;
    uint64_t document_generation;
    uint64_t snapshot_generation;
    uint64_t saved_at_ns;
    uint8_t application_id[RINRUNTIME_SESSION_RECOVERY_APPLICATION_ID_SIZE];
    uint8_t package_digest[RINRUNTIME_SESSION_RECOVERY_PACKAGE_DIGEST_SIZE];
    uint8_t document_id[RINRUNTIME_SESSION_RECOVERY_DOCUMENT_ID_SIZE];
    uint32_t integrity;
} RinRuntimeSessionRecoveryWireV1;

static int recovery_nonzero(const uint8_t* bytes, size_t size)
{
    uint8_t value = 0u;
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index) value |= bytes[index];
    return value != 0u;
}

static uint32_t recovery_crc32(uint32_t value, const uint8_t* bytes,
                               size_t size)
{
    size_t index;
    if (bytes == NULL && size != 0u) return 0u;
    for (index = 0u; index < size; ++index) {
        unsigned int bit;
        value ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit)
            value = (value >> 1u) ^
                (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(value & 1u));
    }
    return value;
}

static uint32_t recovery_integrity(const RinRuntimeSessionRecoveryWireV1* wire,
                                   const uint8_t* payload)
{
    uint32_t value = UINT32_C(0xffffffff);
    value = recovery_crc32(value, (const uint8_t*)wire,
                           offsetof(RinRuntimeSessionRecoveryWireV1,
                                    integrity));
    value = recovery_crc32(value, payload, wire->payload_size);
    return value ^ UINT32_C(0xffffffff);
}

static int recovery_reason_valid(uint16_t reason)
{
    return reason == RINRUNTIME_SESSION_RECOVERY_AFTER_CRASH ||
           reason == RINRUNTIME_SESSION_RECOVERY_AFTER_LOGOUT_OR_REBOOT;
}

int rinruntime_session_recovery_identity_valid(
    const RinRuntimeSessionRecoveryIdentityV1* identity)
{
    return identity != NULL && identity->struct_size == sizeof(*identity) &&
           identity->version == RINRUNTIME_SESSION_RECOVERY_VERSION &&
           identity->reserved0 == 0u && identity->package_generation != 0u &&
           recovery_nonzero(identity->application_id,
                            sizeof(identity->application_id)) &&
           recovery_nonzero(identity->package_digest,
                            sizeof(identity->package_digest)) &&
           identity->reserved[0] == 0u && identity->reserved[1] == 0u;
}

int rinruntime_session_recovery_get_authenticated_identity(
    RinRuntimeSessionRecoveryIdentityV1* identity_out)
{
    int result;
    if (identity_out == NULL)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    memset(identity_out, 0, sizeof(*identity_out));
    if (rin_runtime_get_authenticated_session_identity == NULL)
        return RINRUNTIME_SESSION_RECOVERY_IDENTITY_MISMATCH;
    result = rin_runtime_get_authenticated_session_identity(identity_out);
    if (result != 0 ||
        !rinruntime_session_recovery_identity_valid(identity_out)) {
        memset(identity_out, 0, sizeof(*identity_out));
        return RINRUNTIME_SESSION_RECOVERY_IDENTITY_MISMATCH;
    }
    return RINRUNTIME_SESSION_RECOVERY_OK;
}

static int recovery_snapshot_valid(
    const RinRuntimeSessionRecoverySnapshotV1* snapshot)
{
    return snapshot != NULL && snapshot->struct_size == sizeof(*snapshot) &&
           snapshot->version == RINRUNTIME_SESSION_RECOVERY_VERSION &&
           recovery_reason_valid(snapshot->reason) &&
           rinruntime_session_recovery_identity_valid(&snapshot->identity) &&
           recovery_nonzero(snapshot->document_id,
                            sizeof(snapshot->document_id)) &&
           snapshot->snapshot_generation != 0u && snapshot->saved_at_ns != 0u &&
           snapshot->payload_size <= RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX &&
           (snapshot->payload_size == 0u || snapshot->payload != NULL) &&
           snapshot->reserved0 == 0u && snapshot->reserved[0] == 0u &&
           snapshot->reserved[1] == 0u;
}

static void recovery_metadata_from_wire(
    const RinRuntimeSessionRecoveryWireV1* wire,
    RinRuntimeSessionRecoveryMetadataV1* metadata)
{
    memset(metadata, 0, sizeof(*metadata));
    metadata->struct_size = sizeof(*metadata);
    metadata->version = RINRUNTIME_SESSION_RECOVERY_VERSION;
    metadata->reason = wire->reason;
    metadata->identity.struct_size = sizeof(metadata->identity);
    metadata->identity.version = RINRUNTIME_SESSION_RECOVERY_VERSION;
    memcpy(metadata->identity.application_id, wire->application_id,
           sizeof(metadata->identity.application_id));
    memcpy(metadata->identity.package_digest, wire->package_digest,
           sizeof(metadata->identity.package_digest));
    metadata->identity.package_generation = wire->package_generation;
    memcpy(metadata->document_id, wire->document_id,
           sizeof(metadata->document_id));
    metadata->document_generation = wire->document_generation;
    metadata->snapshot_generation = wire->snapshot_generation;
    metadata->saved_at_ns = wire->saved_at_ns;
    metadata->payload_size = wire->payload_size;
}

static int recovery_metadata_valid(
    const RinRuntimeSessionRecoveryMetadataV1* metadata)
{
    return metadata != NULL && metadata->struct_size == sizeof(*metadata) &&
           metadata->version == RINRUNTIME_SESSION_RECOVERY_VERSION &&
           recovery_reason_valid(metadata->reason) &&
           rinruntime_session_recovery_identity_valid(&metadata->identity) &&
           recovery_nonzero(metadata->document_id,
                            sizeof(metadata->document_id)) &&
           metadata->snapshot_generation != 0u && metadata->saved_at_ns != 0u &&
           metadata->payload_size <= RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX &&
           metadata->reserved0 == 0u && metadata->reserved[0] == 0u &&
           metadata->reserved[1] == 0u;
}

RinRuntimeSessionRecoveryResult rinruntime_session_recovery_encode(
    const RinRuntimeSessionRecoverySnapshotV1* snapshot, uint8_t* bytes_out,
    size_t bytes_capacity, size_t* bytes_size_out)
{
    RinRuntimeSessionRecoveryWireV1 wire;
    size_t size;

    if (bytes_size_out != NULL) *bytes_size_out = 0u;
    if (!recovery_snapshot_valid(snapshot) || bytes_out == NULL ||
        bytes_size_out == NULL)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    size = sizeof(wire) + (size_t)snapshot->payload_size;
    if (size > bytes_capacity)
        return RINRUNTIME_SESSION_RECOVERY_LIMIT;
    memset(&wire, 0, sizeof(wire));
    wire.magic = RINRUNTIME_SESSION_RECOVERY_MAGIC;
    wire.version = RINRUNTIME_SESSION_RECOVERY_VERSION;
    wire.reason = snapshot->reason;
    wire.payload_size = snapshot->payload_size;
    wire.package_generation = snapshot->identity.package_generation;
    wire.document_generation = snapshot->document_generation;
    wire.snapshot_generation = snapshot->snapshot_generation;
    wire.saved_at_ns = snapshot->saved_at_ns;
    memcpy(wire.application_id, snapshot->identity.application_id,
           sizeof(wire.application_id));
    memcpy(wire.package_digest, snapshot->identity.package_digest,
           sizeof(wire.package_digest));
    memcpy(wire.document_id, snapshot->document_id, sizeof(wire.document_id));
    wire.integrity = recovery_integrity(&wire, snapshot->payload);
    memcpy(bytes_out, &wire, sizeof(wire));
    if (snapshot->payload_size != 0u)
        memcpy(bytes_out + sizeof(wire), snapshot->payload,
               snapshot->payload_size);
    *bytes_size_out = size;
    return RINRUNTIME_SESSION_RECOVERY_OK;
}

static RinRuntimeSessionRecoveryResult recovery_wire_validate(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeSessionRecoveryWireV1* wire_out)
{
    RinRuntimeSessionRecoveryWireV1 wire;
    RinRuntimeSessionRecoveryMetadataV1 metadata;
    const uint8_t* payload;
    if (bytes == NULL || bytes_size < sizeof(wire))
        return RINRUNTIME_SESSION_RECOVERY_MALFORMED;
    memcpy(&wire, bytes, sizeof(wire));
    if (wire.magic != RINRUNTIME_SESSION_RECOVERY_MAGIC ||
        wire.version != RINRUNTIME_SESSION_RECOVERY_VERSION ||
        !recovery_reason_valid(wire.reason) ||
        wire.payload_size > RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX ||
        bytes_size != sizeof(wire) + (size_t)wire.payload_size)
        return RINRUNTIME_SESSION_RECOVERY_MALFORMED;
    payload = bytes + sizeof(wire);
    if (wire.integrity != recovery_integrity(&wire, payload))
        return RINRUNTIME_SESSION_RECOVERY_INTEGRITY_FAILED;
    recovery_metadata_from_wire(&wire, &metadata);
    if (!recovery_metadata_valid(&metadata))
        return RINRUNTIME_SESSION_RECOVERY_MALFORMED;
    if (wire_out != NULL) *wire_out = wire;
    return RINRUNTIME_SESSION_RECOVERY_OK;
}

RinRuntimeSessionRecoveryResult rinruntime_session_recovery_inspect(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out)
{
    RinRuntimeSessionRecoveryWireV1 wire;
    RinRuntimeSessionRecoveryResult result;
    if (metadata_out == NULL)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    memset(metadata_out, 0, sizeof(*metadata_out));
    result = recovery_wire_validate(bytes, bytes_size, &wire);
    if (result != RINRUNTIME_SESSION_RECOVERY_OK) return result;
    recovery_metadata_from_wire(&wire, metadata_out);
    return RINRUNTIME_SESSION_RECOVERY_OK;
}

RinRuntimeSessionRecoveryResult rinruntime_session_recovery_save_atomic(
    const RinRuntimeSafeSaveBackendV1* backend, const char* target_path,
    const RinRuntimeSessionRecoverySnapshotV1* snapshot,
    uint8_t* serialization_buffer, size_t serialization_capacity,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out)
{
    RinRuntimeSafeSaveResult save_result;
    size_t size;
    RinRuntimeSessionRecoveryResult result;
    if (metadata_out != NULL) memset(metadata_out, 0, sizeof(*metadata_out));
    result = rinruntime_session_recovery_encode(snapshot, serialization_buffer,
                                                serialization_capacity, &size);
    if (result != RINRUNTIME_SESSION_RECOVERY_OK) return result;
    save_result = rinruntime_safe_save(backend, target_path,
                                       serialization_buffer, (uint32_t)size);
    if (save_result == RINRUNTIME_SAFE_SAVE_COMPLETED) {
        if (metadata_out != NULL) {
            result = rinruntime_session_recovery_inspect(
                serialization_buffer, size, metadata_out);
            if (result != RINRUNTIME_SESSION_RECOVERY_OK) {
                memset(metadata_out, 0, sizeof(*metadata_out));
                return result;
            }
        }
        return RINRUNTIME_SESSION_RECOVERY_OK;
    }
    if (save_result == RINRUNTIME_SAFE_SAVE_COMMITTED_UNSYNCED)
        return RINRUNTIME_SESSION_RECOVERY_COMMITTED_UNSYNCED;
    return RINRUNTIME_SESSION_RECOVERY_STORAGE_FAILED;
}

RinRuntimeSessionRecoveryResult rinruntime_session_recovery_resolve(
    const uint8_t* bytes, size_t bytes_size,
    const RinRuntimeSessionRecoveryIdentityV1* expected_identity,
    uint64_t current_document_generation,
    RinRuntimeSessionRecoveryDecision decision,
    uint8_t* payload_out, size_t payload_capacity,
    size_t* payload_size_out,
    RinRuntimeSessionRecoveryMetadataV1* metadata_out)
{
    RinRuntimeSessionRecoveryWireV1 wire;
    RinRuntimeSessionRecoveryMetadataV1 metadata;
    RinRuntimeSessionRecoveryResult result;
    if (payload_size_out != NULL) *payload_size_out = 0u;
    if (metadata_out != NULL) memset(metadata_out, 0, sizeof(*metadata_out));
    if (!rinruntime_session_recovery_identity_valid(expected_identity) ||
        payload_size_out == NULL)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    result = recovery_wire_validate(bytes, bytes_size, &wire);
    if (result != RINRUNTIME_SESSION_RECOVERY_OK) return result;
    recovery_metadata_from_wire(&wire, &metadata);
    if (memcmp(metadata.identity.application_id, expected_identity->application_id,
               sizeof(metadata.identity.application_id)) != 0 ||
        memcmp(metadata.identity.package_digest, expected_identity->package_digest,
               sizeof(metadata.identity.package_digest)) != 0 ||
        metadata.identity.package_generation != expected_identity->package_generation)
        return RINRUNTIME_SESSION_RECOVERY_IDENTITY_MISMATCH;
    if (current_document_generation != 0u &&
        metadata.document_generation < current_document_generation)
        return RINRUNTIME_SESSION_RECOVERY_STALE;
    if (metadata_out != NULL) *metadata_out = metadata;
    if (decision == RINRUNTIME_SESSION_RECOVERY_DECISION_NONE)
        return RINRUNTIME_SESSION_RECOVERY_DECISION_REQUIRED;
    if (decision == RINRUNTIME_SESSION_RECOVERY_DECISION_DISCARD)
        return RINRUNTIME_SESSION_RECOVERY_DISCARDED;
    if (decision != RINRUNTIME_SESSION_RECOVERY_DECISION_RESTORE ||
        (wire.payload_size != 0u && payload_out == NULL) ||
        payload_capacity < wire.payload_size)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    if (wire.payload_size != 0u)
        memcpy(payload_out, bytes + sizeof(wire), wire.payload_size);
    *payload_size_out = wire.payload_size;
    return RINRUNTIME_SESSION_RECOVERY_OK;
}

RinRuntimeSessionRecoveryResult rinruntime_session_recovery_register_crashd(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    RinRuntimeSessionRecoveryCrashdRegisterFn register_fn, void* context)
{
    if (!recovery_metadata_valid(metadata) || register_fn == NULL)
        return RINRUNTIME_SESSION_RECOVERY_INVALID_ARGUMENT;
    return register_fn(context, metadata) == 0
               ? RINRUNTIME_SESSION_RECOVERY_OK
               : RINRUNTIME_SESSION_RECOVERY_CRASHD_UNAVAILABLE;
}

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeSessionRecoveryWireV1) == 144u,
               "RinRuntimeSessionRecoveryWireV1 ABI drift");
_Static_assert(sizeof(RinRuntimeSessionRecoveryIdentityV1) == 96u,
               "RinRuntimeSessionRecoveryIdentityV1 ABI drift");
_Static_assert(sizeof(RinRuntimeSessionRecoveryMetadataV1) == 184u,
               "RinRuntimeSessionRecoveryMetadataV1 ABI drift");
#endif


