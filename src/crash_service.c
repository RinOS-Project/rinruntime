/* SPDX-License-Identifier: MIT */

#include <rinruntime/crash_service.h>

#include <string.h>

static int crash_service_nonzero(const uint8_t* bytes, size_t size)
{
    uint8_t aggregate = 0u;
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index) aggregate |= bytes[index];
    return aggregate != 0u;
}

static int crash_service_metadata_valid(
    const RinRuntimeSessionRecoveryMetadataV1* metadata)
{
    return metadata != NULL && metadata->struct_size == sizeof(*metadata) &&
           metadata->version == RINRUNTIME_SESSION_RECOVERY_VERSION &&
           (metadata->reason == RINRUNTIME_SESSION_RECOVERY_AFTER_CRASH ||
            metadata->reason ==
                RINRUNTIME_SESSION_RECOVERY_AFTER_LOGOUT_OR_REBOOT) &&
           rinruntime_session_recovery_identity_valid(&metadata->identity) &&
           crash_service_nonzero(metadata->document_id,
                                 sizeof(metadata->document_id)) &&
           metadata->snapshot_generation != 0u && metadata->saved_at_ns != 0u &&
           metadata->payload_size <= RINRUNTIME_SESSION_RECOVERY_PAYLOAD_MAX &&
           metadata->reserved0 == 0u && metadata->reserved[0] == 0u &&
           metadata->reserved[1] == 0u;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_registration_from_metadata(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    RinCrashRecoveryRegistrationV1* registration_out)
{
    if (registration_out == NULL) return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(registration_out, 0, sizeof(*registration_out));
    if (!crash_service_metadata_valid(metadata))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    registration_out->struct_size = sizeof(*registration_out);
    registration_out->version = RIN_CRASH_RECOVERY_REGISTRATION_VERSION;
    registration_out->reason = metadata->reason;
    registration_out->package_generation =
        metadata->identity.package_generation;
    registration_out->document_generation = metadata->document_generation;
    registration_out->snapshot_generation = metadata->snapshot_generation;
    registration_out->saved_at_ns = metadata->saved_at_ns;
    memcpy(registration_out->application_id, metadata->identity.application_id,
           sizeof(registration_out->application_id));
    memcpy(registration_out->package_digest, metadata->identity.package_digest,
           sizeof(registration_out->package_digest));
    memcpy(registration_out->document_id, metadata->document_id,
           sizeof(registration_out->document_id));
    return RINRUNTIME_CRASH_SERVICE_OK;
}


