/* SPDX-License-Identifier: MIT */
#include <assert.h>
#include <string.h>

#include <rinruntime/crash_service.h>

int main(void)
{
    RinRuntimeSessionRecoveryMetadataV1 metadata;
    RinCrashRecoveryRegistrationV1 registration;
    memset(&metadata, 0, sizeof(metadata));
    memset(&registration, 0xa5, sizeof(registration));

    assert(rinruntime_crash_service_registration_from_metadata(
               &metadata, &registration) ==
           RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT);
    for (size_t i = 0u; i < sizeof(registration); ++i)
        assert(((const unsigned char*)&registration)[i] == 0u);

    metadata.struct_size = sizeof(metadata);
    metadata.version = RINRUNTIME_SESSION_RECOVERY_VERSION;
    metadata.reason = RINRUNTIME_SESSION_RECOVERY_AFTER_CRASH;
    metadata.identity.struct_size = sizeof(metadata.identity);
    metadata.identity.version = RINRUNTIME_SESSION_RECOVERY_VERSION;
    metadata.identity.package_generation = 7u;
    metadata.identity.application_id[0] = 1u;
    metadata.identity.package_digest[0] = 2u;
    metadata.document_id[0] = 3u;
    metadata.document_generation = 4u;
    metadata.snapshot_generation = 5u;
    metadata.saved_at_ns = 6u;
    assert(rinruntime_crash_service_registration_from_metadata(
               &metadata, &registration) == RINRUNTIME_CRASH_SERVICE_OK);
    assert(registration.struct_size == sizeof(registration));
    assert(registration.reason == RIN_CRASH_RECOVERY_REASON_CRASH);
    assert(registration.package_generation == 7u);
    assert(registration.snapshot_generation == 5u);
    assert(registration.application_id[0] == 1u);
    assert(registration.package_digest[0] == 2u);
    assert(registration.document_id[0] == 3u);
    return 0;
}
