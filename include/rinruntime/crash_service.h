/* SPDX-License-Identifier: MIT */
/* Authenticated local crashd registration client for application runtimes. */

#ifndef RINRUNTIME_CRASH_SERVICE_H
#define RINRUNTIME_CRASH_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include <rin/crash_service.h>
#include "session_recovery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_CRASH_SERVICE_VERSION UINT16_C(1)
#define RINRUNTIME_CRASH_SERVICE_PATH RIN_CRASH_SERVICE_SOCKET_PATH

typedef enum RinRuntimeCrashServiceResult {
    RINRUNTIME_CRASH_SERVICE_OK = 0,
    RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT = -1,
    RINRUNTIME_CRASH_SERVICE_UNAVAILABLE = -2,
    RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR = -3,
    RINRUNTIME_CRASH_SERVICE_REJECTED = -4
} RinRuntimeCrashServiceResult;

/* Convert the public session metadata into the path-free crashd wire record.
 * The output is cleared on every failure. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_registration_from_metadata(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    RinCrashRecoveryRegistrationV1* registration_out);

/* Register one already-committed recovery record with the authenticated
 * system crashd endpoint.  expected_service_slot must come from the service
 * manager; a path or published bit alone is not accepted as service identity.
 * Failure never changes the caller's durable local recovery record. */
RinRuntimeCrashServiceResult rinruntime_crash_service_register_recovery(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    uint32_t expected_service_slot);

/* Send one already-redacted, bounded diagnostic to crashd. The service slot
 * must come from the authenticated service manager; a path alone is not an
 * acceptable identity. */
RinRuntimeCrashServiceResult rinruntime_crash_service_append_diagnostic(
    const char* message, size_t message_size, uint32_t expected_service_slot);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_SERVICE_H */


