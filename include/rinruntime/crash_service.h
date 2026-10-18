/* SPDX-License-Identifier: MIT */
/* Authenticated local crashd registration client for application runtimes. */

#ifndef RINRUNTIME_CRASH_SERVICE_H
#define RINRUNTIME_CRASH_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#include <rin/crash_service.h>
#include <rin/crash_summary.h>
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
    RINRUNTIME_CRASH_SERVICE_REJECTED = -4,
    RINRUNTIME_CRASH_SERVICE_STALE_HISTORY_STATUS = -5,
    RINRUNTIME_CRASH_SERVICE_CRASH_DETECTED = 1
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

/* Ask crashd whether this exact authenticated local recovery record was
 * matched to a kernel-captured crash from its original process instance.
 * Unavailable or malformed service state never suppresses normal recovery. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_query_recovery_crash(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    uint32_t expected_service_slot);

/* Explicitly request a kernel-managed local physical-consent gesture, then
 * read the current crash summary over the same authenticated crashd
 * connection. This is not a readiness/poll API and opens the secure consent
 * UI on each call. It can wait up to 25 seconds; invoke it from a worker,
 * never from the Desktop input/render loop. summary_out is cleared on every
 * failure. */
RinRuntimeCrashServiceResult rinruntime_crash_service_read_summary_with_consent(
    uint32_t expected_service_slot, RinCrashSummaryV1* summary_out);

/* Read only the count and sequence boundary of inaccessible exact-session
 * history records. No crash contents are returned. The caller must display
 * this count before offering its explicit cleanup confirmation. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_get_legacy_history_status(
    uint32_t expected_service_slot,
    RinCrashServiceLegacyHistoryStatusV1* status_out);

/* Purge the exact count/high-water snapshot shown to the administrator. The
 * call requests fresh kernel-managed physical consent on a worker thread.
 * The service returns STALE_HISTORY_STATUS if the inaccessible set changed;
 * the caller must query and display a fresh count before retrying. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_purge_legacy_history_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServiceLegacyHistoryStatusV1* confirmed_status);

/* Send one already-redacted, bounded diagnostic to crashd. The service slot
 * must come from the authenticated service manager; a path alone is not an
 * acceptable identity. */
RinRuntimeCrashServiceResult rinruntime_crash_service_append_diagnostic(
    const char* message, size_t message_size, uint32_t expected_service_slot);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_SERVICE_H */

