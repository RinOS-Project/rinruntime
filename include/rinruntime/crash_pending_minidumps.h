/* SPDX-License-Identifier: MIT */
/* Consent-gated retrieval of crashd's durable pre-drain minidumps. */

#ifndef RINRUNTIME_CRASH_PENDING_MINIDUMPS_H
#define RINRUNTIME_CRASH_PENDING_MINIDUMPS_H

#include <stdint.h>

#include <rinruntime/crash_service.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reads the current account's bounded pending-dump index after a fresh local
 * physical-confirmation gesture. Call from a worker; the consent flow can
 * wait up to 25 seconds. list_out is cleared on every failure. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_read_pending_minidumps_with_consent(
    uint32_t expected_service_slot,
    RinCrashServicePendingDumpListV1* list_out);

/* Exports one exact index entry after a separate physical-confirmation
 * gesture. The index tuple binds the request to one retained file. Both the
 * output bytes and size are cleared on every failure. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_export_pending_minidump_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpInfoV1* info,
    uint8_t* minidump_out, uint32_t minidump_capacity,
    uint32_t* minidump_size_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_PENDING_MINIDUMPS_H */
