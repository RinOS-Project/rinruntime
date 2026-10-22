/* SPDX-License-Identifier: MIT */
/* Admin-only, consent-gated cleanup for unattributed retained minidumps. */

#ifndef RINRUNTIME_CRASH_PENDING_DUMP_CLEANUP_H
#define RINRUNTIME_CRASH_PENDING_DUMP_CLEANUP_H

#include <rin/crash_pending_dump_cleanup.h>
#include <rinruntime/crash_service.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reads the exact bounded cleanup snapshot after fresh local physical
 * confirmation. Candidates contain either safe canonical dump files with
 * missing/invalid PDM1 metadata or only the matching PDM1 sidecar for an
 * unsafe dump. Unsafe dump objects are never returned for deletion. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_get_pending_dump_cleanup_with_consent(
    uint32_t expected_service_slot,
    RinCrashServicePendingDumpCleanupStatusV2* status_out);

/* Removes only the exact snapshot presented to the administrator. A changed
 * set returns STALE_HISTORY_STATUS so Settings must request and display a new
 * snapshot before retrying. Each batch consumes fresh physical confirmation. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_purge_pending_dumps_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpCleanupStatusV2* confirmed_status,
    uint32_t* removed_count_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_PENDING_DUMP_CLEANUP_H */
