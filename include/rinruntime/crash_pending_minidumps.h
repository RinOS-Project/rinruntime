/* SPDX-License-Identifier: MIT */
/* Consent-gated retrieval of crashd's durable pre-drain minidumps. */

#ifndef RINRUNTIME_CRASH_PENDING_MINIDUMPS_H
#define RINRUNTIME_CRASH_PENDING_MINIDUMPS_H

#include <stdint.h>

#include <rinruntime/crash_service.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Query only whether the authenticated account has any saved dump. This
 * content-free availability signal is for Desktop's notice; it does not
 * disclose dump tuples or bytes and does not replace consented listing. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_get_pending_dump_notice(
    uint32_t expected_service_slot, uint32_t* available_out);

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

/* Deletes one attributed retained dump after a separate physical-confirmation
 * gesture. Corrupt or unattributed files cannot be deleted through this
 * account-scoped operation. */
RinRuntimeCrashServiceResult
rinruntime_crash_service_delete_pending_minidump_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpInfoV1* info);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_PENDING_MINIDUMPS_H */
