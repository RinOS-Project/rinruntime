/* SPDX-License-Identifier: MIT */
/* Public service-manager syscall adapter.  Service discovery and lifecycle
 * ownership remain in the private kernel/service-manager implementation. */

#include <rin/service.h>

#include "../../libc/sys/syscall.h"

#include <rin/syscall_abi.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

#define RINRUNTIME_SERVICE_ID_MAX 64u
#define RINRUNTIME_SERVICE_MAX_VISIBLE 1024

/* This is the public copy-in/copy-out shape used by the service syscalls.
 * It intentionally contains no private service-manager pointers or process
 * objects.  Keep it layout-compatible with the kernel's fixed record. */
typedef struct RinRuntimeServiceInfoV1 {
    uint32_t slot_id;
    char id[RINRUNTIME_SERVICE_ID_MAX];
    char name[64];
    char exec_path[256];
    char control_app[256];
    uint32_t pid;
    uint32_t owner_uid;
    uint32_t restart_count;
    int32_t last_exit_code;
    uint32_t last_start_tick;
    uint32_t last_exit_tick;
    uint32_t last_health_tick;
    uint32_t health_interval_ms;
    uint32_t health_timeout_ms;
    uint16_t scope;
    uint16_t state;
    uint16_t last_exit_reason;
    uint16_t flags;
} RinRuntimeServiceInfoV1;

_Static_assert(sizeof(RinRuntimeServiceInfoV1) == 688u,
               "public service syscall record layout changed");

static size_t service_id_size(const char* id)
{
    size_t index;
    if (id == NULL) return 0u;
    for (index = 0u; index < RINRUNTIME_SERVICE_ID_MAX; ++index) {
        if (id[index] == '\0') return index == 0u ? 0u : index;
    }
    return 0u;
}

static int service_id_matches(const char id[RINRUNTIME_SERVICE_ID_MAX],
                              const char* expected)
{
    size_t index;
    if (id == NULL || service_id_size(expected) == 0u) return 0;
    for (index = 0u; index < RINRUNTIME_SERVICE_ID_MAX; ++index) {
        if (id[index] != expected[index]) return 0;
        if (expected[index] == '\0') return 1;
    }
    return 0;
}

static RinResult service_status_result(intptr_t raw_result)
{
    if (raw_result == 0) return RIN_SUCCESS;
    /* RinOS syscalls use the established negative-errno status convention.
     * Preserve known negative status values; an out-of-range or positive
     * word is never allowed to become a successful public result. */
    if (raw_result < 0 && raw_result >= -4095) return (RinResult)raw_result;
    return RIN_ERROR_IO;
}

static int service_count_result(intptr_t raw_result)
{
    if (raw_result < 0 || raw_result > INT_MAX) return -1;
    return (int)raw_result;
}

static int service_info_get(int scope, int index,
                            RinRuntimeServiceInfoV1* info)
{
    intptr_t raw_result;
    if (info == NULL || index < 0) return -1;
    raw_result = _syscall3((uintptr_t)RIN_SYS_SERVICE_GET_INFO,
                           (uintptr_t)(unsigned int)scope,
                           (uintptr_t)(unsigned int)index,
                           (uintptr_t)info);
    return raw_result == 0 ? 0 : -1;
}

RinResult rin_service_start(int scope, const char* id)
{
    if ((scope != RIN_SERVICE_SCOPE_SYSTEM &&
         scope != RIN_SERVICE_SCOPE_USER) || service_id_size(id) == 0u)
        return RIN_ERROR_INVALID_ARGUMENT;
    return service_status_result(_syscall2(
        (uintptr_t)RIN_SYS_SERVICE_START, (uintptr_t)(unsigned int)scope,
        (uintptr_t)id));
}

int rin_service_find_system_slot(const char* service_id, uint32_t* slot_id)
{
    RinRuntimeServiceInfoV1 info;
    intptr_t raw_count;
    int count;
    uint32_t found_slot = 0u;
    int index;

    if (slot_id == NULL) return -1;
    *slot_id = 0u;
    if (service_id_size(service_id) == 0u) return -1;

    raw_count = _syscall1((uintptr_t)RIN_SYS_SERVICE_COUNT,
                          (uintptr_t)RIN_SERVICE_SCOPE_SYSTEM);
    count = service_count_result(raw_count);
    if (count <= 0 || count > RINRUNTIME_SERVICE_MAX_VISIBLE) return -1;

    for (index = 0; index < count; ++index) {
        info = (RinRuntimeServiceInfoV1){0};
        if (service_info_get(RIN_SERVICE_SCOPE_SYSTEM, index, &info) != 0)
            return -1;
        if (!service_id_matches(info.id, service_id)) continue;

        /* A system endpoint is trusted only when the kernel-published record
         * is unique, live, root-owned, and explicitly system-scoped. */
        if (found_slot != 0u || info.slot_id == 0u || info.pid == 0u ||
            info.owner_uid != 0u || info.scope != RIN_SERVICE_SCOPE_SYSTEM)
            return -1;
        found_slot = info.slot_id;
    }

    if (found_slot == 0u) return -1;
    *slot_id = found_slot;
    return 0;
}
