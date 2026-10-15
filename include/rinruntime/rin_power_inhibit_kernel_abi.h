/* SPDX-License-Identifier: MIT */
/* Private powerd-to-kernel suspend-inhibit ABI. */
#ifndef RIN_SHARED_POWER_INHIBIT_KERNEL_ABI_H
#define RIN_SHARED_POWER_INHIBIT_KERNEL_ABI_H

#include <stdint.h>

#include <rin/syscall_abi.h>

/* Keep this outside the generated public syscall table. The only caller is
 * the signed private powerd image; ordinary applications use the RPI1 socket
 * and never receive this number. */
#define RIN_SYS_POWER_INHIBIT_PRIVATE (RIN_SYS_PRIVATE_BASE + UINT32_C(0xF0))
#define RIN_POWER_INHIBIT_KERNEL_VERSION UINT32_C(1)
/* sched_timer_now_ticks() is the fixed 100 Hz PIT/APIC scheduler clock. */
#define RIN_POWER_INHIBIT_KERNEL_LEASE_TICKS UINT64_C(300)

typedef enum RinPowerInhibitKernelOperationV1 {
    RIN_POWER_INHIBIT_KERNEL_ACQUIRE = 1,
    RIN_POWER_INHIBIT_KERNEL_RELEASE = 2
} RinPowerInhibitKernelOperationV1;

typedef struct RinPowerInhibitKernelRequestV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t reserved0;
    uint32_t reserved1;
    uint64_t session_id;
    uint64_t session_generation;
} RinPowerInhibitKernelRequestV1;

#if defined(__cplusplus)
static_assert(sizeof(RinPowerInhibitKernelRequestV1) == 32u,
              "private power inhibit kernel ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinPowerInhibitKernelRequestV1) == 32u,
               "private power inhibit kernel ABI drift");
#endif

#endif /* RIN_SHARED_POWER_INHIBIT_KERNEL_ABI_H */
