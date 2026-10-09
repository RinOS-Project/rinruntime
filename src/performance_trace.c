/* SPDX-License-Identifier: MIT */
#include "../include/rinruntime/performance_trace.h"

#include "../../libc/sys/syscall.h"
#include <errno.h>
#include <limits.h>
#include <rin/syscall_abi.h>

int rinruntime_performance_trace_submit_latency(
    const RinLatencyTraceV1* trace)
{
    const uint64_t timestamps[8] = {
        trace ? trace->t0_device_ns : 0u,
        trace ? trace->t1_compositor_poll_ns : 0u,
        trace ? trace->t2_dispatch_ns : 0u,
        trace ? trace->t3_route_ns : 0u,
        trace ? trace->t4_client_dequeue_ns : 0u,
        trace ? trace->t5_client_callback_ns : 0u,
        trace ? trace->t6_damage_commit_ns : 0u,
        trace ? trace->t7_present_ns : 0u,
    };

    if (!trace || trace->struct_size != sizeof(*trace) ||
        trace->version != RIN_LATENCY_TRACE_VERSION ||
        trace->sequence == 0u || trace->t7_present_ns == 0u) {
        errno = EINVAL;
        return -1;
    }

    for (uint32_t stage = 0u; stage < 8u; ++stage) {
        intptr_t result;
        uint64_t timestamp = timestamps[stage];
        if (timestamp == 0u) continue;
        result = _syscall5((uintptr_t)RIN_SYS_PERFORMANCE_TRACE_MARK_V1,
                           (uintptr_t)stage,
                           (uintptr_t)(uint32_t)timestamp,
                           (uintptr_t)(uint32_t)(timestamp >> 32u),
                           (uintptr_t)(uint32_t)trace->sequence,
                           (uintptr_t)(uint32_t)(trace->sequence >> 32u));
        if (result < 0) {
            errno = result >= -4095 ? (int)(-result) : EIO;
            return -1;
        }
        if (result > INT_MAX) {
            errno = ERANGE;
            return -1;
        }
        if (result != 0) {
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

int rinruntime_performance_trace_read_cpu(
    uint32_t cpu, uint64_t after_sequence,
    RinPerformanceTraceRecord* records, uint32_t capacity,
    RinPerformanceTraceSnapshotInfo* info)
{
    intptr_t result;

    if (cpu >= RIN_PERFORMANCE_TRACE_MAX_CPUS ||
        capacity > RIN_PERFORMANCE_TRACE_MAX_READ_RECORDS ||
        (capacity != 0u && !records) || !info) {
        errno = EINVAL;
        return -1;
    }

    result = _syscall6((uintptr_t)RIN_SYS_PERFORMANCE_TRACE_READ_V1,
                       (uintptr_t)cpu,
                       (uintptr_t)(uint32_t)after_sequence,
                       (uintptr_t)(uint32_t)(after_sequence >> 32u),
                       (uintptr_t)records,
                       (uintptr_t)capacity,
                       (uintptr_t)info);
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return -1;
    }
    if ((uintptr_t)result > capacity || result > INT_MAX) {
        errno = EIO;
        return -1;
    }
    return (int)result;
}

int rinruntime_performance_trace_read_scheduler_cpu(
    uint32_t cpu, RinPerformanceTraceSchedulerMetricsV1* metrics)
{
    intptr_t result;

    if (cpu >= RIN_PERFORMANCE_TRACE_MAX_CPUS || !metrics) {
        errno = EINVAL;
        return -1;
    }

    result = _syscall2(
        (uintptr_t)RIN_SYS_PERFORMANCE_TRACE_SCHEDULER_READ_V1,
        (uintptr_t)cpu,
        (uintptr_t)metrics);
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return -1;
    }
    if (result != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}
