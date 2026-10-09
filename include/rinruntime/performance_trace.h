/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_PERFORMANCE_TRACE_H
#define RINRUNTIME_PERFORMANCE_TRACE_H

#include <rin/latency_abi.h>
#include <stdint.h>

#define RIN_PERFORMANCE_TRACE_MAX_CPUS 256u
#define RIN_PERFORMANCE_TRACE_RING_CAPACITY 512u
#define RIN_PERFORMANCE_TRACE_MAX_READ_RECORDS 32u
#define RIN_PERFORMANCE_TRACE_SNAPSHOT_VERSION 1u
#define RIN_PERFORMANCE_TRACE_SCHEDULER_METRICS_VERSION 1u
#define RIN_PERFORMANCE_TRACE_SCHEDULER_HISTOGRAM_BINS 16u

typedef enum RinPerformanceTraceEvent {
    RIN_TRACE_SCHED_PICK_START = 1,
    RIN_TRACE_SCHED_PICK_END,
    RIN_TRACE_CONTEXT_SWITCH,
    RIN_TRACE_ENQUEUE,
    RIN_TRACE_DEQUEUE,
    RIN_TRACE_MIGRATE,
    RIN_TRACE_STEAL,
    RIN_TRACE_RUNQUEUE_LOCK_WAIT,
    RIN_TRACE_RUNQUEUE_LOCK_HOLD,
    RIN_TRACE_PAGE_FAULT_START,
    RIN_TRACE_PAGE_FAULT_END,
    RIN_TRACE_COW_FAULT,
    RIN_TRACE_TLB_SHOOTDOWN_REQUEST,
    RIN_TRACE_TLB_SHOOTDOWN_ACK,
    RIN_TRACE_SYSCALL_ENTRY,
    RIN_TRACE_SYSCALL_EXIT,
    RIN_TRACE_PAGE_CACHE_HIT,
    RIN_TRACE_PAGE_CACHE_MISS,
    RIN_TRACE_BLOCK_IO_ISSUE,
    RIN_TRACE_BLOCK_IO_COMPLETE,
    RIN_TRACE_NIC_RX,
    RIN_TRACE_NIC_TX,
    RIN_TRACE_NIC_IRQ,
    RIN_TRACE_COMPOSITOR_T0,
    RIN_TRACE_COMPOSITOR_T1,
    RIN_TRACE_COMPOSITOR_T2,
    RIN_TRACE_COMPOSITOR_T3,
    RIN_TRACE_COMPOSITOR_T4,
    RIN_TRACE_COMPOSITOR_T5,
    RIN_TRACE_COMPOSITOR_T6,
    RIN_TRACE_COMPOSITOR_T7,
    RIN_TRACE_SCHED_PICK_DIAGNOSTIC, /* arg0=queue depth, arg1=fast checks */
    RIN_TRACE_SCHED_IRQ_DISABLED, /* arg0=disabled cycles, arg1=lock wait */
    /* arg0=class, arg1=fault address; see RinPerformanceTracePageFaultClass. */
    RIN_TRACE_PAGE_FAULT_CLASS,
    /* Stage arg0=cycles (bit 63 marks failure), arg1=fault address. */
    RIN_TRACE_PAGE_FAULT_VMA_LOOKUP,
    RIN_TRACE_PAGE_FAULT_PAGE_ALLOC,
    RIN_TRACE_PAGE_FAULT_ZERO_PAGE_ACQUIRE,
    RIN_TRACE_PAGE_FAULT_PAGE_ZERO,
    RIN_TRACE_PAGE_FAULT_PTE_CONSTRUCT,
    RIN_TRACE_PAGE_FAULT_BACKING_READ,
    RIN_TRACE_PAGE_FAULT_COW_COMPLETE,
    RIN_TRACE_EVENT_COUNT
} RinPerformanceTraceEvent;

typedef enum RinPerformanceTracePageFaultClass {
    RIN_TRACE_PAGE_FAULT_CLASS_PRIVATE_ANONYMOUS = 1,
    RIN_TRACE_PAGE_FAULT_CLASS_SHARED_ANONYMOUS,
    RIN_TRACE_PAGE_FAULT_CLASS_FILE_BACKED,
    RIN_TRACE_PAGE_FAULT_CLASS_COPY_ON_WRITE,
    RIN_TRACE_PAGE_FAULT_CLASS_SWAPPED,
    RIN_TRACE_PAGE_FAULT_CLASS_OTHER
} RinPerformanceTracePageFaultClass;

#define RIN_TRACE_PAGE_FAULT_STAGE_FAILED_FLAG (UINT64_C(1) << 63u)

/* Timestamps in records are raw RDTSC values. Event arguments retain the
 * source units documented by the event producer. */
typedef struct RinPerformanceTraceRecord {
    uint64_t sequence;
    uint64_t timestamp;
    uint64_t arg0;
    uint64_t arg1;
    uint32_t pid;
    uint32_t tid;
    uint16_t cpu;
    uint16_t event;
    uint32_t reserved;
} RinPerformanceTraceRecord;

typedef struct RinPerformanceTraceSnapshotInfo {
    uint32_t struct_size;
    uint32_t version;
    uint32_t cpu;
    uint32_t record_count;
    uint64_t first_sequence;
    uint64_t next_sequence;
    uint64_t overwritten_records;
    uint64_t emit_cycles;
    uint64_t emit_count;
} RinPerformanceTraceSnapshotInfo;

/* Cumulative debug scheduler counters for one CPU. Queue-depth histogram
 * bin 0 represents depth 0. Bins 1 through 14 represent [2^(bin-1),
 * 2^bin), and bin 15 represents depth >= 16384. */
typedef struct RinPerformanceTraceSchedulerMetricsV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t cpu;
    uint32_t reserved;
    uint64_t pick_count;
    uint64_t pick_attempts;
    uint64_t pick_rejected;
    uint64_t republish_count;
    uint64_t runqueue_lock_wait_cycles;
    uint64_t runqueue_lock_hold_cycles;
    uint64_t transition_lock_wait_cycles;
    uint64_t migration_count;
    uint64_t steal_count;
    uint64_t cross_cpu_wakeup_count;
    uint64_t queue_depth_histogram[
        RIN_PERFORMANCE_TRACE_SCHEDULER_HISTOGRAM_BINS];
} RinPerformanceTraceSchedulerMetricsV1;

#ifdef __cplusplus
extern "C" {
#endif

/* Submit observed compositor input stages to the debug kernel trace ring.
 * Stage timestamps remain monotonic nanoseconds in arg0; the kernel ring's
 * own timestamp is the RDTSC time at submission. */
int rinruntime_performance_trace_submit_latency(
    const RinLatencyTraceV1* trace);

/* Copy up to MAX_READ_RECORDS events from one CPU ring. Pass the previous
 * info.next_sequence - 1 as after_sequence for the next read. A capacity of
 * zero fetches counters/cursor only. The API is available in trace builds. */
int rinruntime_performance_trace_read_cpu(
    uint32_t cpu, uint64_t after_sequence,
    RinPerformanceTraceRecord* records, uint32_t capacity,
    RinPerformanceTraceSnapshotInfo* info);

/* Read cumulative native x86_64 scheduler counters and the queue-depth
 * histogram for one CPU. Available only in x86_64 debug builds with
 * performance tracing enabled. */
int rinruntime_performance_trace_read_scheduler_cpu(
    uint32_t cpu, RinPerformanceTraceSchedulerMetricsV1* metrics);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_PERFORMANCE_TRACE_H */
