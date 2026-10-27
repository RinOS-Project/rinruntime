/* SPDX-License-Identifier: MIT */
#ifndef RINFS_KERNEL_PORT_V1_H
#define RINFS_KERNEL_PORT_V1_H

#include <stdint.h>

#include <rinruntime/performance_trace.h>

/* Static-link port contract between the RinFS implementation and the OS-Core
 * adapter. Kernel-only definitions stay in the kernel filesystem owner. */
uint32_t rinfs_kernel_port_cpu_id_v1(void);
uint64_t rinfs_kernel_port_trace_cycles_v1(void);
void* rinfs_kernel_port_physical_to_virtual_v1(uint64_t physical_address);
void rinfs_kernel_port_trace_emit_v1(
    uint32_t cpu, uint32_t pid, uint32_t tid, uint32_t event,
    uint64_t arg0, uint64_t arg1);
void rinfs_kernel_port_trace_emit_current_v1(
    uint32_t event, uint64_t arg0, uint64_t arg1);

int rinfs_kernel_port_block_read_v1(
    uint32_t device, uint64_t lba, uint32_t count, void* buffer);
int rinfs_kernel_port_block_write_v1(
    uint32_t device, uint64_t lba, uint32_t count, const void* buffer);
int rinfs_kernel_port_block_flush_v1(uint32_t device);

#endif /* RINFS_KERNEL_PORT_V1_H */
