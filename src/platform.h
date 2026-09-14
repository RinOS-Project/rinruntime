/* SPDX-License-Identifier: MIT */
/* Internal platform carriers for the public RinRuntime implementation. */
#ifndef RINRUNTIME_PLATFORM_H
#define RINRUNTIME_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_shm_get(const char* name, uint32_t size, uint32_t flags);
void* rin_shm_at(int handle, void* address_hint, uint32_t prot);
int rin_shm_dt(int handle, void* address);
uint64_t rin_monotonic_ms(void);
uint64_t rinruntime_process_id(void);
void rin_sleep(unsigned int milliseconds);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_PLATFORM_H */
