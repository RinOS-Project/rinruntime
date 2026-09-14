/* SPDX-License-Identifier: MIT */
/* Public RinOS syscall carriers used by RinRuntime service clients. */

#include "platform.h"

#include "../../libc/sys/syscall.h"
#include <limits.h>
#include <rin/syscall_abi.h>

static int platform_int_result(intptr_t result)
{
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return -1;
    }
    if (result > (intptr_t)INT_MAX) {
        errno = ERANGE;
        return -1;
    }
    return (int)result;
}

static void* platform_pointer_result(intptr_t result)
{
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return (void*)0;
    }
    return (void*)(uintptr_t)result;
}

int rin_shm_get(const char* name, uint32_t size, uint32_t flags)
{
    if (name == NULL || name[0] == '\0' || size == 0u) {
        errno = EINVAL;
        return -1;
    }
    return platform_int_result(_syscall3(
        (uintptr_t)RIN_SYS_SHMGET, (uintptr_t)name,
        (uintptr_t)size, (uintptr_t)flags));
}

void* rin_shm_at(int handle, void* address_hint, uint32_t prot)
{
    if (handle < 0) {
        errno = EBADF;
        return (void*)0;
    }
    return platform_pointer_result(_syscall3(
        (uintptr_t)RIN_SYS_SHMAT, (uintptr_t)(intptr_t)handle,
        (uintptr_t)address_hint, (uintptr_t)prot));
}

int rin_shm_dt(int handle, void* address)
{
    intptr_t result;
    if (handle < 0) {
        errno = EBADF;
        return -1;
    }
    result = _syscall2((uintptr_t)RIN_SYS_SHMDT,
                       (uintptr_t)(intptr_t)handle,
                       (uintptr_t)address);
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return -1;
    }
    if (result != 0) {
        errno = result > INT_MAX ? EOVERFLOW : EIO;
        return -1;
    }
    return 0;
}

uint64_t rin_monotonic_ms(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    intptr_t result = _syscall1((uintptr_t)RIN_SYS_TIME_NS, 0u);
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return 0u;
    }
    return (uint64_t)(uintptr_t)result / UINT64_C(1000000);
#else
    uint64_t nanoseconds = 0u;
    intptr_t result = _syscall1((uintptr_t)RIN_SYS_TIME_NS,
                                (uintptr_t)&nanoseconds);
    if (result < 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return 0u;
    }
    if (result != 0) {
        errno = result > INT_MAX ? EOVERFLOW : EIO;
        return 0u;
    }
    return nanoseconds / UINT64_C(1000000);
#endif
}

uint64_t rinruntime_process_id(void)
{
    intptr_t result = _syscall0((uintptr_t)RIN_SYS_GETPID);
    if (result <= 0) {
        errno = result >= -4095 ? (int)(-result) : EIO;
        return 0u;
    }
    return (uint64_t)(uintptr_t)result;
}

void rin_sleep(unsigned int milliseconds)
{
    intptr_t result = _syscall1((uintptr_t)RIN_SYS_SLEEP,
                                (uintptr_t)milliseconds);
    if (result < 0)
        errno = result >= -4095 ? (int)(-result) : EIO;
}
