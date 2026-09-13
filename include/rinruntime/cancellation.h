/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_CANCELLATION_H
#define RINRUNTIME_CANCELLATION_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*RinRuntimeCancellationFunction)(void* context);

/* Cancellation is a monotonic, caller-owned bit.  The operation owner may
 * poll it from a worker while a UI or IPC caller requests cancellation. */
static inline void rinruntime_cancellation_reset(uint32_t* state)
{
    if (state != NULL)
        __atomic_store_n(state, 0u, __ATOMIC_RELEASE);
}

static inline int rinruntime_cancellation_requested(const uint32_t* state)
{
    return state != NULL &&
           __atomic_load_n(state, __ATOMIC_ACQUIRE) != 0u;
}

static inline int rinruntime_cancellation_request(uint32_t* state)
{
    if (state == NULL) return 0;
    __atomic_store_n(state, 1u, __ATOMIC_RELEASE);
    return 1;
}

/* Adapter used by bounded C++ codecs.  Keeping the callback in this common
 * header lets a caller-owned cancellation bit cross a codec boundary without
 * exposing the operation's private state to the library. */
static inline int rinruntime_cancellation_poll(void* context)
{
    return rinruntime_cancellation_requested((const uint32_t*)context);
}

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CANCELLATION_H */
