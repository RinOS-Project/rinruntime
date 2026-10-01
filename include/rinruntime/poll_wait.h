/* SPDX-License-Identifier: MIT */
/* Public C facade for the POSIX EventLoop poll adapter. */

#ifndef RINRUNTIME_POLL_WAIT_H
#define RINRUNTIME_POLL_WAIT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_POLL_WAIT_READABLE UINT32_C(1)
#define RINRUNTIME_POLL_WAIT_WRITABLE UINT32_C(2)

typedef enum RinRuntimePollWaitResult {
    RINRUNTIME_POLL_WAIT_FAILURE = -1,
    RINRUNTIME_POLL_WAIT_TIMEOUT = 0,
    RINRUNTIME_POLL_WAIT_READY = 1,
} RinRuntimePollWaitResult;

/* Wait for one native userspace descriptor through the public
 * PollEventLoopBackend.  Error/hangup and clock/backend failures are
 * failure-closed.  The descriptor must be a positive native handle; zero is
 * reserved by the public EventLoop watch contract. */
RinRuntimePollWaitResult rinruntime_poll_wait(
    int fd, uint32_t events, uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_POLL_WAIT_H */
