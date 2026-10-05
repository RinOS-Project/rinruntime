/* SPDX-License-Identifier: MIT */

#include <rinruntime/poll_wait.h>

#include "platform.h"

#if defined(RIN_FREESTANDING) && RIN_FREESTANDING && \
    defined(RIN_USERSPACE) && RIN_USERSPACE
#include "../../libc/errno.h"
#include "../../libc/limits.h"
#include "../../libc/poll.h"
#else
#include <errno.h>
#include <limits.h>
#include <poll.h>
#endif

#define RINRUNTIME_POLL_WAIT_INTERRUPTION_LIMIT 4u

static int make_deadline(uint64_t now_ms, uint32_t timeout_ms,
                         uint64_t* deadline_out)
{
    /* UINT64_MAX is the public EventLoop adapter's "no deadline" sentinel.
     * A finite wait that lands exactly on it must fail closed rather than
     * allowing the C adapter to manufacture an ambiguous deadline. */
    if (deadline_out == NULL || now_ms == UINT64_MAX ||
        (uint64_t)timeout_ms >= UINT64_MAX - now_ms)
        return 0;
    *deadline_out = now_ms + (uint64_t)timeout_ms;
    return 1;
}

RinRuntimePollWaitResult rinruntime_poll_wait(
    int fd, uint32_t events, uint32_t timeout_ms)
{
    struct pollfd descriptor;
    uint64_t deadline_ms;
    uint64_t last_now_ms = 0u;
    uint32_t interrupted = 0u;
    int have_last_now = 0;

    if (fd <= 0 || fd > INT_MAX || events == 0u ||
        (events & ~(RINRUNTIME_POLL_WAIT_READABLE |
                    RINRUNTIME_POLL_WAIT_WRITABLE)) != 0u)
        return RINRUNTIME_POLL_WAIT_FAILURE;

    if (!make_deadline(rin_monotonic_ms(), timeout_ms, &deadline_ms))
        return RINRUNTIME_POLL_WAIT_FAILURE;

    descriptor.fd = fd;
    descriptor.events = 0;
    if ((events & RINRUNTIME_POLL_WAIT_READABLE) != 0u)
        descriptor.events |= POLLIN;
    if ((events & RINRUNTIME_POLL_WAIT_WRITABLE) != 0u)
        descriptor.events |= POLLOUT;
    descriptor.revents = 0;

    for (;;) {
        const uint64_t now_ms = rin_monotonic_ms();
        /* UINT64_MAX is the public EventLoop adapter's no-deadline
         * sentinel, not a usable monotonic sample.  The provider may fail
         * between deadline construction and the actual poll; do not turn
         * that failure into a normal timeout. */
        if (now_ms == UINT64_MAX)
            return RINRUNTIME_POLL_WAIT_FAILURE;
        const uint64_t remaining_ms =
            now_ms >= deadline_ms ? 0u : deadline_ms - now_ms;
        int timeout;
        int ready;

        if (have_last_now && now_ms < last_now_ms)
            return RINRUNTIME_POLL_WAIT_FAILURE;
        last_now_ms = now_ms;
        have_last_now = 1;
        if (now_ms >= deadline_ms)
            return RINRUNTIME_POLL_WAIT_TIMEOUT;
        timeout = remaining_ms > (uint64_t)INT_MAX
                      ? INT_MAX
                      : (int)remaining_ms;
        descriptor.revents = 0;
        ready = poll(&descriptor, 1u, timeout);
        if (ready == 0) continue;
        if (ready < 0) {
            if (errno != EINTR ||
                ++interrupted > RINRUNTIME_POLL_WAIT_INTERRUPTION_LIMIT)
                return RINRUNTIME_POLL_WAIT_FAILURE;
            continue;
        }
        if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
            return RINRUNTIME_POLL_WAIT_FAILURE;
        if (((events & RINRUNTIME_POLL_WAIT_READABLE) != 0u &&
             (descriptor.revents & POLLIN) != 0) ||
            ((events & RINRUNTIME_POLL_WAIT_WRITABLE) != 0u &&
             (descriptor.revents & POLLOUT) != 0))
            return RINRUNTIME_POLL_WAIT_READY;
        return RINRUNTIME_POLL_WAIT_FAILURE;
    }
}
