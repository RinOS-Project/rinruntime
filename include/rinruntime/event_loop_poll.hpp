/* SPDX-License-Identifier: MIT */
/*
 * Bounded POSIX poll(2) adapter for EventLoop readiness watches.
 *
 * EventLoop remains a backend-independent model.  This adapter is the host
 * and POSIX-compatible userspace bridge: it translates the model's opaque
 * native handles to descriptors, calls poll(2), and returns only readiness
 * bits requested by the corresponding generation-bound watch.  RinOS
 * syscall-specific adapters can use the same EventLoop::WaitFunction seam
 * without importing this header.
 */

#ifndef RINRUNTIME_EVENT_LOOP_POLL_HPP
#define RINRUNTIME_EVENT_LOOP_POLL_HPP

#include <cstdint>

/* Native RinOS userspace is freestanding and supplies its own POSIX-shaped
 * poll ABI.  Keep this adapter public, but do not mix the hosted CRT errno,
 * limits, and poll declarations with the native libc headers.  Kernel code
 * never includes this header; RIN_FREESTANDING is accepted here only with
 * RIN_USERSPACE. */
#if defined(RIN_FREESTANDING) && RIN_FREESTANDING && \
    defined(RIN_USERSPACE) && RIN_USERSPACE
#include "../../../libc/errno.h"
#include "../../../libc/limits.h"
#include "../../../libc/poll.h"
#else
#include <cerrno>
#include <climits>
#include <poll.h>
#endif

#include "event_loop.hpp"

namespace RinRuntime {

class PollEventLoopBackend final {
public:
    using Size = EventLoop::Size;
    using ClockFunction = std::uint64_t (*)(void*) noexcept;
    static constexpr unsigned kMaxInterruptedPolls = 4u;

private:
    ClockFunction clock_ = nullptr;
    void* clockContext_ = nullptr;
    std::uint64_t lastNow_ = 0u;
    bool haveLastNow_ = false;
    bool waitInFlight_ = false;

    static short pollEvents(std::uint32_t events) noexcept {
        short result = 0;
        if ((events & EventLoop::WAIT_READABLE) != 0u) result |= POLLIN;
        if ((events & EventLoop::WAIT_WRITABLE) != 0u) result |= POLLOUT;
        /* poll reports error/hangup independently of the requested normal
         * events.  Keep events at zero for an error/hangup-only watch: using
         * POLLIN as a wake source would turn ordinary readable data into an
         * immediate false result instead of waiting for the requested event. */
        return result;
    }

    static std::uint32_t loopEvents(short events) noexcept {
        std::uint32_t result = 0u;
        if ((events & POLLIN) != 0) result |= EventLoop::WAIT_READABLE;
        if ((events & POLLOUT) != 0) result |= EventLoop::WAIT_WRITABLE;
        if ((events & POLLERR) != 0) result |= EventLoop::WAIT_ERROR;
        if ((events & POLLHUP) != 0) result |= EventLoop::WAIT_HANGUP;
        return result;
    }

    bool timeoutMilliseconds(std::uint64_t deadline, int* timeout) noexcept {
        if (timeout == nullptr || clock_ == nullptr) return false;
        if (deadline == UINT64_MAX) {
            *timeout = -1;
            return true;
        }

        const std::uint64_t now = clock_(clockContext_);
        /* UINT64_MAX is reserved by EventLoop as the no-deadline sentinel,
         * not a usable monotonic timestamp.  Treat a clock provider that
         * reports it as invalid instead of converting a finite deadline into
         * an immediate poll and publishing readiness from an unknown epoch. */
        if (now == UINT64_MAX) return false;
        if (haveLastNow_ && now < lastNow_) return false;
        lastNow_ = now;
        haveLastNow_ = true;
        if (now >= deadline) {
            *timeout = 0;
            return true;
        }
        const std::uint64_t remaining = deadline - now;
        constexpr std::uint64_t kNanosecondsPerMillisecond = 1000000u;
        const std::uint64_t milliseconds =
            remaining / kNanosecondsPerMillisecond +
            (remaining % kNanosecondsPerMillisecond == 0u ? 0u : 1u);
        *timeout = milliseconds > static_cast<std::uint64_t>(INT_MAX)
                       ? INT_MAX
                       : static_cast<int>(milliseconds);
        return true;
    }

public:
    PollEventLoopBackend(ClockFunction clock, void* clockContext = nullptr)
        : clock_(clock), clockContext_(clockContext) {}

    PollEventLoopBackend(const PollEventLoopBackend&) = delete;
    PollEventLoopBackend& operator=(const PollEventLoopBackend&) = delete;

    /* Start a fresh monotonic-clock session without changing any caller-owned
     * EventLoop watches.  A Poll backend owns no native wait-set handle, but it
     * does retain the last clock sample to detect rollback.  Callers that
     * reconnect to a restarted clock provider may reuse the backend only after
     * retiring that sample; otherwise the first deadline in the new epoch is
     * rejected as a rollback. */
    void resetClock() noexcept {
        lastNow_ = 0u;
        haveLastNow_ = false;
    }

    bool wait(const EventLoop::WaitRequest* requests, Size count,
              std::uint64_t deadline, EventLoop::WaitResult* ready) noexcept {
        if (ready == nullptr) return false;
        if (waitInFlight_) {
            *ready = {};
            return false;
        }
        waitInFlight_ = true;
        struct WaitGuard final {
            bool& inFlight;
            ~WaitGuard() { inFlight = false; }
        } waitGuard{waitInFlight_};
        if (count > EventLoop::kWaitCapacity ||
            detail::eventLoopByteRangesOverlap(
                requests, count * sizeof(EventLoop::WaitRequest), ready,
                sizeof(*ready)))
            return false;
        ready->id = 0u;
        ready->events = 0u;
        if ((requests == nullptr && count != 0u) ||
            (count == 0u && deadline == UINT64_MAX))
            return false;

        struct pollfd descriptors[EventLoop::kWaitCapacity] = {};
        for (Size index = 0u; index < count; ++index) {
            const EventLoop::WaitRequest& request = requests[index];
            if (request.id == 0u || request.nativeHandle == 0u ||
                request.events == 0u ||
                (request.events & ~static_cast<std::uint32_t>(
                                      EventLoop::WAIT_EVENTS_ALL)) != 0u ||
                request.nativeHandle > static_cast<std::uint64_t>(INT_MAX))
                return false;
            for (Size prior = 0u; prior < index; ++prior)
                if (requests[prior].id == request.id) return false;
            descriptors[index].fd = static_cast<int>(request.nativeHandle);
            descriptors[index].events = pollEvents(request.events);
            if (descriptors[index].events == 0 &&
                (request.events & (EventLoop::WAIT_ERROR |
                                   EventLoop::WAIT_HANGUP)) == 0u)
                return false;
        }

        int timeout = 0;
        if (!timeoutMilliseconds(deadline, &timeout)) return false;

        int result = -1;
        for (unsigned attempt = 0u; attempt <= kMaxInterruptedPolls;
             ++attempt) {
            result = ::poll(descriptors, static_cast<nfds_t>(count), timeout);
            if (result >= 0 || errno != EINTR ||
                attempt == kMaxInterruptedPolls)
                break;
            if (!timeoutMilliseconds(deadline, &timeout)) return false;
        }
        if (result <= 0) return false;

        for (Size index = 0u; index < count; ++index) {
            const short revents = descriptors[index].revents;
            if ((revents & POLLNVAL) != 0) return false;
            const std::uint32_t observed = loopEvents(revents);
            const std::uint32_t requested = requests[index].events;
            const std::uint32_t matched = observed & requested;
            if (matched == 0u) continue;
            ready->id = requests[index].id;
            ready->events = matched;
            return true;
        }
        return false;
    }

    static bool waitFunction(void* context,
                             const EventLoop::WaitRequest* requests,
                             Size count, std::uint64_t deadline,
                             EventLoop::WaitResult* ready) noexcept {
        if (context == nullptr) return false;
        return static_cast<PollEventLoopBackend*>(context)->wait(
            requests, count, deadline, ready);
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_EVENT_LOOP_POLL_HPP */
