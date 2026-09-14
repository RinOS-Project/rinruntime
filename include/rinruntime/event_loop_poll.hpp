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

#include <cerrno>
#include <climits>
#include <cstdint>
#include <poll.h>

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

    static short pollEvents(std::uint32_t events) noexcept {
        short result = 0;
        if ((events & EventLoop::WAIT_READABLE) != 0u) result |= POLLIN;
        if ((events & EventLoop::WAIT_WRITABLE) != 0u) result |= POLLOUT;
        /* poll reports error/hangup independently of the requested normal
         * events.  POLLIN is therefore a harmless wake source for a watch
         * interested only in WAIT_ERROR/WAIT_HANGUP. */
        if (result == 0 &&
            (events & (EventLoop::WAIT_ERROR | EventLoop::WAIT_HANGUP)) != 0u)
            result = POLLIN;
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

    bool timeoutMilliseconds(std::uint64_t deadline, int* timeout) const
        noexcept {
        if (timeout == nullptr || clock_ == nullptr) return false;
        if (deadline == UINT64_MAX) {
            *timeout = -1;
            return true;
        }

        const std::uint64_t now = clock_(clockContext_);
        if (now >= deadline) {
            *timeout = 0;
            return true;
        }
        const std::uint64_t remaining = deadline - now;
        *timeout = remaining > static_cast<std::uint64_t>(INT_MAX)
                       ? INT_MAX
                       : static_cast<int>(remaining);
        return true;
    }

public:
    PollEventLoopBackend(ClockFunction clock, void* clockContext = nullptr)
        : clock_(clock), clockContext_(clockContext) {}

    PollEventLoopBackend(const PollEventLoopBackend&) = delete;
    PollEventLoopBackend& operator=(const PollEventLoopBackend&) = delete;

    bool wait(const EventLoop::WaitRequest* requests, Size count,
              std::uint64_t deadline, EventLoop::WaitResult* ready) noexcept {
        if (ready == nullptr) return false;
        ready->id = 0u;
        ready->events = 0u;
        if (requests == nullptr || count == 0u ||
            count > EventLoop::kWaitCapacity)
            return false;

        struct pollfd descriptors[EventLoop::kWaitCapacity] = {};
        for (Size index = 0u; index < count; ++index) {
            const EventLoop::WaitRequest& request = requests[index];
            if (request.id == 0u || request.events == 0u ||
                (request.events & ~static_cast<std::uint32_t>(
                                      EventLoop::WAIT_EVENTS_ALL)) != 0u ||
                request.nativeHandle < 0 ||
                request.nativeHandle > static_cast<std::int64_t>(INT_MAX))
                return false;
            descriptors[index].fd = static_cast<int>(request.nativeHandle);
            descriptors[index].events = pollEvents(request.events);
            if (descriptors[index].events == 0) return false;
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
