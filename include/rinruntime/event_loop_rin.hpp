/* SPDX-License-Identifier: MIT */
/*
 * RinOS SDK wait-set adapter for EventLoop.
 *
 * EventLoop itself is a backend-independent userspace model.  This optional
 * adapter translates its bounded readiness requests to the public RinOS SDK
 * wait-set ABI; it does not contain kernel scheduler code or inspect a native
 * object.  The target/kernel owner supplies the wait-set implementation.
 */

#ifndef RINRUNTIME_EVENT_LOOP_RIN_HPP
#define RINRUNTIME_EVENT_LOOP_RIN_HPP

#include <cstdint>

#include <rin/abi.h>
#include <rin/base.h>
#include <rin/ipc.h>

#include "event_loop.hpp"

namespace RinRuntime {

static_assert(static_cast<std::uint32_t>(EventLoop::WAIT_READABLE) ==
                  static_cast<std::uint32_t>(RIN_WAIT_EVENT_READABLE),
              "RinOS wait-event readable bit drift");
static_assert(static_cast<std::uint32_t>(EventLoop::WAIT_WRITABLE) ==
                  static_cast<std::uint32_t>(RIN_WAIT_EVENT_WRITABLE),
              "RinOS wait-event writable bit drift");
static_assert(static_cast<std::uint32_t>(EventLoop::WAIT_ERROR) ==
                  static_cast<std::uint32_t>(RIN_WAIT_EVENT_ERROR),
              "RinOS wait-event error bit drift");
static_assert(static_cast<std::uint32_t>(EventLoop::WAIT_HANGUP) ==
                  static_cast<std::uint32_t>(RIN_WAIT_EVENT_HANGUP),
              "RinOS wait-event hangup bit drift");
static_assert(static_cast<std::uint32_t>(EventLoop::WAIT_EVENTS_ALL) ==
                  static_cast<std::uint32_t>(RIN_WAIT_EVENT_ALL),
              "RinOS wait-event mask drift");

class RinEventLoopBackend final {
public:
    using Size = EventLoop::Size;
    using ClockFunction = std::uint64_t (*)(void*) noexcept;

private:
    ClockFunction clock_ = nullptr;
    void* clockContext_ = nullptr;
    RinWaitSet waitSet_ = RIN_HANDLE_INVALID;
    RinWaitItemV1 items_[EventLoop::kWaitCapacity] = {};

    bool timeoutNanoseconds(std::uint64_t deadline,
                            std::uint64_t* timeout) const noexcept {
        if (timeout == nullptr || clock_ == nullptr) return false;
        if (deadline == UINT64_MAX) {
            *timeout = RIN_SDK_INFINITE;
            return true;
        }
        const std::uint64_t now = clock_(clockContext_);
        *timeout = now >= deadline ? 0u : deadline - now;
        return true;
    }

public:
    RinEventLoopBackend(ClockFunction clock, void* clockContext = nullptr)
        : clock_(clock), clockContext_(clockContext) {}

    RinEventLoopBackend(const RinEventLoopBackend&) = delete;
    RinEventLoopBackend& operator=(const RinEventLoopBackend&) = delete;

    ~RinEventLoopBackend() {
        if (waitSet_ != RIN_HANDLE_INVALID)
            (void)rin_object_close_v1(static_cast<RinObject>(waitSet_));
    }

    RinResult initialize(std::uint32_t flags = 0u) noexcept {
        if (clock_ == nullptr || waitSet_ != RIN_HANDLE_INVALID)
            return RIN_ERROR_INVALID_ARGUMENT;
        RinWaitSet waitSet = RIN_HANDLE_INVALID;
        const RinResult result = rin_wait_set_create_v1(flags, &waitSet);
        if (result != RIN_SUCCESS) return result;
        if (waitSet == RIN_HANDLE_INVALID) return RIN_ERROR_ABI_MISMATCH;
        waitSet_ = waitSet;
        return RIN_SUCCESS;
    }

    RinResult reset() noexcept {
        if (waitSet_ == RIN_HANDLE_INVALID) return RIN_SUCCESS;
        const RinResult result = rin_object_close_v1(
            static_cast<RinObject>(waitSet_));
        if (result == RIN_SUCCESS) waitSet_ = RIN_HANDLE_INVALID;
        return result;
    }

    bool initialized() const noexcept {
        return waitSet_ != RIN_HANDLE_INVALID;
    }

    bool wait(const EventLoop::WaitRequest* requests, Size count,
              std::uint64_t deadline,
              EventLoop::WaitResult* ready) noexcept {
        if (ready == nullptr || waitSet_ == RIN_HANDLE_INVALID ||
            (requests == nullptr && count != 0u) ||
            count > EventLoop::kWaitCapacity ||
            (count == 0u && deadline == UINT64_MAX))
            return false;
        ready->id = 0u;
        ready->events = 0u;

        for (Size index = 0u; index < count; ++index) {
            const EventLoop::WaitRequest& request = requests[index];
            if (request.id == 0u || request.nativeHandle <= 0 ||
                request.events == 0u ||
                (request.events & ~static_cast<std::uint32_t>(
                                      EventLoop::WAIT_EVENTS_ALL)) != 0u)
                return false;
            items_[index].handle = static_cast<RinHandle>(request.nativeHandle);
            items_[index].events = request.events;
            items_[index].observed = 0u;
            items_[index].user_tag = request.id;
        }
        const RinSliceV1 itemSlice = {
            static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(
                items_)),
            static_cast<std::uint64_t>(count * sizeof(items_[0]))};
        if (rin_wait_set_set_items_v1(waitSet_, itemSlice) != RIN_SUCCESS)
            return false;

        std::uint64_t timeout = 0u;
        if (!timeoutNanoseconds(deadline, &timeout)) return false;
        RinWaitResultV1 result = {};
        result.struct_size = sizeof(result);
        result.version = RIN_SDK_STRUCT_VERSION_1;
        if (rin_wait_set_wait_v1(waitSet_, timeout, &result) != RIN_SUCCESS)
            return false;
        if (result.struct_size < sizeof(result) ||
            result.version != RIN_SDK_STRUCT_VERSION_1)
            return false;
        for (std::uint64_t reserved : result.reserved)
            if (reserved != 0u) return false;
        if (result.index >= count || result.user_tag != items_[result.index].user_tag ||
            result.events == 0u ||
            (result.events & ~items_[result.index].events) != 0u)
            return false;
        ready->id = items_[result.index].user_tag;
        ready->events = result.events;
        return true;
    }

    static bool waitFunction(void* context,
                             const EventLoop::WaitRequest* requests,
                             Size count, std::uint64_t deadline,
                             EventLoop::WaitResult* ready) noexcept {
        if (context == nullptr) return false;
        return static_cast<RinEventLoopBackend*>(context)->wait(
            requests, count, deadline, ready);
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_EVENT_LOOP_RIN_HPP */
