/* SPDX-License-Identifier: MIT */
/*
 * Backend-independent bounded event-loop model.
 *
 * The loop owns only queue and timer metadata.  An OS adapter is responsible
 * for waiting on native handles and translating them into Event values; this
 * type deliberately performs no syscalls and never allocates.
 */

#ifndef RINRUNTIME_EVENT_LOOP_HPP
#define RINRUNTIME_EVENT_LOOP_HPP

#include <cstdint>

#include "cancellation.h"
#include "event.hpp"

namespace RinRuntime {

class EventLoop final {
public:
    using Size = decltype(sizeof(0));
    static constexpr Size kEventCapacity = 64u;
    static constexpr Size kTimerCapacity = 32u;
    static constexpr Size kWaitCapacity = 16u;
    using TimerId = std::uint64_t;
    using WaitId = std::uint64_t;

    enum WaitEvents : std::uint32_t {
        WAIT_READABLE = 1u << 0u,
        WAIT_WRITABLE = 1u << 1u,
        WAIT_ERROR = 1u << 2u,
        WAIT_HANGUP = 1u << 3u,
        WAIT_EVENTS_ALL = WAIT_READABLE | WAIT_WRITABLE | WAIT_ERROR | WAIT_HANGUP,
    };

    /* The OS adapter supplies native wait semantics while the loop owns only
     * bounded metadata.  nativeHandle is intentionally wide enough for both
     * file descriptors and target opaque handles, but is never interpreted by
     * this class. */
    struct WaitRequest {
        WaitId id = 0u;
        std::int64_t nativeHandle = 0;
        std::uint32_t events = 0u;
    };

    struct WaitResult {
        WaitId id = 0u;
        std::uint32_t events = 0u;
    };

    using WaitFunction = bool (*)(void*, const WaitRequest*, Size,
                                  std::uint64_t, WaitResult*);

private:
    struct Timer {
        std::uint64_t deadline = 0u;
        Event event = {};
        std::uint32_t generation = 0u;
        bool active = false;
    };

    struct Watch {
        std::int64_t nativeHandle = 0;
        std::uint32_t events = 0u;
        Event event = {};
        std::uint32_t generation = 0u;
        bool active = false;
    };

    Event events_[kEventCapacity] = {};
    Timer timers_[kTimerCapacity] = {};
    Watch watches_[kWaitCapacity] = {};
    Size eventHead_ = 0u;
    Size eventCount_ = 0u;
    std::uint32_t nextGeneration_ = 1u;
    bool wakePending_ = false;

    static bool validEvent(const Event& event) noexcept {
        return event.type != EventType::None &&
               (event.compositionSize == 0u || event.compositionText != nullptr);
    }

    static TimerId makeTimerId(Size index, std::uint32_t generation) {
        return (static_cast<TimerId>(generation) << 32u) |
               static_cast<TimerId>(index + 1u);
    }

    static bool decodeTimerId(TimerId id, Size* index,
                              std::uint32_t* generation) noexcept {
        if (id == 0u || index == nullptr || generation == nullptr) return false;
        const std::uint32_t rawIndex = static_cast<std::uint32_t>(id);
        const std::uint32_t rawGeneration = static_cast<std::uint32_t>(id >> 32u);
        if (rawIndex == 0u || rawIndex > kTimerCapacity || rawGeneration == 0u)
            return false;
        *index = static_cast<Size>(rawIndex - 1u);
        *generation = rawGeneration;
        return true;
    }

    static WaitId makeWaitId(Size index, std::uint32_t generation) {
        return (static_cast<WaitId>(generation) << 32u) |
               static_cast<WaitId>(index + 1u);
    }

    static bool decodeWaitId(WaitId id, Size* index,
                             std::uint32_t* generation) noexcept {
        if (id == 0u || index == nullptr || generation == nullptr) return false;
        const std::uint32_t rawIndex = static_cast<std::uint32_t>(id);
        const std::uint32_t rawGeneration = static_cast<std::uint32_t>(id >> 32u);
        if (rawIndex == 0u || rawIndex > kWaitCapacity || rawGeneration == 0u)
            return false;
        *index = static_cast<Size>(rawIndex - 1u);
        *generation = rawGeneration;
        return true;
    }

    std::uint32_t allocateGeneration() noexcept {
        const std::uint32_t result = nextGeneration_;
        ++nextGeneration_;
        if (nextGeneration_ == 0u) nextGeneration_ = 1u;
        return result == 0u ? 1u : result;
    }

    bool takeDueTimer(std::uint64_t now, Event* output) noexcept {
        Size selected = kTimerCapacity;
        std::uint64_t selectedDeadline = UINT64_MAX;
        for (Size index = 0u; index < kTimerCapacity; ++index) {
            if (timers_[index].active && timers_[index].deadline <= now &&
                (selected == kTimerCapacity ||
                 timers_[index].deadline < selectedDeadline)) {
                selected = index;
                selectedDeadline = timers_[index].deadline;
            }
        }
        if (selected == kTimerCapacity) return false;
        *output = timers_[selected].event;
        timers_[selected].active = false;
        return true;
    }

    Watch* watchForId(WaitId id) noexcept {
        Size index = 0u;
        std::uint32_t generation = 0u;
        if (!decodeWaitId(id, &index, &generation)) return nullptr;
        Watch& watch = watches_[index];
        return watch.active && watch.generation == generation ? &watch : nullptr;
    }

public:
    EventLoop() = default;

    bool post(const Event& event) noexcept {
        if (!validEvent(event) || eventCount_ >= kEventCapacity) return false;
        const Size slot = (eventHead_ + eventCount_) % kEventCapacity;
        events_[slot] = event;
        ++eventCount_;
        wakePending_ = true;
        return true;
    }

    TimerId scheduleAt(std::uint64_t deadline, const Event& event) noexcept {
        if (!validEvent(event)) return 0u;
        for (Size index = 0u; index < kTimerCapacity; ++index) {
            Timer& timer = timers_[index];
            if (timer.active) continue;
            timer.deadline = deadline;
            timer.event = event;
            timer.generation = allocateGeneration();
            timer.active = true;
            wakePending_ = true;
            return makeTimerId(index, timer.generation);
        }
        return 0u;
    }

    WaitId watch(std::int64_t nativeHandle, std::uint32_t events,
                 const Event& event) noexcept {
        if (!validEvent(event) || events == 0u ||
            (events & ~static_cast<std::uint32_t>(WAIT_EVENTS_ALL)) != 0u)
            return 0u;
        for (Size index = 0u; index < kWaitCapacity; ++index) {
            Watch& candidate = watches_[index];
            if (candidate.active) continue;
            candidate.nativeHandle = nativeHandle;
            candidate.events = events;
            candidate.event = event;
            candidate.generation = allocateGeneration();
            candidate.active = true;
            wakePending_ = true;
            return makeWaitId(index, candidate.generation);
        }
        return 0u;
    }

    bool cancelTimer(TimerId id) noexcept {
        Size index = 0u;
        std::uint32_t generation = 0u;
        if (!decodeTimerId(id, &index, &generation)) return false;
        Timer& timer = timers_[index];
        if (!timer.active || timer.generation != generation) return false;
        timer.active = false;
        return true;
    }

    bool unwatch(WaitId id) noexcept {
        Watch* watch = watchForId(id);
        if (watch == nullptr) return false;
        watch->active = false;
        wakePending_ = true;
        return true;
    }

    bool runOne(std::uint64_t now, Event* output) noexcept {
        if (output == nullptr) return false;
        if (takeDueTimer(now, output)) return true;
        if (eventCount_ == 0u) return false;
        *output = events_[eventHead_];
        eventHead_ = (eventHead_ + 1u) % kEventCapacity;
        --eventCount_;
        return true;
    }

    bool runOneCancellable(std::uint64_t now, Event* output,
                           RinRuntimeCancellationFunction cancellation,
                           void* cancellationContext) noexcept {
        if (cancellation != nullptr && cancellation(cancellationContext))
            return false;
        return runOne(now, output);
    }

    /* Run one already-ready timer/event, otherwise ask the injected OS
     * adapter for one readiness result.  The callback receives the earliest
     * timer deadline as an absolute value, or UINT64_MAX when no timer exists.
     * A result must name an active generation-bound watch and may only report
     * events requested by that watch. */
    bool wait(std::uint64_t now, WaitFunction backend, void* context,
              Event* output) noexcept {
        if (backend == nullptr || output == nullptr) return false;
        if (runOne(now, output)) return true;

        WaitRequest requests[kWaitCapacity] = {};
        Size count = 0u;
        for (Size index = 0u; index < kWaitCapacity; ++index) {
            const Watch& watch = watches_[index];
            if (!watch.active) continue;
            requests[count].id = makeWaitId(index, watch.generation);
            requests[count].nativeHandle = watch.nativeHandle;
            requests[count].events = watch.events;
            ++count;
        }
        if (count == 0u) return false;

        std::uint64_t deadline = UINT64_MAX;
        (void)nextDeadline(&deadline);
        WaitResult ready = {};
        if (!backend(context, requests, count, deadline, &ready) ||
            ready.id == 0u || ready.events == 0u)
            return false;
        for (Size index = 0u; index < count; ++index) {
            if (requests[index].id != ready.id) continue;
            if ((ready.events & requests[index].events) == 0u ||
                (ready.events & ~requests[index].events) != 0u)
                return false;
            Watch* watch = watchForId(ready.id);
            if (watch == nullptr) return false;
            *output = watch->event;
            return true;
        }
        return false;
    }

    bool nextDeadline(std::uint64_t* deadline) const noexcept {
        if (deadline == nullptr) return false;
        bool found = false;
        std::uint64_t earliest = UINT64_MAX;
        for (Size index = 0u; index < kTimerCapacity; ++index) {
            const Timer& timer = timers_[index];
            if (timer.active && (!found || timer.deadline < earliest)) {
                earliest = timer.deadline;
                found = true;
            }
        }
        if (!found) return false;
        *deadline = earliest;
        return true;
    }

    void wake() noexcept { wakePending_ = true; }

    bool consumeWake() noexcept {
        const bool wasPending = wakePending_;
        wakePending_ = false;
        return wasPending;
    }

    Size pendingEvents() const noexcept { return eventCount_; }

    Size pendingWatches() const noexcept {
        Size count = 0u;
        for (const Watch& watch : watches_)
            if (watch.active) ++count;
        return count;
    }

    void clear() noexcept {
        eventHead_ = 0u;
        eventCount_ = 0u;
        wakePending_ = false;
        for (Timer& timer : timers_) timer.active = false;
        for (Watch& watch : watches_) watch.active = false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_EVENT_LOOP_HPP */
