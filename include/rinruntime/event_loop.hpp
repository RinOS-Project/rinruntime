/* SPDX-License-Identifier: MIT */
/*
 * Backend-independent bounded event-loop model.
 *
 * The loop owns only bounded queue, timer, watch, and composition metadata.
 * An OS adapter is responsible for waiting on native handles and translating
 * them into Event values; this type deliberately performs no syscalls and
 * never allocates.
 */

#ifndef RINRUNTIME_EVENT_LOOP_HPP
#define RINRUNTIME_EVENT_LOOP_HPP

#include <cstddef>
#include <cstdint>

#include "cancellation.h"
#include "event.hpp"

namespace RinRuntime {

namespace detail {

inline bool eventLoopByteRangesOverlap(const void* left, std::size_t leftSize,
                                       const void* right,
                                       std::size_t rightSize) noexcept {
    if (left == nullptr || right == nullptr || leftSize == 0u ||
        rightSize == 0u)
        return false;
    const std::uintptr_t leftStart =
        reinterpret_cast<std::uintptr_t>(left);
    const std::uintptr_t rightStart =
        reinterpret_cast<std::uintptr_t>(right);
    const std::uintptr_t leftEnd = leftStart + leftSize;
    const std::uintptr_t rightEnd = rightStart + rightSize;
    if (leftEnd < leftStart || rightEnd < rightStart) return true;
    return leftStart < rightEnd && rightStart < leftEnd;
}

inline bool eventLoopCompositionUtf8Valid(const char* value,
                                           std::size_t size) noexcept {
    if (value == nullptr) return size == 0u;
    std::size_t index = 0u;
    while (index < size) {
        const unsigned char first =
            static_cast<unsigned char>(value[index]);
        std::size_t count = 0u;
        std::uint32_t codepoint = 0u;
        if (first <= 0x7fu) {
            count = 1u;
            codepoint = first;
        } else if (first >= 0xc2u && first <= 0xdfu) {
            count = 2u;
            codepoint = first & 0x1fu;
        } else if (first >= 0xe0u && first <= 0xefu) {
            count = 3u;
            codepoint = first & 0x0fu;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            count = 4u;
            codepoint = first & 0x07u;
        } else {
            return false;
        }
        if (count > size - index) return false;
        for (std::size_t offset = 1u; offset < count; ++offset) {
            const unsigned char continuation = static_cast<unsigned char>(
                value[index + offset]);
            if ((continuation & 0xc0u) != 0x80u) return false;
            codepoint = (codepoint << 6u) | (continuation & 0x3fu);
        }
        if (!isUnicodeScalar(codepoint) ||
            (count == 2u && codepoint < 0x80u) ||
            (count == 3u && codepoint < 0x800u) ||
            (count == 4u && codepoint < 0x10000u))
            return false;
        index += count;
    }
    return true;
}

inline bool eventLoopCompositionUtf8Boundary(const char* value,
                                              std::size_t size,
                                              std::size_t offset) noexcept {
    if (offset > size) return false;
    if (offset == 0u || offset == size) return true;
    if (value == nullptr) return false;
    return (static_cast<unsigned char>(value[offset]) & 0xc0u) != 0x80u;
}

} // namespace detail

class EventLoop final {
public:
    using Size = decltype(sizeof(0));
    static constexpr Size kEventCapacity = 64u;
    static constexpr Size kTimerCapacity = 32u;
    static constexpr Size kWaitCapacity = 16u;
    static constexpr Size kMaxCompositionBytes = kMaxTextCompositionBytes;
    /* Composition payloads are copied into a bounded pool.  Ordinary events
     * still use the full queue/timer/watch capacities when the pool is full. */
    static constexpr Size kCompositionPayloadCapacity = 16u;
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
     * bounded metadata.  nativeHandle covers the full public opaque-handle
     * range; a POSIX adapter narrows it to its descriptor range, but this
     * class never interprets it. */
    struct WaitRequest {
        WaitId id = 0u;
        std::uint64_t nativeHandle = 0u;
        std::uint32_t events = 0u;
    };

    struct WaitResult {
        WaitId id = 0u;
        std::uint32_t events = 0u;
    };

    using WaitFunction = bool (*)(void*, const WaitRequest*, Size,
                                  std::uint64_t, WaitResult*);

private:
    static constexpr Size kNoCompositionPayload =
        kCompositionPayloadCapacity;

    struct StoredEvent {
        Event event = {};
        Size payloadSlot = kNoCompositionPayload;
        std::uint64_t payloadGeneration = 0u;
    };

    struct CompositionPayload {
        char bytes[kMaxCompositionBytes + 1u] = {};
        Size references = 0u;
        std::uint64_t generation = 0u;
    };

    struct Timer {
        std::uint64_t deadline = 0u;
        StoredEvent event = {};
        std::uint32_t generation = 0u;
        bool active = false;
    };

    struct Watch {
        std::uint64_t nativeHandle = 0u;
        std::uint32_t events = 0u;
        StoredEvent event = {};
        std::uint32_t generation = 0u;
        bool active = false;
    };

    StoredEvent events_[kEventCapacity] = {};
    Timer timers_[kTimerCapacity] = {};
    Watch watches_[kWaitCapacity] = {};
    CompositionPayload compositionPayloads_[kCompositionPayloadCapacity] = {};
    Size deliveryPayloadSlot_ = kNoCompositionPayload;
    Size eventHead_ = 0u;
    Size eventCount_ = 0u;
    std::uint32_t nextGeneration_ = 1u;
    bool generationExhausted_ = false;
    bool wakePending_ = false;
    bool waitBackendInFlight_ = false;
    bool preferQueuedEvent_ = false;

    static bool validEvent(const Event& event) noexcept {
        return event.type != EventType::None &&
               (event.type != EventType::TextInput ||
                isUnicodeScalar(event.codepoint)) &&
               event.compositionSize <= kMaxCompositionBytes &&
               (event.type != EventType::TextComposition ||
                (detail::eventLoopCompositionUtf8Valid(
                     event.compositionText, event.compositionSize) &&
                 detail::eventLoopCompositionUtf8Boundary(
                     event.compositionText, event.compositionSize,
                     event.compositionSelectionStart) &&
                 detail::eventLoopCompositionUtf8Boundary(
                     event.compositionText, event.compositionSize,
                     event.compositionSelectionEnd))) &&
               event.compositionSelectionStart <= event.compositionSize &&
               event.compositionSelectionEnd <= event.compositionSize &&
               (event.compositionSize == 0u || event.compositionText != nullptr);
    }

    static bool sameEvent(const Event& left, const Event& right) noexcept {
        return left.type == right.type && left.x == right.x &&
               left.y == right.y && left.wheelX == right.wheelX &&
               left.wheelY == right.wheelY && left.button == right.button &&
               left.key == right.key &&
               left.nativeScancode == right.nativeScancode &&
               left.codepoint == right.codepoint &&
               left.modifiers == right.modifiers && left.flags == right.flags &&
               left.compositionText == right.compositionText &&
               left.compositionSize == right.compositionSize &&
               left.compositionSelectionStart ==
                   right.compositionSelectionStart &&
               left.compositionSelectionEnd == right.compositionSelectionEnd;
    }

    static bool sameStoredEvent(const StoredEvent& left,
                                const StoredEvent& right) noexcept {
        return sameEvent(left.event, right.event) &&
               left.payloadSlot == right.payloadSlot &&
               left.payloadGeneration == right.payloadGeneration;
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
        if (generationExhausted_) return 0u;
        const std::uint32_t result = nextGeneration_;
        if (result == UINT32_MAX) {
            /* Do not wrap into a generation that may still be referenced by
             * a stale timer/watch ID.  The loop remains usable for existing
             * entries, but no new generation-bound entry is accepted. */
            generationExhausted_ = true;
        } else {
            ++nextGeneration_;
        }
        return result;
    }

    Size allocateCompositionPayload(const char* bytes, Size size) noexcept {
        if (bytes == nullptr || size == 0u || size > kMaxCompositionBytes)
            return kNoCompositionPayload;
        for (Size index = 0u; index < kCompositionPayloadCapacity; ++index) {
            CompositionPayload& payload = compositionPayloads_[index];
            if (payload.references != 0u || payload.generation == UINT64_MAX)
                continue;
            ++payload.generation;
            payload.references = 1u;
            for (Size offset = 0u; offset < size; ++offset)
                payload.bytes[offset] = bytes[offset];
            payload.bytes[size] = '\0';
            return index;
        }
        return kNoCompositionPayload;
    }

    void retainCompositionPayload(Size slot) noexcept {
        if (slot < kCompositionPayloadCapacity)
            ++compositionPayloads_[slot].references;
    }

    void releaseCompositionPayload(Size slot) noexcept {
        if (slot >= kCompositionPayloadCapacity) return;
        CompositionPayload& payload = compositionPayloads_[slot];
        if (payload.references == 0u) return;
        --payload.references;
        if (payload.references == 0u) payload.bytes[0] = '\0';
    }

    bool captureEvent(const Event& event, StoredEvent* stored) noexcept {
        if (stored == nullptr) return false;
        StoredEvent captured;
        captured.event = event;
        if (event.type == EventType::TextComposition) {
            captured.event.compositionText = nullptr;
            if (event.compositionSize != 0u) {
                const Size slot = allocateCompositionPayload(
                    event.compositionText, event.compositionSize);
                if (slot == kNoCompositionPayload) return false;
                captured.payloadSlot = slot;
                captured.payloadGeneration =
                    compositionPayloads_[slot].generation;
            }
        }
        *stored = captured;
        return true;
    }

    void releaseStoredEvent(StoredEvent* stored) noexcept {
        if (stored == nullptr) return;
        if (stored->payloadSlot < kCompositionPayloadCapacity &&
            compositionPayloads_[stored->payloadSlot].generation ==
                stored->payloadGeneration)
            releaseCompositionPayload(stored->payloadSlot);
        *stored = StoredEvent{};
    }

    void releaseDeliveryPayload() noexcept {
        releaseCompositionPayload(deliveryPayloadSlot_);
        deliveryPayloadSlot_ = kNoCompositionPayload;
    }

    void deliverStoredEvent(const StoredEvent& stored,
                            Event* output) noexcept {
        *output = stored.event;
        if (stored.event.type != EventType::TextComposition) return;
        if (stored.event.compositionSize == 0u) {
            output->compositionText = nullptr;
            return;
        }
        if (stored.payloadSlot >= kCompositionPayloadCapacity) {
            *output = {};
            return;
        }
        const CompositionPayload& payload =
            compositionPayloads_[stored.payloadSlot];
        /* Slot generations prevent stale references from becoming valid after
         * a cancelled timer or updated watch frees and reuses a pool entry. */
        if (payload.references == 0u ||
            payload.generation != stored.payloadGeneration) {
            *output = {};
            return;
        }
        retainCompositionPayload(stored.payloadSlot);
        deliveryPayloadSlot_ = stored.payloadSlot;
        output->compositionText = payload.bytes;
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
        deliverStoredEvent(timers_[selected].event, output);
        releaseStoredEvent(&timers_[selected].event);
        timers_[selected] = Timer{};
        return true;
    }

    bool takeQueuedEvent(Event* output) noexcept {
        if (output == nullptr || eventCount_ == 0u) return false;
        deliverStoredEvent(events_[eventHead_], output);
        releaseStoredEvent(&events_[eventHead_]);
        eventHead_ = (eventHead_ + 1u) % kEventCapacity;
        --eventCount_;
        preferQueuedEvent_ = false;
        return true;
    }

    Watch* watchForId(WaitId id) noexcept {
        Size index = 0u;
        std::uint32_t generation = 0u;
        if (!decodeWaitId(id, &index, &generation)) return nullptr;
        Watch& watch = watches_[index];
        return watch.active && watch.generation == generation ? &watch : nullptr;
    }

    static bool invokeWaitBackend(WaitFunction backend, void* context,
                                  const WaitRequest* requests, Size count,
                                  std::uint64_t deadline,
                                  WaitResult* ready) noexcept {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            return backend(context, requests, count, deadline, ready);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            /* WaitFunction is caller-owned.  A backend exception must not
             * escape the noexcept public loop boundary or expose partial
             * readiness to the caller. */
            if (ready != nullptr) *ready = {};
            return false;
        }
#endif
    }

    bool callWaitBackend(WaitFunction backend, void* context,
                         const WaitRequest* requests, Size count,
                         std::uint64_t deadline, WaitResult* ready) noexcept {
        if (waitBackendInFlight_) {
            if (ready != nullptr) *ready = {};
            return false;
        }
        waitBackendInFlight_ = true;
        const bool result = invokeWaitBackend(backend, context, requests,
                                              count, deadline, ready);
        waitBackendInFlight_ = false;
        return result;
    }

public:
    EventLoop() = default;

    bool post(const Event& event) noexcept {
        if (!validEvent(event) || eventCount_ >= kEventCapacity) return false;
        StoredEvent captured;
        if (!captureEvent(event, &captured)) return false;
        const Size slot = (eventHead_ + eventCount_) % kEventCapacity;
        events_[slot] = captured;
        ++eventCount_;
        wakePending_ = true;
        return true;
    }

    TimerId scheduleAt(std::uint64_t deadline, const Event& event) noexcept {
        /* UINT64_MAX is the wait-adapter sentinel for "no timer".  It must
         * not be admitted as a real deadline because that timer could never
         * become due and would be indistinguishable from an idle loop. */
        if (deadline == UINT64_MAX || !validEvent(event)) return 0u;
        for (Size index = 0u; index < kTimerCapacity; ++index) {
            Timer& timer = timers_[index];
            if (timer.active) continue;
            StoredEvent captured;
            if (!captureEvent(event, &captured)) return 0u;
            const std::uint32_t generation = allocateGeneration();
            if (generation == 0u) {
                releaseStoredEvent(&captured);
                return 0u;
            }
            timer.deadline = deadline;
            timer.event = captured;
            timer.generation = generation;
            timer.active = true;
            wakePending_ = true;
            return makeTimerId(index, timer.generation);
        }
        return 0u;
    }

    WaitId watch(std::uint64_t nativeHandle, std::uint32_t events,
                 const Event& event) noexcept {
        if (nativeHandle == 0u || !validEvent(event) || events == 0u ||
            (events & ~static_cast<std::uint32_t>(WAIT_EVENTS_ALL)) != 0u)
            return 0u;
        for (Size index = 0u; index < kWaitCapacity; ++index) {
            Watch& candidate = watches_[index];
            if (candidate.active) continue;
            StoredEvent captured;
            if (!captureEvent(event, &captured)) return 0u;
            const std::uint32_t generation = allocateGeneration();
            if (generation == 0u) {
                releaseStoredEvent(&captured);
                return 0u;
            }
            candidate.nativeHandle = nativeHandle;
            candidate.events = events;
            candidate.event = captured;
            candidate.generation = generation;
            candidate.active = true;
            wakePending_ = true;
            return makeWaitId(index, candidate.generation);
        }
        return 0u;
    }

    /* Change the native source or notification payload without retiring the
     * public generation-bound watch ID.  Adapters may already have published
     * this ID to an OS wait-set, so keep the generation stable and publish a
     * wake for the next wait turn. */
    bool updateWatch(WaitId id, std::uint64_t nativeHandle,
                     std::uint32_t events, const Event& event) noexcept {
        if (nativeHandle == 0u || !validEvent(event) || events == 0u ||
            (events & ~static_cast<std::uint32_t>(WAIT_EVENTS_ALL)) != 0u)
            return false;
        Watch* watch = watchForId(id);
        if (watch == nullptr) return false;
        StoredEvent captured;
        if (!captureEvent(event, &captured)) return false;
        releaseStoredEvent(&watch->event);
        watch->nativeHandle = nativeHandle;
        watch->events = events;
        watch->event = captured;
        wakePending_ = true;
        return true;
    }

    bool cancelTimer(TimerId id) noexcept {
        Size index = 0u;
        std::uint32_t generation = 0u;
        if (!decodeTimerId(id, &index, &generation)) return false;
        Timer& timer = timers_[index];
        if (!timer.active || timer.generation != generation) return false;
        releaseStoredEvent(&timer.event);
        timer = Timer{};
        /* Cancelling a timer changes the deadline observed by an adapter.
         * Preserve the same wake contract as unwatch(): a caller that has
         * already consumed the notification from scheduleAt() must still be
         * able to observe this cancellation before it blocks again. */
        wakePending_ = true;
        return true;
    }

    bool unwatch(WaitId id) noexcept {
        Watch* watch = watchForId(id);
        if (watch == nullptr) return false;
        releaseStoredEvent(&watch->event);
        *watch = Watch{};
        wakePending_ = true;
        return true;
    }

    bool runOne(std::uint64_t now, Event* output) noexcept {
        if (output == nullptr) return false;
        releaseDeliveryPayload();
        *output = {};
        /* UINT64_MAX is the public adapter's no-deadline sentinel, not a
         * usable monotonic clock sample.  Do not turn an invalid clock into
         * an observation that every finite timer is due.  Queued events are
         * independent of the clock and remain drainable below. */
        const bool timerMayBeDue = now != UINT64_MAX;
        if (timerMayBeDue && preferQueuedEvent_ && eventCount_ != 0u) {
            /* After a timer dispatch, give already-queued work the next turn.
             * This remains true even if the preceding callback posted the
             * event after the timer was returned to its caller. */
            Size dueTimerCount = 0u;
            for (const Timer& timer : timers_)
                if (timer.active && timer.deadline <= now) ++dueTimerCount;
            if (dueTimerCount != 0u) return takeQueuedEvent(output);
        }
        if (timerMayBeDue && takeDueTimer(now, output)) {
            preferQueuedEvent_ = true;
            return true;
        }
        return takeQueuedEvent(output);
    }

    bool runOneCancellable(std::uint64_t now, Event* output,
                           RinRuntimeCancellationFunction cancellation,
                           void* cancellationContext) noexcept {
        if (output == nullptr) return false;
        *output = {};
        if (cancellation != nullptr) {
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            try {
#endif
                if (cancellation(cancellationContext)) return false;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            } catch (...) {
                /* A caller-owned callback is outside the runtime's control.
                 * Keep this noexcept public boundary failure-closed instead
                 * of allowing an exception to terminate the application. */
                return false;
            }
#endif
        }
        return runOne(now, output);
    }

    /* Run one already-ready timer/event, otherwise ask the injected OS
     * adapter for one readiness result.  The callback receives the earliest
     * timer deadline as an absolute value, or UINT64_MAX when no timer exists.
     * A result must name an active generation-bound watch and may only report
     * events requested by that watch.  A zero-count request is allowed when a
     * finite timer deadline exists so the adapter can sleep for a timer-only
     * loop; it must not manufacture a readiness result in that case. */
    bool wait(std::uint64_t now, WaitFunction backend, void* context,
              Event* output) noexcept {
        if (output == nullptr) return false;
        *output = {};
        if (runOne(now, output)) return true;
        /* A queued event or an already-due timer is entirely owned by this
         * backend-independent model.  Do not make callers manufacture an OS
         * adapter merely to drain work that cannot block. */
        if (backend == nullptr) return false;

        WaitRequest requests[kWaitCapacity] = {};
        StoredEvent requestEvents[kWaitCapacity] = {};
        Size count = 0u;
        for (Size index = 0u; index < kWaitCapacity; ++index) {
            const Watch& watch = watches_[index];
            if (!watch.active) continue;
            requests[count].id = makeWaitId(index, watch.generation);
            requests[count].nativeHandle = watch.nativeHandle;
            requests[count].events = watch.events;
            requestEvents[count] = watch.event;
            ++count;
        }
        std::uint64_t deadline = UINT64_MAX;
        (void)nextDeadline(&deadline);
        if (count == 0u) {
            WaitResult idleResult = {};
            if (deadline != UINT64_MAX) (void)callWaitBackend(
                backend, context, nullptr, 0u, deadline, &idleResult);
            return false;
        }
        WaitResult ready = {};
        if (!callWaitBackend(backend, context, requests, count, deadline,
                             &ready) ||
            ready.id == 0u || ready.events == 0u)
            return false;
        for (Size index = 0u; index < count; ++index) {
            if (requests[index].id != ready.id) continue;
            if ((ready.events & requests[index].events) == 0u ||
                (ready.events & ~requests[index].events) != 0u)
                return false;
            Watch* watch = watchForId(ready.id);
            if (watch == nullptr ||
                watch->nativeHandle != requests[index].nativeHandle ||
                watch->events != requests[index].events ||
                !sameStoredEvent(watch->event, requestEvents[index]))
                return false;
            deliverStoredEvent(watch->event, output);
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
        preferQueuedEvent_ = false;
        for (StoredEvent& event : events_) releaseStoredEvent(&event);
        for (Timer& timer : timers_) {
            releaseStoredEvent(&timer.event);
            timer = Timer{};
        }
        for (Watch& watch : watches_) {
            releaseStoredEvent(&watch.event);
            watch = Watch{};
        }
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_EVENT_LOOP_HPP */
