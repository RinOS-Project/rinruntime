// SPDX-License-Identifier: MIT

#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <stdexcept>
#include <unistd.h>

#include "../include/rinruntime/event_loop_poll.hpp"

static uint64_t g_now = 100u;

static uint64_t test_clock(void*) noexcept { return g_now; }

static bool stateless_wait_backend(
    void* context, const RinRuntime::EventLoop::WaitRequest* requests,
    RinRuntime::EventLoop::Size count, uint64_t,
    RinRuntime::EventLoop::WaitResult* ready) {
    if (context != nullptr || requests == nullptr || count != 1u ||
        ready == nullptr) return false;
    ready->id = requests[0].id;
    ready->events = requests[0].events;
    return true;
}

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
static bool throwing_wait_backend(
    void*, const RinRuntime::EventLoop::WaitRequest*,
    RinRuntime::EventLoop::Size, uint64_t,
    RinRuntime::EventLoop::WaitResult*) {
    throw std::runtime_error("test wait backend failure");
}
#endif

int main() {
    using RinRuntime::Event;
    using RinRuntime::EventLoop;
    using RinRuntime::EventType;
    using RinRuntime::PollEventLoopBackend;

    int pipe_fds[2] = {-1, -1};
    assert(pipe(pipe_fds) == 0);

    PollEventLoopBackend backend(test_clock);
    EventLoop loop;
    Event ready_event = {};
    ready_event.type = EventType::Close;

    EventLoop event_validation_loop;
    char composition[] = "x";
    Event invalid_composition = {};
    invalid_composition.type = EventType::TextComposition;
    invalid_composition.compositionText = composition;
    invalid_composition.compositionSize =
        EventLoop::kMaxCompositionBytes + 1u;
    assert(!event_validation_loop.post(invalid_composition));
    invalid_composition.compositionSize = 1u;
    invalid_composition.compositionSelectionEnd = 2u;
    assert(!event_validation_loop.post(invalid_composition));
    invalid_composition.compositionText = "\xc0";
    invalid_composition.compositionSelectionEnd = 1u;
    assert(!event_validation_loop.post(invalid_composition));
    invalid_composition.compositionText = composition;
    invalid_composition.compositionSelectionEnd = 1u;
    assert(event_validation_loop.post(invalid_composition));
    const char multibyte_composition[] = "\xe3\x81\x82";
    invalid_composition.compositionText = multibyte_composition;
    invalid_composition.compositionSize = sizeof(multibyte_composition) - 1u;
    invalid_composition.compositionSelectionStart = 1u;
    invalid_composition.compositionSelectionEnd = 3u;
    assert(!event_validation_loop.post(invalid_composition));
    invalid_composition.compositionSelectionStart = 0u;
    invalid_composition.compositionSelectionEnd = 2u;
    assert(!event_validation_loop.post(invalid_composition));
    invalid_composition.compositionSelectionEnd = 3u;
    assert(event_validation_loop.post(invalid_composition));
    Event invalid_text = {};
    invalid_text.type = EventType::TextInput;
    invalid_text.codepoint = 0xd800u;
    assert(!event_validation_loop.post(invalid_text));
    invalid_text.codepoint = 0x110000u;
    assert(!event_validation_loop.post(invalid_text));
    invalid_text.codepoint = 0x3042u;
    assert(event_validation_loop.post(invalid_text));
    Event validation_output = {};
    assert(event_validation_loop.runOne(0u, &validation_output));
    assert(validation_output.type == EventType::TextComposition);
    assert(event_validation_loop.runOne(0u, &validation_output));
    assert(validation_output.type == EventType::TextComposition);
    assert(event_validation_loop.runOne(0u, &validation_output));
    assert(validation_output.type == EventType::TextInput &&
           validation_output.codepoint == 0x3042u);

    /* Draining model-owned work must not require an OS wait adapter.  The
     * public EventLoop can be used as a queue/timer model by ordinary
     * applications before they select a platform backend. */
    EventLoop backend_free_loop;
    assert(backend_free_loop.post(ready_event));
    Event backend_free_output = {};
    assert(backend_free_loop.wait(g_now, nullptr, nullptr,
                                  &backend_free_output));
    assert(backend_free_output.type == EventType::Close);
    assert(backend_free_loop.scheduleAt(g_now, ready_event) != 0u);
    backend_free_output = {};
    assert(backend_free_loop.wait(g_now, nullptr, nullptr,
                                  &backend_free_output));
    assert(backend_free_output.type == EventType::Close);

    /* UINT64_MAX is the adapter no-deadline sentinel, not a valid clock
     * sample.  A failed clock sample must not publish every finite timer as
     * already due or discard the timer from the queue. */
    EventLoop sentinel_loop;
    Event paint = {};
    paint.type = EventType::Paint;
    const EventLoop::TimerId sentinel_timer =
        sentinel_loop.scheduleAt(30u, paint);
    assert(sentinel_timer != 0u);
    Event sentinel_output = {};
    assert(!sentinel_loop.runOne(UINT64_MAX, &sentinel_output));
    assert(sentinel_output.type == EventType::None);
    std::uint64_t sentinel_deadline = 0u;
    assert(sentinel_loop.nextDeadline(&sentinel_deadline) &&
           sentinel_deadline == 30u);
    assert(sentinel_loop.runOne(30u, &sentinel_output) &&
           sentinel_output.type == EventType::Paint);

    assert(loop.scheduleAt(UINT64_MAX, ready_event) == 0u);
    assert(loop.scheduleAt(g_now + 1u, ready_event) != 0u);
    Event output = {};
    assert(!loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                      &output));
    ++g_now;
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);

    const EventLoop::WaitId read_id = loop.watch(
        pipe_fds[0], EventLoop::WAIT_READABLE, ready_event);
    assert(read_id != 0u);

    char byte = 'r';
    assert(write(pipe_fds[1], &byte, sizeof(byte)) == 1);
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);
    assert(read(pipe_fds[0], &byte, sizeof(byte)) == 1);

    /* A caller can retarget a live public watch without losing its
     * generation-bound ID.  The adapter must observe the new descriptor and
     * the new caller-owned event on its next wait. */
    Event updated_event = {};
    updated_event.type = EventType::Paint;
    assert(loop.updateWatch(read_id, static_cast<uint64_t>(pipe_fds[1]),
                            EventLoop::WAIT_WRITABLE, updated_event));
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Paint);
    assert(!loop.updateWatch(read_id, 0u, EventLoop::WAIT_READABLE,
                             ready_event));
    assert(loop.unwatch(read_id));

    const EventLoop::WaitId writable_id = loop.watch(
        pipe_fds[1], EventLoop::WAIT_WRITABLE, ready_event);
    assert(writable_id != 0u);
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);
    assert(loop.unwatch(writable_id));

    const EventLoop::WaitId pending_hangup_id = loop.watch(
        pipe_fds[0], EventLoop::WAIT_HANGUP, ready_event);
    assert(pending_hangup_id != 0u);
    assert(write(pipe_fds[1], &byte, sizeof(byte)) == 1);
    EventLoop::WaitRequest pending_hangup_request = {};
    pending_hangup_request.id = 1u;
    pending_hangup_request.nativeHandle = pipe_fds[0];
    pending_hangup_request.events = EventLoop::WAIT_HANGUP;
    EventLoop::WaitResult pending_hangup_ready = {
        99u, EventLoop::WAIT_HANGUP};
    const auto pending_hangup_start = std::chrono::steady_clock::now();
    assert(!backend.wait(&pending_hangup_request, 1u,
                         g_now + 20000000u, &pending_hangup_ready));
    const auto pending_hangup_elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                   pending_hangup_start);
    assert(pending_hangup_elapsed.count() >= 5);
    assert(pending_hangup_ready.id == 0u &&
           pending_hangup_ready.events == 0u);
    assert(loop.unwatch(pending_hangup_id));
    assert(read(pipe_fds[0], &byte, sizeof(byte)) == 1);

    EventLoop::WaitRequest timeout_request = {};
    timeout_request.id = 1u;
    timeout_request.nativeHandle = pipe_fds[0];
    timeout_request.events = EventLoop::WAIT_READABLE;
    EventLoop::WaitResult ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(&timeout_request, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    EventLoop::WaitRequest aliased_request = timeout_request;
    const EventLoop::WaitRequest aliased_before = aliased_request;
    auto* aliased_ready = reinterpret_cast<EventLoop::WaitResult*>(
        &aliased_request);
    assert(!backend.wait(&aliased_request, 1u, g_now, aliased_ready));
    assert(aliased_request.id == aliased_before.id &&
           aliased_request.nativeHandle == aliased_before.nativeHandle &&
           aliased_request.events == aliased_before.events);

    const auto timeout_start = std::chrono::steady_clock::now();
    ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(&timeout_request, 1u, g_now + 2000000u, &ready));
    const auto timeout_elapsed = std::chrono::duration_cast<
        std::chrono::milliseconds>(std::chrono::steady_clock::now() -
                                   timeout_start);
    assert(timeout_elapsed.count() < 500);
    assert(ready.id == 0u && ready.events == 0u);

    timeout_request.nativeHandle = 0u;
    assert(!backend.wait(&timeout_request, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    EventLoop::WaitRequest duplicate_requests[2] = {};
    duplicate_requests[0].id = 7u;
    duplicate_requests[0].nativeHandle = static_cast<uint64_t>(pipe_fds[0]);
    duplicate_requests[0].events = EventLoop::WAIT_READABLE;
    duplicate_requests[1] = duplicate_requests[0];
    ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(duplicate_requests, 2u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    assert(close(pipe_fds[1]) == 0);
    const EventLoop::WaitId hangup_id = loop.watch(
        pipe_fds[0], EventLoop::WAIT_HANGUP, ready_event);
    assert(hangup_id != 0u);
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);
    assert(loop.unwatch(hangup_id));
    assert(close(pipe_fds[0]) == 0);

    timeout_request.nativeHandle = static_cast<uint64_t>(INT32_MAX) + 1u;
    assert(!backend.wait(&timeout_request, 1u, g_now, &ready));

    /* A deadline adapter must not turn a clock rollback into a new long
     * sleep after an interrupted or repeated wait. */
    g_now = 99u;
    timeout_request.nativeHandle = static_cast<uint64_t>(pipe_fds[0]);
    ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(&timeout_request, 1u, 100u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    g_now = 100u;

    /* A restarted clock provider starts a new session.  The public POSIX
     * adapter must allow the caller to retire the previous rollback sample
     * without rebuilding its EventLoop or watches. */
    int reset_pipe[2] = {-1, -1};
    assert(pipe(reset_pipe) == 0);
    assert(write(reset_pipe[1], &byte, sizeof(byte)) == 1);
    backend.resetClock();
    g_now = 10u;
    timeout_request.nativeHandle = static_cast<uint64_t>(reset_pipe[0]);
    ready = {99u, EventLoop::WAIT_READABLE};
    assert(backend.wait(&timeout_request, 1u, 11u, &ready));
    assert(ready.id == timeout_request.id &&
           ready.events == EventLoop::WAIT_READABLE);
    assert(read(reset_pipe[0], &byte, sizeof(byte)) == 1);
    assert(close(reset_pipe[1]) == 0);
    assert(close(reset_pipe[0]) == 0);

    /* UINT64_MAX is EventLoop's no-deadline sentinel, not a valid clock
     * sample.  A finite deadline must fail closed even when the descriptor
     * is already readable; it must not be converted into timeout=0 and
     * published as a ready event. */
    int sentinel_pipe[2] = {-1, -1};
    assert(pipe(sentinel_pipe) == 0);
    assert(write(sentinel_pipe[1], &byte, sizeof(byte)) == 1);
    backend.resetClock();
    g_now = UINT64_MAX;
    timeout_request.nativeHandle = static_cast<uint64_t>(sentinel_pipe[0]);
    ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(&timeout_request, 1u, UINT64_MAX - 1u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(close(sentinel_pipe[1]) == 0);
    assert(close(sentinel_pipe[0]) == 0);

    /* Cancelling a deadline after its scheduling wake was consumed must
     * publish a second wake so an adapter does not sleep on a stale deadline. */
    EventLoop wake_loop;
    const EventLoop::TimerId wake_timer =
        wake_loop.scheduleAt(g_now + 1000000000u, ready_event);
    assert(wake_timer != 0u);
    assert(wake_loop.consumeWake());
    assert(!wake_loop.consumeWake());
    assert(wake_loop.cancelTimer(wake_timer));
    assert(wake_loop.consumeWake());
    assert(!wake_loop.consumeWake());

    /* EventLoop is also a public backend-independent model.  A stateless
     * caller-owned adapter may use the optional context as nullptr; this
     * must not force ordinary applications to manufacture an owner object. */
    EventLoop stateless_loop;
    const EventLoop::WaitId stateless_id = stateless_loop.watch(
        1u, EventLoop::WAIT_READABLE, ready_event);
    assert(stateless_id != 0u);
    output = {};
    assert(stateless_loop.wait(g_now, stateless_wait_backend, nullptr,
                               &output));
    assert(output.type == EventType::Close);

#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
    /* A caller-owned backend exception must be contained at the public
     * noexcept boundary and must not publish poisoned readiness. */
    EventLoop throwing_loop;
    const EventLoop::WaitId throwing_id = throwing_loop.watch(
        1u, EventLoop::WAIT_READABLE, ready_event);
    assert(throwing_id != 0u);
    output.type = EventType::Close;
    assert(!throwing_loop.wait(g_now, throwing_wait_backend, nullptr,
                               &output));
    assert(output.type == EventType::None);
#endif

    return 0;
}
