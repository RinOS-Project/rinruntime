// SPDX-License-Identifier: MIT

#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <unistd.h>

#include "../include/rinruntime/event_loop_poll.hpp"

static uint64_t g_now = 100u;

static uint64_t test_clock(void*) noexcept { return g_now; }

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
    assert(loop.unwatch(read_id));

    const EventLoop::WaitId writable_id = loop.watch(
        pipe_fds[1], EventLoop::WAIT_WRITABLE, ready_event);
    assert(writable_id != 0u);
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);
    assert(loop.unwatch(writable_id));

    EventLoop::WaitRequest timeout_request = {};
    timeout_request.id = 1u;
    timeout_request.nativeHandle = pipe_fds[0];
    timeout_request.events = EventLoop::WAIT_READABLE;
    EventLoop::WaitResult ready = {99u, EventLoop::WAIT_READABLE};
    assert(!backend.wait(&timeout_request, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

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
    return 0;
}
