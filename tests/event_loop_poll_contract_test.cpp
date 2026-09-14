// SPDX-License-Identifier: MIT

#include <assert.h>
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
    const EventLoop::WaitId read_id = loop.watch(
        pipe_fds[0], EventLoop::WAIT_READABLE, ready_event);
    assert(read_id != 0u);

    char byte = 'r';
    assert(write(pipe_fds[1], &byte, sizeof(byte)) == 1);
    Event output = {};
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

    assert(close(pipe_fds[1]) == 0);
    const EventLoop::WaitId hangup_id = loop.watch(
        pipe_fds[0], EventLoop::WAIT_HANGUP, ready_event);
    assert(hangup_id != 0u);
    assert(loop.wait(g_now, PollEventLoopBackend::waitFunction, &backend,
                     &output));
    assert(output.type == EventType::Close);
    assert(loop.unwatch(hangup_id));
    assert(close(pipe_fds[0]) == 0);

    timeout_request.nativeHandle = static_cast<int64_t>(INT32_MAX) + 1;
    assert(!backend.wait(&timeout_request, 1u, g_now, &ready));
    return 0;
}
