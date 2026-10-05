/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include <rin/abi.h>
#include <rin/ipc.h>

#include <rinruntime/event_loop_rin.hpp>

struct SdkArgsV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t value[6];
};

static RinWaitItemV1 g_item;
static uint32_t g_set_items_calls;
static bool g_malformed_wait_result;
static bool g_rollback_after_set;
static bool g_fail_set_items;
static uint64_t g_now = 100u;

static uint64_t test_clock(void*) noexcept { return g_now; }

static RinResult fake_invoke(uint64_t, uint32_t library, uint32_t operation,
                             const void* request, uint32_t request_size,
                             void* response, uint32_t response_size) {
    assert(library == RIN_SDK_LIBRARY_BASE ||
           library == RIN_SDK_LIBRARY_IPC);
    assert(request != nullptr);
    assert(request_size == sizeof(SdkArgsV1));
    const SdkArgsV1* args = static_cast<const SdkArgsV1*>(request);
    assert(args->struct_size == sizeof(SdkArgsV1));
    assert(args->version == RIN_SDK_STRUCT_VERSION_1);

    if (library == RIN_SDK_LIBRARY_BASE && operation == 1u) return RIN_SUCCESS;
    assert(library == RIN_SDK_LIBRARY_IPC);
    if (operation == 9u) {
        assert(response != nullptr && response_size == sizeof(RinWaitSet));
        *static_cast<RinWaitSet*>(response) = UINT64_C(0x44);
        return RIN_SUCCESS;
    }
    if (operation == 10u) {
        assert(args->value[0] == UINT64_C(0x44));
        assert(args->value[2] == sizeof(RinWaitItemV1));
        memcpy(&g_item, reinterpret_cast<const void*>(static_cast<uintptr_t>(
                   args->value[1])), sizeof(g_item));
        ++g_set_items_calls;
        if (g_fail_set_items) return RIN_ERROR_IO;
        if (g_rollback_after_set) {
            g_rollback_after_set = false;
            g_now = 90u;
        }
        return RIN_SUCCESS;
    }
    if (operation == 11u) {
        assert(args->value[0] == UINT64_C(0x44));
        assert(response != nullptr && response_size == sizeof(RinWaitResultV1));
        RinWaitResultV1* result = static_cast<RinWaitResultV1*>(response);
        result->struct_size = sizeof(*result);
        result->version = RIN_SDK_STRUCT_VERSION_1;
        if (g_malformed_wait_result) ++result->version;
        result->index = 0u;
        result->events = g_item.events;
        result->user_tag = g_item.user_tag;
        result->value = UINT64_C(0x1234);
        memset(result->reserved, 0, sizeof(result->reserved));
        return RIN_SUCCESS;
    }
    assert(false);
    return RIN_ERROR_NOT_SUPPORTED;
}

int main() {
    RinSdkBackendV1 sdk_backend = {};
    sdk_backend.struct_size = sizeof(sdk_backend);
    sdk_backend.version = RIN_SDK_STRUCT_VERSION_1;
    sdk_backend.invoke = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(
        &fake_invoke));
    assert(rin_sdk_bind_backend_v1(&sdk_backend) == RIN_SUCCESS);

    RinRuntime::RinEventLoopBackend backend(test_clock);
    assert(backend.initialize() == RIN_SUCCESS);
    assert(backend.initialized());

    RinRuntime::EventLoop loop;
    RinRuntime::Event event = {};
    event.type = RinRuntime::EventType::Close;
    assert(loop.scheduleAt(UINT64_MAX, event) == 0u);
    const uint64_t opaque_handle = UINT64_C(0xfeedface01234567);
    const RinRuntime::EventLoop::WaitId watch = loop.watch(
        opaque_handle, RinRuntime::EventLoop::WAIT_READABLE, event);
    assert(watch != 0u);
    RinRuntime::Event output = {};
    assert(loop.wait(g_now, RinRuntime::RinEventLoopBackend::waitFunction,
                     &backend, &output));
    assert(output.type == RinRuntime::EventType::Close);
    assert(g_set_items_calls == 1u);
    assert(g_item.handle == opaque_handle);
    assert(g_item.events == RinRuntime::EventLoop::WAIT_READABLE);
    assert(g_item.user_tag == watch);

    RinRuntime::EventLoop::WaitRequest valid = {};
    valid.id = watch;
    valid.nativeHandle = opaque_handle;
    valid.events = RinRuntime::EventLoop::WAIT_READABLE;
    RinRuntime::EventLoop::WaitResult ready = {};
    g_malformed_wait_result = true;
    assert(!backend.wait(&valid, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    g_malformed_wait_result = false;

    RinRuntime::EventLoop::WaitRequest aliased = valid;
    const RinRuntime::EventLoop::WaitRequest aliased_before = aliased;
    auto* aliased_ready = reinterpret_cast<RinRuntime::EventLoop::WaitResult*>(
        &aliased);
    assert(!backend.wait(&aliased, 1u, g_now, aliased_ready));
    assert(aliased.id == aliased_before.id &&
           aliased.nativeHandle == aliased_before.nativeHandle &&
           aliased.events == aliased_before.events);

    RinRuntime::EventLoop::WaitRequest invalid = {};
    invalid.id = 1u;
    invalid.nativeHandle = 0u;
    invalid.events = RinRuntime::EventLoop::WAIT_READABLE;
    ready = {};
    assert(!backend.wait(&invalid, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    RinRuntime::EventLoop::WaitRequest duplicate[2] = {};
    duplicate[0].id = 7u;
    duplicate[0].nativeHandle = opaque_handle;
    duplicate[0].events = RinRuntime::EventLoop::WAIT_READABLE;
    duplicate[1] = duplicate[0];
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(!backend.wait(duplicate, 2u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    /* The public SDK wait-set identifies readiness by opaque handle, so two
     * distinct tags for one handle are rejected before item publication. */
    duplicate[1].id = 8u;
    const uint32_t set_items_before_duplicate_handle = g_set_items_calls;
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(!backend.wait(duplicate, 2u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(backend.initialized());
    assert(g_set_items_calls == set_items_before_duplicate_handle);

    /* A clock rollback must fail before the SDK wait receives a new timeout;
     * otherwise a stale deadline can become an unbounded sleep. */
    g_now = 99u;
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    const uint32_t set_items_before_rollback = g_set_items_calls;
    assert(!backend.wait(&valid, 1u, 100u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(g_set_items_calls == set_items_before_rollback);
    g_now = 100u;

    assert(loop.unwatch(watch));

    /* Reset must retire the previous wait-set session's clock sample.  A
     * reconnected target may start its adapter clock at a lower value, which
     * must not be mistaken for a rollback within the same session. */
    g_now = 1000u;
    assert(backend.wait(&valid, 1u, 1001u, &ready));

    /* Publication can consume enough time for the monotonic source to
     * appear to roll back.  The adapter must restore the previously
     * published item list before returning failure instead of leaving the
     * target wait-set with an unissued request. */
    RinRuntime::EventLoop::WaitRequest rollback_request = {};
    rollback_request.id = 88u;
    rollback_request.nativeHandle = opaque_handle;
    rollback_request.events = RinRuntime::EventLoop::WAIT_WRITABLE;
    const uint32_t set_items_before_rollback_after_publish =
        g_set_items_calls;
    g_rollback_after_set = true;
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(!backend.wait(&rollback_request, 1u, 1001u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(g_set_items_calls ==
           set_items_before_rollback_after_publish + 2u);
    assert(g_item.events == RinRuntime::EventLoop::WAIT_READABLE);
    assert(g_item.user_tag == valid.id);
    g_now = 1000u;

    /* If item publication itself fails, the target-side wait-set is no
     * longer a trustworthy session.  The public adapter must retire it
     * rather than retain a mismatched local item list. */
    g_fail_set_items = true;
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(!backend.wait(&valid, 1u, 1001u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(!backend.initialized());
    g_fail_set_items = false;
    g_now = 1000u;
    assert(backend.initialize() == RIN_SUCCESS);

    assert(backend.reset() == RIN_SUCCESS);
    assert(!backend.initialized());
    g_now = 10u;
    assert(backend.initialize() == RIN_SUCCESS);
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(backend.wait(&valid, 1u, 11u, &ready));
    assert(ready.id == valid.id &&
           ready.events == RinRuntime::EventLoop::WAIT_READABLE);

    /* UINT64_MAX is EventLoop's no-deadline sentinel, not a valid clock
     * sample.  The RinOS adapter must fail before mutating the target
     * wait-set or publishing a ready result for a finite deadline. */
    const uint32_t set_items_before_sentinel = g_set_items_calls;
    g_now = UINT64_MAX;
    ready = {99u, RinRuntime::EventLoop::WAIT_READABLE};
    assert(!backend.wait(&valid, 1u, UINT64_MAX - 1u, &ready));
    assert(ready.id == 0u && ready.events == 0u);
    assert(g_set_items_calls == set_items_before_sentinel);

    /* Cancellation must wake a caller that already consumed the scheduling
     * notification; otherwise a backend can sleep until a stale deadline. */
    RinRuntime::EventLoop wake_loop;
    const RinRuntime::EventLoop::TimerId wake_timer =
        wake_loop.scheduleAt(g_now + 1000000000u, event);
    assert(wake_timer != 0u);
    assert(wake_loop.consumeWake());
    assert(!wake_loop.consumeWake());
    assert(wake_loop.cancelTimer(wake_timer));
    assert(wake_loop.consumeWake());
    assert(!wake_loop.consumeWake());

    assert(backend.reset() == RIN_SUCCESS);
    assert(!backend.initialized());
    return 0;
}
