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
        return RIN_SUCCESS;
    }
    if (operation == 11u) {
        assert(args->value[0] == UINT64_C(0x44));
        assert(response != nullptr && response_size == sizeof(RinWaitResultV1));
        RinWaitResultV1* result = static_cast<RinWaitResultV1*>(response);
        result->struct_size = sizeof(*result);
        result->version = RIN_SDK_STRUCT_VERSION_1;
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

    RinRuntime::EventLoop::WaitRequest invalid = {};
    invalid.id = 1u;
    invalid.nativeHandle = 0u;
    invalid.events = RinRuntime::EventLoop::WAIT_READABLE;
    RinRuntime::EventLoop::WaitResult ready = {};
    assert(!backend.wait(&invalid, 1u, g_now, &ready));
    assert(ready.id == 0u && ready.events == 0u);

    assert(loop.unwatch(watch));
    assert(backend.reset() == RIN_SUCCESS);
    assert(!backend.initialized());
    return 0;
}
