/* SPDX-License-Identifier: MIT */

#include <rinruntime/rin_web_serial_portal.h>
#include <rinwire/capability.h>

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

/* VFS mode values are part of the public RinOS app ABI.  Nonblocking reads
 * are essential for a Web Serial readable stream: an empty RX queue is an
 * ordinary pending-read condition, not a process-wide stall. */
#define RIN_WEB_SERIAL_O_RDWR UINT32_C(0x0003)
#define RIN_WEB_SERIAL_O_NONBLOCK UINT32_C(0x0040)

static RinWebSerialFileOpsV1 g_ops;
static int g_ops_installed;
static int g_custom_file_ops;
static RinWebSerialIdentityQueryV1 g_identity_query;
static void* g_identity_query_context;
static RinWebSerialPortalTransportV1 g_portal;
static RinWebSerialPortalExchangeForPageV1 g_portal_page_exchange;
static int g_portal_installed;

#define RIN_WEB_SERIAL_PORTAL_MAX_OPEN UINT32_C(16)
#define RIN_WEB_SERIAL_PORTAL_HANDLE_BASE UINT32_C(0x80000000)
#define RIN_WEB_SERIAL_PORTAL_MAX_EVENTS \
    (RIN_WEB_SERIAL_MAX_DEVICES * UINT32_C(2))

#if !defined(_WIN32)
static int default_fd(uint32_t handle)
{
    if (handle == 0u || handle >= RIN_WEB_SERIAL_PORTAL_HANDLE_BASE ||
        handle - 1u > (uint32_t)INT_MAX)
        return -1;
    return (int)(handle - 1u);
}

static int default_errno_result(void)
{
    switch (errno) {
    case EACCES:
    case EPERM: return RIN_SERIAL_EPERM;
    case EAGAIN: return RIN_SERIAL_EAGAIN;
    case EBADF: return RIN_SERIAL_EBADF;
    case EINVAL: return RIN_SERIAL_EINVAL;
    case ENODEV: return RIN_SERIAL_ENODEV;
    case ENOENT: return RIN_SERIAL_ENODEV;
    case ENOTTY: return RIN_SERIAL_ENOTSUP;
    default: return RIN_SERIAL_EIO;
    }
}
#else
static int default_errno_result(void)
{
    return RIN_SERIAL_ENOTSUP;
}
#endif

static int web_serial_ranges_overlap(const void* first, size_t first_size,
                                     const void* second, size_t second_size)
{
    uintptr_t first_address;
    uintptr_t second_address;

    if (first == NULL || second == NULL || first_size == 0u ||
        second_size == 0u)
        return 0;
    first_address = (uintptr_t)first;
    second_address = (uintptr_t)second;
    if (first_address < second_address)
        return second_address - first_address < first_size;
    return first_address - second_address < second_size;
}

typedef struct RinWebSerialPortalOpenSlot {
    uint32_t handle;
    uint32_t page_id;
    RinSerialCapabilityV1 capability;
    uint8_t used;
} RinWebSerialPortalOpenSlot;

static RinWebSerialPortalOpenSlot g_portal_open[RIN_WEB_SERIAL_PORTAL_MAX_OPEN];
static RinWebSerialDeviceV1 g_portal_snapshot[RIN_WEB_SERIAL_MAX_DEVICES];
static uint32_t g_portal_snapshot_count;
static int g_portal_snapshot_valid;
static RinWebSerialEventV1 g_portal_events[RIN_WEB_SERIAL_PORTAL_MAX_EVENTS];
static uint32_t g_portal_event_head;
static uint32_t g_portal_event_tail;
static uint32_t g_portal_event_count;

static uint64_t portal_next_request_id(void);

static int portal_valid(void)
{
    return g_portal_installed &&
           g_portal.exchange != NULL &&
           g_portal.session_id != 0u && g_portal.session_generation != 0u;
}

static int portal_exchange_for_page(uint32_t page_id, const void* request,
                                    size_t request_size, void* response,
                                    size_t response_capacity,
                                    size_t* response_size)
{
    if (!portal_valid() || !request || !response || !response_size)
        return RIN_SERIAL_EPERM;
    *response_size = 0u;
    if (page_id != 0u) {
        if (g_portal_page_exchange == NULL)
            return RIN_SERIAL_EPERM;
        return g_portal_page_exchange(
            g_portal.context, page_id, request, request_size, response,
            response_capacity, response_size);
    }
    if (g_portal.exchange != NULL)
        return g_portal.exchange(g_portal.context, request, request_size,
                                 response, response_capacity, response_size);
    return RIN_SERIAL_EPERM;
}

static int portal_exchange(const void* request, size_t request_size,
                           void* response, size_t response_capacity,
                           size_t* response_size)
{
    return portal_exchange_for_page(0u, request, request_size, response,
                                    response_capacity, response_size);
}

static int portal_session_matches(const RinSerialPortalFrameV1* frame,
                                  uint64_t request_id)
{
    return frame != NULL &&
           rin_wire_capability_response_valid(
               request_id, g_portal.session_generation, frame->request_id,
               frame->session_generation) == RIN_WIRE_CAPABILITY_OK &&
           frame->session_id == g_portal.session_id &&
           frame->session_generation != 0u;
}

static int portal_device_allowed(const RinSerialPortalDeviceV1* device)
{
    const uint32_t denied = RIN_SERIAL_DEVICE_FLAG_SYSTEM |
        RIN_SERIAL_DEVICE_FLAG_DEBUG | RIN_SERIAL_DEVICE_FLAG_CRITICAL |
        RIN_SERIAL_DEVICE_FLAG_BROWSER_DENY;
    return device != NULL && device->capability.object_id != 0u &&
           device->capability.generation != 0u &&
           (device->info.flags & denied) == 0u &&
           (device->info.capabilities &
            (RIN_SERIAL_CAP_READ | RIN_SERIAL_CAP_WRITE)) ==
               (RIN_SERIAL_CAP_READ | RIN_SERIAL_CAP_WRITE);
}

static RinWebSerialPortalOpenSlot* portal_slot(uint32_t handle)
{
    uint32_t index;
    if (handle < RIN_WEB_SERIAL_PORTAL_HANDLE_BASE ||
        handle - RIN_WEB_SERIAL_PORTAL_HANDLE_BASE >=
            RIN_WEB_SERIAL_PORTAL_MAX_OPEN)
        return NULL;
    index = handle - RIN_WEB_SERIAL_PORTAL_HANDLE_BASE;
    return g_portal_open[index].used ? &g_portal_open[index] : NULL;
}

static RinWebSerialPortalOpenSlot* portal_allocate_slot(void)
{
    uint32_t index;
    for (index = 0u; index < RIN_WEB_SERIAL_PORTAL_MAX_OPEN; ++index) {
        if (!g_portal_open[index].used) {
            memset(&g_portal_open[index], 0, sizeof(g_portal_open[index]));
            g_portal_open[index].used = 1u;
            g_portal_open[index].handle =
                RIN_WEB_SERIAL_PORTAL_HANDLE_BASE + index;
            return &g_portal_open[index];
        }
    }
    return NULL;
}

static int portal_map_result(RinSerialPortalResultV1 result)
{
    switch (result) {
    case RIN_SERIAL_PORTAL_OK: return RIN_SERIAL_OK;
    case RIN_SERIAL_PORTAL_PENDING: return RIN_SERIAL_EAGAIN;
    case RIN_SERIAL_PORTAL_INVALID_ARGUMENT: return RIN_SERIAL_EINVAL;
    case RIN_SERIAL_PORTAL_DENIED: return RIN_SERIAL_EPERM;
    case RIN_SERIAL_PORTAL_STALE: return RIN_SERIAL_EBADF;
    case RIN_SERIAL_PORTAL_DISCONNECTED: return RIN_SERIAL_ENODEV;
    case RIN_SERIAL_PORTAL_LIMIT: return RIN_SERIAL_EOVERFLOW;
    default: return RIN_SERIAL_EIO;
    }
}

static void portal_release_slot(RinWebSerialPortalOpenSlot* slot)
{
    if (slot != NULL) memset(slot, 0, sizeof(*slot));
}

static void portal_event_state_reset(void)
{
    memset(g_portal_snapshot, 0, sizeof(g_portal_snapshot));
    g_portal_snapshot_count = 0u;
    g_portal_snapshot_valid = 0;
    memset(g_portal_events, 0, sizeof(g_portal_events));
    g_portal_event_head = 0u;
    g_portal_event_tail = 0u;
    g_portal_event_count = 0u;
}

static int portal_device_snapshot_equal(const RinWebSerialDeviceV1* left,
                                        const RinWebSerialDeviceV1* right)
{
    return left != NULL && right != NULL &&
           left->capability.object_id == right->capability.object_id &&
           left->capability.generation == right->capability.generation;
}

static int portal_snapshot_contains(const RinWebSerialDeviceV1* devices,
                                    uint32_t count,
                                    const RinWebSerialDeviceV1* needle)
{
    uint32_t index;
    if (devices == NULL || needle == NULL || count > RIN_WEB_SERIAL_MAX_DEVICES)
        return 0;
    for (index = 0u; index < count; ++index)
        if (portal_device_snapshot_equal(&devices[index], needle)) return 1;
    return 0;
}

static int portal_event_enqueue(const RinWebSerialDeviceV1* device,
                                uint32_t connected)
{
    RinWebSerialEventV1* event;
    if (device == NULL || g_portal_event_count >= RIN_WEB_SERIAL_PORTAL_MAX_EVENTS)
        return RIN_SERIAL_EOVERFLOW;
    event = &g_portal_events[g_portal_event_tail];
    memset(event, 0, sizeof(*event));
    event->device = *device;
    event->connected = connected;
    g_portal_event_tail =
        (g_portal_event_tail + 1u) % RIN_WEB_SERIAL_PORTAL_MAX_EVENTS;
    ++g_portal_event_count;
    return RIN_SERIAL_OK;
}

static int portal_event_dequeue(RinWebSerialEventV1* event_out)
{
    if (event_out == NULL || g_portal_event_count == 0u)
        return RIN_SERIAL_EAGAIN;
    *event_out = g_portal_events[g_portal_event_head];
    memset(&g_portal_events[g_portal_event_head], 0,
           sizeof(g_portal_events[g_portal_event_head]));
    g_portal_event_head =
        (g_portal_event_head + 1u) % RIN_WEB_SERIAL_PORTAL_MAX_EVENTS;
    --g_portal_event_count;
    return RIN_SERIAL_OK;
}

static int portal_enumerate(RinWebSerialDeviceV1* output, uint32_t capacity,
                            uint32_t* count_out)
{
    RinSerialPortalFrameV1 request;
    RinSerialPortalEnumerateResponseV1 response;
    const RinSerialPortalDeviceV1* records = NULL;
    size_t count = 0u;
    size_t response_size = 0u;
    uint64_t request_id = portal_next_request_id();
    size_t index;
    uint32_t visible = 0u;
    if (web_serial_ranges_overlap(
            output, (size_t)capacity * sizeof(*output), count_out,
            sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    if (rin_serial_portal_request_encode(
            request_id, g_portal.session_id, g_portal.session_generation,
            RIN_SERIAL_PORTAL_ENUMERATE_REQUEST, &request) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange(&request, sizeof(request), &response, sizeof(response),
                        &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_enumerate_response_decode(
            &response, response_size, NULL, &records, &count, NULL, NULL, NULL) !=
        RIN_SERIAL_PORTAL_OK || !portal_session_matches(
            &response.frame, request.request_id))
        return RIN_SERIAL_EIO;
    if (response.result != RIN_SERIAL_PORTAL_OK)
        return portal_map_result((RinSerialPortalResultV1)response.result);
    for (index = 0u; index < count; ++index) {
        RinWebSerialDeviceV1 device;
        if (!portal_device_allowed(&records[index])) continue;
        if (visible < capacity && output != NULL) {
            memset(&device, 0, sizeof(device));
            device.info = records[index].info;
            device.capability = records[index].capability;
            output[visible] = device;
        }
        ++visible;
    }
    *count_out = visible;
    return visible > capacity ? RIN_SERIAL_EOVERFLOW : RIN_SERIAL_OK;
}

static int portal_refresh_event_snapshot(void)
{
    RinWebSerialDeviceV1 devices[RIN_WEB_SERIAL_MAX_DEVICES];
    uint32_t count = 0u;
    uint32_t index;
    int result;
    memset(devices, 0, sizeof(devices));
    result = portal_enumerate(devices, RIN_WEB_SERIAL_MAX_DEVICES, &count);
    if (result != RIN_SERIAL_OK)
        return result;

    if (!g_portal_snapshot_valid) {
        memcpy(g_portal_snapshot, devices, sizeof(devices));
        g_portal_snapshot_count = count;
        g_portal_snapshot_valid = 1;
        return RIN_SERIAL_EAGAIN;
    }

    g_portal_event_head = 0u;
    g_portal_event_tail = 0u;
    g_portal_event_count = 0u;
    for (index = 0u; index < g_portal_snapshot_count; ++index) {
        if (portal_snapshot_contains(devices, count,
                                     &g_portal_snapshot[index]))
            continue;
        if (portal_event_enqueue(&g_portal_snapshot[index], 0u) !=
            RIN_SERIAL_OK) {
            portal_event_state_reset();
            return RIN_SERIAL_EOVERFLOW;
        }
    }
    for (index = 0u; index < count; ++index) {
        if (portal_snapshot_contains(g_portal_snapshot,
                                     g_portal_snapshot_count, &devices[index]))
            continue;
        if (portal_event_enqueue(&devices[index], 1u) != RIN_SERIAL_OK) {
            portal_event_state_reset();
            return RIN_SERIAL_EOVERFLOW;
        }
    }

    memcpy(g_portal_snapshot, devices, sizeof(devices));
    g_portal_snapshot_count = count;
    return g_portal_event_count == 0u ? RIN_SERIAL_EAGAIN : RIN_SERIAL_OK;
}

static int portal_request_port(const char* origin, uint32_t user_activation,
                               const RinSerialPortalFilterV1* filters,
                               uint32_t filter_count, uint64_t selected_object_id,
                               RinWebSerialDeviceV1* output)
{
    RinSerialPortalRequestPortRequestV1 request;
    RinSerialPortalRequestPortResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialPortalDeviceV1 device;
    size_t response_size = 0u;
    if (!output || rin_serial_portal_request_port_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, origin, user_activation, filters,
            filter_count, selected_object_id, &request) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    memset(&response, 0, sizeof(response));
    if (portal_exchange(&request, sizeof(request), &response, sizeof(response),
                        &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_request_port_response_decode(
            &response, response_size, &result, &device, NULL, NULL, NULL) !=
        RIN_SERIAL_PORTAL_OK || !portal_session_matches(
            &response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK)
        return portal_map_result(result);
    if (!portal_device_allowed(&device))
        return RIN_SERIAL_EPERM;
    memset(output, 0, sizeof(*output));
    output->info = device.info;
    output->capability = device.capability;
    return RIN_SERIAL_OK;
}

static int portal_request_port_begin(uint32_t page_id, const char* origin,
                                     uint32_t user_activation,
                                     const RinSerialPortalFilterV1* filters,
                                     uint32_t filter_count,
                                     uint64_t* request_id_out)
{
    RinSerialPortalRequestPortRequestV1 request;
    RinSerialPortalRequestPortResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    uint64_t request_id = portal_next_request_id();
    size_t response_size = 0u;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (page_id == 0u || request_id_out == NULL ||
        rin_serial_portal_request_port_encode(
            request_id, g_portal.session_id, g_portal.session_generation,
            origin, user_activation, filters, filter_count, 0u, &request) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    memset(&response, 0, sizeof(response));
    if (portal_exchange_for_page(page_id, &request, sizeof(request),
                                 &response, sizeof(response),
                                 &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_request_port_response_decode(
            &response, response_size, &result, NULL, NULL, NULL, NULL) !=
        RIN_SERIAL_PORTAL_OK || !portal_session_matches(
            &response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_PENDING)
        return portal_map_result(result);
    *request_id_out = request_id;
    return RIN_SERIAL_EAGAIN;
}

static int portal_request_port_poll(uint32_t page_id, const char* origin,
                                    uint64_t chooser_id,
                                    RinWebSerialDeviceV1* output)
{
    RinSerialPortalRequestPortPollRequestV1 request;
    RinSerialPortalRequestPortPollResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialPortalDeviceV1 device;
    size_t response_size = 0u;
    if (output != NULL) memset(output, 0, sizeof(*output));
    if (page_id == 0u || output == NULL ||
        rin_serial_portal_request_port_poll_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, chooser_id, origin, &request) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    memset(&response, 0, sizeof(response));
    if (portal_exchange_for_page(page_id, &request, sizeof(request),
                                 &response, sizeof(response),
                                 &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_request_port_poll_response_decode(
            &response, response_size, &result, &device, NULL, NULL, NULL) !=
        RIN_SERIAL_PORTAL_OK || !portal_session_matches(
            &response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result == RIN_SERIAL_PORTAL_PENDING)
        return RIN_SERIAL_EAGAIN;
    if (result != RIN_SERIAL_PORTAL_OK)
        return portal_map_result(result);
    if (!portal_device_allowed(&device))
        return RIN_SERIAL_EPERM;
    output->info = device.info;
    output->capability = device.capability;
    return RIN_SERIAL_OK;
}

static int portal_get_ports(uint32_t page_id, const char* origin,
                            RinWebSerialDeviceV1* output,
                            uint32_t capacity, uint32_t* count_out)
{
    RinSerialPortalGetPortsRequestV1 request;
    RinSerialPortalGetPortsResponseV1 response;
    const RinSerialPortalDeviceV1* devices = NULL;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    size_t count = 0u;
    size_t response_size = 0u;
    if (!count_out || (capacity != 0u && !output) ||
        capacity > RIN_WEB_SERIAL_MAX_DEVICES)
        return RIN_SERIAL_EINVAL;
    if (web_serial_ranges_overlap(
            output, (size_t)capacity * sizeof(*output), count_out,
            sizeof(*count_out)) ||
        rin_serial_portal_get_ports_request_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, origin, &request) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    *count_out = 0u;
    memset(&response, 0, sizeof(response));
    if (portal_exchange_for_page(page_id, &request, sizeof(request),
                                 &response, sizeof(response),
                                 &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_get_ports_response_decode(
            &response, response_size, &result, &devices, &count, NULL, NULL,
            NULL) != RIN_SERIAL_PORTAL_OK || !portal_session_matches(
            &response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK)
        return portal_map_result(result);
    for (size_t index = 0u; index < count; ++index) {
        if (!portal_device_allowed(&devices[index])) continue;
        if (*count_out < capacity) {
            output[*count_out].info = devices[index].info;
            output[*count_out].capability = devices[index].capability;
        }
        ++*count_out;
    }
    return *count_out > capacity ? RIN_SERIAL_EOVERFLOW : RIN_SERIAL_OK;
}

static int portal_open(uint32_t page_id, RinSerialCapabilityV1 capability,
                       const RinSerialConfigV1* config, uint32_t flags,
                       uint32_t* handle_out)
{
    RinSerialPortalOpenRequestV1 request;
    RinSerialPortalOpenResponseV1 response;
    RinWebSerialPortalOpenSlot* slot;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    uint64_t request_id = portal_next_request_id();
    uint64_t response_request_id = 0u;
    uint64_t response_session_id = 0u;
    uint64_t response_generation = 0u;
    size_t response_size = 0u;
    if (!handle_out || !config) return RIN_SERIAL_EINVAL;
    slot = portal_allocate_slot();
    if (!slot) return RIN_SERIAL_ENOSPC;
    if (rin_serial_portal_open_request_encode(
            request_id, g_portal.session_id, g_portal.session_generation,
            capability, *config, flags, &request) != RIN_SERIAL_PORTAL_OK) {
        portal_release_slot(slot);
        return RIN_SERIAL_EINVAL;
    }
    if (portal_exchange_for_page(page_id, &request, sizeof(request), &response,
                                 sizeof(response), &response_size) != 0) {
        portal_release_slot(slot);
        return RIN_SERIAL_EIO;
    }
    if (rin_serial_portal_open_response_decode(
            &response, response_size, RIN_SERIAL_PORTAL_OPEN_RESPONSE, &result,
            &response_capability, &response_request_id, &response_session_id,
            &response_generation) != RIN_SERIAL_PORTAL_OK ||
        !portal_session_matches(&response.frame, request.frame.request_id)) {
        portal_release_slot(slot);
        return RIN_SERIAL_EIO;
    }
    if (result != RIN_SERIAL_PORTAL_OK) {
        portal_release_slot(slot);
        return portal_map_result(result);
    }
    if (response_capability.object_id != capability.object_id ||
        response_capability.generation != capability.generation) {
        portal_release_slot(slot);
        return RIN_SERIAL_EBADF;
    }
    slot->capability = response_capability;
    slot->page_id = page_id;
    *handle_out = slot->handle;
    return RIN_SERIAL_OK;
}

static int portal_close(uint32_t handle)
{
    RinWebSerialPortalOpenSlot* slot = portal_slot(handle);
    RinSerialPortalCloseRequestV1 request;
    RinSerialPortalOpenResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    uint64_t response_request_id = 0u;
    uint64_t response_session_id = 0u;
    uint64_t response_generation = 0u;
    size_t response_size = 0u;
    if (!slot) return RIN_SERIAL_EBADF;
    if (rin_serial_portal_close_request_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation,
            slot->capability, &request) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange_for_page(slot->page_id, &request, sizeof(request),
                                 &response, sizeof(response), &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_open_response_decode(
            &response, response_size, RIN_SERIAL_PORTAL_CLOSE_RESPONSE, &result,
            &response_capability, &response_request_id, &response_session_id,
            &response_generation) != RIN_SERIAL_PORTAL_OK ||
        !portal_session_matches(&response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (response_capability.object_id != slot->capability.object_id ||
        response_capability.generation != slot->capability.generation)
        return RIN_SERIAL_EBADF;
    /* STALE is an authenticated acknowledgement that this capability no
     * longer names an open backend handle in the server session. */
    if (result != RIN_SERIAL_PORTAL_OK && result != RIN_SERIAL_PORTAL_STALE)
        return portal_map_result(result);
    portal_release_slot(slot);
    return RIN_SERIAL_OK;
}

static int portal_drain_open_slots(void)
{
    uint32_t index;
    int first_error = RIN_SERIAL_OK;

    for (index = 0u; index < RIN_WEB_SERIAL_PORTAL_MAX_OPEN; ++index) {
        RinWebSerialPortalOpenSlot* slot = &g_portal_open[index];
        int result;
        if (!slot->used) continue;
        result = portal_close(slot->handle);
        if (result != RIN_SERIAL_OK && first_error == RIN_SERIAL_OK)
            first_error = result;
    }
    return first_error;
}

static uint64_t portal_next_request_id(void)
{
    static uint64_t next_id = 0u;
    if (next_id >= UINT64_MAX - 1u) return 0u;
    return ++next_id;
}

static int portal_transfer(uint32_t handle, uint8_t operation,
                           const uint8_t* input, size_t input_count,
                           uint8_t* output, size_t output_capacity,
                           size_t* count_out)
{
    RinWebSerialPortalOpenSlot* slot = portal_slot(handle);
    uint8_t request[sizeof(RinSerialPortalTransferV1) + RIN_SERIAL_BUFFER_MAX];
    RinSerialPortalTransferResponseV1 response;
    size_t request_size = 0u;
    size_t response_size = 0u;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    const uint8_t* response_bytes = NULL;
    size_t response_count = 0u;
    uint64_t request_id;
    if (web_serial_ranges_overlap(input, input_count, count_out,
                                  sizeof(*count_out)) ||
        web_serial_ranges_overlap(output, output_capacity, count_out,
                                  sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    if (count_out) *count_out = 0u;
    if (!slot || (operation != RIN_SERIAL_PORTAL_READ_REQUEST &&
                  operation != RIN_SERIAL_PORTAL_WRITE_REQUEST) ||
        (input_count != 0u && !input) || input_count > RIN_SERIAL_BUFFER_MAX ||
        (output_capacity != 0u && !output))
        return RIN_SERIAL_EINVAL;
    request_id = portal_next_request_id();
    if (rin_serial_portal_transfer_encode(
            request_id, g_portal.session_id,
            g_portal.session_generation, (RinSerialPortalOperationV1)operation,
            slot->capability, input, input_count, request, sizeof(request),
            &request_size) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange_for_page(slot->page_id, request, request_size,
                                 &response, sizeof(response), &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_transfer_response_decode(
            &response, response_size,
            operation == RIN_SERIAL_PORTAL_READ_REQUEST
                ? RIN_SERIAL_PORTAL_READ_RESPONSE
                : RIN_SERIAL_PORTAL_WRITE_RESPONSE,
            &result, &response_capability, &response_bytes,
            &response_count) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EIO;
    if (!portal_session_matches(&response.frame, request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK) return portal_map_result(result);
    if (response_capability.object_id != slot->capability.object_id ||
        response_capability.generation != slot->capability.generation)
        return RIN_SERIAL_EBADF;
    if (response_count > (operation == RIN_SERIAL_PORTAL_READ_REQUEST
                             ? output_capacity : input_count))
        return RIN_SERIAL_EOVERFLOW;
    if (output && response_count != 0u)
        memcpy(output, response_bytes, response_count);
    if (count_out) *count_out = response_count;
    return RIN_SERIAL_OK;
}

static int portal_set_signals(uint32_t handle, RinSerialSignalsV1 signals)
{
    RinWebSerialPortalOpenSlot* slot = portal_slot(handle);
    RinSerialPortalSignalsRequestV1 request;
    RinSerialPortalOpenResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    uint64_t response_request_id = 0u;
    uint64_t response_session_id = 0u;
    uint64_t response_generation = 0u;
    size_t response_size = 0u;
    if (!slot) return RIN_SERIAL_EBADF;
    if (rin_serial_portal_signals_request_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, RIN_SERIAL_PORTAL_SET_SIGNALS_REQUEST,
            slot->capability, signals, &request) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange_for_page(slot->page_id, &request, sizeof(request),
                                 &response, sizeof(response), &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_open_response_decode(
            &response, response_size, RIN_SERIAL_PORTAL_SET_SIGNALS_RESPONSE,
            &result, &response_capability, &response_request_id,
            &response_session_id, &response_generation) != RIN_SERIAL_PORTAL_OK ||
        !portal_session_matches(&response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK) return portal_map_result(result);
    return response_capability.object_id == slot->capability.object_id &&
               response_capability.generation == slot->capability.generation
        ? RIN_SERIAL_OK : RIN_SERIAL_EBADF;
}

static int portal_get_signals(uint32_t handle, RinSerialStatusV1* status_out)
{
    RinWebSerialPortalOpenSlot* slot = portal_slot(handle);
    RinSerialPortalSignalsRequestV1 request;
    RinSerialPortalStatusResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    uint64_t response_request_id = 0u;
    uint64_t response_session_id = 0u;
    uint64_t response_generation = 0u;
    size_t response_size = 0u;
    if (!slot || !status_out) return RIN_SERIAL_EINVAL;
    memset(status_out, 0, sizeof(*status_out));
    if (rin_serial_portal_signals_request_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST,
            slot->capability, (RinSerialSignalsV1){ 0u, 0u, 0u, 0u }, &request) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange_for_page(slot->page_id, &request, sizeof(request),
                                 &response, sizeof(response), &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_status_response_decode(
            &response, response_size, &result, &response_capability, status_out,
            &response_request_id, &response_session_id,
            &response_generation) != RIN_SERIAL_PORTAL_OK ||
        !portal_session_matches(&response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK) return portal_map_result(result);
    return response_capability.object_id == slot->capability.object_id &&
               response_capability.generation == slot->capability.generation
        ? RIN_SERIAL_OK : RIN_SERIAL_EBADF;
}

static int portal_wait(uint32_t handle, uint32_t events,
                       RinSerialWaitResultV1* result_out)
{
    RinWebSerialPortalOpenSlot* slot = portal_slot(handle);
    RinSerialPortalWaitRequestV1 request;
    RinSerialPortalWaitResponseV1 response;
    RinSerialPortalResultV1 result = RIN_SERIAL_PORTAL_MALFORMED;
    RinSerialCapabilityV1 response_capability;
    RinSerialWaitResultV1 wait_result;
    uint64_t response_request_id = 0u;
    uint64_t response_session_id = 0u;
    uint64_t response_generation = 0u;
    size_t response_size = 0u;
    if (!slot || !result_out) return RIN_SERIAL_EINVAL;
    memset(result_out, 0, sizeof(*result_out));
    if (rin_serial_portal_wait_request_encode(
            portal_next_request_id(), g_portal.session_id,
            g_portal.session_generation, slot->capability, events, &request) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_EINVAL;
    if (portal_exchange_for_page(slot->page_id, &request, sizeof(request),
                                 &response, sizeof(response), &response_size) != 0)
        return RIN_SERIAL_EIO;
    if (rin_serial_portal_wait_response_decode(
            &response, response_size, &result, &response_capability,
            &wait_result, &response_request_id, &response_session_id,
            &response_generation) != RIN_SERIAL_PORTAL_OK ||
        !portal_session_matches(&response.frame, request.frame.request_id))
        return RIN_SERIAL_EIO;
    if (result != RIN_SERIAL_PORTAL_OK) return portal_map_result(result);
    if (response_capability.object_id != slot->capability.object_id ||
        response_capability.generation != slot->capability.generation)
        return RIN_SERIAL_EBADF;
    *result_out = wait_result;
    return RIN_SERIAL_OK;
}

static uint32_t default_open(void* context, const char* path, uint32_t flags)
{
#if defined(_WIN32)
    (void)context;
    (void)path;
    (void)flags;
    return 0u;
#else
    int open_flags = O_RDWR;
    int descriptor;
    (void)context;
    if (!path || (flags & UINT32_C(0x0003)) != RIN_WEB_SERIAL_O_RDWR)
        return 0u;
    if ((flags & RIN_WEB_SERIAL_O_NONBLOCK) != 0u)
        open_flags |= O_NONBLOCK;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOCTTY
    open_flags |= O_NOCTTY;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif
    descriptor = open(path, open_flags);
    if (descriptor < 0) return 0u;
    if ((uint32_t)descriptor >= RIN_WEB_SERIAL_PORTAL_HANDLE_BASE - 1u) {
        (void)close(descriptor);
        return 0u;
    }
    return (uint32_t)descriptor + 1u;
#endif
}

static int default_close(void* context, uint32_t handle)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    return RIN_SERIAL_ENOTSUP;
#else
    int descriptor = default_fd(handle);
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    return close(descriptor) == 0 ? RIN_SERIAL_OK : default_errno_result();
#endif
}

static int default_read(void* context, uint32_t handle, void* bytes,
                        size_t capacity)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)bytes;
    (void)capacity;
    return RIN_SERIAL_ENOTSUP;
#else
    int descriptor = default_fd(handle);
    ssize_t result;
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    if ((!bytes && capacity != 0u) || capacity > (size_t)INT_MAX)
        return RIN_SERIAL_EINVAL;
    result = read(descriptor, bytes, capacity);
    if (result < 0) return default_errno_result();
    return (int)result;
#endif
}

static int default_write(void* context, uint32_t handle, const void* bytes,
                         size_t count)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)bytes;
    (void)count;
    return RIN_SERIAL_ENOTSUP;
#else
    int descriptor = default_fd(handle);
    ssize_t result;
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    if ((!bytes && count != 0u) || count > (size_t)INT_MAX)
        return RIN_SERIAL_EINVAL;
    result = write(descriptor, bytes, count);
    if (result < 0) return default_errno_result();
    return (int)result;
#endif
}

static int default_configure(void* context, uint32_t handle,
                             const RinSerialConfigV1* config)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)config;
    return RIN_SERIAL_ENOTSUP;
#else
    int result;
    int descriptor = default_fd(handle);
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    if (!config) return RIN_SERIAL_EINVAL;
    result = ioctl(descriptor, RIN_SERIAL_IOCTL_SET_CONFIG, config);
    return result == 0 ? RIN_SERIAL_OK : default_errno_result();
#endif
}

static int default_set_signals(void* context, uint32_t handle, uint8_t dtr,
                               uint8_t rts, uint8_t break_signal)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)dtr;
    (void)rts;
    (void)break_signal;
    return RIN_SERIAL_ENOTSUP;
#else
    RinSerialSignalsV1 signals;
    int result;
    int descriptor = default_fd(handle);
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    signals.dtr = dtr;
    signals.rts = rts;
    signals.break_signal = break_signal;
    signals.reserved0 = 0u;
    result = ioctl(descriptor, RIN_SERIAL_IOCTL_SET_SIGNALS, &signals);
    return result == 0 ? RIN_SERIAL_OK : default_errno_result();
#endif
}

static int default_get_signals(void* context, uint32_t handle,
                               RinSerialStatusV1* status)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)status;
    return RIN_SERIAL_ENOTSUP;
#else
    int result;
    int descriptor = default_fd(handle);
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    if (!status) return RIN_SERIAL_EINVAL;
    result = ioctl(descriptor, RIN_SERIAL_IOCTL_GET_SIGNALS, status);
    return result == 0 ? RIN_SERIAL_OK : default_errno_result();
#endif
}

static int default_get_identity(uint32_t handle,
                                RinSerialDeviceIdentityV1* identity)
{
    int result;
#if !defined(_WIN32)
    int descriptor;
#endif
    if (!identity || handle == 0u) return RIN_SERIAL_EINVAL;
    memset(identity, 0, sizeof(*identity));
    if (g_identity_query) {
        result = g_identity_query(g_identity_query_context, handle, identity);
    } else if (g_custom_file_ops) {
        return RIN_SERIAL_ENOTSUP;
    } else {
#if defined(_WIN32)
        return RIN_SERIAL_ENOTSUP;
#else
        descriptor = default_fd(handle);
        if (descriptor < 0) return RIN_SERIAL_EINVAL;
        result = ioctl(descriptor, RIN_SERIAL_IOCTL_GET_IDENTITY, identity);
#endif
    }
    if (result != 0) {
        memset(identity, 0, sizeof(*identity));
        return g_custom_file_ops || g_identity_query
            ? RIN_SERIAL_ENOTSUP : default_errno_result();
    }
    if (identity->abi_version != RIN_SERIAL_ABI_VERSION ||
        identity->struct_size != sizeof(*identity) ||
        identity->object_id == 0u || identity->object_id == UINT64_MAX ||
        identity->generation == 0u || identity->generation == UINT64_MAX ||
        identity->reserved0[0] != 0u || identity->reserved0[1] != 0u ||
        identity->reserved_tail[0] != 0u ||
        identity->reserved_tail[1] != 0u ||
        identity->reserved_tail[2] != 0u ||
        identity->reserved_tail[3] != 0u) {
        memset(identity, 0, sizeof(*identity));
        return RIN_SERIAL_EIO;
    }
    return RIN_SERIAL_OK;
}

static int default_wait(void* context, uint32_t handle, uint32_t events,
                        RinSerialWaitResultV1* result)
{
#if defined(_WIN32)
    (void)context;
    (void)handle;
    (void)events;
    (void)result;
    return RIN_SERIAL_ENOTSUP;
#else
    RinSerialWaitRequestV1 request;
    int ioctl_result;
    int descriptor = default_fd(handle);
    (void)context;
    if (descriptor < 0) return RIN_SERIAL_EBADF;
    if (!result || events == 0u) return RIN_SERIAL_EINVAL;
    memset(&request, 0, sizeof(request));
    request.events = events;
    ioctl_result = ioctl(descriptor, RIN_SERIAL_IOCTL_WAIT, &request);
    if (ioctl_result != 0) {
        memset(result, 0, sizeof(*result));
        return default_errno_result();
    }
    *result = request.result;
    return RIN_SERIAL_OK;
#endif
}

static void ensure_default_ops(void)
{
    if (g_ops_installed) return;
    memset(&g_ops, 0, sizeof(g_ops));
    g_ops.open = default_open;
    g_ops.close = default_close;
    g_ops.read = default_read;
    g_ops.write = default_write;
    g_ops.configure = default_configure;
    g_ops.set_signals = default_set_signals;
    g_ops.get_signals = default_get_signals;
    g_ops.wait = default_wait;
    g_custom_file_ops = 0;
    g_ops_installed = 1;
}

int rin_web_serial_try_set_file_ops(const RinWebSerialFileOpsV1* ops)
{
    int drain_result;
    if (ops && (!ops->open || !ops->close || !ops->read || !ops->write ||
                !ops->configure || !ops->set_signals || !ops->get_signals))
        return RIN_SERIAL_EINVAL;
    drain_result = portal_drain_open_slots();
    if (drain_result != RIN_SERIAL_OK) return drain_result;

    g_portal_installed = 0;
    memset(&g_portal, 0, sizeof(g_portal));
    g_portal_page_exchange = NULL;
    portal_event_state_reset();
    g_identity_query = NULL;
    g_identity_query_context = NULL;
    if (!ops) {
        g_ops_installed = 0;
        g_custom_file_ops = 0;
        memset(&g_ops, 0, sizeof(g_ops));
        return RIN_SERIAL_OK;
    }
    g_ops = *ops;
    g_custom_file_ops = 1;
    g_ops_installed = 1;
    return RIN_SERIAL_OK;
}

void rin_web_serial_set_file_ops(const RinWebSerialFileOpsV1* ops)
{
    (void)rin_web_serial_try_set_file_ops(ops);
}

void rin_web_serial_set_identity_query(
    RinWebSerialIdentityQueryV1 query, void* context)
{
    g_identity_query = query;
    g_identity_query_context = query ? context : NULL;
}

int rin_web_serial_try_set_portal_transport(
    const RinWebSerialPortalTransportV1* transport)
{
    int drain_result;
    if (transport && (!transport->exchange || transport->session_id == 0u ||
                      transport->session_generation == 0u))
        return RIN_SERIAL_EINVAL;
    drain_result = portal_drain_open_slots();
    if (drain_result != RIN_SERIAL_OK) return drain_result;

    g_ops_installed = 0;
    g_custom_file_ops = 0;
    g_identity_query = NULL;
    g_identity_query_context = NULL;
    g_portal_page_exchange = NULL;
    memset(&g_ops, 0, sizeof(g_ops));
    portal_event_state_reset();
    if (!transport) {
        g_portal_installed = 0;
        memset(&g_portal, 0, sizeof(g_portal));
        return RIN_SERIAL_OK;
    }
    g_portal = *transport;
    g_portal_installed = 1;
    return RIN_SERIAL_OK;
}

void rin_web_serial_set_portal_transport(
    const RinWebSerialPortalTransportV1* transport)
{
    (void)rin_web_serial_try_set_portal_transport(transport);
}

void rin_web_serial_set_portal_page_exchange(
    RinWebSerialPortalExchangeForPageV1 exchange_for_page)
{
    g_portal_page_exchange = exchange_for_page;
}

static uint32_t web_serial_decimal(uint32_t value, char output[10])
{
    char reverse[10];
    uint32_t count = 0u;
    uint32_t index;
    do {
        reverse[count++] = (char)('0' + value % 10u);
        value /= 10u;
    } while (value != 0u && count < sizeof(reverse));
    for (index = 0u; index < count; ++index)
        output[index] = reverse[count - index - 1u];
    output[count] = '\0';
    return count;
}

#if !defined(_WIN32)
static int web_serial_name_parse(const char* name, uint8_t* transport_out,
                                 uint32_t* instance_out)
{
    const char* digits;
    uint8_t transport;
    uint32_t value = 0u;
    uint32_t count = 0u;
    if (transport_out) *transport_out = 0u;
    if (instance_out) *instance_out = 0u;
    if (!name || !transport_out || !instance_out) return -1;
    if (memcmp(name, "ttyS", 4u) == 0) {
        if (name[4] < '0' || name[4] > '3' || name[5] != '\0') return -1;
        *transport_out = RIN_SERIAL_TRANSPORT_PLATFORM_UART;
        *instance_out = (uint32_t)(name[4] - '0');
        return 0;
    }
    if (memcmp(name, "ttyACM", 6u) == 0) {
        transport = RIN_SERIAL_TRANSPORT_USB_CDC_ACM;
        digits = name + 6u;
    } else if (memcmp(name, "ttyUSB", 6u) == 0) {
        transport = RIN_SERIAL_TRANSPORT_USB_VENDOR;
        digits = name + 6u;
    } else {
        return -1;
    }
    if (*digits < '0' || *digits > '9') return -1;
    while (*digits >= '0' && *digits <= '9') {
        uint32_t digit = (uint32_t)(*digits - '0');
        if (count >= 6u || value > (999999u - digit) / 10u) return -1;
        value = value * 10u + digit;
        ++count;
        ++digits;
    }
    if (*digits != '\0' || count == 0u) return -1;
    *transport_out = transport;
    *instance_out = value;
    return 0;
}
#endif

static int web_serial_name_format(uint8_t transport, uint32_t instance,
                                  char* name, uint32_t name_capacity,
                                  char* path, uint32_t path_capacity)
{
    const char* prefix;
    uint32_t prefix_length;
    uint32_t number_length;
    char number[10];
    if (!name || !path || instance > 999999u) return -1;
    if (transport == RIN_SERIAL_TRANSPORT_PLATFORM_UART) {
        if (instance > 3u) return -1;
        prefix = "ttyS";
        prefix_length = 4u;
    } else if (transport == RIN_SERIAL_TRANSPORT_USB_CDC_ACM) {
        prefix = "ttyACM";
        prefix_length = 6u;
    } else if (transport == RIN_SERIAL_TRANSPORT_USB_VENDOR) {
        prefix = "ttyUSB";
        prefix_length = 6u;
    } else {
        return -1;
    }
    number_length = web_serial_decimal(instance, number);
    if (prefix_length + number_length + 1u > name_capacity ||
        prefix_length + number_length + 6u > path_capacity)
        return -1;
    memset(name, 0, name_capacity);
    memset(path, 0, path_capacity);
    memcpy(name, prefix, prefix_length);
    memcpy(name + prefix_length, number, number_length + 1u);
    memcpy(path, "/dev/", 5u);
    memcpy(path + 5u, name, prefix_length + number_length + 1u);
    return 0;
}

static int make_device_path(const char* device_name, uint8_t transport,
                            uint32_t stable_instance,
                            RinWebSerialDeviceV1* output)
{
    char expected_name[RIN_SERIAL_NAME_MAX];
    char path[RIN_SERIAL_PATH_MAX];
    RinSerialDeviceIdentityV1 identity;
    uint32_t handle;
    uint32_t name_length;
    int identity_result;
    int close_result;
    const uint32_t denied_flags = RIN_SERIAL_DEVICE_FLAG_SYSTEM |
        RIN_SERIAL_DEVICE_FLAG_DEBUG | RIN_SERIAL_DEVICE_FLAG_CRITICAL |
        RIN_SERIAL_DEVICE_FLAG_BROWSER_DENY;
    const uint32_t required_capabilities = RIN_SERIAL_CAP_READ |
        RIN_SERIAL_CAP_WRITE | RIN_SERIAL_CAP_CONFIGURE;
    if (!output || !device_name || web_serial_name_format(
            transport, stable_instance, expected_name, sizeof(expected_name),
            path, sizeof(path)) != 0 || strcmp(device_name, expected_name) != 0)
        return RIN_SERIAL_EINVAL;
    memset(output, 0, sizeof(*output));
    ensure_default_ops();
    handle = g_ops.open(g_ops.context, path,
                        RIN_WEB_SERIAL_O_RDWR | RIN_WEB_SERIAL_O_NONBLOCK);
    if (handle == 0u) return RIN_SERIAL_ENODEV;
    identity_result = default_get_identity(handle, &identity);
    close_result = g_ops.close(g_ops.context, handle);
    if (close_result != 0) return RIN_SERIAL_EIO;
    if (identity_result != RIN_SERIAL_OK) return identity_result;
    if (identity.stable_instance != stable_instance ||
        identity.transport != transport)
        return RIN_SERIAL_EIO;
    if ((identity.flags & denied_flags) != 0u ||
        (identity.capabilities & required_capabilities) !=
            required_capabilities)
        return RIN_SERIAL_EPERM;
    output->info.object_id = identity.object_id;
    output->info.generation = identity.generation;
    output->info.stable_instance = identity.stable_instance;
    output->info.flags = identity.flags;
    output->info.capabilities = identity.capabilities;
    output->info.vendor_id = identity.vendor_id;
    output->info.product_id = identity.product_id;
    output->info.transport = identity.transport;
    output->info.device_class = identity.device_class;
    name_length = (uint32_t)strlen(expected_name);
    memcpy(output->info.name, expected_name, name_length + 1u);
    memcpy(output->info.path, path, sizeof(path));
    output->capability.object_id = identity.object_id;
    output->capability.generation = identity.generation;
    return RIN_SERIAL_OK;
}

static int enumerate_local_devices(RinWebSerialDeviceV1* output,
                                   uint32_t capacity, uint32_t* count_out)
{
#if defined(_WIN32)
    (void)output;
    (void)capacity;
    if (count_out) *count_out = 0u;
    return RIN_SERIAL_ENOTSUP;
#else
    DIR* directory;
    struct dirent* entry;
    RinWebSerialDeviceV1 seen[RIN_WEB_SERIAL_MAX_DEVICES];
    uint32_t count = 0u;
    uint32_t index;
    int too_many = 0;
    int read_error = 0;
    if (count_out) *count_out = 0u;
    if (!count_out || (capacity != 0u && !output) ||
        capacity > RIN_WEB_SERIAL_MAX_DEVICES)
        return RIN_SERIAL_EINVAL;
    if (output && capacity != 0u)
        memset(output, 0, (size_t)capacity * sizeof(*output));
    memset(seen, 0, sizeof(seen));
    directory = opendir("/dev");
    if (!directory) return default_errno_result();
    for (;;) {
        uint8_t transport = 0u;
        uint32_t stable_instance = 0u;
        RinWebSerialDeviceV1 candidate;
        struct stat status;
        char device_path[sizeof(candidate.info.path)];
        size_t name_length;
        errno = 0;
        entry = readdir(directory);
        if (!entry) {
            read_error = errno;
            break;
        }
        name_length = strlen(entry->d_name);
        if (name_length == 0u || name_length >= sizeof(device_path) - 5u ||
            memchr(entry->d_name, '/', name_length) != NULL ||
            memchr(entry->d_name, '\\', name_length) != NULL ||
            web_serial_name_parse(entry->d_name, &transport,
                                  &stable_instance) != 0)
            continue;

        memcpy(device_path, "/dev/", 5u);
        memcpy(device_path + 5u, entry->d_name, name_length + 1u);
        if (lstat(device_path, &status) != 0 || !S_ISCHR(status.st_mode))
            continue;
        if (make_device_path(entry->d_name, transport, stable_instance,
                             &candidate) != RIN_SERIAL_OK)
            continue;
        for (index = 0u; index < count; ++index) {
            if (seen[index].capability.object_id ==
                    candidate.capability.object_id &&
                seen[index].capability.generation ==
                    candidate.capability.generation)
                break;
        }
        if (index != count) continue;
        if (count >= RIN_WEB_SERIAL_MAX_DEVICES) {
            too_many = 1;
            break;
        }
        seen[count] = candidate;
        ++count;
    }
    if (closedir(directory) != 0 || read_error != 0) {
        if (output && capacity != 0u)
            memset(output, 0, (size_t)capacity * sizeof(*output));
        return RIN_SERIAL_EIO;
    }
    if (too_many) {
        *count_out = RIN_WEB_SERIAL_MAX_DEVICES + 1u;
        return RIN_SERIAL_EOVERFLOW;
    }
    *count_out = count;
    if (count > capacity) return RIN_SERIAL_EOVERFLOW;
    for (index = 0u; index < count; ++index) output[index] = seen[index];
    return RIN_SERIAL_OK;
#endif
}

int rin_web_serial_enumerate(RinWebSerialDeviceV1* output, uint32_t capacity,
                             uint32_t* count_out)
{
    if (!count_out || (capacity != 0u && !output) ||
        capacity > RIN_WEB_SERIAL_MAX_DEVICES)
        return RIN_SERIAL_EINVAL;
    if (web_serial_ranges_overlap(
            output, (size_t)capacity * sizeof(*output), count_out,
            sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    *count_out = 0u;
    if (portal_valid()) return portal_enumerate(output, capacity, count_out);
    ensure_default_ops();
    return enumerate_local_devices(output, capacity, count_out);
}

int rin_web_serial_poll_event(RinWebSerialEventV1* event_out)
{
    int result;
    if (event_out == NULL)
        return RIN_SERIAL_EINVAL;
    memset(event_out, 0, sizeof(*event_out));
    if (!portal_valid())
        return RIN_SERIAL_ENOTSUP;
    if (g_portal_event_count != 0u)
        return portal_event_dequeue(event_out);
    result = portal_refresh_event_snapshot();
    if (result != RIN_SERIAL_OK)
        return result;
    return portal_event_dequeue(event_out);
}

int rin_web_serial_request_port(const char* origin, uint32_t user_activation,
                                const RinSerialPortalFilterV1* filters,
                                uint32_t filter_count,
                                uint64_t selected_object_id,
                                RinWebSerialDeviceV1* output)
{
    if (portal_valid())
        return portal_request_port(origin, user_activation, filters,
                                   filter_count, selected_object_id, output);
    return RIN_SERIAL_ENOTSUP;
}

int rin_web_serial_request_port_begin(
    uint32_t page_id, const char* origin, uint32_t user_activation,
    const RinSerialPortalFilterV1* filters, uint32_t filter_count,
    uint64_t* request_id_out)
{
    if (request_id_out != NULL) *request_id_out = 0u;
    if (page_id == 0u || request_id_out == NULL || user_activation > 1u ||
        filter_count > RIN_SERIAL_PORTAL_MAX_FILTERS ||
        (filter_count != 0u && filters == NULL))
        return RIN_SERIAL_EINVAL;
    if (!portal_valid()) return RIN_SERIAL_ENOTSUP;
    return portal_request_port_begin(page_id, origin, user_activation, filters,
                                     filter_count, request_id_out);
}

int rin_web_serial_request_port_poll(uint32_t page_id, const char* origin,
                                    uint64_t request_id,
                                    RinWebSerialDeviceV1* device_out)
{
    if (device_out != NULL) memset(device_out, 0, sizeof(*device_out));
    if (page_id == 0u || device_out == NULL || request_id == 0u)
        return RIN_SERIAL_EINVAL;
    if (!portal_valid()) return RIN_SERIAL_ENOTSUP;
    return portal_request_port_poll(page_id, origin, request_id, device_out);
}

int rin_web_serial_get_ports(const char* origin, RinWebSerialDeviceV1* output,
                             uint32_t capacity, uint32_t* count_out)
{
    if (!count_out || (capacity != 0u && !output) ||
        capacity > RIN_WEB_SERIAL_MAX_DEVICES)
        return RIN_SERIAL_EINVAL;
    if (web_serial_ranges_overlap(
            output, (size_t)capacity * sizeof(*output), count_out,
            sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    *count_out = 0u;
    if (portal_valid())
        return portal_get_ports(0u, origin, output, capacity, count_out);
    return RIN_SERIAL_ENOTSUP;
}

int rin_web_serial_get_ports_for_page(
    uint32_t page_id, const char* origin, RinWebSerialDeviceV1* output,
    uint32_t capacity, uint32_t* count_out)
{
    if (page_id == 0u || !count_out || (capacity != 0u && !output) ||
        capacity > RIN_WEB_SERIAL_MAX_DEVICES)
        return RIN_SERIAL_EINVAL;
    if (web_serial_ranges_overlap(
            output, (size_t)capacity * sizeof(*output), count_out,
            sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    *count_out = 0u;
    if (!portal_valid()) return RIN_SERIAL_ENOTSUP;
    return portal_get_ports(page_id, origin, output, capacity, count_out);
}

int rin_web_serial_open_for_page(
    uint32_t page_id, RinSerialCapabilityV1 capability, uint32_t baud_rate,
    uint8_t data_bits, uint8_t stop_bits, uint8_t parity,
    uint8_t flow_control, uint32_t buffer_size, uint32_t* handle_out)
{
    uint32_t index;
    int matched_protected_device = 0;
    RinSerialConfigV1 config;
    if (handle_out) *handle_out = 0u;
    if (!handle_out || baud_rate == 0u || baud_rate > 4000000u ||
        (data_bits != 7u && data_bits != 8u) ||
        (stop_bits != 1u && stop_bits != 2u) ||
        parity > RIN_SERIAL_PARITY_EVEN ||
        flow_control > RIN_SERIAL_FLOW_HARDWARE || buffer_size == 0u ||
        buffer_size > RIN_SERIAL_BUFFER_MAX)
        return RIN_SERIAL_EINVAL;
    if (flow_control == RIN_SERIAL_FLOW_HARDWARE)
        return RIN_SERIAL_ENOTSUP;
    if (portal_valid()) {
        RinSerialConfigV1 config;
        memset(&config, 0, sizeof(config));
        config.baud_rate = baud_rate;
        config.data_bits = data_bits;
        config.stop_bits = stop_bits;
        config.parity = parity;
        config.flow_control = flow_control;
        config.rts = 1u;
        config.dtr = 1u;
        config.buffer_size = buffer_size;
        return portal_open(page_id, capability, &config, 0u, handle_out);
    }
    if (page_id != 0u) return RIN_SERIAL_EPERM;
    ensure_default_ops();
    memset(&config, 0, sizeof(config));
    config.baud_rate = baud_rate;
    config.data_bits = data_bits;
    config.stop_bits = stop_bits;
    config.parity = parity;
    config.flow_control = flow_control;
    config.rts = 1u;
    config.dtr = 1u;
    config.buffer_size = buffer_size;
    {
        RinWebSerialDeviceV1 devices[RIN_WEB_SERIAL_MAX_DEVICES];
        uint32_t device_count = 0u;
        int enumerate_result = rin_web_serial_enumerate(
            devices, RIN_WEB_SERIAL_MAX_DEVICES, &device_count);
        if (enumerate_result != RIN_SERIAL_OK)
            return enumerate_result;
        for (index = 0u; index < device_count; ++index) {
        char path[RIN_SERIAL_PATH_MAX];
        RinSerialDeviceIdentityV1 identity;
        uint32_t handle;
        int identity_result;
        const uint32_t denied_flags = RIN_SERIAL_DEVICE_FLAG_SYSTEM |
            RIN_SERIAL_DEVICE_FLAG_DEBUG | RIN_SERIAL_DEVICE_FLAG_CRITICAL |
            RIN_SERIAL_DEVICE_FLAG_BROWSER_DENY;
        if (devices[index].info.path[0] == '\0' ||
            memchr(devices[index].info.path, '\0',
                   sizeof(devices[index].info.path)) == NULL)
            return RIN_SERIAL_EIO;
        memcpy(path, devices[index].info.path, sizeof(path));
        if (devices[index].capability.object_id != capability.object_id ||
            devices[index].capability.generation != capability.generation)
            continue;
        handle = g_ops.open(g_ops.context, path,
                            RIN_WEB_SERIAL_O_RDWR | RIN_WEB_SERIAL_O_NONBLOCK);
        if (handle == 0u) continue;
        identity_result = default_get_identity(handle, &identity);
        if (identity_result != RIN_SERIAL_OK) {
            if (g_ops.close(g_ops.context, handle) != 0)
                return RIN_SERIAL_EIO;
            continue;
        }
        if (identity.stable_instance != devices[index].info.stable_instance ||
            identity.transport != devices[index].info.transport ||
            identity.object_id != capability.object_id ||
            identity.generation != capability.generation) {
            if (g_ops.close(g_ops.context, handle) != 0)
                return RIN_SERIAL_EIO;
            continue;
        }
        if ((identity.flags & denied_flags) != 0u ||
            (identity.capabilities & (RIN_SERIAL_CAP_READ |
                                      RIN_SERIAL_CAP_WRITE |
                                      RIN_SERIAL_CAP_CONFIGURE)) !=
                (RIN_SERIAL_CAP_READ | RIN_SERIAL_CAP_WRITE |
                 RIN_SERIAL_CAP_CONFIGURE)) {
            matched_protected_device = 1;
            if (g_ops.close(g_ops.context, handle) != 0)
                return RIN_SERIAL_EIO;
            continue;
        }
        if (g_ops.configure(g_ops.context, handle, &config) != 0) {
            g_ops.close(g_ops.context, handle);
            return RIN_SERIAL_EIO;
        }
        *handle_out = handle;
        return RIN_SERIAL_OK;
        }
    }
    return matched_protected_device ? RIN_SERIAL_EPERM : RIN_SERIAL_EBADF;
}

int rin_web_serial_open(RinSerialCapabilityV1 capability, uint32_t baud_rate,
                        uint8_t data_bits, uint8_t stop_bits, uint8_t parity,
                        uint8_t flow_control, uint32_t buffer_size,
                        uint32_t* handle_out)
{
    return rin_web_serial_open_for_page(
        0u, capability, baud_rate, data_bits, stop_bits, parity, flow_control,
        buffer_size, handle_out);
}

int rin_web_serial_close(uint32_t handle)
{
    if (portal_valid()) return portal_close(handle);
    ensure_default_ops();
    return handle == 0u ? RIN_SERIAL_EBADF : g_ops.close(g_ops.context, handle);
}

int rin_web_serial_read(uint32_t handle, uint8_t* bytes, size_t capacity,
                        size_t* count_out)
{
    int result;
    if (web_serial_ranges_overlap(bytes, capacity, count_out,
                                  sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    if (count_out) *count_out = 0u;
    if (handle == 0u || !bytes || capacity == 0u ||
        capacity > RIN_SERIAL_BUFFER_MAX || !count_out)
        return RIN_SERIAL_EINVAL;
    if (portal_valid())
        return portal_transfer(handle, RIN_SERIAL_PORTAL_READ_REQUEST, NULL, 0u,
                               bytes, capacity, count_out);
    ensure_default_ops();
    result = g_ops.read(g_ops.context, handle, bytes, capacity);
    if (result < 0) return result;
    if ((size_t)result > capacity) return RIN_SERIAL_EOVERFLOW;
    *count_out = (size_t)result;
    return RIN_SERIAL_OK;
}

int rin_web_serial_write(uint32_t handle, const uint8_t* bytes, size_t count,
                         size_t* count_out)
{
    int result;
    if (web_serial_ranges_overlap(bytes, count, count_out,
                                  sizeof(*count_out)))
        return RIN_SERIAL_EINVAL;
    if (count_out) *count_out = 0u;
    if (handle == 0u || !bytes || count == 0u ||
        count > RIN_SERIAL_BUFFER_MAX || !count_out)
        return RIN_SERIAL_EINVAL;
    if (portal_valid())
        return portal_transfer(handle, RIN_SERIAL_PORTAL_WRITE_REQUEST, bytes,
                               count, NULL, 0u, count_out);
    ensure_default_ops();
    result = g_ops.write(g_ops.context, handle, bytes, count);
    if (result < 0) return result;
    if ((size_t)result > count) return RIN_SERIAL_EOVERFLOW;
    *count_out = (size_t)result;
    return RIN_SERIAL_OK;
}

int rin_web_serial_set_signals(uint32_t handle, uint8_t dtr, uint8_t rts,
                               uint8_t break_signal)
{
    if (handle == 0u || dtr > 1u || rts > 1u || break_signal > 1u)
        return RIN_SERIAL_EINVAL;
    if (portal_valid()) {
        RinSerialSignalsV1 signals = { dtr, rts, break_signal, 0u };
        return portal_set_signals(handle, signals);
    }
    ensure_default_ops();
    return g_ops.set_signals(g_ops.context, handle, dtr, rts, break_signal);
}

int rin_web_serial_get_signals(uint32_t handle, RinSerialStatusV1* status_out)
{
    if (handle == 0u || !status_out) return RIN_SERIAL_EINVAL;
    if (portal_valid()) return portal_get_signals(handle, status_out);
    ensure_default_ops();
    memset(status_out, 0, sizeof(*status_out));
    return g_ops.get_signals(g_ops.context, handle, status_out);
}

int rin_web_serial_wait(uint32_t handle, uint32_t events,
                        RinSerialWaitResultV1* result_out)
{
    if (handle == 0u || !result_out) return RIN_SERIAL_EINVAL;
    if (portal_valid()) return portal_wait(handle, events, result_out);
    ensure_default_ops();
    if (!g_ops.wait) {
        memset(result_out, 0, sizeof(*result_out));
        return RIN_SERIAL_ENOTSUP;
    }
    return g_ops.wait(g_ops.context, handle, events, result_out);
}
