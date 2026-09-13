/* SPDX-License-Identifier: MIT */

#include <rinruntime/crash_service.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rin/socket_abi.h>
#include <rin/contract_abi.h>

#define RINRUNTIME_CRASH_SERVICE_IO_POLL_MS 1000
#define RINRUNTIME_CRASH_SERVICE_IO_IDLE_LIMIT 5u
#define RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT 32u
#define RINRUNTIME_CRASH_SERVICE_SYSTEM_SCOPE UINT16_C(1)
static uint64_t g_crash_service_diagnostic_request_id = UINT64_C(1);

static int crash_service_wait(int fd, short events)
{
    uint32_t idle = 0u;
    uint32_t interrupted = 0u;
    while (idle < RINRUNTIME_CRASH_SERVICE_IO_IDLE_LIMIT) {
        struct pollfd descriptor = {0};
        int ready;
        descriptor.fd = fd;
        descriptor.events = (short)(events | POLLERR | POLLHUP | POLLNVAL);
        ready = poll(&descriptor, 1u, RINRUNTIME_CRASH_SERVICE_IO_POLL_MS);
        if (ready > 0) {
            if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0 ||
                (descriptor.revents & events) == 0)
                return 0;
            return (descriptor.revents & events) != 0;
        }
        if (ready < 0 && errno == EINTR) {
            if (++interrupted >= RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (ready < 0) return 0;
        ++idle;
    }
    return 0;
}

static int crash_service_send_exact(int fd, const void* input, size_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    size_t offset = 0u;
    while (offset < size) {
        ssize_t count;
        if (!crash_service_wait(fd, POLLOUT)) return 0;
        count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0) {
            if ((size_t)count > size - offset) return 0;
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int crash_service_receive_exact(int fd, void* output, size_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    size_t offset = 0u;
    while (offset < size) {
        ssize_t count;
        if (!crash_service_wait(fd, POLLIN)) return 0;
        count = recv(fd, bytes + offset, size - offset, 0);
        if (count > 0) {
            if ((size_t)count > size - offset) return 0;
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int crash_service_endpoint_valid(int fd, uint32_t expected_slot)
{
    rin_unix_service_identity_v1 identity = {};
    socklen_t identity_size = sizeof(identity);
    if (expected_slot == 0u ||
        getsockopt(fd, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
                   &identity, &identity_size) != 0 ||
        identity_size != sizeof(identity) || identity.slot_id != expected_slot ||
        identity.owner_uid != 0u ||
        identity.scope != RINRUNTIME_CRASH_SERVICE_SYSTEM_SCOPE ||
        identity.flags != RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED)
        return 0;
    memset(&identity, 0, sizeof(identity));
    return 1;
}

RinRuntimeCrashServiceResult rinruntime_crash_service_register_recovery(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    uint32_t expected_service_slot)
{
    RinCrashRecoveryRegistrationV1 registration;
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    struct sockaddr_un address = {};
    size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    int fd = -1;
    RinRuntimeCrashServiceResult result;

    result = rinruntime_crash_service_registration_from_metadata(
        metadata, &registration);
    if (result != RINRUNTIME_CRASH_SERVICE_OK || expected_service_slot == 0u)
        return result == RINRUNTIME_CRASH_SERVICE_OK
            ? RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT
            : result;
    if (path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot)) {
        close(fd);
        return RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
    }

    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = RIN_CRASH_SERVICE_OP_REGISTER_RECOVERY;
    request.request_id = 1u;
    request.payload_size = sizeof(registration);
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &registration, sizeof(registration)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply))) {
        memset(&registration, 0, sizeof(registration));
        close(fd);
        return RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
    }
    memset(&registration, 0, sizeof(registration));
    close(fd);
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode || reply.request_id != request.request_id ||
        reply.payload_size != 0u || reply.flags != 0u || reply.reserved != 0u)
        return RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
    return reply.status == RIN_RESULT_OK ? RINRUNTIME_CRASH_SERVICE_OK
                                         : RINRUNTIME_CRASH_SERVICE_REJECTED;
}

RinRuntimeCrashServiceResult rinruntime_crash_service_append_diagnostic(
    const char* message, size_t message_size, uint32_t expected_service_slot)
{
    RinCrashDiagnosticLogV1 diagnostic;
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    struct sockaddr_un address = {};
    size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id;
    int fd = -1;
    RinRuntimeCrashServiceResult result = RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    memset(&diagnostic, 0, sizeof(diagnostic));
    if (message == NULL || message_size == 0u ||
        message_size > RIN_CRASH_DIAGNOSTIC_MAX_MESSAGE ||
        expected_service_slot == 0u || path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    for (size_t index = 0u; index < message_size; ++index) {
        unsigned char value = (unsigned char)message[index];
        if (value == 0u || (value < 0x20u && value != '\t' &&
                            value != '\n' && value != '\r') ||
            value == 0x7fu)
            return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    }
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.version = RIN_CRASH_DIAGNOSTIC_VERSION;
    diagnostic.flags = RIN_CRASH_DIAGNOSTIC_FLAG_REDACTED;
    diagnostic.message_size = (uint32_t)message_size;
    memcpy(diagnostic.message, message, message_size);
    diagnostic.message[message_size] = '\0';

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) goto done;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot))
        goto done;
    request_id = __atomic_fetch_add(&g_crash_service_diagnostic_request_id,
                                    UINT64_C(1), __ATOMIC_RELAXED);
    if (request_id == 0u)
        request_id = __atomic_fetch_add(&g_crash_service_diagnostic_request_id,
                                        UINT64_C(1), __ATOMIC_RELAXED);
    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = RIN_CRASH_SERVICE_OP_APPEND_DIAGNOSTIC;
    request.request_id = request_id;
    request.payload_size = sizeof(diagnostic);
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &diagnostic, sizeof(diagnostic)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode || reply.request_id != request.request_id ||
        reply.payload_size != 0u || reply.flags != 0u || reply.reserved != 0u) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    result = reply.status == RIN_RESULT_OK
        ? RINRUNTIME_CRASH_SERVICE_OK
        : RINRUNTIME_CRASH_SERVICE_REJECTED;
done:
    memset(&diagnostic, 0, sizeof(diagnostic));
    if (fd >= 0) close(fd);
    return result;
}


