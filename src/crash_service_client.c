/* SPDX-License-Identifier: MIT */

#include <rinruntime/crash_service.h>
#include <rinruntime/crash_consent.h>
#include <rinruntime/poll_wait.h>
#include "private_service_socket.h"
#include "platform.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rin/socket_abi.h>
#include <rin/contract_abi.h>

#define RINRUNTIME_CRASH_SERVICE_IO_IDLE_LIMIT 5u
#define RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT 32u
#define RINRUNTIME_CRASH_SERVICE_SYSTEM_SCOPE UINT16_C(1)
#define RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_STEPS 250u
#define RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_MS 100u
static uint64_t g_crash_service_request_id = UINT64_C(1);

static int crash_service_request_id_valid(uint64_t request_id)
{
    return request_id != 0u && request_id != UINT64_MAX;
}

static uint64_t crash_service_next_request_id(void)
{
    uint64_t request_id = 0u;
    /* Two values are reserved, so three consecutive fetches always find a
     * usable identity even when the counter crosses the wrap boundary. */
    for (unsigned attempt = 0u; attempt < 3u; ++attempt) {
        request_id = __atomic_fetch_add(&g_crash_service_request_id,
                                        UINT64_C(1), __ATOMIC_RELAXED);
        if (crash_service_request_id_valid(request_id)) return request_id;
    }
    return 0u;
}

static int crash_service_wait(int fd, uint32_t events)
{
    uint32_t idle = 0u;
    while (idle < RINRUNTIME_CRASH_SERVICE_IO_IDLE_LIMIT) {
        const RinRuntimePollWaitResult ready = rinruntime_poll_wait(
            fd, events, 1000u);
        if (ready == RINRUNTIME_POLL_WAIT_READY) return 1;
        if (ready == RINRUNTIME_POLL_WAIT_FAILURE) return 0;
        ++idle;
    }
    return 0;
}

static int crash_service_send_exact(int fd, const void* input, size_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    size_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        ssize_t count;
        if (!crash_service_wait(fd, RINRUNTIME_POLL_WAIT_WRITABLE)) return 0;
        count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0) {
            if ((size_t)count > size - offset) return 0;
            offset += (size_t)count;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        return 0;
    }
    return 1;
}

static int crash_service_receive_exact(int fd, void* output, size_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    size_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        ssize_t count;
        if (!crash_service_wait(fd, RINRUNTIME_POLL_WAIT_READABLE)) return 0;
        count = recv(fd, bytes + offset, size - offset, 0);
        if (count > 0) {
            if ((size_t)count > size - offset) return 0;
            offset += (size_t)count;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RINRUNTIME_CRASH_SERVICE_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
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

static int crash_service_result_valid(int32_t status)
{
    switch (status) {
    case RIN_RESULT_OK:
    case RIN_RESULT_INVALID_ARGUMENT:
    case RIN_RESULT_NOT_FOUND:
    case RIN_RESULT_IO:
    case RIN_RESULT_ACCESS_DENIED:
    case RIN_RESULT_NO_MEMORY:
    case RIN_RESULT_ALREADY_EXISTS:
    case RIN_RESULT_BUSY:
    case RIN_RESULT_TIMED_OUT:
    case RIN_RESULT_NOT_SUPPORTED:
    case RIN_RESULT_INVALID_HANDLE:
    case RIN_RESULT_WRONG_TYPE:
    case RIN_RESULT_TABLE_FULL:
    case RIN_RESULT_WOULD_BLOCK:
    case RIN_RESULT_INTERRUPTED:
    case RIN_RESULT_BUFFER_TOO_SMALL:
    case RIN_RESULT_CORRUPT_DATA:
    case RIN_RESULT_SIGNATURE_REJECTED:
    case RIN_RESULT_VERSION_MISMATCH:
    case RIN_RESULT_LIMIT_EXCEEDED:
    case RIN_RESULT_DEVICE_LOST:
        return 1;
    default:
        return 0;
    }
}

static RinRuntimeCrashServiceResult crash_service_recovery_request(
    uint16_t opcode, const RinCrashRecoveryRegistrationV1* registration,
    uint32_t expected_service_slot)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    struct sockaddr_un address = {};
    size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (registration == NULL || expected_service_slot == 0u ||
        path_size >= sizeof(address.sun_path) ||
        (opcode != RIN_CRASH_SERVICE_OP_REGISTER_RECOVERY &&
         opcode != RIN_CRASH_SERVICE_OP_QUERY_RECOVERY_CRASH))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0) goto done;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot))
        goto done;

    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = opcode;
    request.request_id = 1u;
    request.payload_size = sizeof(*registration);
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, registration, sizeof(*registration)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode ||
        reply.request_id != request.request_id || reply.payload_size != 0u ||
        reply.flags != 0u || reply.reserved != 0u ||
        !crash_service_result_valid(reply.status)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (opcode == RIN_CRASH_SERVICE_OP_QUERY_RECOVERY_CRASH) {
        if (reply.status == RIN_RESULT_OK)
            result = RINRUNTIME_CRASH_SERVICE_CRASH_DETECTED;
        else if (reply.status == RIN_RESULT_NOT_FOUND)
            result = RINRUNTIME_CRASH_SERVICE_OK;
        else
            result = RINRUNTIME_CRASH_SERVICE_REJECTED;
    } else {
        result = reply.status == RIN_RESULT_OK
            ? RINRUNTIME_CRASH_SERVICE_OK
            : RINRUNTIME_CRASH_SERVICE_REJECTED;
    }
done:
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    return result;
}

static RinRuntimeCrashServiceResult crash_service_read_summary_request(
    uint32_t expected_service_slot, RinCrashSummaryV1* summary_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashConsentProofV1 proof = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id = 0u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (summary_out == NULL || expected_service_slot == 0u ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(summary_out, 0, sizeof(*summary_out));
    fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0) goto done;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot))
        goto done;

    request_id = crash_service_next_request_id();
    if (!crash_service_request_id_valid(request_id)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    /* The broker binds its proof to this exact authenticated socket and
     * request ID. Reconnecting between consent and READ would invalidate it. */
    if (rin_crash_consent_request(fd, request_id, &request_generation) !=
        (int)RIN_RESULT_OK || request_generation == 0u) {
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    for (wait_step = 0u;
         wait_step < RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_STEPS;
         ++wait_step) {
        const int consent_result = rin_crash_consent_take(
            fd, request_id, request_generation, &proof);
        if (consent_result == (int)RIN_RESULT_OK) break;
        if (consent_result != (int)RIN_RESULT_ACCESS_DENIED) {
            result = consent_result == (int)RIN_RESULT_TIMED_OUT ||
                     consent_result == (int)RIN_RESULT_NOT_FOUND
                ? RINRUNTIME_CRASH_SERVICE_REJECTED
                : RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
            goto done;
        }
        rin_sleep(RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_MS);
    }
    if (wait_step == RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_STEPS) {
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }

    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = RIN_CRASH_SERVICE_OP_READ;
    request.request_id = request_id;
    request.payload_size = sizeof(proof);
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &proof, sizeof(proof)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode || reply.request_id != request_id ||
        reply.flags != 0u || reply.reserved != 0u ||
        (reply.status != RIN_CRASH_SERVICE_STATUS_CONSENT_REQUIRED &&
         !crash_service_result_valid(reply.status))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.status != RIN_RESULT_OK) {
        if (reply.payload_size != 0u) {
            result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
            goto done;
        }
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    if (reply.payload_size != sizeof(*summary_out) ||
        !crash_service_receive_exact(fd, summary_out, sizeof(*summary_out))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (summary_out->struct_size != sizeof(*summary_out) ||
        summary_out->version != RIN_CRASH_SUMMARY_VERSION ||
        summary_out->reserved != 0u ||
        summary_out->disclosure_policy !=
            RIN_CRASH_SUMMARY_POLICY_LOCAL_ONLY ||
        (summary_out->kind != RIN_CRASH_RECORD_KERNEL_PANIC &&
         summary_out->kind != RIN_CRASH_RECORD_USER_MINIDUMP) ||
        (summary_out->architecture != RIN_CRASH_ARCH_X86_64 &&
         summary_out->architecture != RIN_CRASH_ARCH_X86_32) ||
        summary_out->sequence == 0u ||
        summary_out->message_size > RIN_CRASH_RECORD_MAX_MESSAGE ||
        summary_out->message[summary_out->message_size] != '\0' ||
        summary_out->has_process > 1u ||
        summary_out->stack_frame_count > RIN_CRASH_RECORD_MAX_FRAMES ||
        summary_out->has_scheduler > 1u ||
        (summary_out->kind == RIN_CRASH_RECORD_USER_MINIDUMP &&
         (summary_out->has_process != 1u || summary_out->process_id == 0u ||
          summary_out->thread_id == 0u ||
          summary_out->process.process_instance_cookie == 0u ||
          summary_out->process.reserved != 0u ||
          !rin_crash_owner_session_valid(
              &summary_out->process.owner_session,
              summary_out->process.owner_uid) ||
          summary_out->process.owner_session.session_id == 0u))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request_id, request_generation);
    if (result != RINRUNTIME_CRASH_SERVICE_OK && summary_out != NULL)
        memset(summary_out, 0, sizeof(*summary_out));
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&proof, 0, sizeof(proof));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    return result;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_read_summary_with_consent(
    uint32_t expected_service_slot, RinCrashSummaryV1* summary_out)
{
    if (summary_out != NULL) memset(summary_out, 0, sizeof(*summary_out));
    if (summary_out == NULL || expected_service_slot == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_read_summary_request(expected_service_slot,
                                              summary_out);
}

RinRuntimeCrashServiceResult rinruntime_crash_service_register_recovery(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    uint32_t expected_service_slot)
{
    RinCrashRecoveryRegistrationV1 registration;
    RinRuntimeCrashServiceResult result =
        rinruntime_crash_service_registration_from_metadata(
        metadata, &registration);
    if (result == RINRUNTIME_CRASH_SERVICE_OK)
        result = crash_service_recovery_request(
            RIN_CRASH_SERVICE_OP_REGISTER_RECOVERY, &registration,
            expected_service_slot);
    memset(&registration, 0, sizeof(registration));
    return result;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_query_recovery_crash(
    const RinRuntimeSessionRecoveryMetadataV1* metadata,
    uint32_t expected_service_slot)
{
    RinCrashRecoveryRegistrationV1 registration;
    RinRuntimeCrashServiceResult result =
        rinruntime_crash_service_registration_from_metadata(
            metadata, &registration);
    if (result == RINRUNTIME_CRASH_SERVICE_OK)
        result = crash_service_recovery_request(
            RIN_CRASH_SERVICE_OP_QUERY_RECOVERY_CRASH, &registration,
            expected_service_slot);
    memset(&registration, 0, sizeof(registration));
    return result;
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

    fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0) goto done;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot))
        goto done;
    request_id = crash_service_next_request_id();
    if (!crash_service_request_id_valid(request_id)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
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
        reply.payload_size != 0u || reply.flags != 0u || reply.reserved != 0u ||
        !crash_service_result_valid(reply.status)) {
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
