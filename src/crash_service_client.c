/* SPDX-License-Identifier: MIT */

#include <rinruntime/crash_service.h>
#include <rinruntime/crash_pending_minidumps.h>
#include <rinruntime/crash_pending_dump_cleanup.h>
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

static int crash_service_notice_valid(const RinCrashServiceNoticeV1* notice)
{
    return notice != NULL && notice->struct_size == sizeof(*notice) &&
           notice->version == RIN_CRASH_SERVICE_NOTICE_VERSION &&
           notice->reserved0 == 0u &&
           (notice->boot_id_high != 0u || notice->boot_id_low != 0u) &&
           notice->sequence != 0u && notice->sequence != UINT64_MAX &&
           notice->reserved[0] == 0u && notice->reserved[1] == 0u;
}

static RinRuntimeCrashServiceResult crash_service_desktop_notice_request(
    uint32_t expected_service_slot, RinCrashServiceNoticeV1* notice_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (notice_out == NULL || expected_service_slot == 0u ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(notice_out, 0, sizeof(*notice_out));
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
    request.opcode = RIN_CRASH_SERVICE_OP_DESKTOP_NOTICE;
    request.request_id = request_id;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
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
    if (reply.status == RIN_RESULT_NOT_FOUND) {
        result = reply.payload_size == 0u
            ? RINRUNTIME_CRASH_SERVICE_NO_NOTICE
            : RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.status != RIN_RESULT_OK ||
        reply.payload_size != sizeof(*notice_out) ||
        !crash_service_receive_exact(fd, notice_out, sizeof(*notice_out))) {
        result = reply.status == RIN_RESULT_OK
            ? RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR
            : RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    if (!crash_service_notice_valid(notice_out)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    result = RINRUNTIME_CRASH_SERVICE_CRASH_DETECTED;

done:
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    if (result != RINRUNTIME_CRASH_SERVICE_CRASH_DETECTED)
        memset(notice_out, 0, sizeof(*notice_out));
    return result;
}

static int crash_service_summary_valid(const RinCrashSummaryV1* summary)
{
    if (summary == NULL || summary->struct_size != sizeof(*summary) ||
        summary->version != RIN_CRASH_SUMMARY_VERSION ||
        summary->reserved != 0u ||
        summary->disclosure_policy != RIN_CRASH_SUMMARY_POLICY_LOCAL_ONLY ||
        (summary->kind != RIN_CRASH_RECORD_KERNEL_PANIC &&
         summary->kind != RIN_CRASH_RECORD_USER_MINIDUMP) ||
        (summary->architecture != RIN_CRASH_ARCH_X86_64 &&
         summary->architecture != RIN_CRASH_ARCH_X86_32) ||
        summary->sequence == 0u || summary->sequence == UINT64_MAX ||
        summary->message_size > RIN_CRASH_RECORD_MAX_MESSAGE ||
        summary->message[summary->message_size] != '\0' ||
        summary->has_process > 1u ||
        summary->stack_frame_count > RIN_CRASH_RECORD_MAX_FRAMES ||
        summary->has_scheduler > 1u)
        return 0;
    if (summary->kind == RIN_CRASH_RECORD_USER_MINIDUMP &&
        (summary->has_process != 1u || summary->process_id == 0u ||
         summary->thread_id == 0u ||
         summary->process.process_instance_cookie == 0u ||
         summary->process.reserved != 0u ||
         !rin_crash_owner_session_valid(&summary->process.owner_session,
                                        summary->process.owner_uid) ||
         summary->process.owner_session.session_id == 0u))
        return 0;
    return 1;
}

static int crash_service_recovery_authority_valid(
    const RinCrashServiceRecoveryAuthorityV1* authority,
    const RinCrashServiceNoticeV1* notice)
{
    uint8_t application_id_nonzero = 0u;
    uint8_t package_digest_nonzero = 0u;
    uint32_t index;
    if (authority == NULL || notice == NULL ||
        authority->struct_size != sizeof(*authority) ||
        authority->version !=
            RIN_CRASH_SERVICE_RECOVERY_AUTHORITY_VERSION ||
        (authority->flags &
         ~RIN_CRASH_SERVICE_RECOVERY_AUTHORITY_FLAG_MASK) != 0u ||
        authority->boot_id_high != notice->boot_id_high ||
        authority->boot_id_low != notice->boot_id_low ||
        authority->sequence != notice->sequence ||
        authority->reserved[0] != 0u || authority->reserved[1] != 0u)
        return 0;
    for (index = 0u; index < sizeof(authority->application_id); ++index)
        application_id_nonzero |= authority->application_id[index];
    for (index = 0u; index < sizeof(authority->package_digest); ++index)
        package_digest_nonzero |= authority->package_digest[index];
    if ((authority->flags &
         RIN_CRASH_SERVICE_RECOVERY_AUTHORITY_FLAG_AVAILABLE) != 0u)
        return authority->package_generation != 0u &&
               authority->owner_uid != 0u && authority->session_id != 0u &&
               authority->session_instance_cookie != 0u &&
               authority->process_id != 0u &&
               authority->process_instance_cookie != 0u &&
               application_id_nonzero != 0u && package_digest_nonzero != 0u;
    return authority->package_generation == 0u &&
           authority->owner_uid == 0u && authority->session_id == 0u &&
           authority->session_instance_cookie == 0u &&
           authority->process_id == 0u &&
           authority->process_instance_cookie == 0u &&
           application_id_nonzero == 0u && package_digest_nonzero == 0u;
}

static RinRuntimeCrashServiceResult crash_service_read_summary_request(
    uint32_t expected_service_slot, const RinCrashServiceNoticeV1* notice,
    RinCrashSummaryV1* summary_out,
    RinCrashServiceRecoveryAuthorityV1* recovery_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashConsentProofV1 proof = {};
    RinCrashServiceNoticeReadV1 notice_read = {};
    RinCrashServiceNoticeRecoveryV1 notice_recovery = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id = 0u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (summary_out == NULL || expected_service_slot == 0u ||
        (recovery_out != NULL && notice == NULL) ||
        (notice != NULL && !crash_service_notice_valid(notice)) ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(summary_out, 0, sizeof(*summary_out));
    if (recovery_out != NULL) memset(recovery_out, 0, sizeof(*recovery_out));
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
    request.opcode = notice != NULL
        ? (recovery_out != NULL
               ? RIN_CRASH_SERVICE_OP_READ_NOTICE_RECOVERY
               : RIN_CRASH_SERVICE_OP_READ_NOTICE)
        : RIN_CRASH_SERVICE_OP_READ;
    request.request_id = request_id;
    request.payload_size = notice != NULL
        ? sizeof(notice_read) : sizeof(proof);
    if (notice != NULL) {
        notice_read.proof = proof;
        notice_read.notice = *notice;
    }
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd,
            notice != NULL ? (const void*)&notice_read : (const void*)&proof,
            request.payload_size) ||
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
    if (recovery_out != NULL) {
        if (reply.payload_size != sizeof(notice_recovery) ||
            !crash_service_receive_exact(fd, &notice_recovery,
                                         sizeof(notice_recovery))) {
            result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
            goto done;
        }
    } else if (reply.payload_size != sizeof(*summary_out) ||
               !crash_service_receive_exact(fd, summary_out,
                                            sizeof(*summary_out))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    const RinCrashSummaryV1* received_summary = recovery_out != NULL
        ? &notice_recovery.summary : summary_out;
    if (!crash_service_summary_valid(received_summary) ||
        (notice != NULL &&
         (received_summary->kind != RIN_CRASH_RECORD_USER_MINIDUMP ||
          received_summary->sequence != notice->sequence ||
          received_summary->boot_id_high != notice->boot_id_high ||
          received_summary->boot_id_low != notice->boot_id_low)) ||
        (recovery_out != NULL &&
         !crash_service_recovery_authority_valid(
             &notice_recovery.recovery, notice))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (recovery_out != NULL) {
        *summary_out = notice_recovery.summary;
        *recovery_out = notice_recovery.recovery;
    }
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request_id, request_generation);
    if (result != RINRUNTIME_CRASH_SERVICE_OK && summary_out != NULL)
        memset(summary_out, 0, sizeof(*summary_out));
    if (result != RINRUNTIME_CRASH_SERVICE_OK && recovery_out != NULL)
        memset(recovery_out, 0, sizeof(*recovery_out));
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&proof, 0, sizeof(proof));
    memset(&notice_read, 0, sizeof(notice_read));
    memset(&notice_recovery, 0, sizeof(notice_recovery));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    return result;
}

static RinRuntimeCrashServiceResult crash_service_read_history_request(
    uint32_t expected_service_slot, uint64_t after_sequence,
    uint16_t capacity, RinCrashServiceHistoryPageV1* page_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashConsentProofV1 proof = {};
    RinCrashServiceHistoryReadV1 history_read = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id = 0u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    uint32_t index;
    uint64_t previous_sequence;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (page_out == NULL || expected_service_slot == 0u ||
        after_sequence == UINT64_MAX || capacity == 0u ||
        capacity > RIN_CRASH_SERVICE_HISTORY_PAGE_MAX_RECORDS ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(page_out, 0, sizeof(*page_out));
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
    request.opcode = RIN_CRASH_SERVICE_OP_READ_HISTORY;
    request.request_id = request_id;
    request.payload_size = sizeof(history_read);
    history_read.proof = proof;
    history_read.after_sequence = after_sequence;
    history_read.capacity = capacity;
    history_read.version = RIN_CRASH_SERVICE_HISTORY_READ_VERSION;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &history_read, sizeof(history_read)) ||
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
        result = reply.payload_size == 0u
            ? RINRUNTIME_CRASH_SERVICE_REJECTED
            : RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.payload_size != sizeof(*page_out) ||
        !crash_service_receive_exact(fd, page_out, sizeof(*page_out))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (page_out->struct_size != sizeof(*page_out) ||
        page_out->version != RIN_CRASH_SERVICE_HISTORY_PAGE_VERSION ||
        page_out->record_count > capacity ||
        (page_out->flags & ~RIN_CRASH_SERVICE_HISTORY_PAGE_FLAG_MASK) != 0u ||
        page_out->reserved != 0u ||
        page_out->after_sequence != after_sequence ||
        page_out->gap_before_sequence == UINT64_MAX ||
        page_out->next_sequence == UINT64_MAX ||
        page_out->next_sequence < after_sequence ||
        (((page_out->flags & RIN_CRASH_SERVICE_HISTORY_PAGE_FLAG_GAP) != 0u) !=
         (page_out->gap_before_sequence != 0u &&
          after_sequence < page_out->gap_before_sequence))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    previous_sequence = after_sequence;
    for (index = 0u; index < page_out->record_count; ++index) {
        const RinCrashSummaryV1* summary = &page_out->records[index];
        if (!crash_service_summary_valid(summary) ||
            summary->sequence <= previous_sequence) {
            result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
            goto done;
        }
        previous_sequence = summary->sequence;
    }
    if (page_out->next_sequence < previous_sequence) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request_id, request_generation);
    if (result != RINRUNTIME_CRASH_SERVICE_OK && page_out != NULL)
        memset(page_out, 0, sizeof(*page_out));
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&proof, 0, sizeof(proof));
    memset(&history_read, 0, sizeof(history_read));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    return result;
}

static RinRuntimeCrashServiceResult crash_service_export_notice_request(
    uint32_t expected_service_slot, const RinCrashServiceNoticeV1* notice,
    uint8_t* minidump_out, uint32_t minidump_capacity,
    uint32_t* minidump_size_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashConsentProofV1 proof = {};
    RinCrashServiceNoticeReadV1 notice_read = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id = 0u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (minidump_size_out != NULL) *minidump_size_out = 0u;
    if (minidump_out != NULL && minidump_capacity != 0u)
        memset(minidump_out, 0,
               minidump_capacity < RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES
                   ? minidump_capacity
                   : RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES);
    if (expected_service_slot == 0u || !crash_service_notice_valid(notice) ||
        minidump_out == NULL || minidump_size_out == NULL ||
        minidump_capacity != RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
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
    request.opcode = RIN_CRASH_SERVICE_OP_EXPORT_NOTICE;
    request.request_id = request_id;
    request.payload_size = sizeof(notice_read);
    notice_read.proof = proof;
    notice_read.notice = *notice;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &notice_read, sizeof(notice_read)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode || reply.request_id != request_id ||
        reply.flags != 0u || reply.reserved != 0u ||
        !crash_service_result_valid(reply.status)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.status != RIN_RESULT_OK) {
        result = reply.payload_size == 0u
            ? RINRUNTIME_CRASH_SERVICE_REJECTED
            : RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.payload_size < 32u ||
        reply.payload_size > RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES ||
        reply.payload_size > minidump_capacity ||
        !crash_service_receive_exact(fd, minidump_out, reply.payload_size)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (minidump_out[0] != 'M' || minidump_out[1] != 'D' ||
        minidump_out[2] != 'M' || minidump_out[3] != 'P' ||
        minidump_out[4] != 0x93u || minidump_out[5] != 0xa7u ||
        minidump_out[6] != 0u || minidump_out[7] != 0u) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    *minidump_size_out = reply.payload_size;
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request_id, request_generation);
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&proof, 0, sizeof(proof));
    memset(&notice_read, 0, sizeof(notice_read));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    if (result != RINRUNTIME_CRASH_SERVICE_OK) {
        memset(minidump_out, 0, RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES);
        *minidump_size_out = 0u;
    }
    return result;
}

static RinRuntimeCrashServiceResult crash_service_legacy_history_status_request(
    uint32_t expected_service_slot,
    RinCrashServiceLegacyHistoryStatusV1* status_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashServiceLegacyHistoryStatusQueryV1 query = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
    int fd = -1;

    if (status_out == NULL || expected_service_slot == 0u ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    memset(status_out, 0, sizeof(*status_out));
    fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0) goto done;
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, RINRUNTIME_CRASH_SERVICE_PATH, path_size);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        !crash_service_endpoint_valid(fd, expected_service_slot))
        goto done;

    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = RIN_CRASH_SERVICE_OP_LEGACY_HISTORY_STATUS;
    request.request_id = crash_service_next_request_id();
    request.payload_size = sizeof(query);
    query.version = RIN_CRASH_SERVICE_LEGACY_HISTORY_STATUS_VERSION;
    if (!crash_service_request_id_valid(request.request_id) ||
        !crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &query, sizeof(query)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode ||
        reply.request_id != request.request_id || reply.flags != 0u ||
        reply.reserved != 0u || !crash_service_result_valid(reply.status)) {
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
    if (reply.payload_size != sizeof(*status_out) ||
        !crash_service_receive_exact(fd, status_out, sizeof(*status_out))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (status_out->struct_size != sizeof(*status_out) ||
        status_out->version !=
            RIN_CRASH_SERVICE_LEGACY_HISTORY_STATUS_VERSION ||
        status_out->reserved0 != 0u || status_out->reserved1 != 0u ||
        status_out->inaccessible_record_count >
            RIN_CRASH_SERVICE_LEGACY_HISTORY_MAX_RECORDS ||
        (status_out->inaccessible_record_count != 0u &&
         status_out->through_sequence == 0u)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (result != RINRUNTIME_CRASH_SERVICE_OK && status_out != NULL)
        memset(status_out, 0, sizeof(*status_out));
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&query, 0, sizeof(query));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    return result;
}

static RinRuntimeCrashServiceResult crash_service_legacy_history_purge_request(
    uint32_t expected_service_slot,
    const RinCrashServiceLegacyHistoryStatusV1* confirmed_status)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashServiceLegacyHistoryPurgeV1 purge = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;
    int fd = -1;

    if (confirmed_status == NULL || expected_service_slot == 0u ||
        confirmed_status->struct_size != sizeof(*confirmed_status) ||
        confirmed_status->version !=
            RIN_CRASH_SERVICE_LEGACY_HISTORY_STATUS_VERSION ||
        confirmed_status->reserved0 != 0u ||
        confirmed_status->reserved1 != 0u ||
        confirmed_status->inaccessible_record_count == 0u ||
        confirmed_status->inaccessible_record_count >
            RIN_CRASH_SERVICE_LEGACY_HISTORY_MAX_RECORDS ||
        confirmed_status->through_sequence == 0u ||
        path_size >= sizeof(address.sun_path))
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
    request.opcode = RIN_CRASH_SERVICE_OP_PURGE_LEGACY_HISTORY;
    request.request_id = crash_service_next_request_id();
    request.payload_size = sizeof(purge);
    if (!crash_service_request_id_valid(request.request_id)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (rin_crash_consent_request(fd, request.request_id,
                                  &request_generation) !=
            (int)RIN_RESULT_OK || request_generation == 0u) {
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    for (wait_step = 0u;
         wait_step < RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_STEPS;
         ++wait_step) {
        const int consent_result = rin_crash_consent_take(
            fd, request.request_id, request_generation, &purge.proof);
        if (consent_result == (int)RIN_RESULT_OK) break;
        if (consent_result != (int)RIN_RESULT_ACCESS_DENIED) {
            result = RINRUNTIME_CRASH_SERVICE_REJECTED;
            goto done;
        }
        rin_sleep(RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_MS);
    }
    if (wait_step == RINRUNTIME_CRASH_SERVICE_CONSENT_WAIT_STEPS) {
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    purge.through_sequence = confirmed_status->through_sequence;
    purge.expected_inaccessible_record_count =
        confirmed_status->inaccessible_record_count;
    purge.version = RIN_CRASH_SERVICE_LEGACY_HISTORY_PURGE_VERSION;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &purge, sizeof(purge)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode ||
        reply.request_id != request.request_id || reply.payload_size != 0u ||
        reply.flags != 0u || reply.reserved != 0u ||
        (reply.status != RIN_CRASH_SERVICE_STATUS_CONSENT_REQUIRED &&
         !crash_service_result_valid(reply.status))) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.status == RIN_RESULT_OK)
        result = RINRUNTIME_CRASH_SERVICE_OK;
    else if (reply.status == RIN_RESULT_BUSY)
        result = RINRUNTIME_CRASH_SERVICE_STALE_HISTORY_STATUS;
    else
        result = RINRUNTIME_CRASH_SERVICE_REJECTED;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request.request_id,
                                       request_generation);
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&purge, 0, sizeof(purge));
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
                                              NULL, summary_out, NULL);
}

RinRuntimeCrashServiceResult rinruntime_crash_service_get_desktop_notice(
    uint32_t expected_service_slot, RinCrashServiceNoticeV1* notice_out)
{
    if (notice_out != NULL) memset(notice_out, 0, sizeof(*notice_out));
    if (notice_out == NULL || expected_service_slot == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_desktop_notice_request(expected_service_slot,
                                                notice_out);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_read_notice_with_consent(
    uint32_t expected_service_slot, const RinCrashServiceNoticeV1* notice,
    RinCrashSummaryV1* summary_out)
{
    if (summary_out != NULL) memset(summary_out, 0, sizeof(*summary_out));
    if (summary_out == NULL || expected_service_slot == 0u ||
        !crash_service_notice_valid(notice))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_read_summary_request(expected_service_slot, notice,
                                              summary_out, NULL);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_read_notice_with_consent_and_recovery(
    uint32_t expected_service_slot, const RinCrashServiceNoticeV1* notice,
    RinCrashSummaryV1* summary_out,
    RinCrashServiceRecoveryAuthorityV1* recovery_out)
{
    if (summary_out != NULL) memset(summary_out, 0, sizeof(*summary_out));
    if (recovery_out != NULL) memset(recovery_out, 0, sizeof(*recovery_out));
    if (summary_out == NULL || recovery_out == NULL ||
        expected_service_slot == 0u || !crash_service_notice_valid(notice))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_read_summary_request(expected_service_slot, notice,
                                              summary_out, recovery_out);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_export_notice_with_consent(
    uint32_t expected_service_slot, const RinCrashServiceNoticeV1* notice,
    uint8_t* minidump_out, uint32_t minidump_capacity,
    uint32_t* minidump_size_out)
{
    return crash_service_export_notice_request(
        expected_service_slot, notice, minidump_out, minidump_capacity,
        minidump_size_out);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_read_history_with_consent(
    uint32_t expected_service_slot, uint64_t after_sequence,
    uint16_t capacity, RinCrashServiceHistoryPageV1* page_out)
{
    if (page_out != NULL) memset(page_out, 0, sizeof(*page_out));
    if (page_out == NULL || expected_service_slot == 0u ||
        after_sequence == UINT64_MAX || capacity == 0u ||
        capacity > RIN_CRASH_SERVICE_HISTORY_PAGE_MAX_RECORDS)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_read_history_request(
        expected_service_slot, after_sequence, capacity, page_out);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_get_legacy_history_status(
    uint32_t expected_service_slot,
    RinCrashServiceLegacyHistoryStatusV1* status_out)
{
    if (status_out != NULL) memset(status_out, 0, sizeof(*status_out));
    if (status_out == NULL || expected_service_slot == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_legacy_history_status_request(expected_service_slot,
                                                       status_out);
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_purge_legacy_history_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServiceLegacyHistoryStatusV1* confirmed_status)
{
    if (confirmed_status == NULL || expected_service_slot == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    return crash_service_legacy_history_purge_request(expected_service_slot,
                                                      confirmed_status);
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

static int crash_service_pending_dump_info_less(
    const RinCrashServicePendingDumpInfoV1* left,
    const RinCrashServicePendingDumpInfoV1* right)
{
    if (left->timestamp_ns != right->timestamp_ns)
        return left->timestamp_ns < right->timestamp_ns;
    if (left->boot_id_high != right->boot_id_high)
        return left->boot_id_high < right->boot_id_high;
    if (left->boot_id_low != right->boot_id_low)
        return left->boot_id_low < right->boot_id_low;
    return left->queue_sequence < right->queue_sequence;
}

static RinRuntimeCrashServiceResult crash_service_pending_exchange(
    uint32_t expected_service_slot, uint16_t opcode,
    const void* payload_tail, uint32_t payload_tail_size,
    void* response_out, uint32_t response_capacity,
    uint32_t expected_response_size, uint32_t* response_size_out)
{
    RinCrashServiceMessageHeaderV1 request = {};
    RinCrashServiceMessageHeaderV1 reply = {};
    RinCrashConsentProofV1 proof = {};
    union {
        RinCrashServicePendingDumpExportV1 pending_export;
        RinCrashServicePendingDumpDeleteV1 pending_delete;
        RinCrashServicePendingDumpCleanupRequestV2 cleanup;
    } payload = {};
    struct sockaddr_un address = {};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    const uint32_t proof_size = sizeof(proof);
    uint64_t request_id = 0u;
    uint64_t request_generation = 0u;
    uint32_t wait_step;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (response_size_out != NULL) *response_size_out = 0u;
    if (response_out != NULL && response_capacity != 0u)
        memset(response_out, 0, response_capacity);
    if (expected_service_slot == 0u || response_out == NULL ||
        response_capacity == 0u || response_size_out == NULL ||
        payload_tail_size > sizeof(payload) - proof_size ||
        (payload_tail_size != 0u && payload_tail == NULL) ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
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

    if (payload_tail_size != 0u)
        memcpy((uint8_t*)&payload + proof_size, payload_tail,
               payload_tail_size);
    memcpy(&payload, &proof, sizeof(proof));
    request.struct_size = sizeof(request);
    request.version = RIN_CRASH_SERVICE_ABI_VERSION;
    request.opcode = opcode;
    request.request_id = request_id;
    request.payload_size = proof_size + payload_tail_size;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_send_exact(fd, &payload, request.payload_size) ||
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
        if (reply.payload_size != 0u)
            result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        else if (reply.status == RIN_RESULT_BUSY &&
                 opcode ==
                     RIN_CRASH_SERVICE_OP_PURGE_PENDING_DUMP_CLEANUP)
            result = RINRUNTIME_CRASH_SERVICE_STALE_PENDING_DUMP_CLEANUP;
        else
            result = RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    if ((expected_response_size != 0u &&
         reply.payload_size != expected_response_size) ||
        reply.payload_size > response_capacity ||
        reply.payload_size == 0u ||
        !crash_service_receive_exact(fd, response_out, reply.payload_size)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    *response_size_out = reply.payload_size;
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    if (request_generation != 0u)
        (void)rin_crash_consent_cancel(fd, request_id, request_generation);
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&proof, 0, sizeof(proof));
    memset(&payload, 0, sizeof(payload));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    if (result != RINRUNTIME_CRASH_SERVICE_OK) {
        memset(response_out, 0, response_capacity);
        *response_size_out = 0u;
    }
    return result;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_get_pending_dump_notice(
    uint32_t expected_service_slot, uint32_t* available_out)
{
    RinCrashServiceMessageHeaderV1 request = {0};
    RinCrashServiceMessageHeaderV1 reply = {0};
    RinCrashServicePendingDumpNoticeV1 notice = {0};
    struct sockaddr_un address = {0};
    const size_t path_size = sizeof(RINRUNTIME_CRASH_SERVICE_PATH) - 1u;
    uint64_t request_id;
    int fd = -1;
    RinRuntimeCrashServiceResult result =
        RINRUNTIME_CRASH_SERVICE_UNAVAILABLE;

    if (available_out != NULL) *available_out = 0u;
    if (available_out == NULL || expected_service_slot == 0u ||
        path_size >= sizeof(address.sun_path))
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
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
    request.opcode = RIN_CRASH_SERVICE_OP_PENDING_DUMP_NOTICE;
    request.request_id = request_id;
    if (!crash_service_send_exact(fd, &request, sizeof(request)) ||
        !crash_service_receive_exact(fd, &reply, sizeof(reply)))
        goto done;
    if (reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_ABI_VERSION ||
        reply.opcode != request.opcode || reply.request_id != request_id ||
        reply.flags != 0u || reply.reserved != 0u ||
        !crash_service_result_valid(reply.status)) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (reply.status != RIN_RESULT_OK ||
        reply.payload_size != sizeof(notice) ||
        !crash_service_receive_exact(fd, &notice, sizeof(notice))) {
        result = reply.status == RIN_RESULT_OK
            ? RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR
            : RINRUNTIME_CRASH_SERVICE_REJECTED;
        goto done;
    }
    if (notice.struct_size != sizeof(notice) ||
        notice.version != RIN_CRASH_SERVICE_PENDING_DUMP_NOTICE_VERSION ||
        (notice.flags &
         (uint16_t)~RIN_CRASH_SERVICE_PENDING_DUMP_NOTICE_FLAG_MASK) != 0u ||
        notice.reserved[0] != 0u || notice.reserved[1] != 0u) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto done;
    }
    *available_out =
        (notice.flags &
         RIN_CRASH_SERVICE_PENDING_DUMP_NOTICE_FLAG_AVAILABLE) != 0u
            ? 1u : 0u;
    result = RINRUNTIME_CRASH_SERVICE_OK;

done:
    memset(&request, 0, sizeof(request));
    memset(&reply, 0, sizeof(reply));
    memset(&notice, 0, sizeof(notice));
    memset(&address, 0, sizeof(address));
    if (fd >= 0) close(fd);
    if (result != RINRUNTIME_CRASH_SERVICE_OK && available_out != NULL)
        *available_out = 0u;
    return result;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_read_pending_minidumps_with_consent(
    uint32_t expected_service_slot,
    RinCrashServicePendingDumpListV1* list_out)
{
    uint32_t response_size = 0u;
    RinRuntimeCrashServiceResult result;
    uint16_t index;
    if (list_out != NULL) memset(list_out, 0, sizeof(*list_out));
    if (list_out == NULL) return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    result = crash_service_pending_exchange(
        expected_service_slot, RIN_CRASH_SERVICE_OP_READ_PENDING_DUMPS,
        NULL, 0u, list_out, sizeof(*list_out), sizeof(*list_out),
        &response_size);
    if (result != RINRUNTIME_CRASH_SERVICE_OK) return result;
    if (response_size != sizeof(*list_out) ||
        list_out->struct_size != sizeof(*list_out) ||
        list_out->version != RIN_CRASH_SERVICE_PENDING_DUMP_LIST_VERSION ||
        list_out->record_count > RIN_CRASH_SERVICE_PENDING_DUMP_MAX_RECORDS ||
        list_out->reserved != 0u) {
        result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
        goto invalid;
    }
    for (index = 0u; index < list_out->record_count; ++index) {
        const RinCrashServicePendingDumpInfoV1* info =
            &list_out->records[index];
        if ((info->boot_id_high == 0u && info->boot_id_low == 0u) ||
            info->queue_sequence == 0u ||
            (info->architecture != RIN_CRASH_ARCH_X86_64 &&
             info->architecture != RIN_CRASH_ARCH_X86_32) ||
            (index != 0u && !crash_service_pending_dump_info_less(
                &list_out->records[index - 1u], info))) {
            result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
            goto invalid;
        }
    }
    for (; index < RIN_CRASH_SERVICE_PENDING_DUMP_MAX_RECORDS; ++index) {
        const uint8_t* bytes = (const uint8_t*)&list_out->records[index];
        for (size_t byte = 0u; byte < sizeof(list_out->records[index]); ++byte) {
            if (bytes[byte] != 0u) {
                result = RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
                goto invalid;
            }
        }
    }
    return RINRUNTIME_CRASH_SERVICE_OK;

invalid:
    memset(list_out, 0, sizeof(*list_out));
    return result;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_export_pending_minidump_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpInfoV1* info,
    uint8_t* minidump_out, uint32_t minidump_capacity,
    uint32_t* minidump_size_out)
{
    RinCrashServicePendingDumpExportV1 request = {};
    const size_t tail_offset =
        offsetof(RinCrashServicePendingDumpExportV1, boot_id_high);
    uint32_t response_size = 0u;
    RinRuntimeCrashServiceResult result;
    if (minidump_size_out != NULL) *minidump_size_out = 0u;
    if (minidump_out != NULL && minidump_capacity != 0u)
        memset(minidump_out, 0,
               minidump_capacity < RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES
                   ? minidump_capacity
                   : RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES);
    if (expected_service_slot == 0u || info == NULL ||
        minidump_out == NULL || minidump_size_out == NULL ||
        minidump_capacity != RIN_CRASH_SERVICE_MINIDUMP_MAX_BYTES ||
        (info->boot_id_high == 0u && info->boot_id_low == 0u) ||
        info->queue_sequence == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    request.boot_id_high = info->boot_id_high;
    request.boot_id_low = info->boot_id_low;
    request.queue_sequence = info->queue_sequence;
    request.version = RIN_CRASH_SERVICE_PENDING_DUMP_EXPORT_VERSION;
    result = crash_service_pending_exchange(
        expected_service_slot, RIN_CRASH_SERVICE_OP_EXPORT_PENDING_DUMP,
        (const uint8_t*)&request + tail_offset,
        sizeof(request) - (uint32_t)tail_offset,
        minidump_out, minidump_capacity, 0u, &response_size);
    memset(&request, 0, sizeof(request));
    if (result != RINRUNTIME_CRASH_SERVICE_OK) return result;
    if (response_size < 32u ||
        response_size > minidump_capacity ||
        minidump_out[0] != 'M' || minidump_out[1] != 'D' ||
        minidump_out[2] != 'M' || minidump_out[3] != 'P' ||
        minidump_out[4] != 0x93u || minidump_out[5] != 0xa7u ||
        minidump_out[6] != 0u || minidump_out[7] != 0u) {
        memset(minidump_out, 0, minidump_capacity);
        return RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
    }
    *minidump_size_out = response_size;
    return RINRUNTIME_CRASH_SERVICE_OK;
}

static int crash_service_cleanup_candidate_less(
    const RinCrashServicePendingDumpCleanupCandidateV2* left,
    const RinCrashServicePendingDumpCleanupCandidateV2* right)
{
    if (left->boot_id_high != right->boot_id_high)
        return left->boot_id_high < right->boot_id_high;
    if (left->boot_id_low != right->boot_id_low)
        return left->boot_id_low < right->boot_id_low;
    if (left->queue_sequence != right->queue_sequence)
        return left->queue_sequence < right->queue_sequence;
    return left->kind < right->kind;
}

static int crash_service_cleanup_status_valid(
    const RinCrashServicePendingDumpCleanupStatusV2* status)
{
    uint16_t index;
    if (status == NULL || status->struct_size != sizeof(*status) ||
        status->version != RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_VERSION ||
        status->candidate_count >
            RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_MAX_CANDIDATES ||
        status->total_candidate_count < status->candidate_count ||
        status->unattributed_count < status->total_candidate_count ||
        (status->flags &
         ~RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_FLAG_MASK) != 0u ||
        status->metadata_sidecar_candidate_count >
            status->total_candidate_count ||
        status->reserved[0] != 0u ||
        status->reserved[1] != 0u)
        return 0;
    if (status->total_candidate_count >
        RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_MAX_CANDIDATES) {
        if (status->candidate_count !=
                RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_MAX_CANDIDATES ||
            status->flags !=
                RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_FLAG_MORE)
            return 0;
    } else if (status->candidate_count != status->total_candidate_count ||
               status->flags != 0u) {
        return 0;
    }
    uint16_t sidecar_candidate_count = 0u;
    for (index = 0u; index < status->candidate_count; ++index) {
        const RinCrashServicePendingDumpCleanupCandidateV2* candidate =
            &status->candidates[index];
        if ((candidate->boot_id_high == 0u &&
             candidate->boot_id_low == 0u) ||
            candidate->queue_sequence == 0u || candidate->file_inode == 0u ||
            candidate->kind >
                RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_KIND_METADATA_SIDECAR ||
            candidate->reserved1 != 0u || candidate->reserved2 != 0u ||
            candidate->reserved3 != 0u ||
            (candidate->kind ==
                 RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_KIND_DUMP &&
             (candidate->dump_device != 0u || candidate->dump_inode != 0u ||
              candidate->dump_size != 0u ||
              candidate->dump_mtime_seconds != 0u ||
              candidate->dump_ctime_seconds != 0u)) ||
            (candidate->kind ==
                 RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_KIND_METADATA_SIDECAR &&
             candidate->dump_inode == 0u) ||
            (index != 0u && !crash_service_cleanup_candidate_less(
                &status->candidates[index - 1u], candidate)))
            return 0;
        if (candidate->kind ==
            RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_KIND_METADATA_SIDECAR)
            ++sidecar_candidate_count;
    }
    for (; index < RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_MAX_CANDIDATES;
         ++index) {
        const uint8_t* bytes = (const uint8_t*)&status->candidates[index];
        for (size_t byte = 0u;
             byte < sizeof(status->candidates[index]); ++byte)
            if (bytes[byte] != 0u) return 0;
    }
    return sidecar_candidate_count <=
               status->metadata_sidecar_candidate_count &&
           (uint32_t)(status->candidate_count - sidecar_candidate_count) <=
               status->total_candidate_count -
                   status->metadata_sidecar_candidate_count;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_get_pending_dump_cleanup_with_consent(
    uint32_t expected_service_slot,
    RinCrashServicePendingDumpCleanupStatusV2* status_out)
{
    uint32_t response_size = 0u;
    RinRuntimeCrashServiceResult result;
    if (status_out != NULL) memset(status_out, 0, sizeof(*status_out));
    if (expected_service_slot == 0u || status_out == NULL)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    result = crash_service_pending_exchange(
        expected_service_slot,
        RIN_CRASH_SERVICE_OP_QUERY_PENDING_DUMP_CLEANUP,
        NULL, 0u, status_out, sizeof(*status_out), sizeof(*status_out),
        &response_size);
    if (result != RINRUNTIME_CRASH_SERVICE_OK) return result;
    if (response_size != sizeof(*status_out) ||
        !crash_service_cleanup_status_valid(status_out)) {
        memset(status_out, 0, sizeof(*status_out));
        return RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
    }
    return RINRUNTIME_CRASH_SERVICE_OK;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_purge_pending_dumps_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpCleanupStatusV2* confirmed_status,
    uint32_t* removed_count_out)
{
    RinCrashServicePendingDumpCleanupRequestV2 request = {};
    RinCrashServicePendingDumpCleanupResultV2 reply = {};
    const size_t tail_offset = offsetof(
        RinCrashServicePendingDumpCleanupRequestV2, version);
    uint32_t response_size = 0u;
    RinRuntimeCrashServiceResult result;
    if (removed_count_out != NULL) *removed_count_out = 0u;
    if (expected_service_slot == 0u || confirmed_status == NULL ||
        removed_count_out == NULL ||
        !crash_service_cleanup_status_valid(confirmed_status) ||
        confirmed_status->candidate_count == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    request.version = RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_REQUEST_VERSION;
    request.snapshot = *confirmed_status;
    result = crash_service_pending_exchange(
        expected_service_slot,
        RIN_CRASH_SERVICE_OP_PURGE_PENDING_DUMP_CLEANUP,
        (const uint8_t*)&request + tail_offset,
        sizeof(request) - (uint32_t)tail_offset,
        &reply, sizeof(reply), sizeof(reply), &response_size);
    memset(&request, 0, sizeof(request));
    if (result != RINRUNTIME_CRASH_SERVICE_OK) {
        memset(&reply, 0, sizeof(reply));
        return result;
    }
    if (response_size != sizeof(reply) ||
        reply.struct_size != sizeof(reply) ||
        reply.version != RIN_CRASH_SERVICE_PENDING_DUMP_CLEANUP_VERSION ||
        reply.reserved0 != 0u || reply.reserved1 != 0u ||
        reply.removed_count != confirmed_status->candidate_count) {
        memset(&reply, 0, sizeof(reply));
        return RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
    }
    *removed_count_out = reply.removed_count;
    memset(&reply, 0, sizeof(reply));
    return RINRUNTIME_CRASH_SERVICE_OK;
}

RinRuntimeCrashServiceResult
rinruntime_crash_service_delete_pending_minidump_with_consent(
    uint32_t expected_service_slot,
    const RinCrashServicePendingDumpInfoV1* info)
{
    RinCrashServicePendingDumpDeleteV1 request = {};
    RinCrashServicePendingDumpDeleteResultV1 reply = {};
    const size_t tail_offset = offsetof(
        RinCrashServicePendingDumpDeleteV1, boot_id_high);
    uint32_t response_size = 0u;
    RinRuntimeCrashServiceResult result;
    if (expected_service_slot == 0u || info == NULL ||
        (info->boot_id_high == 0u && info->boot_id_low == 0u) ||
        info->queue_sequence == 0u)
        return RINRUNTIME_CRASH_SERVICE_INVALID_ARGUMENT;
    request.boot_id_high = info->boot_id_high;
    request.boot_id_low = info->boot_id_low;
    request.queue_sequence = info->queue_sequence;
    request.version = RIN_CRASH_SERVICE_PENDING_DUMP_DELETE_VERSION;
    result = crash_service_pending_exchange(
        expected_service_slot, RIN_CRASH_SERVICE_OP_DELETE_PENDING_DUMP,
        (const uint8_t*)&request + tail_offset,
        sizeof(request) - (uint32_t)tail_offset,
        &reply, sizeof(reply), sizeof(reply), &response_size);
    memset(&request, 0, sizeof(request));
    if (result != RINRUNTIME_CRASH_SERVICE_OK) {
        memset(&reply, 0, sizeof(reply));
        return result;
    }
    if (response_size != sizeof(reply) ||
        reply.struct_size != sizeof(reply) ||
        reply.version !=
            RIN_CRASH_SERVICE_PENDING_DUMP_DELETE_RESULT_VERSION ||
        reply.reserved != 0u) {
        memset(&reply, 0, sizeof(reply));
        return RINRUNTIME_CRASH_SERVICE_PROTOCOL_ERROR;
    }
    memset(&reply, 0, sizeof(reply));
    return RINRUNTIME_CRASH_SERVICE_OK;
}
