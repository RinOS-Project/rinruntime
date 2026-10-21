/* SPDX-License-Identifier: MIT */

#include <rinruntime/crash_consent.h>
#include <rin/contract_abi.h>

#include <stddef.h>

#if !defined(_WIN32)
#include <libc/sys/syscall.h>
#include <rin/syscall_abi.h>
#endif

static void consent_zero(void* memory, uint32_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (!bytes) return;
    while (size != 0u) {
        *bytes++ = 0u;
        --size;
    }
}

static void consent_copy(void* destination, const void* source, uint32_t size)
{
    uint8_t* out = (uint8_t*)destination;
    const uint8_t* in = (const uint8_t*)source;
    uint32_t index;
    for (index = 0u; index < size; ++index) out[index] = in[index];
}

static int consent_nonzero(const void* memory, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)memory;
    uint8_t combined = 0u;
    uint32_t index;
    if (!bytes) return 0;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined != 0u;
}

static int consent_proof_valid(
    const RinCrashConsentProofV1* proof, uint64_t request_id)
{
    static const uint64_t zero_reserved[2] = {0u, 0u};
    uint8_t reserved_diff = 0u;
    const uint8_t* actual = (const uint8_t*)proof->reserved;
    const uint8_t* expected = (const uint8_t*)zero_reserved;
    for (uint32_t index = 0u; index < sizeof(zero_reserved); ++index)
        reserved_diff |= (uint8_t)(actual[index] ^ expected[index]);
    return proof->struct_size == sizeof(*proof) && proof->version != 0u &&
           proof->flags == RIN_CRASH_CONSENT_FLAG_LOCAL_PHYSICAL_GESTURE &&
           proof->request_id == request_id && proof->peer_process_id != 0u &&
           proof->peer_process_instance_cookie != 0u &&
           proof->peer_connection_id != 0u && proof->expires_at_ns != 0u &&
           consent_nonzero(proof->nonce, sizeof(proof->nonce)) &&
           consent_nonzero(proof->authenticator,
                           sizeof(proof->authenticator)) &&
           reserved_diff == 0u;
}

int rin_crash_consent_call(RinCrashConsentCallV1* call)
{
    intptr_t syscall_result;
    if (!call) return (int)RIN_RESULT_INVALID_ARGUMENT;
    if (call->struct_size != sizeof(*call) ||
        call->version != RIN_CRASH_CONSENT_CALL_VERSION) {
        consent_zero(&call->proof, (uint32_t)sizeof(call->proof));
        call->request_generation = 0u;
        call->result = RIN_RESULT_INVALID_ARGUMENT;
        return call->result;
    }
#if defined(_WIN32)
    syscall_result = (intptr_t)RIN_RESULT_NOT_SUPPORTED;
#else
    syscall_result = _syscall1((uintptr_t)RIN_SYS_CRASH_CONSENT_CALL,
                               (uintptr_t)call);
#endif
    if (syscall_result != (intptr_t)RIN_RESULT_OK) {
        consent_zero(&call->proof, (uint32_t)sizeof(call->proof));
        if (call->operation == RIN_CRASH_CONSENT_CALL_REQUEST)
            call->request_generation = 0u;
    }
    call->result = (int32_t)syscall_result;
    return (int)syscall_result;
}

static void consent_call_init(
    RinCrashConsentCallV1* call, uint16_t operation, int socket_fd,
    uint64_t request_id, uint64_t generation,
    const RinCrashConsentProofV1* proof)
{
    consent_zero(call, (uint32_t)sizeof(*call));
    call->struct_size = (uint32_t)sizeof(*call);
    call->version = RIN_CRASH_CONSENT_CALL_VERSION;
    call->operation = operation;
    call->socket_fd = socket_fd;
    call->request_id = request_id;
    call->request_generation = generation;
    if (proof) consent_copy(&call->proof, proof,
                            (uint32_t)sizeof(call->proof));
}

int rin_crash_consent_request(
    int socket_fd, uint64_t request_id, uint64_t* request_generation)
{
    RinCrashConsentCallV1 call;
    int result;
    if (request_generation) *request_generation = 0u;
    if (socket_fd < 0 || request_id == 0u || !request_generation)
        return (int)RIN_RESULT_INVALID_ARGUMENT;
    consent_call_init(&call, RIN_CRASH_CONSENT_CALL_REQUEST, socket_fd,
                      request_id, 0u, NULL);
    result = rin_crash_consent_call(&call);
    if (result == (int)RIN_RESULT_OK) {
        if (call.request_generation == 0u)
            result = (int)RIN_RESULT_CORRUPT_DATA;
        else
            *request_generation = call.request_generation;
    }
    consent_zero(&call, (uint32_t)sizeof(call));
    return result;
}

int rin_crash_consent_take(
    int socket_fd, uint64_t request_id, uint64_t request_generation,
    RinCrashConsentProofV1* proof)
{
    RinCrashConsentCallV1 call;
    int result;
    if (proof) consent_zero(proof, (uint32_t)sizeof(*proof));
    if (socket_fd < 0 || request_id == 0u || request_generation == 0u ||
        !proof)
        return (int)RIN_RESULT_INVALID_ARGUMENT;
    consent_call_init(&call, RIN_CRASH_CONSENT_CALL_TAKE, socket_fd,
                      request_id, request_generation, NULL);
    result = rin_crash_consent_call(&call);
    if (result == (int)RIN_RESULT_OK) {
        if (!consent_proof_valid(&call.proof, request_id))
            result = (int)RIN_RESULT_CORRUPT_DATA;
        else
            consent_copy(proof, &call.proof, (uint32_t)sizeof(*proof));
    }
    if (result != (int)RIN_RESULT_OK)
        consent_zero(proof, (uint32_t)sizeof(*proof));
    consent_zero(&call, (uint32_t)sizeof(call));
    return result;
}

int rin_crash_consent_consume(
    int accepted_socket_fd, const RinCrashConsentProofV1* proof)
{
    RinCrashConsentCallV1 call;
    int result;
    if (accepted_socket_fd < 0 || !proof || proof->request_id == 0u ||
        !consent_proof_valid(proof, proof->request_id))
        return (int)RIN_RESULT_INVALID_ARGUMENT;
    consent_call_init(&call, RIN_CRASH_CONSENT_CALL_CONSUME,
                      accepted_socket_fd, proof->request_id, 0u, proof);
    result = rin_crash_consent_call(&call);
    consent_zero(&call, (uint32_t)sizeof(call));
    return result;
}

int rin_crash_consent_cancel(
    int socket_fd, uint64_t request_id, uint64_t request_generation)
{
    RinCrashConsentCallV1 call;
    int result;
    if (socket_fd < 0 || request_id == 0u || request_generation == 0u)
        return (int)RIN_RESULT_INVALID_ARGUMENT;
    consent_call_init(&call, RIN_CRASH_CONSENT_CALL_CANCEL, socket_fd,
                      request_id, request_generation, NULL);
    result = rin_crash_consent_call(&call);
    consent_zero(&call, (uint32_t)sizeof(call));
    return result;
}
