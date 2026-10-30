/* SPDX-License-Identifier: MIT */
#if !defined(__rinos__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include <rinruntime/rin_keyring_client.h>
#include <rinruntime/poll_wait.h>
#include "private_service_socket.h"

#include <rin/capability.h>
#include <rin/service.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT 32u
/* Keep the authenticated keyring IPC bounded even when a peer accepts the
 * connection but stops making progress.  This is a transport bound for each
 * blocking send/recv; the operation-wide deadline and cancellation contract
 * remains owned by the versioned Kerberos operation ABI. */
#define RIN_KEYRING_CLIENT_IO_TIMEOUT_MS UINT32_C(1000)
/* Kerberos owner operations use one monotonic budget across connect, request
 * framing, response framing, and response payload.  This is only the local
 * keyring IPC budget; KDC/AS/TGS policy belongs to the authenticated session
 * credential producer and must not be inferred here. */
#define RIN_KEYRING_CLIENT_KERBEROS_OPERATION_TIMEOUT_MS UINT64_C(1000)

static int send_exact(int fd, const void* input, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        ssize_t count = send(fd, bytes + offset, size - offset,
                             MSG_NOSIGNAL);
        if (count > 0) {
            offset += (uint32_t)count;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted < RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT)
                continue;
        }
        return -1;
    }
    return 0;
}

static int recv_exact(int fd, void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        ssize_t count = recv(fd, bytes + offset, size - offset, 0);
        if (count > 0) {
            offset += (uint32_t)count;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted < RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT)
                continue;
        }
        return -1;
    }
    return 0;
}

static int client_monotonic_ms(uint64_t* output)
{
    struct timespec now = {0};
    uint64_t seconds;
    if (output == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000L)
        return -1;
    seconds = (uint64_t)now.tv_sec;
    if (seconds > (UINT64_MAX - (uint64_t)now.tv_nsec / UINT64_C(1000000)) /
                    UINT64_C(1000))
        return -1;
    *output = seconds * UINT64_C(1000) +
              (uint64_t)now.tv_nsec / UINT64_C(1000000);
    return 0;
}

static int client_set_deadline_timeout(int fd, uint64_t deadline_ms)
{
    uint64_t now_ms;
    uint64_t remaining_ms;
    struct timeval timeout;
    if (fd < 0 || client_monotonic_ms(&now_ms) != 0 ||
        now_ms >= deadline_ms)
        return -1;
    remaining_ms = deadline_ms - now_ms;
    if (remaining_ms > UINT64_C(1000)) remaining_ms = UINT64_C(1000);
    timeout.tv_sec = (time_t)(remaining_ms / UINT64_C(1000));
    timeout.tv_usec = (suseconds_t)((remaining_ms % UINT64_C(1000)) *
                                    UINT64_C(1000));
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) !=
                   0 ||
               setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                          sizeof(timeout)) != 0
        ? -1
        : 0;
}

static int client_deadline_poll_timeout(uint64_t deadline_ms, int* timeout_ms)
{
    uint64_t now_ms;
    uint64_t remaining_ms;
    if (timeout_ms == NULL || client_monotonic_ms(&now_ms) != 0 ||
        now_ms >= deadline_ms)
        return -1;
    remaining_ms = deadline_ms - now_ms;
    *timeout_ms = remaining_ms > (uint64_t)INT_MAX
        ? INT_MAX : (int)remaining_ms;
    if (*timeout_ms == 0) *timeout_ms = 1;
    return 0;
}

static int send_exact_until(int fd, const void* input, uint32_t size,
                            uint64_t deadline_ms)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    if (fd < 0 || (size != 0u && input == NULL)) return -1;
    while (offset < size) {
        ssize_t count;
        if (client_set_deadline_timeout(fd, deadline_ms) != 0) return -1;
        count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT)
                return -1;
            continue;
        }
        if (count <= 0 || (uint32_t)count > size - offset) return -1;
        offset += (uint32_t)count;
        interrupted = 0u;
    }
    return 0;
}

static int recv_exact_until(int fd, void* output, uint32_t size,
                            uint64_t deadline_ms)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    if (fd < 0 || (size != 0u && output == NULL)) return -1;
    while (offset < size) {
        ssize_t count;
        if (client_set_deadline_timeout(fd, deadline_ms) != 0) return -1;
        count = recv(fd, bytes + offset, size - offset, 0);
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT)
                return -1;
            continue;
        }
        if (count <= 0 || (uint32_t)count > size - offset) return -1;
        offset += (uint32_t)count;
        interrupted = 0u;
    }
    return 0;
}

static void secure_clear(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (bytes == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int client_ranges_overlap(const void* left, uint32_t left_size,
                                 const void* right, uint32_t right_size)
{
    uintptr_t left_begin;
    uintptr_t right_begin;
    uintptr_t left_end;
    uintptr_t right_end;
    if (!left || !right || left_size == 0u || right_size == 0u) return 0;
    left_begin = (uintptr_t)left;
    right_begin = (uintptr_t)right;
    left_end = left_begin + left_size;
    right_end = right_begin + right_size;
    if (left_end < left_begin || right_end < right_begin) return 1;
    return left_begin < right_end && right_begin < left_end;
}

static int client_kerberos_operation_ranges_alias(
    const RinKeyringHandleV1* handle,
    const RinKerberosOperationRequestV1* request,
    const uint8_t* context_token, uint32_t context_token_size,
    const uint8_t* input, uint32_t input_size, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size,
    uint8_t* next_context_token, uint32_t next_context_capacity,
    uint32_t* next_context_token_size, uint64_t* generation,
    uint32_t* provider_result, uint32_t* return_flags)
{
    const void* ranges[] = {
        handle,
        request,
        context_token,
        input,
        output,
        next_context_token,
        output_size,
        next_context_token_size,
        generation,
        provider_result,
        return_flags,
    };
    const uint32_t sizes[] = {
        (uint32_t)sizeof(*handle),
        (uint32_t)sizeof(*request),
        context_token_size,
        input_size,
        output_capacity,
        next_context_capacity,
        (uint32_t)sizeof(*output_size),
        (uint32_t)sizeof(*next_context_token_size),
        (uint32_t)sizeof(*generation),
        (uint32_t)sizeof(*provider_result),
        (uint32_t)sizeof(*return_flags),
    };
    uint32_t left;
    uint32_t right;
    for (left = 0u; left < sizeof(ranges) / sizeof(ranges[0]); ++left) {
        for (right = left + 1u;
             right < sizeof(ranges) / sizeof(ranges[0]); ++right) {
            if (client_ranges_overlap(ranges[left], sizes[left],
                                      ranges[right], sizes[right]))
                return 1;
        }
    }
    return 0;
}

static int client_kerberos_principal_ranges_alias(
    const RinKeyringHandleV1* handle, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size, uint64_t* generation)
{
    return client_ranges_overlap(handle, (uint32_t)sizeof(*handle), output,
                                 output_capacity) ||
           client_ranges_overlap(handle, (uint32_t)sizeof(*handle),
                                 output_size, (uint32_t)sizeof(*output_size)) ||
           client_ranges_overlap(handle, (uint32_t)sizeof(*handle), generation,
                                 (uint32_t)sizeof(*generation)) ||
           client_ranges_overlap(output, output_capacity, output_size,
                                 (uint32_t)sizeof(*output_size)) ||
           client_ranges_overlap(output, output_capacity, generation,
                                 (uint32_t)sizeof(*generation)) ||
           client_ranges_overlap(output_size, (uint32_t)sizeof(*output_size),
                                 generation, (uint32_t)sizeof(*generation));
}

static int keyring_result_valid(int status);

void rin_keyring_client_clear(void* memory, size_t size)
{
    secure_clear(memory, size);
}

static int connect_service_with_deadline(uint64_t deadline_ms)
{
    struct sockaddr_un address;
    rin_unix_service_identity_v1 identity;
    socklen_t identity_size = sizeof(identity);
    struct timeval timeout;
    uint32_t expected_slot_id = 0u;
    int socket_flags = -1;
    int nonblocking = deadline_ms != 0u;
    int fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0) return -1;
    memset(&identity, 0, sizeof(identity));
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, RIN_KEYRING_SOCKET_PATH,
            sizeof(address.sun_path) - 1u);
    if (nonblocking) {
        int poll_timeout;
        if ((socket_flags = fcntl(fd, F_GETFL, 0)) < 0 ||
            fcntl(fd, F_SETFL, socket_flags | O_NONBLOCK) != 0) {
            close(fd);
            return -1;
        }
        for (;;) {
            int connect_result = connect(
                fd, (const struct sockaddr*)&address, sizeof(address));
            if (connect_result == 0) break;
            if (errno != EINPROGRESS && errno != EALREADY &&
                errno != EINTR) {
                close(fd);
                return -1;
            }
            if (client_deadline_poll_timeout(deadline_ms, &poll_timeout) != 0 ||
                rinruntime_poll_wait(
                    fd, RINRUNTIME_POLL_WAIT_WRITABLE,
                    (uint32_t)poll_timeout) != RINRUNTIME_POLL_WAIT_READY) {
                close(fd);
                return -1;
            }
            {
                int socket_error = 0;
                socklen_t socket_error_size = sizeof(socket_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                               &socket_error_size) != 0 || socket_error != 0) {
                    close(fd);
                    return -1;
                }
            }
            break;
        }
        if (fcntl(fd, F_SETFL, socket_flags) != 0) {
            close(fd);
            return -1;
        }
    } else if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) !=
               0) {
        close(fd);
        return -1;
    }
    if (rin_service_find_system_slot(RIN_KEYRING_SERVICE_ID,
                                     &expected_slot_id) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
                   &identity, &identity_size) != 0 ||
        identity_size != sizeof(identity) ||
        !rin_keyring_client_service_identity_valid(&identity,
                                                   expected_slot_id)) {
        close(fd);
        return -1;
    }
    if (nonblocking) {
        if (client_set_deadline_timeout(fd, deadline_ms) != 0) {
            close(fd);
            return -1;
        }
    } else {
        timeout.tv_sec = (time_t)(RIN_KEYRING_CLIENT_IO_TIMEOUT_MS / 1000u);
        timeout.tv_usec = (suseconds_t)((RIN_KEYRING_CLIENT_IO_TIMEOUT_MS %
                                         1000u) * 1000u);
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
                       sizeof(timeout)) != 0) {
            close(fd);
            return -1;
        }
    }
    return fd;
}

static int connect_service(void)
{
    return connect_service_with_deadline(0u);
}

static int receive_header_until(int fd, uint16_t opcode,
                                RinKeyringMessageHeaderV1* response,
                                uint64_t deadline_ms)
{
    if (recv_exact_until(fd, response, sizeof(*response), deadline_ms) != 0 ||
        response->struct_size != sizeof(*response) ||
        response->version != 1u || response->opcode != opcode ||
        response->request_id != 1u || response->flags != 0u ||
        response->reserved != 0u || !keyring_result_valid(response->status)) {
        return RIN_KEYRING_STORAGE_FAILED;
    }
    return response->status;
}

/* Keep the legacy helpers above for the existing short keyring operations.
 * Kerberos uses the _until variants so a partial response cannot extend the
 * owner IPC budget by resetting SO_RCVTIMEO for every frame. */
static int receive_header(int fd, uint16_t opcode,
                          RinKeyringMessageHeaderV1* response)
{
    if (recv_exact(fd, response, sizeof(*response)) != 0 ||
        response->struct_size != sizeof(*response) ||
        response->version != 1u || response->opcode != opcode ||
        response->request_id != 1u || response->flags != 0u ||
        response->reserved != 0u || !keyring_result_valid(response->status)) {
        return RIN_KEYRING_STORAGE_FAILED;
    }
    return response->status;
}

static void request_header(RinKeyringMessageHeaderV1* header,
                           uint16_t opcode, uint32_t payload_size)
{
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = 1u;
    header->opcode = opcode;
    header->request_id = 1u;
    header->payload_size = payload_size;
}

static int keyring_result_valid(int status)
{
    switch (status) {
    case RIN_KEYRING_OK:
    case RIN_KEYRING_INVALID:
    case RIN_KEYRING_DENIED:
    case RIN_KEYRING_LOCKED:
    case RIN_KEYRING_NOT_FOUND:
    case RIN_KEYRING_CONFLICT:
    case RIN_KEYRING_STORAGE_FAILED:
    case RIN_KEYRING_INTEGRITY_FAILED:
    case RIN_KEYRING_ENTROPY_UNAVAILABLE:
    case RIN_KEYRING_TOO_LARGE:
    case RIN_KEYRING_REPLAY:
    case RIN_KEYRING_NOT_SUPPORTED:
    case RIN_KEYRING_CONTEXT_EXPIRED:
    case RIN_KEYRING_BAD_BINDINGS:
        return 1;
    default:
        return 0;
    }
}


int rin_keyring_client_status(void)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    int fd = connect_service();
    int status;
    if (fd < 0) return RIN_KEYRING_LOCKED;
    request_header(&request, RIN_KEYRING_OP_STATUS, 0u);
    status = send_exact(fd, &request, sizeof(request)) == 0
        ? receive_header(fd, RIN_KEYRING_OP_STATUS, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    /* STATUS has no response payload.  Do not accept a successful status
     * header while silently discarding an unexpected body; otherwise a
     * peer/protocol version mismatch can be mistaken for a healthy keyring. */
    if (status == RIN_KEYRING_OK && response.payload_size != 0u)
        status = RIN_KEYRING_STORAGE_FAILED;
    close(fd);
    return status;
}

int rin_keyring_client_put(const char* name, const void* secret,
                           uint32_t secret_size, uint64_t* generation)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringPutRequestV1 put;
    RinKeyringSecretResponseV1 result;
    uint32_t name_size = rin_keyring_client_secret_name_size(name);
    int fd;
    int status;
    if (generation) *generation = 0u;
    if (!name || !secret || secret_size == 0u || name_size == 0u ||
        name_size > RIN_KEYRING_MAX_SECRET_NAME ||
        secret_size > RIN_KEYRING_MAX_SECRET_SIZE)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&put, 0, sizeof(put));
    memset(&result, 0, sizeof(result));
    put.expected_generation = RIN_KEYRING_GENERATION_ANY;
    put.secret_name_size = name_size;
    put.secret_size = secret_size;
    request_header(&request, RIN_KEYRING_OP_PUT,
                   sizeof(put) + name_size + secret_size);
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &put, sizeof(put)) == 0 &&
             send_exact(fd, name, name_size) == 0 &&
             send_exact(fd, secret, secret_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_PUT, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size != sizeof(result) ||
            recv_exact(fd, &result, sizeof(result)) != 0 ||
            result.reserved != 0u ||
            rin_wire_capability_generation_valid(result.generation) !=
                RIN_WIRE_CAPABILITY_OK) {
            status = RIN_KEYRING_STORAGE_FAILED;
        } else if (generation) {
            *generation = result.generation;
        }
    }
    close(fd);
    secure_clear(&result, sizeof(result));
    return status;
}

int rin_keyring_client_import_kerberos_credential(
    const char* scope, const void* credential, uint32_t credential_size,
    uint64_t expected_generation, uint64_t* generation)
{
    static const char session_scope[] = "credential.kerberos.session";
    static const char acceptor_scope[] = "credential.kerberos.acceptor";
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringImportKerberosCredentialRequestV1 import_request;
    RinKeyringSecretResponseV1 result;
    const uint32_t scope_size = rin_keyring_client_secret_name_size(scope);
    const uint32_t session_scope_size =
        (uint32_t)sizeof(session_scope) - 1u;
    const uint32_t acceptor_scope_size =
        (uint32_t)sizeof(acceptor_scope) - 1u;
    int fd;
    int status;

    if (generation) *generation = 0u;
    if (!scope || !credential || credential_size == 0u ||
        credential_size > RIN_KEYRING_MAX_SECRET_SIZE ||
        scope_size == 0u || scope_size > RIN_KEYRING_MAX_SECRET_NAME ||
        !((scope_size == session_scope_size &&
           memcmp(scope, session_scope, session_scope_size) == 0) ||
          (scope_size == acceptor_scope_size &&
           memcmp(scope, acceptor_scope, acceptor_scope_size) == 0)))
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&import_request, 0, sizeof(import_request));
    memset(&result, 0, sizeof(result));
    import_request.expected_generation = expected_generation;
    import_request.secret_name_size = scope_size;
    import_request.credential_size = credential_size;
    request_header(
        &request, RIN_KEYRING_OP_IMPORT_KERBEROS_CREDENTIAL,
        (uint32_t)(sizeof(import_request) + scope_size + credential_size));
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &import_request, sizeof(import_request)) == 0 &&
             send_exact(fd, scope, scope_size) == 0 &&
             send_exact(fd, credential, credential_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_IMPORT_KERBEROS_CREDENTIAL,
                         &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size != sizeof(result) ||
            recv_exact(fd, &result, sizeof(result)) != 0 ||
            result.reserved != 0u ||
            rin_wire_capability_generation_valid(result.generation) !=
                RIN_WIRE_CAPABILITY_OK) {
            status = RIN_KEYRING_STORAGE_FAILED;
        } else if (generation) {
            *generation = result.generation;
        }
    }
    close(fd);
    secure_clear(&import_request, sizeof(import_request));
    secure_clear(&result, sizeof(result));
    return status;
}

int rin_keyring_client_get(const char* name, void* secret,
                           uint32_t secret_capacity, uint32_t* secret_size,
                           uint64_t* generation)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringGetRequestV1 get;
    RinKeyringSecretResponseV1 result;
    uint32_t name_size = rin_keyring_client_secret_name_size(name);
    int fd;
    int status;
    if (secret && secret_capacity) secure_clear(secret, secret_capacity);
    if (secret_size) *secret_size = 0u;
    if (generation) *generation = 0u;
    if (!name || !secret || !secret_size || secret_capacity == 0u ||
        name_size == 0u || name_size > RIN_KEYRING_MAX_SECRET_NAME ||
        secret_capacity > RIN_KEYRING_MAX_SECRET_SIZE)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&get, 0, sizeof(get));
    memset(&result, 0, sizeof(result));
    get.secret_name_size = name_size;
    request_header(&request, RIN_KEYRING_OP_GET, sizeof(get) + name_size);
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &get, sizeof(get)) == 0 &&
             send_exact(fd, name, name_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_GET, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size < sizeof(result) ||
            recv_exact(fd, &result, sizeof(result)) != 0 ||
            result.reserved != 0u ||
            rin_wire_capability_generation_valid(result.generation) !=
                RIN_WIRE_CAPABILITY_OK ||
            result.secret_size > secret_capacity ||
            response.payload_size != sizeof(result) + result.secret_size ||
            recv_exact(fd, secret, result.secret_size) != 0) {
            secure_clear(secret, secret_capacity);
            status = result.secret_size > secret_capacity
                ? RIN_KEYRING_TOO_LARGE : RIN_KEYRING_STORAGE_FAILED;
        } else {
            *secret_size = result.secret_size;
            if (generation) *generation = result.generation;
        }
    }
    close(fd);
    secure_clear(&result, sizeof(result));
    return status;
}

int rin_keyring_client_remove(const char* name)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringRemoveRequestV1 remove;
    uint32_t name_size = rin_keyring_client_secret_name_size(name);
    int fd;
    int status;
    if (!name || name_size == 0u || name_size > RIN_KEYRING_MAX_SECRET_NAME)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&remove, 0, sizeof(remove));
    remove.expected_generation = RIN_KEYRING_GENERATION_ANY;
    remove.secret_name_size = name_size;
    request_header(&request, RIN_KEYRING_OP_REMOVE,
                   sizeof(remove) + name_size);
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &remove, sizeof(remove)) == 0 &&
             send_exact(fd, name, name_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_REMOVE, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK && response.payload_size != 0u)
        status = RIN_KEYRING_STORAGE_FAILED;
    close(fd);
    return status;
}

int rin_keyring_client_acquire_handle(const char* name,
                                      RinKeyringHandleV1* handle)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringGetRequestV1 acquire;
    uint32_t name_size = rin_keyring_client_secret_name_size(name);
    int fd;
    int status;
    if (handle) secure_clear(handle, sizeof(*handle));
    if (!name || !handle || name_size == 0u ||
        name_size > RIN_KEYRING_MAX_SECRET_NAME)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&acquire, 0, sizeof(acquire));
    acquire.secret_name_size = name_size;
    request_header(&request, RIN_KEYRING_OP_ACQUIRE_HANDLE,
                   sizeof(acquire) + name_size);
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &acquire, sizeof(acquire)) == 0 &&
             send_exact(fd, name, name_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_ACQUIRE_HANDLE, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size != sizeof(*handle) ||
            recv_exact(fd, handle, sizeof(*handle)) != 0 ||
            rin_wire_capability_generation_valid(handle->generation) !=
                RIN_WIRE_CAPABILITY_OK) {
            secure_clear(handle, sizeof(*handle));
            status = RIN_KEYRING_STORAGE_FAILED;
        }
    }
    close(fd);
    return status;
}

static int send_handle_request(uint16_t opcode,
                               const RinKeyringHandleV1* handle,
                               RinKeyringMessageHeaderV1* response,
                               void* secret, uint32_t secret_capacity,
                               uint32_t* secret_size, uint64_t* generation)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringHandleRequestV1 request_body;
    int fd;
    int status;
    if (secret && secret_capacity) secure_clear(secret, secret_capacity);
    if (secret_size) *secret_size = 0u;
    if (generation) *generation = 0u;
    if (!handle || rin_wire_capability_generation_valid(handle->generation) !=
                     RIN_WIRE_CAPABILITY_OK)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&request_body, 0, sizeof(request_body));
    request_body.handle_size = RIN_KEYRING_HANDLE_SIZE;
    request_header(&request, opcode, sizeof(request_body) + sizeof(*handle));
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &request_body, sizeof(request_body)) == 0 &&
             send_exact(fd, handle, sizeof(*handle)) == 0
        ? receive_header(fd, opcode, response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK && opcode == RIN_KEYRING_OP_GET_HANDLE) {
        RinKeyringSecretResponseV1 result;
        memset(&result, 0, sizeof(result));
        if (!secret || !secret_size || !generation ||
            secret_capacity == 0u ||
            secret_capacity > RIN_KEYRING_MAX_SECRET_SIZE ||
            response->payload_size < sizeof(result) ||
            recv_exact(fd, &result, sizeof(result)) != 0 ||
            result.reserved != 0u ||
            rin_wire_capability_generation_valid(result.generation) !=
                RIN_WIRE_CAPABILITY_OK ||
            result.secret_size > secret_capacity ||
            response->payload_size != sizeof(result) + result.secret_size ||
            recv_exact(fd, secret, result.secret_size) != 0) {
            if (secret && secret_capacity) secure_clear(secret, secret_capacity);
            status = result.secret_size > secret_capacity
                ? RIN_KEYRING_TOO_LARGE : RIN_KEYRING_STORAGE_FAILED;
        } else {
            *secret_size = result.secret_size;
            *generation = result.generation;
        }
        secure_clear(&result, sizeof(result));
    } else if (status == RIN_KEYRING_OK && response->payload_size != 0u) {
        status = RIN_KEYRING_STORAGE_FAILED;
    }
    close(fd);
    return status;
}

int rin_keyring_client_get_handle(const RinKeyringHandleV1* handle,
                                  void* secret, uint32_t secret_capacity,
                                  uint32_t* secret_size,
                                  uint64_t* generation)
{
    RinKeyringMessageHeaderV1 response;
    if (!secret || !secret_size || !generation || secret_capacity == 0u ||
        secret_capacity > RIN_KEYRING_MAX_SECRET_SIZE)
        return RIN_KEYRING_INVALID;
    return send_handle_request(RIN_KEYRING_OP_GET_HANDLE, handle, &response,
                               secret, secret_capacity, secret_size,
                               generation);
}

int rin_keyring_client_remove_handle(const RinKeyringHandleV1* handle)
{
    RinKeyringMessageHeaderV1 response;
    return send_handle_request(RIN_KEYRING_OP_REMOVE_HANDLE, handle, &response,
                               NULL, 0u, NULL, NULL);
}

int rin_keyring_client_kerberos_principal(
    const RinKeyringHandleV1* handle, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size, uint64_t* generation)
{
    RinKeyringMessageHeaderV1 request;
    RinKeyringMessageHeaderV1 response;
    RinKeyringHandleRequestV1 request_body;
    RinKeyringKerberosPrincipalResponseV1 principal_response;
    int fd;
    int status;

    /* Reject aliases before clearing anything: output_size/generation are
     * caller-owned metadata, and an overlapping output buffer would make a
     * failure cleanup overwrite the very metadata used to report failure. */
    if (client_kerberos_principal_ranges_alias(
            handle, output, output_capacity, output_size, generation))
        return RIN_KEYRING_INVALID;
    if (output_size) *output_size = 0u;
    if (generation) *generation = 0u;
    /* Every failure path must discard a principal that may have belonged to
     * an earlier successful request.  Do not wipe an unbounded caller range;
     * capacities above the public maximum are rejected without dereference. */
    if (output != NULL && output_capacity <= RIN_KEYRING_MAX_SECRET_SIZE)
        secure_clear(output, output_capacity);
    memset(&response, 0, sizeof(response));
    memset(&principal_response, 0, sizeof(principal_response));
    if (!handle || !output || output_capacity == 0u ||
        output_capacity > RIN_KEYRING_MAX_SECRET_SIZE || !output_size ||
        !generation || rin_wire_capability_generation_valid(handle->generation) !=
            RIN_WIRE_CAPABILITY_OK)
        return RIN_KEYRING_INVALID;
    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    memset(&request_body, 0, sizeof(request_body));
    request_body.handle_size = RIN_KEYRING_HANDLE_SIZE;
    request_header(&request, RIN_KEYRING_OP_KERBEROS_PRINCIPAL,
                   sizeof(request_body) + sizeof(*handle));
    status = send_exact(fd, &request, sizeof(request)) == 0 &&
             send_exact(fd, &request_body, sizeof(request_body)) == 0 &&
             send_exact(fd, handle, sizeof(*handle)) == 0
        ? receive_header(fd, RIN_KEYRING_OP_KERBEROS_PRINCIPAL, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size < sizeof(principal_response) ||
            recv_exact(fd, &principal_response,
                       sizeof(principal_response)) != 0 ||
            principal_response.reserved != 0u ||
            rin_wire_capability_generation_valid(
                principal_response.generation) != RIN_WIRE_CAPABILITY_OK ||
            principal_response.principal_size == 0u ||
            principal_response.principal_size > output_capacity ||
            response.payload_size != sizeof(principal_response) +
                principal_response.principal_size ||
            recv_exact(fd, output, principal_response.principal_size) != 0) {
            secure_clear(output, output_capacity);
            status = principal_response.principal_size > output_capacity
                ? RIN_KEYRING_TOO_LARGE : RIN_KEYRING_STORAGE_FAILED;
        } else {
            *output_size = principal_response.principal_size;
            *generation = principal_response.generation;
        }
    } else if (response.payload_size != 0u) {
        status = RIN_KEYRING_STORAGE_FAILED;
    }
    close(fd);
    if (status != RIN_KEYRING_OK) {
        secure_clear(output, output_capacity);
        *output_size = 0u;
        *generation = 0u;
    }
    secure_clear(&principal_response, sizeof(principal_response));
    return status;
}

int rin_keyring_client_kerberos_operation(
    const RinKeyringHandleV1* handle,
    const RinKerberosOperationRequestV1* request,
    const uint8_t* context_token, uint32_t context_token_size,
    const uint8_t* input, uint32_t input_size, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size,
    uint8_t* next_context_token, uint32_t next_context_capacity,
    uint32_t* next_context_token_size, uint64_t* generation,
    uint32_t* provider_result, uint32_t* return_flags)
{
    RinKeyringMessageHeaderV1 message;
    RinKeyringMessageHeaderV1 response;
    RinKerberosOperationResponseV1 operation_response;
    uint64_t start_ms;
    uint64_t deadline_ms;
    int fd;
    int status;

    if (client_kerberos_operation_ranges_alias(
            handle, request, context_token, context_token_size, input,
            input_size, output, output_capacity, output_size,
            next_context_token, next_context_capacity,
            next_context_token_size, generation, provider_result,
            return_flags))
        return RIN_KEYRING_INVALID;
    if (output && output_capacity) secure_clear(output, output_capacity);
    if (next_context_token && next_context_capacity)
        secure_clear(next_context_token, next_context_capacity);
    if (output_size) *output_size = 0u;
    if (next_context_token_size) *next_context_token_size = 0u;
    if (generation) *generation = 0u;
    if (provider_result) *provider_result = 0u;
    if (return_flags) *return_flags = 0u;
    memset(&response, 0, sizeof(response));
    memset(&operation_response, 0, sizeof(operation_response));
    if (!handle || !request || !output_size || !next_context_token_size ||
        !generation || !provider_result || !return_flags ||
        request->struct_size != sizeof(*request) ||
        request->version != RIN_KERBEROS_OPERATION_ABI_VERSION ||
        request->operation == 0u || request->operation > 16u ||
        (RIN_KERBEROS_OPERATION_KNOWN_OPERATIONS &
         UINT16_C(1u << (request->operation - 1u))) == 0u ||
        (request->flags & ~RIN_KERBEROS_OPERATION_KNOWN_FLAGS) != 0u ||
        ((request->operation != RIN_KERBEROS_OPERATION_WRAP &&
          request->operation != RIN_KERBEROS_OPERATION_UNWRAP) &&
         request->flags != 0u) ||
        request->context_token_size != context_token_size ||
        request->input_size != input_size ||
        request->output_capacity != output_capacity ||
        context_token_size > RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE ||
        input_size > RIN_KERBEROS_OPERATION_MAX_INPUT_SIZE ||
        output_capacity > RIN_KERBEROS_OPERATION_MAX_OUTPUT_SIZE ||
        next_context_capacity > RIN_KERBEROS_OPERATION_MAX_CONTEXT_TOKEN_SIZE ||
        (context_token_size != 0u && context_token == NULL) ||
        (input_size != 0u && input == NULL) ||
        (output_capacity != 0u && output == NULL) ||
        (next_context_capacity != 0u && next_context_token == NULL))
        return RIN_KEYRING_INVALID;

    if (client_monotonic_ms(&start_ms) != 0 ||
        start_ms > UINT64_MAX -
            RIN_KEYRING_CLIENT_KERBEROS_OPERATION_TIMEOUT_MS)
        return RIN_KEYRING_STORAGE_FAILED;
    deadline_ms = start_ms + RIN_KEYRING_CLIENT_KERBEROS_OPERATION_TIMEOUT_MS;
    fd = connect_service_with_deadline(deadline_ms);
    if (fd < 0) return RIN_KEYRING_LOCKED;
    request_header(&message, RIN_KEYRING_OP_KERBEROS_OPERATION,
                   (uint32_t)(sizeof(*request) + sizeof(*handle) +
                              context_token_size + input_size));
    status = send_exact_until(fd, &message, sizeof(message), deadline_ms) == 0 &&
             send_exact_until(fd, request, sizeof(*request), deadline_ms) == 0 &&
             send_exact_until(fd, handle, sizeof(*handle), deadline_ms) == 0 &&
             send_exact_until(fd, context_token, context_token_size,
                              deadline_ms) == 0 &&
             send_exact_until(fd, input, input_size, deadline_ms) == 0
        ? receive_header_until(fd, RIN_KEYRING_OP_KERBEROS_OPERATION,
                               &response, deadline_ms)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size < sizeof(operation_response) ||
            recv_exact_until(fd, &operation_response,
                             sizeof(operation_response), deadline_ms) != 0 ||
            operation_response.struct_size != sizeof(operation_response) ||
            operation_response.version !=
                RIN_KERBEROS_OPERATION_ABI_VERSION ||
            operation_response.operation != request->operation ||
            operation_response.provider_result >
                RIN_KERBEROS_OPERATION_RESULT_ERROR ||
            (operation_response.provider_result ==
                 RIN_KERBEROS_OPERATION_RESULT_CONTINUE_NEEDED &&
             request->operation != RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
             request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) ||
            (operation_response.provider_result ==
                 RIN_KERBEROS_OPERATION_RESULT_ERROR &&
             ((request->operation != RIN_KERBEROS_OPERATION_INIT_SEC_CONTEXT &&
               request->operation != RIN_KERBEROS_OPERATION_ACCEPT_SEC_CONTEXT) ||
              operation_response.output_size == 0u ||
              operation_response.context_token_size != 0u ||
              (operation_response.return_flags &
               ~RIN_KERBEROS_OPERATION_RETURN_FLAG_EXTENDED_ERROR) != 0u)) ||
            (operation_response.return_flags &
             ~RIN_KERBEROS_OPERATION_KNOWN_RETURN_FLAGS) != 0u ||
            ((request->operation != RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
              rin_wire_capability_generation_valid(
                  operation_response.generation) != RIN_WIRE_CAPABILITY_OK) ||
             (request->operation == RIN_KERBEROS_OPERATION_DELETE_SEC_CONTEXT &&
              operation_response.generation != 0u)) ||
            operation_response.context_token_size > next_context_capacity ||
            operation_response.output_size > output_capacity ||
            response.payload_size != sizeof(operation_response) +
                operation_response.context_token_size +
                operation_response.output_size ||
            recv_exact_until(fd, next_context_token,
                             operation_response.context_token_size,
                             deadline_ms) != 0 ||
            recv_exact_until(fd, output, operation_response.output_size,
                             deadline_ms) != 0) {
            if (output && output_capacity) secure_clear(output, output_capacity);
            if (next_context_token && next_context_capacity)
                secure_clear(next_context_token, next_context_capacity);
            status = RIN_KEYRING_STORAGE_FAILED;
        } else {
            *next_context_token_size = operation_response.context_token_size;
            *output_size = operation_response.output_size;
            *generation = operation_response.generation;
            *provider_result = operation_response.provider_result;
            *return_flags = operation_response.return_flags;
        }
    } else if (response.payload_size != 0u) {
        status = RIN_KEYRING_STORAGE_FAILED;
    }
    close(fd);
    if (status != RIN_KEYRING_OK) {
        if (output && output_capacity) secure_clear(output, output_capacity);
        if (next_context_token && next_context_capacity)
            secure_clear(next_context_token, next_context_capacity);
        *output_size = 0u;
        *next_context_token_size = 0u;
        *generation = 0u;
        *provider_result = 0u;
        *return_flags = 0u;
    }
    secure_clear(&operation_response, sizeof(operation_response));
    return status;
}
