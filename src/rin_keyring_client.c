/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_keyring_client.h>

#include <rin/capability.h>
#include <rin/service.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define RIN_KEYRING_CLIENT_IO_INTERRUPTION_LIMIT 32u

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
    uint32_t* next_context_token_size, uint64_t* generation)
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

void rin_keyring_client_clear(void* memory, size_t size)
{
    secure_clear(memory, size);
}

static int connect_service(void)
{
    struct sockaddr_un address;
    rin_unix_service_identity_v1 identity;
    socklen_t identity_size = sizeof(identity);
    uint32_t expected_slot_id = 0u;
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    memset(&identity, 0, sizeof(identity));
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, RIN_KEYRING_SOCKET_PATH,
            sizeof(address.sun_path) - 1u);
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0 ||
        rin_service_find_system_slot(RIN_KEYRING_SERVICE_ID,
                                     &expected_slot_id) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
                   &identity, &identity_size) != 0 ||
        identity_size != sizeof(identity) ||
        !rin_keyring_client_service_identity_valid(&identity,
                                                   expected_slot_id)) {
        close(fd);
        return -1;
    }
    return fd;
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
        return 1;
    default:
        return 0;
    }
}

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

int rin_keyring_client_kerberos_operation(
    const RinKeyringHandleV1* handle,
    const RinKerberosOperationRequestV1* request,
    const uint8_t* context_token, uint32_t context_token_size,
    const uint8_t* input, uint32_t input_size, uint8_t* output,
    uint32_t output_capacity, uint32_t* output_size,
    uint8_t* next_context_token, uint32_t next_context_capacity,
    uint32_t* next_context_token_size, uint64_t* generation)
{
    RinKeyringMessageHeaderV1 message;
    RinKeyringMessageHeaderV1 response;
    RinKerberosOperationResponseV1 operation_response;
    int fd;
    int status;

    if (client_kerberos_operation_ranges_alias(
            handle, request, context_token, context_token_size, input,
            input_size, output, output_capacity, output_size,
            next_context_token, next_context_capacity,
            next_context_token_size, generation))
        return RIN_KEYRING_INVALID;
    if (output && output_capacity) secure_clear(output, output_capacity);
    if (next_context_token && next_context_capacity)
        secure_clear(next_context_token, next_context_capacity);
    if (output_size) *output_size = 0u;
    if (next_context_token_size) *next_context_token_size = 0u;
    if (generation) *generation = 0u;
    memset(&response, 0, sizeof(response));
    memset(&operation_response, 0, sizeof(operation_response));
    if (!handle || !request || !output_size || !next_context_token_size ||
        !generation || request->struct_size != sizeof(*request) ||
        request->version != RIN_KERBEROS_OPERATION_ABI_VERSION ||
        request->flags != 0u ||
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

    fd = connect_service();
    if (fd < 0) return RIN_KEYRING_LOCKED;
    request_header(&message, RIN_KEYRING_OP_KERBEROS_OPERATION,
                   (uint32_t)(sizeof(*request) + sizeof(*handle) +
                              context_token_size + input_size));
    status = send_exact(fd, &message, sizeof(message)) == 0 &&
             send_exact(fd, request, sizeof(*request)) == 0 &&
             send_exact(fd, handle, sizeof(*handle)) == 0 &&
             send_exact(fd, context_token, context_token_size) == 0 &&
             send_exact(fd, input, input_size) == 0
        ? receive_header(fd, RIN_KEYRING_OP_KERBEROS_OPERATION, &response)
        : RIN_KEYRING_STORAGE_FAILED;
    if (status == RIN_KEYRING_OK) {
        if (response.payload_size < sizeof(operation_response) ||
            recv_exact(fd, &operation_response,
                       sizeof(operation_response)) != 0 ||
            operation_response.struct_size != sizeof(operation_response) ||
            operation_response.version !=
                RIN_KERBEROS_OPERATION_ABI_VERSION ||
            operation_response.operation != request->operation ||
            operation_response.reserved != 0u ||
            rin_wire_capability_generation_valid(
                operation_response.generation) != RIN_WIRE_CAPABILITY_OK ||
            operation_response.context_token_size > next_context_capacity ||
            operation_response.output_size > output_capacity ||
            response.payload_size != sizeof(operation_response) +
                operation_response.context_token_size +
                operation_response.output_size ||
            recv_exact(fd, next_context_token,
                       operation_response.context_token_size) != 0 ||
            recv_exact(fd, output, operation_response.output_size) != 0) {
            if (output && output_capacity) secure_clear(output, output_capacity);
            if (next_context_token && next_context_capacity)
                secure_clear(next_context_token, next_context_capacity);
            status = RIN_KEYRING_STORAGE_FAILED;
        } else {
            *next_context_token_size = operation_response.context_token_size;
            *output_size = operation_response.output_size;
            *generation = operation_response.generation;
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
    }
    secure_clear(&operation_response, sizeof(operation_response));
    return status;
}
