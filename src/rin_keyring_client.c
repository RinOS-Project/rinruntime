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

static int receive_header(int fd, uint16_t opcode,
                          RinKeyringMessageHeaderV1* response)
{
    if (recv_exact(fd, response, sizeof(*response)) != 0 ||
        response->struct_size != sizeof(*response) ||
        response->version != 1u || response->opcode != opcode ||
        response->request_id != 1u || response->flags != 0u ||
        response->reserved != 0u) {
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
