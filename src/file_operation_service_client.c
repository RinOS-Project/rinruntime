/* SPDX-License-Identifier: MIT */

#include <rinruntime/file_operation_service.h>
#include <rinruntime/path.h>
#include <rin/capability.h>
#include <rin/net/socket_abi.h>
#include <rin/validation.h>
#include <rinruntime/poll_wait.h>
#include "private_service_socket.h"
#include "platform.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define RINRUNTIME_FILE_OPERATION_SERVICE_IO_INTERRUPTION_LIMIT 32u
#define RINRUNTIME_FILE_OPERATION_SERVICE_TIMEOUT_MS 5000u
#define RINRUNTIME_FILE_OPERATION_CLIENT_IDLE 0u
#define RINRUNTIME_FILE_OPERATION_CLIENT_ACTIVE 1u
#define RINRUNTIME_FILE_OPERATION_CLIENT_CANCELLED 2u

/* This lock protects only the short client socket/state handoff. It is never
 * held while waiting for readiness or transferring protocol bytes. */
static volatile uint32_t g_file_operation_client_lock;
static uint64_t g_file_operation_next_request_id = 1u;
static uint64_t g_file_operation_pending_submit_id;
static uint64_t g_file_operation_pending_submit_fingerprint;
static uint64_t g_file_operation_request_owner_pid;

static void service_client_lock(void);
static void service_client_unlock(void);

static void service_client_lock(void)
{
    while (__atomic_exchange_n(&g_file_operation_client_lock, 1u,
                               __ATOMIC_ACQUIRE) != 0u) {
#if defined(__i386__) || defined(__x86_64__)
        __asm__ volatile("pause" ::: "memory");
#else
        __asm__ volatile("" ::: "memory");
#endif
    }
}

static void service_client_unlock(void)
{
    __atomic_store_n(&g_file_operation_client_lock, 0u, __ATOMIC_RELEASE);
}

static int service_client_bytes_zero(const void* value, size_t size)
{
    const uint8_t* bytes = (const uint8_t*)value;
    uint8_t combined = 0u;
    size_t index;
    if (value == 0) return 0;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined == 0u;
}

static int service_client_request_id_valid(uint64_t request_id);

static int service_client_allocate_request_id(uint64_t* request_id_out)
{
    uint64_t current;
    if (request_id_out == 0) return 0;
    service_client_lock();
    current = g_file_operation_next_request_id;
    if (!service_client_request_id_valid(current) ||
        current >= UINT64_MAX - 1u) {
        service_client_unlock();
        return 0;
    }
    g_file_operation_next_request_id = current + 1u;
    service_client_unlock();
    *request_id_out = current;
    return 1;
}

static uint64_t service_client_submit_fingerprint(
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries)
{
    const uint8_t* parts[2];
    size_t sizes[2];
    uint64_t hash = UINT64_C(14695981039346656037);
    uint32_t part;
    parts[0] = (const uint8_t*)request;
    sizes[0] = sizeof(*request);
    parts[1] = (const uint8_t*)entries;
    sizes[1] = (size_t)request->entry_count * sizeof(*entries);
    for (part = 0u; part < 2u; ++part) {
        size_t index;
        for (index = 0u; index < sizes[part]; ++index) {
            hash ^= parts[part][index];
            hash *= UINT64_C(1099511628211);
        }
    }
    return hash == 0u ? 1u : hash;
}

static int service_client_prepare_submit(uint64_t* request_id_slot,
                                         uint64_t* fingerprint_slot,
                                         uint64_t* next_request_id,
                                         const RinRuntimeFileOperationServiceSubmitV1* request,
                                         const RinRuntimeFileOperationServiceEntryV1* entries)
{
    const uint64_t fingerprint =
        service_client_submit_fingerprint(request, entries);
    uint64_t request_id;
    int result = 0;
    if (request_id_slot == 0 || fingerprint_slot == 0 ||
        next_request_id == 0)
        return 0;
    service_client_lock();
    if (*request_id_slot != 0u) {
        result = *fingerprint_slot == fingerprint &&
                 service_client_request_id_valid(*request_id_slot) &&
                 g_file_operation_pending_submit_id == *request_id_slot &&
                 g_file_operation_pending_submit_fingerprint == fingerprint
            ? 1 : -1;
    } else if (g_file_operation_pending_submit_id == 0u) {
        request_id = g_file_operation_next_request_id;
        if (service_client_request_id_valid(request_id) &&
            request_id < UINT64_MAX - 1u) {
            g_file_operation_next_request_id = request_id + 1u;
            g_file_operation_pending_submit_id = request_id;
            g_file_operation_pending_submit_fingerprint = fingerprint;
            *request_id_slot = request_id;
            *fingerprint_slot = fingerprint;
            *next_request_id = request_id + 1u;
            result = 1;
        }
    } else result = -1;
    service_client_unlock();
    return result;
}

static void service_client_clear_pending_submit(uint64_t* request_id_slot,
                                                uint64_t* fingerprint_slot)
{
    if (request_id_slot == 0 || fingerprint_slot == 0) return;
    service_client_lock();
    if (*request_id_slot != 0u &&
        g_file_operation_pending_submit_id == *request_id_slot) {
        g_file_operation_pending_submit_id = 0u;
        g_file_operation_pending_submit_fingerprint = 0u;
        *request_id_slot = 0u;
        *fingerprint_slot = 0u;
    }
    service_client_unlock();
}

static int service_client_begin(
    RinRuntimeFileOperationServiceClientV1* client)
{
    int result = 0;
    const uint64_t process_id = (uint64_t)getpid();
    if (client == 0) return 0;
    service_client_lock();
    if (g_file_operation_request_owner_pid != process_id) {
        g_file_operation_request_owner_pid = process_id;
        g_file_operation_next_request_id = 1u;
        g_file_operation_pending_submit_id = 0u;
        g_file_operation_pending_submit_fingerprint = 0u;
    }
    if (client->owner_process_id != process_id) {
        if (client->socket_fd >= 0) (void)close(client->socket_fd);
        client->socket_fd = -1;
        client->reserved = RINRUNTIME_FILE_OPERATION_CLIENT_IDLE;
        client->owner_process_id = process_id;
        client->next_request_id = 1u;
        client->pending_submit_request_id = 0u;
        client->pending_submit_fingerprint = 0u;
    }
    if (client->reserved == RINRUNTIME_FILE_OPERATION_CLIENT_IDLE &&
        client->socket_fd < 0 &&
        service_client_request_id_valid(client->next_request_id)) {
        client->reserved = RINRUNTIME_FILE_OPERATION_CLIENT_ACTIVE;
        result = 1;
    }
    service_client_unlock();
    return result;
}

static int service_broker_begin(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    int result = 0;
    const uint64_t process_id = (uint64_t)getpid();
    if (client == 0) return 0;
    service_client_lock();
    if (g_file_operation_request_owner_pid != process_id) {
        g_file_operation_request_owner_pid = process_id;
        g_file_operation_next_request_id = 1u;
        g_file_operation_pending_submit_id = 0u;
        g_file_operation_pending_submit_fingerprint = 0u;
    }
    if (client->owner_process_id != process_id) {
        if (client->socket_fd >= 0) (void)close(client->socket_fd);
        client->socket_fd = -1;
        client->reserved = RINRUNTIME_FILE_OPERATION_CLIENT_IDLE;
        client->owner_process_id = process_id;
        client->next_request_id = 1u;
        client->pending_submit_request_id = 0u;
        client->pending_submit_fingerprint = 0u;
    }
    if (client->reserved == RINRUNTIME_FILE_OPERATION_CLIENT_IDLE &&
        client->socket_fd < 0 &&
        service_client_request_id_valid(client->next_request_id)) {
        client->reserved = RINRUNTIME_FILE_OPERATION_CLIENT_ACTIVE;
        result = 1;
    }
    service_client_unlock();
    return result;
}

static int service_client_cancelled(const uint32_t* operation_state)
{
    int cancelled;
    if (operation_state == 0) return 0;
    service_client_lock();
    cancelled = *operation_state == RINRUNTIME_FILE_OPERATION_CLIENT_CANCELLED;
    service_client_unlock();
    return cancelled;
}

static void service_client_close_socket(int32_t* socket_slot,
                                        uint32_t* operation_state,
                                        int finish_operation)
{
    int32_t fd;
    if (socket_slot == 0) return;
    service_client_lock();
    fd = *socket_slot;
    *socket_slot = -1;
    if (finish_operation && operation_state != 0)
        *operation_state = RINRUNTIME_FILE_OPERATION_CLIENT_IDLE;
    if (fd >= 0) (void)close(fd);
    service_client_unlock();
}

static void service_client_cancel_socket(int32_t* socket_slot,
                                         uint32_t* operation_state)
{
    if (socket_slot == 0 || operation_state == 0) return;
    service_client_lock();
    if (*operation_state == RINRUNTIME_FILE_OPERATION_CLIENT_ACTIVE) {
        *operation_state = RINRUNTIME_FILE_OPERATION_CLIENT_CANCELLED;
        if (*socket_slot >= 0) (void)shutdown(*socket_slot, SHUT_RDWR);
    }
    service_client_unlock();
}

static int service_client_deadline_start(uint64_t* deadline_out)
{
    const uint64_t now = rin_monotonic_ms();
    const uint64_t timeout = RINRUNTIME_FILE_OPERATION_SERVICE_TIMEOUT_MS;
    if (deadline_out == 0 || now == UINT64_MAX ||
        now > UINT64_MAX - timeout)
        return 0;
    *deadline_out = now + timeout;
    return 1;
}

static int service_client_wait(int fd, uint32_t events, uint64_t deadline_ms,
                               const uint32_t* operation_state)
{
    for (;;) {
        const uint64_t now = rin_monotonic_ms();
        const uint64_t remaining = now < deadline_ms ? deadline_ms - now : 0u;
        RinRuntimePollWaitResult ready;
        uint32_t timeout_ms;
        if (service_client_cancelled(operation_state) || now == UINT64_MAX ||
            remaining == 0u)
            return 0;
        timeout_ms = remaining > UINT32_MAX
            ? UINT32_MAX : (uint32_t)remaining;
        ready = rinruntime_poll_wait(fd, events, timeout_ms);
        if (ready == RINRUNTIME_POLL_WAIT_TIMEOUT) continue;
        return ready == RINRUNTIME_POLL_WAIT_READY &&
               !service_client_cancelled(operation_state);
    }
}

static int service_client_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static int service_client_request_id_valid(uint64_t request_id)
{
    return request_id != 0u && request_id != UINT64_MAX;
}

static int service_client_identity_valid(int fd)
{
    rin_unix_peer_service_identity_v1 identity;
    socklen_t identity_size = (socklen_t)sizeof(identity);
    int valid;
    memset(&identity, 0, sizeof(identity));
    valid = getsockopt(fd, SOL_SOCKET, SO_RIN_UNIX_PEER_SERVICE_IDENTITY,
                       &identity, &identity_size) == 0 &&
            identity_size == (socklen_t)sizeof(identity) &&
            rin_unix_peer_service_identity_valid(&identity) &&
            identity.scope == RIN_UNIX_SCOPE_USER &&
            identity.owner_uid == (uint32_t)getuid() &&
            strcmp(identity.service_id, "fileoperationd") == 0;
    memset(&identity, 0, sizeof(identity));
    return valid;
}

static int service_client_send_all(int fd, const void* input, uint32_t size,
                                   uint64_t deadline_ms,
                                   const uint32_t* operation_state)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        if (!service_client_wait(fd, RINRUNTIME_POLL_WAIT_WRITABLE,
                                 deadline_ms, operation_state))
            return 0;
        ssize_t result = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (result > 0) {
            if ((uint32_t)result > size - offset) return 0;
            offset += (uint32_t)result;
            interrupted = 0u;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            if (++interrupted >=
                RINRUNTIME_FILE_OPERATION_SERVICE_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return 0;
    }
    return 1;
}

static int service_client_receive_all(int fd, void* output, uint32_t size,
                                      uint64_t deadline_ms,
                                      const uint32_t* operation_state)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t offset = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        if (!service_client_wait(fd, RINRUNTIME_POLL_WAIT_READABLE,
                                 deadline_ms, operation_state))
            return 0;
        ssize_t result = recv(fd, bytes + offset, size - offset, 0);
        if (result > 0) {
            if ((uint32_t)result > size - offset) return 0;
            offset += (uint32_t)result;
            interrupted = 0u;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            if (++interrupted >=
                RINRUNTIME_FILE_OPERATION_SERVICE_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            continue;
        return 0;
    }
    return 1;
}

static int service_client_path_valid(const char* path, uint32_t capacity)
{
    size_t size = 0u;
    return rin_wire_bounded_string_valid(path, capacity, capacity - 1u, &size) &&
           rin_path_absolute_canonical_valid(path, size);
}

static int service_client_submit_valid(
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries)
{
    uint32_t index;
    if (!rin_wire_struct_version_valid(
            request, sizeof(*request), request == 0 ? 0u : request->struct_size,
            request == 0 ? 0u : request->version,
            RINRUNTIME_FILE_OPERATION_SERVICE_VERSION) || entries == 0 ||
        !rin_wire_enum_u16_valid(
            request->operation, RINRUNTIME_FILE_OPERATION_COPY,
            RINRUNTIME_FILE_OPERATION_RESTORE) ||
        !rin_wire_enum_u32_valid(
            request->conflict_policy, RINRUNTIME_FILE_OPERATION_CONFLICT_FAIL,
            RINRUNTIME_FILE_OPERATION_CONFLICT_RENAME) ||
        request->entry_count == 0u ||
        request->entry_count > RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_LIMIT ||
        !rin_wire_reserved_zero(request->reserved, sizeof(request->reserved)) ||
        !service_client_path_valid(request->state_directory,
                                   sizeof(request->state_directory))) return 0;
    for (index = 0u; index < request->entry_count; ++index) {
        const RinRuntimeFileOperationServiceEntryV1* entry = &entries[index];
        if (!rin_wire_reserved_zero(&entry->reserved, sizeof(entry->reserved)) ||
            entry->source_identity_reserved != 0u ||
            (entry->source_identity_flags != 0u &&
             entry->source_identity_flags !=
                 RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_SOURCE_IDENTITY_REQUIRED) ||
            (entry->source_identity_flags ==
                 RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_SOURCE_IDENTITY_REQUIRED
                 ? (request->operation != RINRUNTIME_FILE_OPERATION_TRASH ||
                    entry->kind != RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY ||
                    entry->expected_source_inode == 0u)
                 : (entry->expected_source_device != 0u ||
                    entry->expected_source_inode != 0u)) ||
            !rin_wire_flags_valid(
                entry->flags, RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_FLAGS_KNOWN) ||
            !service_client_path_valid(entry->source_path,
                                       sizeof(entry->source_path)) ||
            entry->destination_path[sizeof(entry->destination_path) - 1u] != '\0' ||
            entry->cleanup_path[sizeof(entry->cleanup_path) - 1u] != '\0') return 0;
        if (request->operation != RINRUNTIME_FILE_OPERATION_DELETE &&
            !service_client_path_valid(entry->destination_path,
                                       sizeof(entry->destination_path))) return 0;
        if (request->operation == RINRUNTIME_FILE_OPERATION_DELETE &&
            entry->destination_path[0] != '\0') return 0;
        if (entry->flags != 0u &&
            !service_client_path_valid(entry->cleanup_path,
                                       sizeof(entry->cleanup_path))) return 0;
        if (entry->flags == 0u && entry->cleanup_path[0] != '\0') return 0;
    }
    return 1;
}

static int service_client_control_valid(
    const RinRuntimeFileOperationServiceControlV1* request)
{
    return rin_wire_struct_version_valid(
               request, sizeof(*request), request == 0 ? 0u : request->struct_size,
               request == 0 ? 0u : request->version,
               RINRUNTIME_FILE_OPERATION_SERVICE_VERSION) &&
           rin_wire_reserved_zero(&request->reserved0,
                                  sizeof(request->reserved0)) &&
           service_client_path_valid(request->state_directory,
                                     sizeof(request->state_directory));
}

static RinRuntimeFileOperationServiceStatus service_client_open_path(
    int32_t* socket_fd, uint32_t* reserved, uint64_t next_request_id,
    const char* service_path, uint64_t deadline_ms,
    const uint32_t* operation_state)
{
    struct sockaddr_un address;
    socklen_t error_size;
    int socket_error = 0;
    int connect_result;
    int fd;
    if (socket_fd == 0 || reserved == 0 ||
        !service_client_request_id_valid(next_request_id) || service_path == 0 ||
        strlen(service_path) + 1u > sizeof(address.sun_path))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    if ((operation_state == 0 && *reserved != 0u) ||
        (operation_state != 0 &&
         service_client_cancelled(operation_state)))
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, service_path, strlen(service_path) + 1u);
    fd = rinruntime_create_private_unix_stream_socket();
    if (fd < 0 || !service_client_nonblocking(fd)) {
        if (fd >= 0) (void)close(fd);
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    service_client_lock();
    if ((operation_state != 0 &&
         *operation_state != RINRUNTIME_FILE_OPERATION_CLIENT_ACTIVE) ||
        (operation_state == 0 && *reserved != 0u) || *socket_fd >= 0) {
        service_client_unlock();
        (void)close(fd);
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    *socket_fd = fd;
    service_client_unlock();

    connect_result = connect(fd, (const struct sockaddr*)&address,
                             sizeof(address));
    if (connect_result != 0) {
        if (errno != EINPROGRESS && errno != EALREADY && errno != EAGAIN &&
            errno != EWOULDBLOCK)
            goto open_failed;
        if (!service_client_wait(fd, RINRUNTIME_POLL_WAIT_WRITABLE,
                                 deadline_ms, operation_state))
            goto open_failed;
        error_size = (socklen_t)sizeof(socket_error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                       &error_size) != 0 ||
            error_size != (socklen_t)sizeof(socket_error) || socket_error != 0)
            goto open_failed;
    }
    if (service_client_cancelled(operation_state) ||
        !service_client_identity_valid(fd))
        goto open_failed;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;

open_failed:
    service_client_close_socket(socket_fd, 0, 0);
    return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
}

static RinRuntimeFileOperationServiceStatus service_client_open(
    RinRuntimeFileOperationServiceClientV1* client, uint64_t deadline_ms)
{
    if (client == 0) return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    return service_client_open_path(&client->socket_fd, &client->reserved,
                                    client->next_request_id,
                                    RINRUNTIME_FILE_OPERATION_SERVICE_PATH,
                                    deadline_ms, &client->reserved);
}

static RinRuntimeFileOperationServiceStatus service_client_begin_request(
    RinRuntimeFileOperationServiceClientV1* client, uint64_t* deadline_out)
{
    if (!service_client_begin(client))
        return client == 0
            ? RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT
            : RINRUNTIME_FILE_OPERATION_SERVICE_BUSY;
    if (!service_client_deadline_start(deadline_out)) {
        service_client_close_socket(&client->socket_fd, &client->reserved, 1);
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static void service_client_finish(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return;
    service_client_close_socket(&client->socket_fd, &client->reserved, 1);
}

static int service_client_broker_deadline_start(uint64_t* deadline_out)
{
    return service_client_deadline_start(deadline_out);
}

static RinRuntimeFileOperationServiceStatus service_client_broker_open(
    RinRuntimeFileOperationServiceBrokerClientV1* client,
    uint64_t deadline_ms)
{
    if (client == 0) return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    return service_client_open_path(&client->socket_fd, &client->reserved,
                                    client->next_request_id,
                                    RINRUNTIME_FILE_OPERATION_SERVICE_BROKER_PATH,
                                    deadline_ms, &client->reserved);
}

static void service_client_broker_finish(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    if (client == 0) return;
    service_client_close_socket(&client->socket_fd, &client->reserved, 1);
}


static RinRuntimeFileOperationServiceStatus service_client_header(
    RinRuntimeFileOperationServiceClientV1* client, uint16_t request_kind,
    uint32_t payload_size, RinRuntimeFileOperationServiceHeaderV1* header)
{
    uint64_t request_id;
    if (client == 0 || header == 0 || client->socket_fd < 0 ||
        !service_client_allocate_request_id(&request_id))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    client->next_request_id = request_id + 1u;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RINRUNTIME_FILE_OPERATION_SERVICE_VERSION;
    header->request_kind = request_kind;
    header->request_id = request_id;
    header->payload_size = payload_size;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static RinRuntimeFileOperationServiceStatus service_client_header_with_id(
    RinRuntimeFileOperationServiceClientV1* client, uint16_t request_kind,
    uint32_t payload_size, uint64_t request_id,
    RinRuntimeFileOperationServiceHeaderV1* header)
{
    if (client == 0 || header == 0 || client->socket_fd < 0 ||
        !service_client_request_id_valid(request_id))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RINRUNTIME_FILE_OPERATION_SERVICE_VERSION;
    header->request_kind = request_kind;
    header->request_id = request_id;
    header->payload_size = payload_size;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static RinRuntimeFileOperationServiceStatus service_broker_header(
    RinRuntimeFileOperationServiceBrokerClientV1* client, uint32_t payload_size,
    uint16_t request_kind, uint64_t request_id,
    RinRuntimeFileOperationServiceHeaderV1* header)
{
    if (client == 0 || header == 0 || client->socket_fd < 0 ||
        !service_client_request_id_valid(request_id))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RINRUNTIME_FILE_OPERATION_SERVICE_VERSION;
    header->request_kind = request_kind;
    header->request_id = request_id;
    header->payload_size = payload_size;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static int service_client_authorization_valid(
    const RinRuntimeFileOperationServiceAuthorizationV1* authorization,
    uint16_t operation)
{
    if (!rin_wire_struct_version_valid(
            authorization, sizeof(*authorization),
            authorization == 0 ? 0u : authorization->struct_size,
            authorization == 0 ? 0u : authorization->version,
            RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZATION_VERSION) ||
        authorization->operation != operation ||
        !rin_wire_request_id_valid(authorization->process_instance_cookie) ||
        !rin_wire_request_id_valid(authorization->connection_id) ||
        rin_wire_capability_generation_valid(authorization->object_generation) !=
            RIN_WIRE_CAPABILITY_OK ||
        !rin_wire_reserved_zero(authorization->reserved,
                                 sizeof(authorization->reserved)))
        return 0;
    return rin_wire_nonzero_bytes_valid(authorization->application_id,
                                        sizeof(authorization->application_id)) &&
           rin_wire_capability_token_valid(
               authorization->capability, sizeof(authorization->capability),
               sizeof(authorization->capability),
               sizeof(authorization->capability)) == RIN_WIRE_CAPABILITY_OK;
}

static int service_client_status_valid(int32_t status)
{
    switch (status) {
    case RINRUNTIME_FILE_OPERATION_SERVICE_OK:
    case RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT:
    case RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE:
    case RINRUNTIME_FILE_OPERATION_SERVICE_BUSY:
    case RINRUNTIME_FILE_OPERATION_SERVICE_ACCESS_DENIED:
    case RINRUNTIME_FILE_OPERATION_SERVICE_NOT_FOUND:
    case RINRUNTIME_FILE_OPERATION_SERVICE_NOT_UNDOABLE:
    case RINRUNTIME_FILE_OPERATION_SERVICE_IO_FAILED:
    case RINRUNTIME_FILE_OPERATION_SERVICE_CONFLICT:
        return 1;
    default:
        return 0;
    }
}

static RinRuntimeFileOperationServiceStatus service_client_reply(
    const RinRuntimeFileOperationServiceHeaderV1* request,
    const RinRuntimeFileOperationServiceHeaderV1* reply_header,
    uint16_t request_kind, RinRuntimeFileOperationServiceReplyV1* reply,
    int* valid_out)
{
    if (valid_out != 0) *valid_out = 0;
    if (request == 0 || reply_header == 0 || reply == 0 ||
        !rin_wire_struct_version_valid(
            reply_header, sizeof(*reply_header), reply_header->struct_size,
            reply_header->version, RINRUNTIME_FILE_OPERATION_SERVICE_VERSION) ||
        reply_header->request_kind != request_kind ||
        !rin_wire_request_id_echo_valid(request->request_id,
                                        reply_header->request_id) ||
        !rin_wire_flags_valid(reply_header->flags, 0u) ||
        !rin_wire_reserved_zero(&reply_header->reserved,
                                sizeof(reply_header->reserved)) ||
        reply_header->payload_size != sizeof(*reply) ||
        !service_client_status_valid(reply_header->status) ||
        !rin_wire_struct_version_valid(
            reply, sizeof(*reply), reply->struct_size, reply->version,
            RINRUNTIME_FILE_OPERATION_SERVICE_VERSION) ||
        !rin_wire_reserved_zero(&reply->reserved, sizeof(reply->reserved)))
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (valid_out != 0) *valid_out = 1;
    return (RinRuntimeFileOperationServiceStatus)reply_header->status;
}

static RinRuntimeFileOperationServiceStatus service_client_control(
    RinRuntimeFileOperationServiceClientV1* client, uint16_t request_kind,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    RinRuntimeFileOperationServiceHeaderV1 header;
    RinRuntimeFileOperationServiceHeaderV1 reply_header;
    RinRuntimeFileOperationServiceStatus status;
    uint64_t deadline_ms = 0u;
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (!service_client_control_valid(request) || reply_out == 0)
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    status = service_client_begin_request(client, &deadline_ms);
    if (status != RINRUNTIME_FILE_OPERATION_SERVICE_OK) return status;
    status = service_client_open(client, deadline_ms);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_header(client, request_kind, sizeof(*request), &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header),
                                  deadline_ms, &client->reserved) ||
         !service_client_send_all(client->socket_fd, request, sizeof(*request),
                                  deadline_ms, &client->reserved) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header), deadline_ms,
                                     &client->reserved) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out), deadline_ms,
                                     &client->reserved)))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        service_client_cancelled(&client->reserved))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header, request_kind,
                                      reply_out, 0);
    service_client_finish(client);
    return status;
}

void rinruntime_file_operation_service_client_init(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return;
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->next_request_id = 1u;
    client->owner_process_id = (uint64_t)getpid();
}

void rinruntime_file_operation_service_client_close(
    RinRuntimeFileOperationServiceClientV1* client)
{
    rinruntime_file_operation_service_client_cancel(client);
}

void rinruntime_file_operation_service_client_cancel(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return;
    service_client_cancel_socket(&client->socket_fd, &client->reserved);
}

RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_submit(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    RinRuntimeFileOperationServiceHeaderV1 header;
    RinRuntimeFileOperationServiceHeaderV1 reply_header;
    RinRuntimeFileOperationServiceStatus status;
    uint64_t deadline_ms = 0u;
    uint32_t payload_size;
    uint64_t fingerprint;
    int reply_valid = 0;
    int prepare_result;
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (reply_out == 0 || !service_client_submit_valid(request, entries) ||
        request->entry_count >
            (UINT32_MAX - (uint32_t)sizeof(*request)) / (uint32_t)sizeof(*entries))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    payload_size = (uint32_t)sizeof(*request) +
                   request->entry_count * (uint32_t)sizeof(*entries);
    status = service_client_begin_request(client, &deadline_ms);
    if (status != RINRUNTIME_FILE_OPERATION_SERVICE_OK) return status;
    fingerprint = service_client_submit_fingerprint(request, entries);
    if (client->pending_submit_request_id != 0u &&
        client->pending_submit_fingerprint != fingerprint) {
        service_client_finish(client);
        return RINRUNTIME_FILE_OPERATION_SERVICE_CONFLICT;
    }
    prepare_result = service_client_prepare_submit(
        &client->pending_submit_request_id,
        &client->pending_submit_fingerprint, &client->next_request_id,
        request, entries);
    if (prepare_result != 1) {
        service_client_finish(client);
        return prepare_result < 0
            ? RINRUNTIME_FILE_OPERATION_SERVICE_BUSY
            : RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    status = service_client_open(client, deadline_ms);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_header_with_id(
            client, RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT, payload_size,
            client->pending_submit_request_id, &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header),
                                  deadline_ms, &client->reserved) ||
         !service_client_send_all(client->socket_fd, request, sizeof(*request),
                                  deadline_ms, &client->reserved) ||
         !service_client_send_all(client->socket_fd, entries,
                                  request->entry_count * (uint32_t)sizeof(*entries),
                                  deadline_ms, &client->reserved) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header), deadline_ms,
                                     &client->reserved) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out), deadline_ms,
                                     &client->reserved)))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        service_client_cancelled(&client->reserved))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header,
                                      RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                      reply_out, &reply_valid);
    if (reply_valid) {
        service_client_clear_pending_submit(
            &client->pending_submit_request_id,
            &client->pending_submit_fingerprint);
    }
    service_client_finish(client);
    return status;
}

RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_query(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    return service_client_control(client, RINRUNTIME_FILE_OPERATION_SERVICE_QUERY,
                                  request, reply_out);
}

RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_cancel(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    return service_client_control(client, RINRUNTIME_FILE_OPERATION_SERVICE_CANCEL,
                                  request, reply_out);
}

RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_undo(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    return service_client_control(client, RINRUNTIME_FILE_OPERATION_SERVICE_UNDO,
                                  request, reply_out);
}

RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_recover(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    return service_client_control(client,
                                  RINRUNTIME_FILE_OPERATION_SERVICE_RECOVER,
                                  request, reply_out);
}

void rinruntime_file_operation_service_broker_client_init(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    if (client == 0) return;
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->next_request_id = 1u;
    client->owner_process_id = (uint64_t)getpid();
}

void rinruntime_file_operation_service_broker_client_close(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    rinruntime_file_operation_service_broker_client_cancel(client);
}

void rinruntime_file_operation_service_broker_client_cancel(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    if (client == 0) return;
    service_client_cancel_socket(&client->socket_fd, &client->reserved);
}

RinRuntimeFileOperationServiceStatus
rinruntime_file_operation_service_recover_authorized(
    RinRuntimeFileOperationServiceBrokerClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    const RinRuntimeFileOperationServiceAuthorizationV1* authorizations,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    RinRuntimeFileOperationServiceAuthorizedRecoverV1 wire;
    RinRuntimeFileOperationServiceHeaderV1 header;
    RinRuntimeFileOperationServiceHeaderV1 reply_header;
    RinRuntimeFileOperationServiceStatus status;
    uint64_t deadline_ms = 0u;
    uint64_t request_id = 0u;
    uint32_t index;
    int reply_valid = 0;
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (client == 0 || request == 0 || authorizations == 0 ||
        reply_out == 0 || !service_client_control_valid(request))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    for (index = 0u;
         index < RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_LIMIT; ++index) {
        const RinRuntimeFileOperationServiceAuthorizationV1* authorization =
            &authorizations[index];
        if (!service_client_bytes_zero(authorization,
                                       sizeof(*authorization)) &&
            !service_client_authorization_valid(
                authorization, authorization->operation))
            return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    }
    if (!service_broker_begin(client))
        return RINRUNTIME_FILE_OPERATION_SERVICE_BUSY;
    if (!service_client_allocate_request_id(&request_id)) {
        service_client_broker_finish(client);
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    client->next_request_id = request_id;
    memset(&wire, 0, sizeof(wire));
    wire.struct_size = sizeof(wire);
    wire.version =
        RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZED_RECOVER_VERSION;
    wire.control = *request;
    memcpy(wire.authorization, authorizations,
           sizeof(wire.authorization));
    status = service_client_broker_deadline_start(&deadline_ms)
        ? service_client_broker_open(client, deadline_ms)
        : RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_broker_header(
            client, sizeof(wire), RINRUNTIME_FILE_OPERATION_SERVICE_RECOVER,
            request_id, &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK) {
        client->next_request_id = request_id + 1u;
        if (!service_client_send_all(client->socket_fd, &header,
                                     sizeof(header), deadline_ms,
                                     &client->reserved) ||
            !service_client_send_all(client->socket_fd, &wire, sizeof(wire),
                                     deadline_ms, &client->reserved) ||
            !service_client_receive_all(client->socket_fd, &reply_header,
                                        sizeof(reply_header), deadline_ms,
                                        &client->reserved) ||
            !service_client_receive_all(client->socket_fd, reply_out,
                                        sizeof(*reply_out), deadline_ms,
                                        &client->reserved))
            status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        service_client_cancelled(&client->reserved))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(
            &header, &reply_header,
            RINRUNTIME_FILE_OPERATION_SERVICE_RECOVER, reply_out,
            &reply_valid);
    memset(&wire, 0, sizeof(wire));
    service_client_broker_finish(client);
    return status;
}

RinRuntimeFileOperationServiceStatus
rinruntime_file_operation_service_submit_authorized(
    RinRuntimeFileOperationServiceBrokerClientV1* client,
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries,
    const RinRuntimeFileOperationServiceAuthorizationV1* authorization,
    RinRuntimeFileOperationServiceReplyV1* reply_out)
{
    RinRuntimeFileOperationServiceAuthorizedSubmitV1 wire;
    RinRuntimeFileOperationServiceHeaderV1 header;
    RinRuntimeFileOperationServiceHeaderV1 reply_header;
    RinRuntimeFileOperationServiceStatus status;
    uint32_t payload_size;
    uint64_t deadline_ms = 0u;
    uint64_t fingerprint;
    int reply_valid = 0;
    int prepare_result;
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (client == 0 || reply_out == 0 ||
        !service_client_submit_valid(request, entries) ||
        !service_client_authorization_valid(authorization, request->operation) ||
        request->entry_count >
            (UINT32_MAX - (uint32_t)sizeof(wire)) /
                (uint32_t)sizeof(*entries))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    if (!service_broker_begin(client))
        return client == 0
            ? RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT
            : RINRUNTIME_FILE_OPERATION_SERVICE_BUSY;
    fingerprint = service_client_submit_fingerprint(request, entries);
    if (client->pending_submit_request_id != 0u &&
        client->pending_submit_fingerprint != fingerprint) {
        service_client_broker_finish(client);
        return RINRUNTIME_FILE_OPERATION_SERVICE_CONFLICT;
    }
    prepare_result = service_client_prepare_submit(
        &client->pending_submit_request_id,
        &client->pending_submit_fingerprint, &client->next_request_id,
        request, entries);
    if (prepare_result != 1) {
        service_client_broker_finish(client);
        return prepare_result < 0
            ? RINRUNTIME_FILE_OPERATION_SERVICE_BUSY
            : RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    memset(&wire, 0, sizeof(wire));
    wire.struct_size = sizeof(wire);
    wire.version = RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZED_SUBMIT_VERSION;
    wire.authorization = *authorization;
    wire.submit = *request;
    payload_size = (uint32_t)sizeof(wire) +
                   request->entry_count * (uint32_t)sizeof(*entries);
    status = service_client_broker_deadline_start(&deadline_ms)
        ? service_client_broker_open(client, deadline_ms)
        : RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_broker_header(
                                       client, payload_size,
                                       RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                       client->pending_submit_request_id,
                                       &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header),
                                  deadline_ms, &client->reserved) ||
         !service_client_send_all(client->socket_fd, &wire, sizeof(wire),
                                  deadline_ms, &client->reserved) ||
         !service_client_send_all(client->socket_fd, entries,
                                  request->entry_count * (uint32_t)sizeof(*entries),
                                  deadline_ms, &client->reserved) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header), deadline_ms,
                                     &client->reserved) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out), deadline_ms,
                                     &client->reserved)))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        service_client_cancelled(&client->reserved))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header,
                                      RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                      reply_out, &reply_valid);
    if (reply_valid) {
        service_client_clear_pending_submit(
            &client->pending_submit_request_id,
            &client->pending_submit_fingerprint);
    }
    memset(&wire, 0, sizeof(wire));
    service_client_broker_finish(client);
    return status;
}
