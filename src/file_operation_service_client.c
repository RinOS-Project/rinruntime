/* SPDX-License-Identifier: MIT */

#include <rinruntime/file_operation_service.h>
#include <rinruntime/path.h>
#include <rin/capability.h>
#include <rin/validation.h>

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int service_client_send_all(int fd, const void* input, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint32_t offset = 0u;
    while (offset < size) {
        ssize_t result = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (result > 0) {
            if ((uint32_t)result > size - offset) return 0;
            offset += (uint32_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int service_client_receive_all(int fd, void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t offset = 0u;
    while (offset < size) {
        ssize_t result = recv(fd, bytes + offset, size - offset, 0);
        if (result > 0) {
            if ((uint32_t)result > size - offset) return 0;
            offset += (uint32_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) continue;
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
    int32_t* socket_fd, uint32_t reserved, uint64_t next_request_id,
    const char* service_path)
{
    struct sockaddr_un address;
    int fd;
    if (socket_fd == 0 || *socket_fd >= 0 || reserved != 0u ||
        next_request_id == 0u || service_path == 0 ||
        strlen(service_path) + 1u > sizeof(address.sun_path))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, service_path, strlen(service_path) + 1u);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0) {
        (void)close(fd);
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    }
    *socket_fd = fd;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static RinRuntimeFileOperationServiceStatus service_client_open(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    return service_client_open_path(&client->socket_fd, client->reserved,
                                    client->next_request_id,
                                    RINRUNTIME_FILE_OPERATION_SERVICE_PATH);
}

static RinRuntimeFileOperationServiceStatus service_client_header(
    RinRuntimeFileOperationServiceClientV1* client, uint16_t request_kind,
    uint32_t payload_size, RinRuntimeFileOperationServiceHeaderV1* header)
{
    if (client == 0 || header == 0 || client->socket_fd < 0 ||
        client->next_request_id == 0u) return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RINRUNTIME_FILE_OPERATION_SERVICE_VERSION;
    header->request_kind = request_kind;
    header->request_id = client->next_request_id++;
    if (client->next_request_id == 0u) client->next_request_id = 1u;
    header->payload_size = payload_size;
    return RINRUNTIME_FILE_OPERATION_SERVICE_OK;
}

static RinRuntimeFileOperationServiceStatus service_broker_header(
    RinRuntimeFileOperationServiceBrokerClientV1* client, uint32_t payload_size,
    RinRuntimeFileOperationServiceHeaderV1* header)
{
    if (client == 0 || header == 0 || client->socket_fd < 0 ||
        client->next_request_id == 0u)
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RINRUNTIME_FILE_OPERATION_SERVICE_VERSION;
    header->request_kind = RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT;
    header->request_id = client->next_request_id++;
    if (client->next_request_id == 0u) client->next_request_id = 1u;
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

static RinRuntimeFileOperationServiceStatus service_client_reply(
    const RinRuntimeFileOperationServiceHeaderV1* request,
    const RinRuntimeFileOperationServiceHeaderV1* reply_header,
    uint16_t request_kind, RinRuntimeFileOperationServiceReplyV1* reply)
{
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
        reply_header->payload_size != sizeof(*reply) || reply_header->status > 0 ||
        !rin_wire_struct_version_valid(
            reply, sizeof(*reply), reply->struct_size, reply->version,
            RINRUNTIME_FILE_OPERATION_SERVICE_VERSION) ||
        !rin_wire_reserved_zero(&reply->reserved, sizeof(reply->reserved)))
        return RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
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
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (!service_client_control_valid(request) || reply_out == 0)
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    status = service_client_open(client);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_header(client, request_kind, sizeof(*request), &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header)) ||
         !service_client_send_all(client->socket_fd, request, sizeof(*request)) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header)) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out))))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header, request_kind, reply_out);
    rinruntime_file_operation_service_client_close(client);
    return status;
}

void rinruntime_file_operation_service_client_init(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return;
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->next_request_id = 1u;
}

void rinruntime_file_operation_service_client_close(
    RinRuntimeFileOperationServiceClientV1* client)
{
    if (client == 0) return;
    if (client->socket_fd >= 0) (void)close(client->socket_fd);
    client->socket_fd = -1;
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
    uint32_t payload_size;
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (reply_out == 0 || !service_client_submit_valid(request, entries) ||
        request->entry_count >
            (UINT32_MAX - (uint32_t)sizeof(*request)) / (uint32_t)sizeof(*entries))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    payload_size = (uint32_t)sizeof(*request) +
                   request->entry_count * (uint32_t)sizeof(*entries);
    status = service_client_open(client);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_header(client,
                                       RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                       payload_size, &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header)) ||
         !service_client_send_all(client->socket_fd, request, sizeof(*request)) ||
         !service_client_send_all(client->socket_fd, entries,
                                  request->entry_count * (uint32_t)sizeof(*entries)) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header)) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out))))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header,
                                      RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                      reply_out);
    rinruntime_file_operation_service_client_close(client);
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

void rinruntime_file_operation_service_broker_client_init(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    if (client == 0) return;
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->next_request_id = 1u;
}

void rinruntime_file_operation_service_broker_client_close(
    RinRuntimeFileOperationServiceBrokerClientV1* client)
{
    if (client == 0) return;
    if (client->socket_fd >= 0) (void)close(client->socket_fd);
    client->socket_fd = -1;
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
    if (reply_out != 0) memset(reply_out, 0, sizeof(*reply_out));
    if (client == 0 || reply_out == 0 ||
        !service_client_submit_valid(request, entries) ||
        !service_client_authorization_valid(authorization, request->operation) ||
        request->entry_count >
            (UINT32_MAX - (uint32_t)sizeof(wire)) /
                (uint32_t)sizeof(*entries))
        return RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT;
    memset(&wire, 0, sizeof(wire));
    wire.struct_size = sizeof(wire);
    wire.version = RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZED_SUBMIT_VERSION;
    wire.authorization = *authorization;
    wire.submit = *request;
    payload_size = (uint32_t)sizeof(wire) +
                   request->entry_count * (uint32_t)sizeof(*entries);
    status = service_client_open_path(&client->socket_fd, client->reserved,
                                      client->next_request_id,
                                      RINRUNTIME_FILE_OPERATION_SERVICE_BROKER_PATH);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_broker_header(client, payload_size, &header);
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK &&
        (!service_client_send_all(client->socket_fd, &header, sizeof(header)) ||
         !service_client_send_all(client->socket_fd, &wire, sizeof(wire)) ||
         !service_client_send_all(client->socket_fd, entries,
                                  request->entry_count * (uint32_t)sizeof(*entries)) ||
         !service_client_receive_all(client->socket_fd, &reply_header,
                                     sizeof(reply_header)) ||
         !service_client_receive_all(client->socket_fd, reply_out,
                                     sizeof(*reply_out))))
        status = RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE;
    if (status == RINRUNTIME_FILE_OPERATION_SERVICE_OK)
        status = service_client_reply(&header, &reply_header,
                                      RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT,
                                      reply_out);
    memset(&wire, 0, sizeof(wire));
    rinruntime_file_operation_service_broker_client_close(client);
    return status;
}


