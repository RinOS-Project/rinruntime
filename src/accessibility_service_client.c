/* SPDX-License-Identifier: MIT */

#include <rinruntime/accessibility_service_client.h>

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define RIN_ACCESSIBILITY_CLIENT_IO_POLL_MS 1000
#define RIN_ACCESSIBILITY_CLIENT_IO_IDLE_LIMIT 5u
#define RIN_ACCESSIBILITY_CLIENT_IO_INTERRUPTION_LIMIT 32u

static int client_receive_exact(int fd, void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t offset = 0u;
    uint32_t idle = 0u;
    uint32_t interrupted = 0u;
    while (offset < size) {
        struct pollfd descriptor;
        int ready;
        ssize_t count;
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.fd = fd;
        descriptor.events = POLLIN | POLLERR | POLLHUP;
        ready = poll(&descriptor, 1u, RIN_ACCESSIBILITY_CLIENT_IO_POLL_MS);
        if (ready == 0) {
            if (++idle >= RIN_ACCESSIBILITY_CLIENT_IO_IDLE_LIMIT) return 0;
            continue;
        }
        if (ready < 0 && errno == EINTR) {
            if (++interrupted >= RIN_ACCESSIBILITY_CLIENT_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (ready < 0 || (descriptor.revents & POLLERR) != 0 ||
            (descriptor.revents & POLLIN) == 0) return 0;
        count = recv(fd, bytes + offset, size - offset, 0);
        if (count > 0) {
            if ((uint32_t)count > size - offset) return 0;
            offset += (uint32_t)count;
            idle = 0u;
            interrupted = 0u;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            if (++interrupted >= RIN_ACCESSIBILITY_CLIENT_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        return 0;
    }
    return 1;
}

static int client_send_exact(int fd, const void* input, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint32_t offset = 0u;
    while (offset < size) {
        ssize_t count = send(fd, bytes + offset, size - offset, MSG_NOSIGNAL);
        if (count > 0) {
            if ((uint32_t)count > size - offset) return 0;
            offset += (uint32_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static RinResultCode client_wait_readable(int fd, uint32_t timeout_ms)
{
    struct pollfd descriptor;
    int ready;
    int poll_timeout;
    uint32_t interrupted = 0u;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.fd = fd;
    descriptor.events = POLLIN | POLLERR | POLLHUP;
    poll_timeout = timeout_ms > (uint32_t)INT_MAX ? INT_MAX : (int)timeout_ms;
    for (;;) {
        ready = poll(&descriptor, 1u, poll_timeout);
        if (ready >= 0) break;
        if (errno != EINTR ||
            ++interrupted >= RIN_ACCESSIBILITY_CLIENT_IO_INTERRUPTION_LIMIT)
            return RIN_RESULT_IO;
    }
    if (ready == 0) return RIN_RESULT_TIMED_OUT;
    if (ready < 0 || (descriptor.revents & POLLERR) != 0 ||
        (descriptor.revents & POLLIN) == 0) return RIN_RESULT_IO;
    return RIN_RESULT_OK;
}

static RinResultCode client_next_header(RinAccessibilityServiceClientV1* client,
                                        uint16_t opcode, uint32_t payload_size,
                                        RinAccessibilityServiceMessageHeaderV1* header)
{
    if (client == NULL || header == NULL || client->socket_fd < 0 ||
        client->next_request_id == 0u) return RIN_RESULT_INVALID_ARGUMENT;
    memset(header, 0, sizeof(*header));
    header->struct_size = sizeof(*header);
    header->version = RIN_ACCESSIBILITY_SERVICE_ABI_VERSION;
    header->opcode = opcode;
    header->request_id = client->next_request_id++;
    if (client->next_request_id == 0u) client->next_request_id = 1u;
    header->payload_size = payload_size;
    return RIN_RESULT_OK;
}

static RinResultCode client_reply_header(
    const RinAccessibilityServiceMessageHeaderV1* request,
    const RinAccessibilityServiceMessageHeaderV1* reply,
    uint16_t opcode, uint32_t expected_payload_size)
{
    if (request == NULL || reply == NULL ||
        reply->struct_size != sizeof(*reply) ||
        reply->version != RIN_ACCESSIBILITY_SERVICE_ABI_VERSION ||
        reply->opcode != opcode || reply->request_id != request->request_id ||
        reply->flags != 0u || reply->reserved != 0u ||
        reply->payload_size != expected_payload_size) {
        return RIN_RESULT_CORRUPT_DATA;
    }
    return (RinResultCode)reply->status;
}

void rin_accessibility_service_client_init(RinAccessibilityServiceClientV1* client)
{
    if (client == NULL) return;
    memset(client, 0, sizeof(*client));
    client->socket_fd = -1;
    client->next_request_id = 1u;
}

RinResultCode rin_accessibility_service_client_open(
    RinAccessibilityServiceClientV1* client)
{
    struct sockaddr_un address;
    int fd;
    if (client == NULL || client->socket_fd >= 0 ||
        client->next_request_id == 0u) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(RIN_ACCESSIBILITY_SERVICE_SOCKET_PATH) >=
        sizeof(address.sun_path)) return RIN_RESULT_INVALID_ARGUMENT;
    strcpy(address.sun_path, RIN_ACCESSIBILITY_SERVICE_SOCKET_PATH);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return RIN_RESULT_IO;
    if (connect(fd, (const struct sockaddr*)&address, sizeof(address)) != 0) {
        close(fd);
        return RIN_RESULT_IO;
    }
    client->socket_fd = fd;
    return RIN_RESULT_OK;
}

void rin_accessibility_service_client_close(RinAccessibilityServiceClientV1* client)
{
    if (client == NULL) return;
    if (client->socket_fd >= 0) close(client->socket_fd);
    client->socket_fd = -1;
}

RinResultCode rin_accessibility_service_client_publish(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityWireSnapshotV1* snapshot)
{
    RinAccessibilityServiceMessageHeaderV1 request;
    RinAccessibilityServiceMessageHeaderV1 reply;
    RinResultCode result;
    if (snapshot == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    result = client_next_header(client, RIN_ACCESSIBILITY_SERVICE_OP_PUBLISH,
                                sizeof(*snapshot), &request);
    if (result != RIN_RESULT_OK) return result;
    if (!client_send_exact(client->socket_fd, &request, sizeof(request)) ||
        !client_send_exact(client->socket_fd, snapshot, sizeof(*snapshot)) ||
        !client_receive_exact(client->socket_fd, &reply, sizeof(reply))) {
        return RIN_RESULT_IO;
    }
    return client_reply_header(&request, &reply,
                               RIN_ACCESSIBILITY_SERVICE_OP_PUBLISH, 0u);
}

RinResultCode rin_accessibility_service_client_query(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityServiceQueryV1* query,
    RinAccessibilityWireSnapshotV1* snapshot_out)
{
    RinAccessibilityServiceMessageHeaderV1 request;
    RinAccessibilityServiceMessageHeaderV1 reply;
    RinResultCode result;
    if (query == NULL || snapshot_out == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    result = client_next_header(client, RIN_ACCESSIBILITY_SERVICE_OP_QUERY,
                                sizeof(*query), &request);
    if (result != RIN_RESULT_OK) return result;
    if (!client_send_exact(client->socket_fd, &request, sizeof(request)) ||
        !client_send_exact(client->socket_fd, query, sizeof(*query)) ||
        !client_receive_exact(client->socket_fd, &reply, sizeof(reply))) {
        return RIN_RESULT_IO;
    }
    if (reply.status != RIN_RESULT_OK)
        return client_reply_header(&request, &reply,
                                   RIN_ACCESSIBILITY_SERVICE_OP_QUERY, 0u);
    result = client_reply_header(&request, &reply,
                                 RIN_ACCESSIBILITY_SERVICE_OP_QUERY,
                                 sizeof(*snapshot_out));
    if (result != RIN_RESULT_OK) return result;
    if (!client_receive_exact(client->socket_fd, snapshot_out, sizeof(*snapshot_out)))
        return RIN_RESULT_IO;
    return RIN_RESULT_OK;
}

RinResultCode rin_accessibility_service_client_revoke(
    RinAccessibilityServiceClientV1* client)
{
    RinAccessibilityServiceMessageHeaderV1 request;
    RinAccessibilityServiceMessageHeaderV1 reply;
    RinResultCode result = client_next_header(
        client, RIN_ACCESSIBILITY_SERVICE_OP_REVOKE, 0u, &request);
    if (result != RIN_RESULT_OK) return result;
    if (!client_send_exact(client->socket_fd, &request, sizeof(request)) ||
        !client_receive_exact(client->socket_fd, &reply, sizeof(reply))) {
        return RIN_RESULT_IO;
    }
    return client_reply_header(&request, &reply,
                               RIN_ACCESSIBILITY_SERVICE_OP_REVOKE, 0u);
}

RinResultCode rin_accessibility_service_client_request_action(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityServiceActionV2* action)
{
    RinAccessibilityServiceMessageHeaderV1 request;
    RinAccessibilityServiceMessageHeaderV1 reply;
    RinResultCode result;
    if (action == NULL) return RIN_RESULT_INVALID_ARGUMENT;
    result = client_next_header(client, RIN_ACCESSIBILITY_SERVICE_OP_ACTION,
                                sizeof(*action), &request);
    if (result != RIN_RESULT_OK) return result;
    if (!client_send_exact(client->socket_fd, &request, sizeof(request)) ||
        !client_send_exact(client->socket_fd, action, sizeof(*action)) ||
        !client_receive_exact(client->socket_fd, &reply, sizeof(reply))) {
        return RIN_RESULT_IO;
    }
    return client_reply_header(&request, &reply,
                               RIN_ACCESSIBILITY_SERVICE_OP_ACTION, 0u);
}

RinResultCode rin_accessibility_service_client_receive_action(
    RinAccessibilityServiceClientV1* client, uint32_t timeout_ms,
    RinAccessibilityServiceActionV2* action_out)
{
    RinAccessibilityServiceMessageHeaderV1 request;
    RinResultCode result;
    if (client == NULL || action_out == NULL || client->socket_fd < 0 ||
        client->pending_service_action_id != 0u) return RIN_RESULT_INVALID_ARGUMENT;
    result = client_wait_readable(client->socket_fd, timeout_ms);
    if (result != RIN_RESULT_OK) return result;
    memset(&request, 0, sizeof(request));
    if (!client_receive_exact(client->socket_fd, &request, sizeof(request)) ||
        request.struct_size != sizeof(request) ||
        request.version != RIN_ACCESSIBILITY_SERVICE_ABI_VERSION ||
        request.opcode != RIN_ACCESSIBILITY_SERVICE_OP_ACTION ||
        request.request_id == 0u || request.payload_size != sizeof(*action_out) ||
        request.flags != 0u || request.status != 0 || request.reserved != 0u ||
        !client_receive_exact(client->socket_fd, action_out, sizeof(*action_out))) {
        return RIN_RESULT_CORRUPT_DATA;
    }
    client->pending_service_action_id = request.request_id;
    return RIN_RESULT_OK;
}

RinResultCode rin_accessibility_service_client_complete_action(
    RinAccessibilityServiceClientV1* client, RinResultCode action_status)
{
    RinAccessibilityServiceMessageHeaderV1 reply;
    if (client == NULL || client->socket_fd < 0 ||
        client->pending_service_action_id == 0u) return RIN_RESULT_INVALID_ARGUMENT;
    memset(&reply, 0, sizeof(reply));
    reply.struct_size = sizeof(reply);
    reply.version = RIN_ACCESSIBILITY_SERVICE_ABI_VERSION;
    reply.opcode = RIN_ACCESSIBILITY_SERVICE_OP_ACTION;
    reply.request_id = client->pending_service_action_id;
    reply.status = action_status;
    if (!client_send_exact(client->socket_fd, &reply, sizeof(reply)))
        return RIN_RESULT_IO;
    client->pending_service_action_id = 0u;
    return RIN_RESULT_OK;
}


