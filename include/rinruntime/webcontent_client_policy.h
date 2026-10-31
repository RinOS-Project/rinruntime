/* SPDX-License-Identifier: MIT */

#ifndef RIN_SHARED_WEBCONTENT_CLIENT_POLICY_H
#define RIN_SHARED_WEBCONTENT_CLIENT_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <rin/contract_abi.h>
#include <rin/web/webcontent_protocol.h>
#include "webcontent_tls_identity_owner_abi.h"
#include "webcontent_location_permission.h"
#include <rinruntime/text_codec.h>

#define RIN_WEBCONTENT_CLIENT_DIMENSION_MAX 16384u
#define RIN_WEBCONTENT_CLIENT_PAINT_BYTES_MAX UINT32_C(268435456)
#define RIN_WEBCONTENT_CLIENT_MARKUP_BYTES_MAX UINT32_C(67108864)

typedef enum RinWebContentClientValidation {
    RIN_WEBCONTENT_CLIENT_VALID = 0,
    RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL = 1,
    RIN_WEBCONTENT_CLIENT_INVALID_SIZE = 2
} RinWebContentClientValidation;

typedef enum RinWebContentClientPollDecision {
    RIN_WEBCONTENT_CLIENT_POLL_INVALID = 0,
    RIN_WEBCONTENT_CLIENT_POLL_READY = 1,
    RIN_WEBCONTENT_CLIENT_POLL_TERMINAL = 2
} RinWebContentClientPollDecision;

/* WebContent replies carry negative errno-style status values.  Keep the
 * conversion at the authenticated client boundary so callers can inspect
 * errno without losing the original service status returned by transact().
 * Unknown/out-of-range values fail closed as EIO. */
static inline int rin_webcontent_client_status_errno(int status)
{
    if (status == 0)
        return 0;
    if (status < 0 && status >= -4095)
        return -status;
    return EIO;
}

static inline RinWebContentClientPollDecision
rin_webcontent_client_poll_decide(uint16_t returned_events,
                                  uint16_t requested_events,
                                  uint16_t error_event,
                                  uint16_t hangup_event,
                                  uint16_t invalid_event)
{
    if ((returned_events & (uint16_t)(error_event | invalid_event)) != 0u)
        return RIN_WEBCONTENT_CLIENT_POLL_TERMINAL;
    if ((returned_events & requested_events) != 0u)
        return RIN_WEBCONTENT_CLIENT_POLL_READY;
    if ((returned_events & hangup_event) != 0u)
        return RIN_WEBCONTENT_CLIENT_POLL_TERMINAL;
    return RIN_WEBCONTENT_CLIENT_POLL_INVALID;
}

static inline int rin_webcontent_client_command_valid(uint32_t command)
{
    return (command >= RIN_WEBCONTENT_CMD_CREATE_PAGE_V1 &&
            command <= RIN_WEBCONTENT_CMD_REVOKE_LOCATION_V1) ||
           command == RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1;
}

/* Keep this declaration above the accessibility validators because the
 * validators are intentionally defined before the rest of the request
 * schemas.  The definition remains below with the other byte helpers. */
static inline int rin_webcontent_client_bytes_zero(const void* value,
                                                   size_t size);

static inline int rin_webcontent_accessibility_text_valid(
    const RinWebContentAccessibilityTextV1* text)
{
    if (text == NULL || text->reserved != 0u ||
        text->size > RIN_WEBCONTENT_ACCESSIBILITY_MAX_TEXT_BYTES ||
        !rin_webcontent_client_bytes_zero(text->bytes + text->size,
                                          sizeof(text->bytes) - text->size))
        return 0;
    return rinruntime_text_utf8_validate(text->bytes, text->size) ==
           RINRUNTIME_TEXT_CODEC_OK;
}

static inline int rin_webcontent_accessibility_range_valid(
    uint32_t start, uint32_t end, uint16_t value_size)
{
    return start <= end && end <= value_size;
}

static inline int rin_webcontent_accessibility_node_valid(
    const RinWebContentAccessibilityNodeV1* node)
{
    if (node == NULL || node->id == 0u ||
        node->role > RIN_WEBCONTENT_ACCESSIBILITY_ROLE_MAX ||
        node->reserved0 != 0u || (node->state & ~UINT32_C(0x000007ff)) != 0u ||
        (node->actions & ~UINT32_C(0x000007ff)) != 0u ||
        node->width < 0 || node->height < 0 ||
        !rin_webcontent_accessibility_text_valid(&node->name) ||
        !rin_webcontent_accessibility_text_valid(&node->description) ||
        !rin_webcontent_accessibility_text_valid(&node->value) ||
        !rin_webcontent_accessibility_range_valid(
            node->cursor_start, node->cursor_end, node->value.size) ||
        !rin_webcontent_accessibility_range_valid(
            node->selection_start, node->selection_end, node->value.size) ||
        !rin_webcontent_accessibility_range_valid(
            node->editable_start, node->editable_end, node->value.size) ||
        !rin_webcontent_client_bytes_zero(node->reserved,
                                          sizeof(node->reserved)))
        return 0;
    return 1;
}

static inline int rin_webcontent_client_accessibility_snapshot_valid(
    const RinWebContentAccessibilitySnapshotV1* snapshot,
    uint64_t expected_window)
{
    uint32_t index;
    if (snapshot == NULL || snapshot->struct_size != sizeof(*snapshot) ||
        snapshot->version != RIN_WEBCONTENT_VERSION || snapshot->flags != 0u ||
        snapshot->window != expected_window || snapshot->window == 0u ||
        snapshot->generation == 0u || snapshot->node_count == 0u ||
        snapshot->node_count > RIN_WEBCONTENT_ACCESSIBILITY_MAX_NODES ||
        snapshot->reserved0 != 0u)
        return 0;
    for (index = 0u; index < snapshot->node_count; ++index) {
        const RinWebContentAccessibilityNodeV1* node =
            &snapshot->nodes[index];
        uint32_t previous;
        int parent_found = index == 0u && node->parent_id == 0u;
        if (!rin_webcontent_accessibility_node_valid(node)) return 0;
        if (index > 0u && node->parent_id == 0u) return 0;
        for (previous = 0u; previous < index; ++previous) {
            if (snapshot->nodes[previous].id == node->id) return 0;
            if (snapshot->nodes[previous].id == node->parent_id)
                parent_found = 1;
        }
        if (!parent_found) return 0;
    }
    for (index = snapshot->node_count;
         index < RIN_WEBCONTENT_ACCESSIBILITY_MAX_NODES; ++index) {
        if (!rin_webcontent_client_bytes_zero(&snapshot->nodes[index],
                                              sizeof(snapshot->nodes[index])))
            return 0;
    }
    return 1;
}

static inline int rin_webcontent_client_accessibility_action_valid(
    const RinWebContentAccessibilityActionV1* action)
{
    const uint32_t known_actions =
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_FOCUS |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_ACTIVATE |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_SET_VALUE |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_INCREMENT |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_DECREMENT |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_EXPAND |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_COLLAPSE |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_SELECT |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_DISMISS |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_SCROLL_FORWARD |
        RIN_WEBCONTENT_ACCESSIBILITY_ACTION_SCROLL_BACKWARD;
    if (action == NULL || action->window == 0u || action->generation == 0u ||
        action->node_id == 0u || action->action == 0u ||
        (action->action & ~known_actions) != 0u ||
        (action->action & (action->action - 1u)) != 0u ||
        action->reserved0 != 0u ||
        action->reserved1 != 0u ||
        !rin_webcontent_accessibility_text_valid(&action->value) ||
        !rin_webcontent_client_bytes_zero(action->reserved,
                                          sizeof(action->reserved)))
        return 0;
    if (action->action != RIN_WEBCONTENT_ACCESSIBILITY_ACTION_SET_VALUE &&
        action->value.size != 0u)
        return 0;
    return 1;
}

static inline RinWebContentClientValidation
rin_webcontent_client_response_header_validate(
    const RinWebContentMsgHeader* header,
    uint32_t expected_command,
    uint32_t expected_page_id,
    uint32_t expected_payload_len)
{
    if (header == NULL ||
        !rin_webcontent_client_command_valid(expected_command) ||
        ((expected_command == RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1 ||
          expected_command == RIN_WEBCONTENT_CMD_OPEN_SERVICE_WORKER_OWNER_V1 ||
          expected_command == RIN_WEBCONTENT_CMD_SERIAL_PORTAL_V1 ||
          expected_command == RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1) !=
         (expected_page_id == 0u)) ||
        header->magic != RIN_WEBCONTENT_MAGIC ||
        header->version != RIN_WEBCONTENT_VERSION ||
        header->command != expected_command ||
        header->page_id != expected_page_id || header->reserved0 != 0u ||
        header->reserved1 != 0u || header->status > 0) {
        return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
    }

    if ((header->status == 0 &&
         header->payload_len != expected_payload_len) ||
        (header->status < 0 && header->payload_len != 0u)) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }
    return RIN_WEBCONTENT_CLIENT_VALID;
}

static inline int rin_webcontent_client_fixed_cstr_valid(const char* value,
                                                         size_t capacity)
{
    size_t index;
    if (value == NULL || capacity == 0u)
        return 0;
    for (index = 0u; index < capacity; ++index) {
        if (value[index] == '\0')
            return rinruntime_text_utf8_validate(
                       (const uint8_t*)value, index) == RINRUNTIME_TEXT_CODEC_OK;
    }
    return 0;
}

static inline int rin_webcontent_client_cache_fetch_policy_valid(uint32_t policy)
{
    if ((policy & ~(
            RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_CREDENTIALS_INCLUDE |
            RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_MODE_MASK)) != 0u)
        return 0;
    uint32_t modes = policy & RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_MODE_MASK;
    return modes == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_MODE_CORS ||
           modes == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_MODE_NO_CORS ||
           modes == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_CACHE_FETCH_POLICY_MODE_SAME_ORIGIN;
}

static inline int rin_webcontent_client_service_worker_owner_request_valid(
    const RinWebContentServiceWorkerOwnerRequestV1* request)
{
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        ((request->operation != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_AUTHORIZE_CACHE_FETCH &&
          request->operation != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COMMIT_REGISTER &&
          request->operation != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_ABORT_REGISTER &&
          request->operation != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_LIST &&
          request->update_via_cache > 2u) ||
         (request->operation == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_LIST &&
          request->update_via_cache > 256u) ||
         (request->operation == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_AUTHORIZE_CACHE_FETCH &&
          !rin_webcontent_client_cache_fetch_policy_valid(request->update_via_cache))) ||
        (request->flags & ~RIN_WEBCONTENT_SERVICE_WORKER_OWNER_FLAG_PRIVATE) != 0u ||
        request->reserved0 != 0u ||
        request->reserved1 != 0u ||
        !rin_webcontent_client_fixed_cstr_valid(request->client_url, sizeof(request->client_url)) ||
        !rin_webcontent_client_fixed_cstr_valid(request->origin, sizeof(request->origin)) ||
        !rin_webcontent_client_fixed_cstr_valid(request->script_url, sizeof(request->script_url)) ||
        !rin_webcontent_client_fixed_cstr_valid(request->scope, sizeof(request->scope)) ||
        (request->operation == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_LIST
             ? request->reserved[1] == 0u
             : request->reserved[0] != 0u))
        return 0;

    switch (request->operation) {
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_REGISTER:
        return request->client_url[0] != '\0' && request->origin[0] == '\0' &&
               request->script_url[0] != '\0' && request->scope[0] != '\0' &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COMMIT_REGISTER:
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_ABORT_REGISTER:
        return request->client_url[0] == '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] != '\0' &&
               request->update_via_cache != 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_MATCH:
        return request->client_url[0] != '\0' && request->origin[0] == '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_LIST:
        return request->client_url[0] != '\0' && request->origin[0] == '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->flags == 0u &&
               request->reserved[1] != 0u &&
               ((request->reserved[0] == 0u && request->update_via_cache == 0u) ||
                (request->reserved[0] != 0u && request->update_via_cache != 0u));
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_UNREGISTER:
        return request->client_url[0] == '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] != '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_AUTHORIZE_CACHE:
        return request->client_url[0] == '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] != '\0' &&
               request->update_via_cache == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_AUTHORIZE_CACHE_FETCH:
        return request->client_url[0] != '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->flags == 0u && request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_QUERY_NOTIFICATION_PERMISSION:
        return request->client_url[0] != '\0' && request->origin[0] == '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_SHOW_NOTIFICATION:
        return request->client_url[0] != '\0' && request->origin[0] == '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RETIRE_DOCUMENT:
        return request->client_url[0] == '\0' && request->origin[0] == '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_REGISTER_DOCUMENT:
        return request->client_url[0] == '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] == '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_BEGIN_CACHE_BATCH:
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COMMIT_CACHE_BATCH:
    case RIN_WEBCONTENT_SERVICE_WORKER_OWNER_ABORT_CACHE_BATCH:
        return request->client_url[0] == '\0' && request->origin[0] != '\0' &&
               request->script_url[0] == '\0' && request->scope[0] != '\0' &&
               request->update_via_cache == 0u && request->flags == 0u &&
               request->reserved[1] != 0u;
    default:
        return 0;
    }
}

static inline int rin_webcontent_client_cache_storage_owner_request_valid(
    const RinWebContentCacheStorageOwnerRequestV1* request,
    const void* trailing_data,
    size_t trailing_size)
{
    size_t expected_size;
    const uint8_t* bytes = (const uint8_t*)trailing_data;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        (request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_SET &&
         request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_REMOVE &&
         request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_SET_CACHE_NAME &&
         request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_REMOVE_CACHE_NAME &&
         request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_READ_SNAPSHOT &&
         request->operation != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_INITIALIZE) ||
        request->owner_generation == 0u || request->origin_size == 0u ||
        request->origin_size >= RIN_WEBCONTENT_URL_MAX ||
        request->reserved[0] == 0u || request->reserved[1] == 0u ||
        request->reserved[1] >= RIN_WEBCONTENT_URL_MAX ||
        request->key_size > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_KEY_BYTES ||
        request->value_size > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_VALUE_BYTES ||
        request->reserved0 != 0u)
        return 0;
    if (request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_READ_SNAPSHOT ||
        request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_INITIALIZE) {
        if (request->key_size != 0u || request->value_size != 0u)
            return 0;
    } else if (request->key_size == 0u) {
        return 0;
    }
    if ((request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_SET &&
         request->value_size == 0u) ||
        (request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_SET_CACHE_NAME &&
         request->value_size == 0u) ||
        (request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_REMOVE &&
         request->value_size != 0u) ||
        (request->operation == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_REMOVE_CACHE_NAME &&
         request->value_size != 0u))
        return 0;
    expected_size = (size_t)request->origin_size +
        (size_t)request->reserved[1] + request->key_size + request->value_size;
    if (expected_size != trailing_size || (trailing_size != 0u && bytes == NULL))
        return 0;
    for (size_t index = 0u; index < trailing_size; ++index)
        if (bytes[index] == 0u)
            return 0;
    if (rinruntime_text_utf8_validate(bytes, request->origin_size) !=
            RINRUNTIME_TEXT_CODEC_OK ||
        rinruntime_text_utf8_validate(bytes + request->origin_size,
                                      (size_t)request->reserved[1]) !=
            RINRUNTIME_TEXT_CODEC_OK ||
        rinruntime_text_utf8_validate(bytes + request->origin_size +
                                      (size_t)request->reserved[1],
                                      request->key_size) !=
            RINRUNTIME_TEXT_CODEC_OK ||
        (request->value_size != 0u &&
         rinruntime_text_utf8_validate(bytes + request->origin_size +
                                           (size_t)request->reserved[1] + request->key_size,
                                       request->value_size) != RINRUNTIME_TEXT_CODEC_OK))
        return 0;
    return 1;
}

static inline int rin_webcontent_client_http_cookie_owner_request_valid(
    const RinWebContentHttpCookieOwnerRequestV1* request,
    const void* trailing_data,
    size_t trailing_size)
{
    const uint8_t* bytes = (const uint8_t*)trailing_data;
    size_t expected_size;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        (request->operation != RIN_WEBCONTENT_HTTP_COOKIE_OWNER_GET_HEADER &&
         request->operation != RIN_WEBCONTENT_HTTP_COOKIE_OWNER_COMMIT_SET_COOKIE) ||
        (request->policy & ~RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_POLICY_MASK) != 0u ||
        request->origin_size == 0u || request->origin_size >= RIN_WEBCONTENT_URL_MAX ||
        request->request_url_size == 0u || request->request_url_size >= RIN_WEBCONTENT_URL_MAX ||
        request->cookie_data_size > RIN_WEBCONTENT_HTTP_COOKIE_OWNER_MAX_DATA_BYTES ||
        request->reserved0 != 0u || request->reserved1 != 0u ||
        !rin_webcontent_client_bytes_zero(request->reserved, sizeof(request->reserved)))
        return 0;
    if (request->cookie_data_size == 0u)
        return 0;
    if ((request->policy &
         RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_CREDENTIALS_INCLUDE) == 0u)
        return 0;
    if (request->operation == RIN_WEBCONTENT_HTTP_COOKIE_OWNER_GET_HEADER) {
        if (request->policy !=
            RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_CREDENTIALS_INCLUDE)
            return 0;
    } else {
        const uint32_t mode = request->policy &
            RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_MASK;
        if ((mode != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_CORS &&
             mode != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_NO_CORS &&
             mode != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_SAME_ORIGIN &&
             mode != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_NAVIGATE) ||
            (mode == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_MODE_CORS &&
             (request->policy &
              RIN_WEBCONTENT_SERVICE_WORKER_OWNER_COOKIE_CORS_VALIDATED) == 0u))
            return 0;
    }
    expected_size = (size_t)request->origin_size + request->request_url_size +
        request->cookie_data_size;
    if (expected_size != trailing_size || (trailing_size != 0u && bytes == NULL))
        return 0;
    for (size_t index = 0u; index < trailing_size; ++index)
        if (bytes[index] == 0u)
            return 0;
    if (rinruntime_text_utf8_validate(bytes, request->origin_size) !=
            RINRUNTIME_TEXT_CODEC_OK ||
        rinruntime_text_utf8_validate(bytes + request->origin_size,
                                      request->request_url_size) !=
            RINRUNTIME_TEXT_CODEC_OK ||
        (request->cookie_data_size != 0u &&
         rinruntime_text_utf8_validate(
             bytes + request->origin_size + request->request_url_size,
             request->cookie_data_size) != RINRUNTIME_TEXT_CODEC_OK))
        return 0;
    return 1;
}

static inline int rin_webcontent_client_http_cookie_owner_response_valid(
    const RinWebContentHttpCookieOwnerResponseV1* response)
{
    return response != NULL && response->struct_size == sizeof(*response) &&
        response->version == RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
        (response->result == RIN_WEBCONTENT_HTTP_COOKIE_OWNER_RESULT_REJECTED ||
         response->result == RIN_WEBCONTENT_HTTP_COOKIE_OWNER_RESULT_COMMITTED) &&
        (response->result != RIN_WEBCONTENT_HTTP_COOKIE_OWNER_RESULT_COMMITTED ||
         response->generation != 0u) &&
        (response->result != RIN_WEBCONTENT_HTTP_COOKIE_OWNER_RESULT_REJECTED ||
         (response->generation == 0u && response->data_size == 0u)) &&
        response->data_size <= RIN_WEBCONTENT_HTTP_COOKIE_OWNER_MAX_DATA_BYTES;
}

static inline int rin_webcontent_client_cache_storage_owner_response_valid(
    const RinWebContentCacheStorageOwnerResponseV1* response)
{
    return response != NULL && response->struct_size == sizeof(*response) &&
        response->version == RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
        (response->result == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_RESULT_REJECTED ||
         response->result == RIN_WEBCONTENT_CACHE_STORAGE_OWNER_RESULT_COMMITTED) &&
        (response->result != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_RESULT_COMMITTED ||
         response->owner_generation != 0u) &&
        (response->result != RIN_WEBCONTENT_CACHE_STORAGE_OWNER_RESULT_REJECTED ||
         response->reserved == 0u) &&
        response->reserved <=
            RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_SNAPSHOT_BYTES;
}

static inline uint16_t rin_webcontent_client_cache_snapshot_read_u16(
    const uint8_t* bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8u));
}

static inline uint32_t rin_webcontent_client_cache_snapshot_read_u32(
    const uint8_t* bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8u) |
           ((uint32_t)bytes[2] << 16u) | ((uint32_t)bytes[3] << 24u);
}

static inline uint32_t rin_webcontent_client_cache_snapshot_crc32(
    const uint8_t* bytes, size_t size)
{
    uint32_t crc = UINT32_C(0xffffffff);
    for (size_t index = 0u; index < size; ++index) {
        crc ^= bytes[index];
        for (unsigned bit = 0u; bit < 8u; ++bit)
            crc = (crc >> 1u) ^
                  (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}

/* RCS1 contains an origin-filtered list of CacheStorage bottle key/value
 * records. Validate framing, UTF-8, limits, and CRC before replacing any
 * WebContent storage rows. */
static inline int rin_webcontent_client_cache_storage_snapshot_valid(
    const void* snapshot_data, size_t snapshot_size,
    uint32_t* record_count_out, int* owner_initialized_out)
{
    const uint8_t* bytes = (const uint8_t*)snapshot_data;
    if (record_count_out != NULL)
        *record_count_out = 0u;
    if (owner_initialized_out != NULL)
        *owner_initialized_out = 0;
    if (bytes == NULL || snapshot_size < 20u ||
        snapshot_size > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_SNAPSHOT_BYTES ||
        memcmp(bytes, "RCS1", 4u) != 0 ||
        rin_webcontent_client_cache_snapshot_read_u16(bytes + 4u) != 1u)
        return 0;

    const uint16_t flags = rin_webcontent_client_cache_snapshot_read_u16(bytes + 6u);
    const uint32_t record_count = rin_webcontent_client_cache_snapshot_read_u32(bytes + 8u);
    const uint32_t body_size = rin_webcontent_client_cache_snapshot_read_u32(bytes + 12u);
    const uint32_t expected_crc = rin_webcontent_client_cache_snapshot_read_u32(bytes + 16u);
    if ((flags & ~UINT16_C(1)) != 0u ||
        record_count > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_RECORDS ||
        body_size != snapshot_size - 20u ||
        rin_webcontent_client_cache_snapshot_crc32(bytes + 20u, body_size) != expected_crc)
        return 0;

    size_t offset = 20u;
    for (uint32_t index = 0u; index < record_count; ++index) {
        if (snapshot_size - offset < 8u)
            return 0;
        const uint32_t key_size = rin_webcontent_client_cache_snapshot_read_u32(bytes + offset);
        const uint32_t value_size = rin_webcontent_client_cache_snapshot_read_u32(bytes + offset + 4u);
        offset += 8u;
        if (key_size == 0u ||
            key_size > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_KEY_BYTES ||
            value_size == 0u ||
            value_size > RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_VALUE_BYTES ||
            (size_t)key_size > snapshot_size - offset ||
            (size_t)value_size > snapshot_size - offset - key_size)
            return 0;
        for (size_t byte_index = 0u; byte_index < (size_t)key_size + value_size; ++byte_index)
            if (bytes[offset + byte_index] == 0u)
                return 0;
        if (rinruntime_text_utf8_validate(bytes + offset, key_size) !=
                RINRUNTIME_TEXT_CODEC_OK ||
            rinruntime_text_utf8_validate(bytes + offset + key_size, value_size) !=
                RINRUNTIME_TEXT_CODEC_OK)
            return 0;
        offset += (size_t)key_size + value_size;
    }
    if (offset != snapshot_size)
        return 0;
    if (record_count_out != NULL)
        *record_count_out = record_count;
    if (owner_initialized_out != NULL)
        *owner_initialized_out = (flags & 1u) != 0u;
    return 1;
}

static inline int rin_webcontent_client_service_worker_owner_response_valid(
    const RinWebContentServiceWorkerOwnerResponseV1* response)
{
    if (response == NULL || response->struct_size != sizeof(*response) ||
        response->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        response->update_via_cache > 2u || response->state > 3u ||
        !rin_webcontent_client_fixed_cstr_valid(response->origin, sizeof(response->origin)) ||
        !rin_webcontent_client_fixed_cstr_valid(response->script_url, sizeof(response->script_url)) ||
        !rin_webcontent_client_fixed_cstr_valid(response->scope, sizeof(response->scope)) ||
        response->reserved[1] > 256u)
        return 0;

    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_REJECTED)
        return response->generation == 0u && response->state == 0u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] == '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_NOT_FOUND)
        return response->generation == 0u && response->state == 0u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] == '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_LIST_DONE)
        return response->generation == 0u && response->state == 0u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] == '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_PERMISSION)
        return response->generation != 0u && response->state <= 2u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] != '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_NOTIFICATION_POSTED)
        return response->generation != 0u && response->state == 0u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] != '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_CONTEXT_UPDATED)
        return response->generation != 0u && response->state == 0u &&
               response->update_via_cache == 0u &&
               response->reserved[0] == 0u && response->reserved[1] == 0u &&
               response->origin[0] == '\0' && response->script_url[0] == '\0' &&
               response->scope[0] == '\0';
    if (response->result == RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_LIST_ITEM)
        return response->generation != 0u && response->state <= 2u &&
               response->update_via_cache <= 2u && response->reserved[0] != 0u &&
               response->reserved[1] != 0u &&
               response->origin[0] != '\0' && response->script_url[0] != '\0' &&
               response->scope[0] != '\0';
    if (response->result != RIN_WEBCONTENT_SERVICE_WORKER_OWNER_RESULT_COMMITTED)
        return 0;
    return response->generation != 0u && response->reserved[0] == 0u &&
           response->reserved[1] == 0u && response->origin[0] != '\0' &&
           response->script_url[0] != '\0' && response->scope[0] != '\0';
}

static inline int rin_webcontent_client_bounded_cstr_length(
    const char* value,
    size_t capacity,
    int allow_empty,
    int reject_controls,
    size_t* out_length)
{
    size_t index;
    if (value == NULL || capacity == 0u || out_length == NULL)
        return 0;
    for (index = 0u; index < capacity; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (byte == 0u) {
            if (!allow_empty && index == 0u)
                return 0;
            if (rinruntime_text_utf8_validate(
                    (const uint8_t*)value, index) != RINRUNTIME_TEXT_CODEC_OK)
                return 0;
            *out_length = index;
            return 1;
        }
        if (reject_controls && (byte < 0x20u || byte == 0x7fu))
            return 0;
    }
    return 0;
}

static inline int rin_webcontent_client_url_valid(const char* value)
{
    size_t length = 0u;
    return rin_webcontent_client_bounded_cstr_length(
        value, RIN_WEBCONTENT_URL_MAX, 0, 1, &length);
}

static inline int rin_webcontent_client_text_valid(const char* value)
{
    size_t length = 0u;
    return rin_webcontent_client_bounded_cstr_length(
        value, RIN_WEBCONTENT_TEXT_MAX, 1, 0, &length);
}

static inline int rin_webcontent_client_markup_length(const char* markup,
                                                       size_t* out_length)
{
    return rin_webcontent_client_bounded_cstr_length(
        markup, (size_t)RIN_WEBCONTENT_CLIENT_MARKUP_BYTES_MAX + 1u,
        1, 0, out_length);
}

static inline int rin_webcontent_client_dimensions_valid(uint32_t width,
                                                         uint32_t height)
{
    return width != 0u && height != 0u &&
           width <= RIN_WEBCONTENT_CLIENT_DIMENSION_MAX &&
           height <= RIN_WEBCONTENT_CLIENT_DIMENSION_MAX;
}

static inline int rin_webcontent_client_bytes_zero(const void* value,
                                                   size_t size)
{
    const unsigned char* bytes = (const unsigned char*)value;
    unsigned char combined = 0u;
    size_t index;
    if (value == NULL && size != 0u)
        return 0;
    for (index = 0u; index < size; ++index)
        combined = (unsigned char)(combined | bytes[index]);
    return combined == 0u;
}

static inline int rin_webcontent_client_capabilities_valid(
    const RinWebContentCapabilitiesV1* capabilities)
{
    int has_webauthn;
    const uint64_t known_capabilities =
        RIN_WEBCONTENT_CAPABILITY_WEBAUTHN_V1 |
        RIN_WEBCONTENT_CAPABILITY_PERMISSIONS_V1 |
        RIN_WEBCONTENT_CAPABILITY_SERVICE_WORKER_OWNER_V1 |
        RIN_WEBCONTENT_CAPABILITY_SERIAL_PORTAL_V1 |
        RIN_WEBCONTENT_CAPABILITY_CAMERA_CAPTURE_OWNER_V1;
    if (capabilities == NULL ||
        capabilities->struct_size != sizeof(*capabilities) ||
        capabilities->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        capabilities->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(capabilities->reserved,
                                          sizeof(capabilities->reserved)) ||
        (capabilities->capabilities & ~known_capabilities) != 0u)
        return 0;
    has_webauthn =
        (capabilities->capabilities &
         RIN_WEBCONTENT_CAPABILITY_WEBAUTHN_V1) != 0u;
    if (!has_webauthn)
        return capabilities->webauthn_min_version == 0u &&
               capabilities->webauthn_max_version == 0u;
    return capabilities->webauthn_min_version != 0u &&
           capabilities->webauthn_min_version <=
               RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
           capabilities->webauthn_max_version >=
               RIN_WEBCONTENT_EXTENSION_ABI_VERSION;
}

static inline int rin_webcontent_client_webauthn_poll_valid(
    const RinWebContentWebAuthnPollV1* poll)
{
    return poll != NULL && poll->struct_size == sizeof(*poll) &&
           poll->version == RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
           poll->flags == 0u && poll->navigation_generation != 0u &&
           poll->reserved0 == 0u &&
           rin_webcontent_client_bytes_zero(poll->reserved,
                                            sizeof(poll->reserved));
}

static inline int rin_webcontent_client_webauthn_event_valid(
    const RinWebContentWebAuthnEventV1* event)
{
    const uint32_t known_flags =
        RIN_WEBCONTENT_WEBAUTHN_FLAG_CROSS_ORIGIN |
        RIN_WEBCONTENT_WEBAUTHN_FLAG_PERMISSIONS_POLICY_ALLOWED |
        RIN_WEBCONTENT_WEBAUTHN_FLAG_ANCESTORS_VALIDATED;
    size_t rp_id_size = 0u;
    uint16_t expected_operation;
    if (event == NULL || event->struct_size != sizeof(*event) ||
        event->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        event->request_id == 0u || event->navigation_generation == 0u ||
        !rin_webcontent_client_bytes_zero(event->reserved,
                                          sizeof(event->reserved)))
        return 0;
    if (event->event == RIN_WEBCONTENT_WEBAUTHN_EVENT_CANCEL) {
        return event->operation == 0u && event->timeout_ms == 0u &&
               event->flags == 0u &&
               rin_webcontent_client_bytes_zero(
                   event->document_url, sizeof(event->document_url)) &&
               rin_webcontent_client_bytes_zero(event->rp_id,
                                                 sizeof(event->rp_id)) &&
               rin_webcontent_client_bytes_zero(&event->request,
                                                 sizeof(event->request));
    }
    if (event->event != RIN_WEBCONTENT_WEBAUTHN_EVENT_BEGIN ||
        (event->flags & ~known_flags) != 0u || event->timeout_ms == 0u ||
        event->timeout_ms > RIN_WEBCONTENT_WEBAUTHN_TIMEOUT_MAX_MS ||
        !rin_webcontent_client_url_valid(event->document_url) ||
        !rin_webcontent_client_bounded_cstr_length(
            event->rp_id, sizeof(event->rp_id), 0, 1, &rp_id_size))
        return 0;
    if (event->operation == RIN_PASS_OPERATION_WEBAUTHN_CREATE)
        expected_operation = RIN_PASS_OPERATION_WEBAUTHN_CREATE;
    else if (event->operation == RIN_PASS_OPERATION_WEBAUTHN_GET)
        expected_operation = RIN_PASS_OPERATION_WEBAUTHN_GET;
    else
        return 0;
    if (event->request.struct_size != sizeof(event->request) ||
        event->request.version != RIN_PASS_ABI_VERSION ||
        event->request.operation != expected_operation ||
        event->request.rp_id_size != rp_id_size ||
        event->request.rp_id_size > RIN_PASS_WEBAUTHN_RP_ID_MAX ||
        memcmp(event->request.rp_id, event->rp_id, rp_id_size) != 0 ||
        !rin_webcontent_client_bytes_zero(
            event->request.rp_id + rp_id_size,
            sizeof(event->request.rp_id) - rp_id_size) ||
        event->request.credential_count >
            RIN_PASS_WEBAUTHN_MAX_CREDENTIALS ||
        event->request.algorithm_count > 8u ||
        event->request.reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(event->request.reserved,
                                          sizeof(event->request.reserved)))
        return 0;
    return ((event->request.flags & RIN_PASS_WEBAUTHN_FLAG_CROSS_ORIGIN) !=
            0u) ==
           ((event->flags & RIN_WEBCONTENT_WEBAUTHN_FLAG_CROSS_ORIGIN) !=
            0u);
}

/*
 * A successful poll is not merely a well-formed event: it must advance the
 * cursor the caller supplied and remain within the same navigation.  Keep
 * this replay/order rule next to the wire validation so every client uses the
 * same fail-closed decision.
 */
static inline int rin_webcontent_client_webauthn_poll_response_valid(
    const RinWebContentWebAuthnEventV1* event,
    uint32_t expected_navigation_generation,
    uint64_t after_request_id)
{
    return expected_navigation_generation != 0u &&
           rin_webcontent_client_webauthn_event_valid(event) &&
           event->navigation_generation == expected_navigation_generation &&
           event->request_id > after_request_id;
}

static inline int rin_webcontent_client_webauthn_complete_valid(
    const RinWebContentWebAuthnCompleteV1* completion)
{
    RinPassWebAuthnResultHeaderV1 header;
    const uint8_t* authenticator_data;
    uint64_t expected_size;
    uint32_t sign_count;
    uint32_t authenticator_offset;
    uint8_t authenticator_flags;
    const uint32_t known_result_flags =
        RIN_PASS_WEBAUTHN_RESULT_FLAG_UP |
        RIN_PASS_WEBAUTHN_RESULT_FLAG_UV |
        RIN_PASS_WEBAUTHN_RESULT_FLAG_USER_SELECTED |
        RIN_PASS_WEBAUTHN_RESULT_FLAG_ATTESTATION_NONE;
    if (completion == NULL ||
        completion->struct_size != sizeof(*completion) ||
        completion->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        completion->reserved0 != 0u || completion->flags != 0u ||
        completion->request_id == 0u ||
        completion->navigation_generation == 0u ||
        !rin_webcontent_client_bytes_zero(completion->reserved,
                                          sizeof(completion->reserved)))
        return 0;
    if (completion->result < RIN_RESULT_OK) {
        if (completion->result < RIN_RESULT_DEVICE_LOST)
            return 0;
        return completion->result_stream_size == 0u &&
               rin_webcontent_client_bytes_zero(
                   completion->result_stream,
                   sizeof(completion->result_stream));
    }
    if (completion->result != RIN_RESULT_OK ||
        completion->result_stream_size < sizeof(header) ||
        completion->result_stream_size >
            RIN_PASS_WEBAUTHN_RESULT_STREAM_MAX)
        return 0;
    memcpy(&header, completion->result_stream, sizeof(header));
    expected_size = sizeof(header) + (uint64_t)header.credential_id_size +
                    (uint64_t)header.authenticator_data_size +
                    (uint64_t)header.signature_size +
                    (uint64_t)header.user_id_size;
    if (header.struct_size != sizeof(header) ||
        header.version != RIN_PASS_ABI_VERSION ||
        (header.kind != RIN_PASS_RESULT_KIND_WEBAUTHN_CREATE &&
         header.kind != RIN_PASS_RESULT_KIND_WEBAUTHN_GET) ||
        (header.flags & ~known_result_flags) != 0u ||
        (header.transport != RIN_PASS_WEBAUTHN_RESULT_TRANSPORT_INTERNAL &&
         header.transport != RIN_PASS_WEBAUTHN_RESULT_TRANSPORT_USB) ||
        header.credential_id_size == 0u ||
        header.credential_id_size > RIN_PASS_WEBAUTHN_MAX_CREDENTIAL_ID ||
        header.authenticator_data_size < 37u ||
        header.authenticator_data_size >
            RIN_WEBCONTENT_WEBAUTHN_AUTHENTICATOR_DATA_MAX ||
        header.signature_size > RIN_WEBCONTENT_WEBAUTHN_SIGNATURE_MAX ||
        header.user_id_size > RIN_PASS_WEBAUTHN_USER_ID_MAX ||
        header.total_size != completion->result_stream_size ||
        expected_size != completion->result_stream_size ||
        header.reserved != 0u)
        return 0;
    if (header.kind == RIN_PASS_RESULT_KIND_WEBAUTHN_CREATE) {
        if ((header.flags &
             RIN_PASS_WEBAUTHN_RESULT_FLAG_ATTESTATION_NONE) == 0u ||
            (header.flags &
             RIN_PASS_WEBAUTHN_RESULT_FLAG_USER_SELECTED) != 0u ||
            header.signature_size != 0u || header.user_id_size != 0u)
            return 0;
    } else if ((header.flags &
                RIN_PASS_WEBAUTHN_RESULT_FLAG_ATTESTATION_NONE) != 0u ||
               header.signature_size == 0u) {
        return 0;
    }
    authenticator_offset =
        (uint32_t)sizeof(header) + header.credential_id_size;
    authenticator_data =
        completion->result_stream + authenticator_offset;
    authenticator_flags = authenticator_data[32u];
    sign_count = ((uint32_t)authenticator_data[33u] << 24u) |
                 ((uint32_t)authenticator_data[34u] << 16u) |
                 ((uint32_t)authenticator_data[35u] << 8u) |
                 (uint32_t)authenticator_data[36u];
    if ((authenticator_flags & 0x01u) == 0u ||
        (((authenticator_flags & 0x04u) != 0u) !=
         ((header.flags & RIN_PASS_WEBAUTHN_RESULT_FLAG_UV) != 0u)) ||
        sign_count != header.sign_count ||
        (header.kind == RIN_PASS_RESULT_KIND_WEBAUTHN_CREATE &&
         (authenticator_flags & 0x40u) == 0u) ||
        (header.kind == RIN_PASS_RESULT_KIND_WEBAUTHN_GET &&
         (authenticator_flags & 0x40u) != 0u))
        return 0;
    return rin_webcontent_client_bytes_zero(
        completion->result_stream + completion->result_stream_size,
        sizeof(completion->result_stream) - completion->result_stream_size);
}

static inline int rin_webcontent_client_file_picker_complete_valid(
    const RinWebContentFilePickerCompleteV1* completion)
{
    size_t index;
    if (completion == NULL ||
        completion->struct_size != sizeof(*completion) ||
        completion->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        completion->reserved0 != 0u || completion->reserved1 != 0u ||
        completion->request_id == 0u ||
        completion->display_name_size > RIN_WEBCONTENT_FILE_PICKER_NAME_MAX ||
        !rin_webcontent_client_bytes_zero(completion->reserved,
                                          sizeof(completion->reserved)))
        return 0;

    if (completion->result == RIN_WEBCONTENT_FILE_PICKER_RESULT_CANCELLED) {
        return completion->flags == 0u && completion->display_name_size == 0u &&
               rin_webcontent_client_bytes_zero(completion->display_name,
                                                sizeof(completion->display_name));
    }
    if (completion->result != RIN_WEBCONTENT_FILE_PICKER_RESULT_OK ||
        completion->flags != RIN_WEBCONTENT_FILE_PICKER_FLAG_HAS_DESCRIPTOR ||
        completion->display_name_size == 0u)
        return 0;
    if (rinruntime_text_utf8_validate(
            (const uint8_t*)completion->display_name,
            completion->display_name_size) != RINRUNTIME_TEXT_CODEC_OK)
        return 0;
    for (index = 0u; index < completion->display_name_size; ++index) {
        unsigned char byte = (unsigned char)completion->display_name[index];
        if (byte < 0x20u || byte == 0x7fu || byte == '/' || byte == '\\')
            return 0;
    }
    return rin_webcontent_client_bytes_zero(
        completion->display_name + completion->display_name_size,
        sizeof(completion->display_name) - completion->display_name_size);
}

static inline int rin_webcontent_client_download_event_request_valid(
    const RinWebContentDownloadEventRequestV1* request)
{
    return request != NULL && request->struct_size == sizeof(*request) &&
           request->version == RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
           request->reserved0 == 0u && request->reserved1 == 0u;
}

static inline int rin_webcontent_client_permission_type_valid(const char* value)
{
    size_t length = 0u;
    size_t index;
    if (!rin_webcontent_client_bounded_cstr_length(
            value, RIN_WEBCONTENT_PERMISSION_TYPE_MAX, 0, 1, &length))
        return 0;
    for (index = 0u; index < length; ++index) {
        unsigned char byte = (unsigned char)value[index];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'_' || byte == (unsigned char)'-'))
            return 0;
    }
    return 1;
}

static inline int rin_webcontent_client_permission_description_valid(
    const char* value)
{
    size_t length = 0u;
    return rin_webcontent_client_bounded_cstr_length(
        value, RIN_WEBCONTENT_PERMISSION_DESCRIPTION_MAX, 1, 0, &length);
}

static inline int rin_webcontent_client_permission_poll_valid(
    const RinWebContentPermissionPollV1* request,
    uint32_t expected_navigation_generation)
{
    return request != NULL && request->struct_size == sizeof(*request) &&
           request->version == RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION &&
           request->flags == 0u && request->navigation_generation != 0u &&
           request->navigation_generation == expected_navigation_generation &&
           rin_webcontent_client_bytes_zero(request->reserved,
                                            sizeof(request->reserved));
}

static inline int rin_webcontent_client_permission_event_valid(
    const RinWebContentPermissionEventV1* event,
    uint32_t expected_navigation_generation, uint64_t after_request_id)
{
    if (event == NULL || event->struct_size != sizeof(*event) ||
        event->version != RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION ||
        event->flags != 0u ||
        event->navigation_generation != expected_navigation_generation ||
        !rin_webcontent_client_bytes_zero(event->reserved,
                                          sizeof(event->reserved)))
        return 0;
    if (event->event == RIN_WEBCONTENT_PERMISSION_EVENT_NONE) {
        return event->request_id == 0u &&
               rin_webcontent_client_bytes_zero(event->permission_type,
                                                sizeof(event->permission_type)) &&
               rin_webcontent_client_bytes_zero(event->origin,
                                                sizeof(event->origin)) &&
               rin_webcontent_client_bytes_zero(event->description,
                                                sizeof(event->description));
    }
    if (event->event != RIN_WEBCONTENT_PERMISSION_EVENT_REQUEST &&
        event->event != RIN_WEBCONTENT_PERMISSION_EVENT_CANCEL)
        return 0;
    if (event->request_id == 0u || event->request_id <= after_request_id)
        return 0;
    if (event->event == RIN_WEBCONTENT_PERMISSION_EVENT_CANCEL) {
        const int legacy_empty_type = rin_webcontent_client_bytes_zero(
            event->permission_type, sizeof(event->permission_type));
        return (legacy_empty_type ||
                rin_webcontent_client_permission_type_valid(
                    event->permission_type)) &&
               rin_webcontent_client_bytes_zero(event->origin,
                                                sizeof(event->origin)) &&
               rin_webcontent_client_bytes_zero(event->description,
                                                sizeof(event->description));
    }
    return rin_webcontent_client_permission_type_valid(event->permission_type) &&
           rin_webcontent_client_url_valid(event->origin) &&
           rin_webcontent_client_permission_description_valid(event->description);
}

static inline int rin_webcontent_client_permission_complete_valid(
    const RinWebContentPermissionCompleteV1* completion)
{
    return completion != NULL && completion->struct_size == sizeof(*completion) &&
           completion->version == RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION &&
           completion->reserved0 == 0u && completion->reserved1 == 0u &&
           completion->reserved2 == 0u && completion->request_id != 0u &&
           completion->navigation_generation != 0u &&
           completion->result >= RIN_WEBCONTENT_PERMISSION_RESULT_DENIED &&
           completion->result <= RIN_WEBCONTENT_PERMISSION_RESULT_CANCELLED &&
           rin_webcontent_client_bytes_zero(completion->reserved,
                                            sizeof(completion->reserved));
}

static inline int rin_webcontent_client_file_picker_complete_multiple_valid(
    const RinWebContentFilePickerCompleteV2* completion)
{
    size_t index;
    if (completion == NULL ||
        completion->struct_size != sizeof(*completion) ||
        completion->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        completion->flags != 0u || completion->reserved0 != 0u ||
        completion->reserved1 != 0u || completion->request_id == 0u ||
        completion->selection_count > RIN_WEBCONTENT_FILE_PICKER_MAX_SELECTIONS ||
        !rin_webcontent_client_bytes_zero(completion->reserved,
                                          sizeof(completion->reserved)))
        return 0;
    if (completion->result == RIN_WEBCONTENT_FILE_PICKER_RESULT_CANCELLED) {
        if (completion->selection_count != 0u)
            return 0;
        return rin_webcontent_client_bytes_zero(
            completion->selections, sizeof(completion->selections));
    }
    if (completion->result != RIN_WEBCONTENT_FILE_PICKER_RESULT_OK ||
        completion->selection_count == 0u)
        return 0;
    for (index = 0u; index < RIN_WEBCONTENT_FILE_PICKER_MAX_SELECTIONS;
         ++index) {
        const RinWebContentFilePickerSelectionV2* selection =
            &completion->selections[index];
        if (selection->reserved != 0u ||
            selection->display_name_size == 0u ||
            selection->display_name_size > RIN_WEBCONTENT_FILE_PICKER_NAME_MAX) {
            if (index < completion->selection_count)
                return 0;
            if (!rin_webcontent_client_bytes_zero(
                    selection, sizeof(*selection)))
                return 0;
            continue;
        }
        if (rinruntime_text_utf8_validate(
                (const uint8_t*)selection->display_name,
                selection->display_name_size) != RINRUNTIME_TEXT_CODEC_OK)
            return 0;
        for (size_t byte_index = 0u;
             byte_index < selection->display_name_size; ++byte_index) {
            unsigned char byte =
                (unsigned char)selection->display_name[byte_index];
            if (byte < 0x20u || byte == 0x7fu || byte == '/' || byte == '\\')
                return 0;
        }
        if (!rin_webcontent_client_bytes_zero(
                selection->display_name + selection->display_name_size,
                sizeof(selection->display_name) - selection->display_name_size))
            return 0;
    }
    return 1;
}

static inline int rin_webcontent_client_download_control_valid(
    const RinWebContentDownloadControlV1* request)
{
    return request != NULL && request->struct_size == sizeof(*request) &&
           request->version == RIN_WEBCONTENT_EXTENSION_ABI_VERSION &&
           request->reserved0 == 0u && request->transfer_id != 0u &&
           rin_webcontent_client_bytes_zero(request->reserved,
                                            sizeof(request->reserved));
}

static inline int rin_webcontent_client_download_event_valid(
    const RinWebContentDownloadEventV1* event)
{
    if (event == NULL || event->struct_size != sizeof(*event) ||
        event->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        event->flags != 0u || event->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(event->reserved,
                                          sizeof(event->reserved)))
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_NONE) {
        return event->revision == 0u && event->transfer_id == 0u &&
               event->timestamp_ms == 0u && event->size_bytes == 0u &&
               event->failure_status == RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->url[0] == '\0' && event->filename[0] == '\0';
    }
    if (event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_STARTED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_COMPLETED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED)
        return 0;
    if (event->revision == 0u || event->transfer_id == 0u ||
        event->timestamp_ms == 0u ||
        !rin_webcontent_client_url_valid(event->url) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->filename, sizeof(event->filename)) ||
        event->filename[0] == '\0')
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED)
        return event->failure_status > RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->failure_status <= RIN_WEBCONTENT_DOWNLOAD_STATUS_TLS_FAILED;
    return event->failure_status == RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
           (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_STARTED
                ? event->size_bytes != 0u
                : event->size_bytes != 0u && event->size_bytes != UINT64_MAX);
}

static inline int rin_webcontent_client_microphone_revoke_valid(
    const RinWebContentMicrophoneRevokeV1* revocation)
{
    size_t length = 0u;
    if (revocation == NULL ||
        revocation->struct_size != sizeof(*revocation) ||
        revocation->version != RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION ||
        revocation->flags != 0u || revocation->sequence == 0u ||
        !rin_webcontent_client_bounded_cstr_length(
            revocation->domain, sizeof(revocation->domain), 0, 1, &length) ||
        length == 0u ||
        !rin_webcontent_client_bytes_zero(revocation->reserved,
                                          sizeof(revocation->reserved)))
        return 0;
    if (length == 1u && revocation->domain[0] == '*')
        return 1;
    for (size_t index = 0u; index < length; ++index) {
        unsigned char byte = (unsigned char)revocation->domain[index];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'-' ||
              byte == (unsigned char)'[' || byte == (unsigned char)']' ||
              byte == (unsigned char)':'))
            return 0;
    }
    return revocation->domain[0] != '.' &&
           revocation->domain[length - 1u] != '.';
}

static inline int rin_webcontent_client_camera_capture_profile_valid(
    const RinWebContentCameraCaptureProfileV1* profile)
{
    uint64_t pixels;
    uint64_t expected_size;
    if (profile == NULL || profile->struct_size != sizeof(*profile) ||
        profile->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        profile->stream_id == 0u || profile->max_frame_size == 0u ||
        profile->max_frame_size >
            RIN_WEBCONTENT_CAMERA_CAPTURE_MAX_FRAME_BYTES ||
        profile->sample_rate != 0u || profile->channels != 0u ||
        profile->width == 0u || profile->width > 16384u ||
        profile->height == 0u || profile->height > 16384u ||
        profile->flags != 0u || profile->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(profile->reserved,
                                          sizeof(profile->reserved)))
        return 0;
    pixels = (uint64_t)profile->width * profile->height;
    if (profile->format == RIN_WEBCONTENT_CAMERA_FORMAT_RGBX8888) {
        expected_size = pixels * UINT64_C(4);
    } else if (profile->format == RIN_WEBCONTENT_CAMERA_FORMAT_NV12) {
        if ((profile->width & 1u) != 0u || (profile->height & 1u) != 0u)
            return 0;
        expected_size = pixels + pixels / UINT64_C(2);
    } else if (profile->format == RIN_WEBCONTENT_CAMERA_FORMAT_MJPEG) {
        return 1;
    } else {
        return 0;
    }
    return expected_size == profile->max_frame_size;
}

static inline int rin_webcontent_client_camera_capture_chunk_valid(
    const RinWebContentCameraCaptureChunkV1* chunk,
    const uint8_t* payload, uint32_t data_size)
{
    uint64_t end;
    if (chunk == NULL || payload == NULL ||
        chunk->struct_size != sizeof(*chunk) ||
        chunk->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        chunk->sequence == 0u || chunk->monotonic_time_ns == 0u ||
        chunk->total_size == 0u ||
        chunk->total_size > RIN_WEBCONTENT_CAMERA_CAPTURE_MAX_FRAME_BYTES ||
        chunk->payload_size == 0u ||
        chunk->payload_size > RIN_WEBCONTENT_CAMERA_CAPTURE_MAX_CHUNK_BYTES -
                                 sizeof(*chunk) ||
        data_size != sizeof(*chunk) + chunk->payload_size ||
        chunk->reserved0 != 0u ||
        (chunk->flags & ~(RIN_WEBCONTENT_CAMERA_CHUNK_FRAME_START |
                          RIN_WEBCONTENT_CAMERA_CHUNK_FRAME_END |
                          RIN_WEBCONTENT_CAMERA_CHUNK_DROPPED_BEFORE)) != 0u)
        return 0;
    end = (uint64_t)chunk->offset + chunk->payload_size;
    if (chunk->offset >= chunk->total_size || end > chunk->total_size ||
        (((chunk->flags & RIN_WEBCONTENT_CAMERA_CHUNK_FRAME_START) != 0u) !=
         (chunk->offset == 0u)) ||
        (((chunk->flags & RIN_WEBCONTENT_CAMERA_CHUNK_FRAME_END) != 0u) !=
         (end == chunk->total_size)) ||
        ((chunk->flags & RIN_WEBCONTENT_CAMERA_CHUNK_DROPPED_BEFORE) != 0u &&
         (chunk->flags & RIN_WEBCONTENT_CAMERA_CHUNK_FRAME_START) == 0u) ||
        chunk->width == 0u || chunk->width > 16384u ||
        chunk->height == 0u || chunk->height > 16384u ||
        chunk->sample_rate != 0u || chunk->channels != 0u)
        return 0;
    if (chunk->format == RIN_WEBCONTENT_CAMERA_FORMAT_RGBX8888) {
        return (uint64_t)chunk->width * chunk->height * UINT64_C(4) ==
               chunk->total_size;
    }
    if (chunk->format == RIN_WEBCONTENT_CAMERA_FORMAT_NV12) {
        if ((chunk->width & 1u) != 0u || (chunk->height & 1u) != 0u)
            return 0;
        return (uint64_t)chunk->width * chunk->height * UINT64_C(3) /
                   UINT64_C(2) == chunk->total_size;
    }
    return chunk->format == RIN_WEBCONTENT_CAMERA_FORMAT_MJPEG;
}

static inline int rin_webcontent_client_camera_capture_owner_request_valid(
    const RinWebContentCameraCaptureOwnerRequestV1* request)
{
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        !rin_webcontent_client_bytes_zero(request->reserved,
                                          sizeof(request->reserved)))
        return 0;
    if (request->operation == RIN_WEBCONTENT_CAMERA_CAPTURE_OPEN)
        return request->session_id == 0u &&
               rin_webcontent_client_url_valid(request->origin);
    if (request->operation == RIN_WEBCONTENT_CAMERA_CAPTURE_READ_CHUNK ||
        request->operation == RIN_WEBCONTENT_CAMERA_CAPTURE_CLOSE)
        return request->session_id != 0u &&
               rin_webcontent_client_bytes_zero(request->origin,
                                                sizeof(request->origin));
    return 0;
}

static inline int rin_webcontent_client_camera_capture_owner_response_valid(
    const RinWebContentCameraCaptureOwnerResponseV1* response,
    const uint8_t* data, size_t data_size, uint16_t operation,
    uint64_t expected_session_id)
{
    if (response == NULL || response->struct_size != sizeof(*response) ||
        response->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        response->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(response->reserved,
                                          sizeof(response->reserved)) ||
        response->data_size != data_size ||
        data_size > RIN_WEBCONTENT_CAMERA_CAPTURE_MAX_CHUNK_BYTES ||
        (data_size != 0u && data == NULL))
        return 0;
    if (operation == RIN_WEBCONTENT_CAMERA_CAPTURE_OPEN)
        return response->result == RIN_WEBCONTENT_CAMERA_CAPTURE_RESULT_OPEN &&
               response->session_id != 0u && data_size == 0u &&
               rin_webcontent_client_camera_capture_profile_valid(
                   &response->profile);
    if (operation == RIN_WEBCONTENT_CAMERA_CAPTURE_READ_CHUNK) {
        if (response->session_id != expected_session_id ||
            !rin_webcontent_client_camera_capture_profile_valid(
                &response->profile))
            return 0;
        if (response->result ==
            RIN_WEBCONTENT_CAMERA_CAPTURE_RESULT_WOULD_BLOCK)
            return data_size == 0u;
        if (response->result != RIN_WEBCONTENT_CAMERA_CAPTURE_RESULT_CHUNK ||
            data_size < sizeof(RinWebContentCameraCaptureChunkV1))
            return 0;
        const RinWebContentCameraCaptureChunkV1* chunk =
            (const RinWebContentCameraCaptureChunkV1*)data;
        return rin_webcontent_client_camera_capture_chunk_valid(
                   chunk,
                   data + sizeof(RinWebContentCameraCaptureChunkV1),
                   (uint32_t)data_size) &&
               chunk->format == response->profile.format &&
               chunk->width == response->profile.width &&
               chunk->height == response->profile.height &&
               chunk->total_size <= response->profile.max_frame_size;
    }
    if (operation == RIN_WEBCONTENT_CAMERA_CAPTURE_CLOSE) {
        RinWebContentCameraCaptureProfileV1 zero_profile;
        memset(&zero_profile, 0, sizeof(zero_profile));
        return response->result ==
                   RIN_WEBCONTENT_CAMERA_CAPTURE_RESULT_CLOSED &&
               response->session_id == 0u && data_size == 0u &&
               memcmp(&response->profile, &zero_profile,
                      sizeof(zero_profile)) == 0;
    }
    return 0;
}

static inline int rin_webcontent_client_camera_revoke_valid(
    const RinWebContentCameraRevokeV1* revocation)
{
    size_t length = 0u;
    if (revocation == NULL ||
        revocation->struct_size != sizeof(*revocation) ||
        revocation->version != RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION ||
        revocation->flags != 0u || revocation->sequence == 0u ||
        !rin_webcontent_client_bounded_cstr_length(
            revocation->domain, sizeof(revocation->domain), 0, 1, &length) ||
        length == 0u ||
        !rin_webcontent_client_bytes_zero(revocation->reserved,
                                          sizeof(revocation->reserved)))
        return 0;
    if (length == 1u && revocation->domain[0] == '*')
        return 1;
    for (size_t index = 0u; index < length; ++index) {
        unsigned char byte = (unsigned char)revocation->domain[index];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'-' ||
              byte == (unsigned char)'[' || byte == (unsigned char)']' ||
              byte == (unsigned char)':'))
            return 0;
    }
    return revocation->domain[0] != '.' &&
           revocation->domain[length - 1u] != '.';
}

static inline int rin_webcontent_client_location_revoke_valid(
    const RinWebContentLocationRevokeV1* revocation)
{
    size_t length = 0u;
    if (revocation == NULL ||
        revocation->struct_size != sizeof(*revocation) ||
        revocation->version != RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION ||
        revocation->flags != 0u || revocation->sequence == 0u ||
        !rin_webcontent_client_bounded_cstr_length(
            revocation->domain, sizeof(revocation->domain), 0, 1, &length) ||
        length == 0u ||
        !rin_webcontent_client_bytes_zero(revocation->reserved,
                                          sizeof(revocation->reserved)))
        return 0;
    if (length == 1u && revocation->domain[0] == '*')
        return 1;
    for (size_t index = 0u; index < length; ++index) {
        unsigned char byte = (unsigned char)revocation->domain[index];
        if (!((byte >= (unsigned char)'a' && byte <= (unsigned char)'z') ||
              (byte >= (unsigned char)'A' && byte <= (unsigned char)'Z') ||
              (byte >= (unsigned char)'0' && byte <= (unsigned char)'9') ||
              byte == (unsigned char)'.' || byte == (unsigned char)'-' ||
              byte == (unsigned char)'[' || byte == (unsigned char)']' ||
              byte == (unsigned char)':'))
            return 0;
    }
    return revocation->domain[0] != '.' &&
           revocation->domain[length - 1u] != '.';
}

static inline int rin_webcontent_client_download_event_v2_valid(
    const RinWebContentDownloadEventV2* event)
{
    if (event == NULL || event->struct_size != sizeof(*event) ||
        event->version != RIN_WEBCONTENT_DOWNLOAD_EVENT_V2_VERSION ||
        event->flags != 0u || event->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(event->reserved,
                                          sizeof(event->reserved)))
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_NONE) {
        return event->revision == 0u && event->transfer_id == 0u &&
               event->timestamp_ms == 0u && event->size_bytes == 0u &&
               event->committed_bytes == 0u && event->generation == 0u &&
               event->failure_status == RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->url[0] == '\0' && event->filename[0] == '\0' &&
               event->validator[0] == '\0';
    }
    if (event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_STARTED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_COMPLETED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_PROGRESS &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_PAUSED)
        return 0;
    if (event->revision == 0u || event->transfer_id == 0u ||
        event->timestamp_ms == 0u ||
        !rin_webcontent_client_url_valid(event->url) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->filename, sizeof(event->filename)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->validator, sizeof(event->validator)) ||
        event->filename[0] == '\0' || event->size_bytes == 0u)
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED)
        return event->failure_status > RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->failure_status <= RIN_WEBCONTENT_DOWNLOAD_STATUS_TLS_FAILED;
    if (event->failure_status != RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE)
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_PROGRESS ||
        event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_PAUSED) {
        size_t validator_size = 0u;
        if (!rin_webcontent_client_bounded_cstr_length(
                event->validator, sizeof(event->validator), 0, 1,
                &validator_size) || validator_size < 2u ||
            event->validator[0] != '"' ||
            event->validator[validator_size - 1u] != '"')
            return 0;
        for (size_t index = 1u; index + 1u < validator_size; ++index) {
            unsigned char byte = (unsigned char)event->validator[index];
            if (byte < 0x21u || byte > 0x7eu || byte == '"')
                return 0;
        }
        return event->generation != 0u && event->committed_bytes != 0u &&
               (event->size_bytes == UINT64_MAX ||
                event->committed_bytes < event->size_bytes);
    }
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_COMPLETED)
        return event->committed_bytes == event->size_bytes;
    return event->committed_bytes < event->size_bytes;
}

static inline int rin_webcontent_client_download_event_v3_valid(
    const RinWebContentDownloadEventV3* event)
{
    if (event == NULL || event->struct_size != sizeof(*event) ||
        event->version != RIN_WEBCONTENT_DOWNLOAD_EVENT_V3_VERSION ||
        event->flags != 0u || event->reserved0 != 0u ||
        !rin_webcontent_client_bytes_zero(event->reserved,
                                          sizeof(event->reserved)))
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_NONE) {
        return event->revision == 0u && event->transfer_id == 0u &&
               event->timestamp_ms == 0u && event->size_bytes == 0u &&
               event->committed_bytes == 0u && event->generation == 0u &&
               event->failure_status == RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->url[0] == '\0' && event->referrer[0] == '\0' &&
               event->filename[0] == '\0' && event->validator[0] == '\0';
    }
    if (event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_STARTED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_COMPLETED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_PROGRESS &&
        event->event != RIN_WEBCONTENT_DOWNLOAD_EVENT_PAUSED)
        return 0;
    if (event->revision == 0u || event->transfer_id == 0u ||
        event->timestamp_ms == 0u ||
        !rin_webcontent_client_url_valid(event->url) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->referrer, sizeof(event->referrer)) ||
        (event->referrer[0] != '\0' &&
         !rin_webcontent_client_url_valid(event->referrer)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->filename, sizeof(event->filename)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            event->validator, sizeof(event->validator)) ||
        event->filename[0] == '\0' || event->size_bytes == 0u)
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_FAILED)
        return event->failure_status > RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE &&
               event->failure_status <= RIN_WEBCONTENT_DOWNLOAD_STATUS_TLS_FAILED;
    if (event->failure_status != RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE)
        return 0;
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_PROGRESS ||
        event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_PAUSED) {
        size_t validator_size = 0u;
        if (!rin_webcontent_client_bounded_cstr_length(
                event->validator, sizeof(event->validator), 0, 1,
                &validator_size) || validator_size < 2u ||
            event->validator[0] != '"' ||
            event->validator[validator_size - 1u] != '"')
            return 0;
        for (size_t index = 1u; index + 1u < validator_size; ++index) {
            unsigned char byte = (unsigned char)event->validator[index];
            if (byte < 0x21u || byte > 0x7eu || byte == '"')
                return 0;
        }
        return event->generation != 0u && event->committed_bytes != 0u &&
               (event->size_bytes == UINT64_MAX ||
                event->committed_bytes < event->size_bytes);
    }
    if (event->event == RIN_WEBCONTENT_DOWNLOAD_EVENT_COMPLETED)
        return event->committed_bytes == event->size_bytes;
    return event->committed_bytes < event->size_bytes;
}

static inline int rin_webcontent_client_download_resume_valid(
    const RinWebContentDownloadResumeV1* request)
{
    size_t validator_size = 0u;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        request->flags != 0u || request->transfer_id == 0u ||
        request->generation == 0u || request->total_bytes == 0u ||
        request->total_bytes > RIN_WEBCONTENT_DOWNLOAD_MAX_BYTES ||
        request->committed_bytes == 0u ||
        request->committed_bytes >= request->total_bytes ||
        !rin_webcontent_client_url_valid(request->url) ||
        !rin_webcontent_client_fixed_cstr_valid(
            request->filename, sizeof(request->filename)) ||
        request->filename[0] == '\0' ||
        !rin_webcontent_client_fixed_cstr_valid(
            request->validator, sizeof(request->validator)) ||
        !rin_webcontent_client_bytes_zero(request->reserved,
                                          sizeof(request->reserved)) ||
        !rin_webcontent_client_bounded_cstr_length(
            request->validator, sizeof(request->validator), 0, 1,
            &validator_size) || validator_size < 2u ||
        request->validator[0] != '"' ||
        request->validator[validator_size - 1u] != '"')
        return 0;
    for (size_t index = 1u; index + 1u < validator_size; ++index) {
        unsigned char byte = (unsigned char)request->validator[index];
        if (byte < 0x21u || byte > 0x7eu || byte == '"')
            return 0;
    }
    return 1;
}

static inline int rin_webcontent_client_download_resume_v2_valid(
    const RinWebContentDownloadResumeV2* request)
{
    size_t validator_size = 0u;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_WEBCONTENT_DOWNLOAD_RESUME_V2_VERSION ||
        request->flags != 0u || request->transfer_id == 0u ||
        request->generation == 0u || request->total_bytes == 0u ||
        request->total_bytes > RIN_WEBCONTENT_DOWNLOAD_MAX_BYTES ||
        request->committed_bytes == 0u ||
        request->committed_bytes >= request->total_bytes ||
        !rin_webcontent_client_url_valid(request->url) ||
        !rin_webcontent_client_fixed_cstr_valid(
            request->referrer, sizeof(request->referrer)) ||
        (request->referrer[0] != '\0' &&
         !rin_webcontent_client_url_valid(request->referrer)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            request->filename, sizeof(request->filename)) ||
        request->filename[0] == '\0' ||
        !rin_webcontent_client_fixed_cstr_valid(
            request->validator, sizeof(request->validator)) ||
        !rin_webcontent_client_bytes_zero(request->reserved,
                                          sizeof(request->reserved)) ||
        !rin_webcontent_client_bounded_cstr_length(
            request->validator, sizeof(request->validator), 0, 1,
            &validator_size) || validator_size < 2u ||
        request->validator[0] != '"' ||
        request->validator[validator_size - 1u] != '"')
        return 0;
    for (size_t index = 1u; index + 1u < validator_size; ++index) {
        unsigned char byte = (unsigned char)request->validator[index];
        if (byte < 0x21u || byte > 0x7eu || byte == '"')
            return 0;
    }
    return 1;
}

static inline int rin_webcontent_client_call_valid(uint32_t command,
                                                   uint32_t page_id,
                                                   const void* payload,
                                                   uint32_t payload_len,
                                                   const void* response,
                                                   uint32_t response_len)
{
    uint32_t expected_response_len = 0u;

    if (!rin_webcontent_client_command_valid(command) ||
        ((command == RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1 ||
          command == RIN_WEBCONTENT_CMD_OPEN_SERVICE_WORKER_OWNER_V1 ||
          command == RIN_WEBCONTENT_CMD_SERIAL_PORTAL_V1 ||
          command == RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1) !=
         (page_id == 0u)))
        return 0;

    switch (command) {
    case RIN_WEBCONTENT_CMD_CREATE_PAGE_V1: {
        RinWebContentCreatePageRequest request;
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_dimensions_valid(
                request.viewport_width, request.viewport_height))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_DESTROY_PAGE_V1:
        if (payload != NULL || payload_len != 0u)
            return 0;
        break;
    case RIN_WEBCONTENT_CMD_NAVIGATE_V1: {
        RinWebContentNavigateRequest request;
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_url_valid(request.url))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_LOAD_MARKUP_V1: {
        RinWebContentLoadMarkupRequest request;
        uint32_t inline_payload_len;
        if (payload == NULL ||
            payload_len < (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_url_valid(request.base_url) ||
            request.markup_len > RIN_WEBCONTENT_CLIENT_MARKUP_BYTES_MAX)
            return 0;
        if (request.markup_storage_kind == RIN_WEBCONTENT_STORAGE_INLINE) {
            if (request.markup_len > RIN_WEBCONTENT_INLINE_THRESHOLD ||
                request.markup_region.size != 0u ||
                request.markup_region.name[0] != '\0')
                return 0;
            inline_payload_len =
                (uint32_t)sizeof(request) + request.markup_len;
            if (payload_len != inline_payload_len)
                return 0;
        } else if (request.markup_storage_kind ==
                   RIN_WEBCONTENT_STORAGE_SHM) {
            if (request.markup_len <= RIN_WEBCONTENT_INLINE_THRESHOLD ||
                payload_len != (uint32_t)sizeof(request) ||
                request.markup_region.size != request.markup_len ||
                request.markup_region.name[0] == '\0' ||
                !rin_webcontent_client_fixed_cstr_valid(
                    request.markup_region.name,
                    sizeof(request.markup_region.name)))
                return 0;
        } else {
            return 0;
        }
        break;
    }
    case RIN_WEBCONTENT_CMD_RESIZE_V1: {
        RinWebContentResizeRequest request;
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_dimensions_valid(
                request.viewport_width, request.viewport_height))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_PUMP_EVENTS_V1:
        if (payload != NULL || payload_len != 0u)
            return 0;
        expected_response_len = (uint32_t)sizeof(RinWebContentPageState);
        break;
    case RIN_WEBCONTENT_CMD_PAINT_V1:
        if (payload != NULL || payload_len != 0u)
            return 0;
        expected_response_len = (uint32_t)sizeof(RinWebContentPaintResponse);
        break;
    case RIN_WEBCONTENT_CMD_DISPATCH_POINTER_V1: {
        RinWebContentPointerRequest request;
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_pointer_request_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_DISPATCH_KEY_OR_TEXT_V1: {
        RinWebContentKeyOrTextRequest request;
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (request.action > RIN_WEBCONTENT_KEY_ACTION_ESCAPE ||
            !rin_webcontent_client_fixed_cstr_valid(
                request.text, sizeof(request.text)))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_SCROLL_TO_V1:
        if (payload == NULL ||
            payload_len != (uint32_t)sizeof(RinWebContentScrollRequest))
            return 0;
        break;
    case RIN_WEBCONTENT_CMD_GET_PAGE_STATE_V1:
        if (payload != NULL || payload_len != 0u)
            return 0;
        expected_response_len = (uint32_t)sizeof(RinWebContentPageState);
        break;
    case RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1:
        if (payload != NULL || payload_len != 0u)
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentCapabilitiesV1);
        break;
    case RIN_WEBCONTENT_CMD_OPEN_SERVICE_WORKER_OWNER_V1:
        if ((payload_len != 0u && payload_len !=
             sizeof(RinWebContentOwnerChannelSessionV1)) ||
            (payload_len != 0u && payload == NULL))
            return 0;
        if (payload_len != 0u) {
            RinWebContentOwnerChannelSessionV1 session;
            memcpy(&session, payload, sizeof(session));
            if (session.session_id == 0u ||
                session.session_generation == 0u ||
                session.reserved[0] != 0u || session.reserved[1] != 0u)
                return 0;
        }
        break;
    case RIN_WEBCONTENT_CMD_SERVICE_WORKER_OWNER_V1: {
        RinWebContentServiceWorkerOwnerRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_service_worker_owner_request_valid(&request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentServiceWorkerOwnerResponseV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_CACHE_STORAGE_OWNER_V1: {
        RinWebContentCacheStorageOwnerRequestV1 request;
        if (payload == NULL || payload_len < sizeof(request) || response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_cache_storage_owner_request_valid(
                &request, (const uint8_t*)payload + sizeof(request),
                payload_len - sizeof(request)))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentCacheStorageOwnerResponseV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_HTTP_COOKIE_OWNER_V1: {
        RinWebContentHttpCookieOwnerRequestV1 request;
        if (payload == NULL || payload_len < sizeof(request) || response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_http_cookie_owner_request_valid(
                &request, (const uint8_t*)payload + sizeof(request),
                payload_len - sizeof(request)))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentHttpCookieOwnerResponseV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1: {
        RinWebContentTlsIdentityOwnerRequestV1 request;
        if (payload == NULL || payload_len < sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_tls_identity_owner_request_valid(
                &request, (const uint8_t*)payload + sizeof(request),
                payload_len - sizeof(request)))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentTlsIdentityOwnerResponseV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_POLL_WEBAUTHN_V1: {
        RinWebContentWebAuthnPollV1 request;
        if (payload == NULL || payload_len != sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_webauthn_poll_valid(&request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentWebAuthnEventV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_COMPLETE_WEBAUTHN_V1: {
        RinWebContentWebAuthnCompleteV1 request;
        if (payload == NULL || payload_len != sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_webauthn_complete_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_COMPLETE_FILE_PICKER_V1: {
        RinWebContentFilePickerCompleteV1 request;
        if (payload == NULL || payload_len != sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_file_picker_complete_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_GET_ACCESSIBILITY_TREE_V1: {
        RinWebContentAccessibilityRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL) return 0;
        memcpy(&request, payload, sizeof(request));
        if (request.window == 0u) return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentAccessibilitySnapshotV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_PERFORM_ACCESSIBILITY_ACTION_V1: {
        RinWebContentAccessibilityActionV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_accessibility_action_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_GET_DOWNLOAD_EVENT_V1: {
        RinWebContentDownloadEventRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_event_request_valid(&request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentDownloadEventV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_GET_DOWNLOAD_EVENT_V2: {
        RinWebContentDownloadEventRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_event_request_valid(&request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentDownloadEventV2);
        break;
    }
    case RIN_WEBCONTENT_CMD_GET_DOWNLOAD_EVENT_V3: {
        RinWebContentDownloadEventRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_event_request_valid(&request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentDownloadEventV3);
        break;
    }
    case RIN_WEBCONTENT_CMD_RESUME_DOWNLOAD_V1: {
        RinWebContentDownloadResumeV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_resume_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_RESUME_DOWNLOAD_V2: {
        RinWebContentDownloadResumeV2 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_resume_v2_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_POLL_PERMISSION_V1: {
        RinWebContentPermissionPollV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_permission_poll_valid(
                &request, request.navigation_generation))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentPermissionEventV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_COMPLETE_PERMISSION_V1: {
        RinWebContentPermissionCompleteV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_permission_complete_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_COMPLETE_LOCATION_V1: {
        RinWebContentLocationPermissionCompleteV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_location_permission_complete_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_REVOKE_MICROPHONE_V1: {
        RinWebContentMicrophoneRevokeV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_microphone_revoke_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_CAMERA_CAPTURE_OWNER_V1: {
        RinWebContentCameraCaptureOwnerRequestV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response == NULL)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_camera_capture_owner_request_valid(
                &request))
            return 0;
        expected_response_len =
            (uint32_t)sizeof(RinWebContentCameraCaptureOwnerResponseV1);
        break;
    }
    case RIN_WEBCONTENT_CMD_REVOKE_CAMERA_V1: {
        RinWebContentCameraRevokeV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_camera_revoke_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_REVOKE_LOCATION_V1: {
        RinWebContentLocationRevokeV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_location_revoke_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_COMPLETE_FILE_PICKER_V2: {
        RinWebContentFilePickerCompleteV2 request;
        if (payload == NULL || payload_len != sizeof(request))
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_file_picker_complete_multiple_valid(&request))
            return 0;
        break;
    }
    case RIN_WEBCONTENT_CMD_CANCEL_DOWNLOAD_V1:
    case RIN_WEBCONTENT_CMD_RETRY_DOWNLOAD_V1:
    case RIN_WEBCONTENT_CMD_PAUSE_DOWNLOAD_V1: {
        RinWebContentDownloadControlV1 request;
        if (payload == NULL || payload_len != sizeof(request) ||
            response != NULL || response_len != 0u)
            return 0;
        memcpy(&request, payload, sizeof(request));
        if (!rin_webcontent_client_download_control_valid(&request))
            return 0;
        break;
    }
    default:
        return 0;
    }

    if (response_len != expected_response_len)
        return 0;
    return expected_response_len == 0u ? response == NULL : response != NULL;
}

static inline RinWebContentClientValidation
rin_webcontent_client_page_state_validate(
    const RinWebContentPageState* state,
    uint32_t expected_page_id)
{
    const uint32_t known_flags =
        RIN_WEBCONTENT_STATE_FLAG_LOADING |
        RIN_WEBCONTENT_STATE_FLAG_CRASHED |
        RIN_WEBCONTENT_STATE_FLAG_DIRTY |
        RIN_WEBCONTENT_STATE_FLAG_HAS_LOAD_PHASE |
        RIN_WEBCONTENT_STATE_FLAG_SUSPECTED_STALL |
        RIN_WEBCONTENT_STATE_FLAG_TEXT_INPUT_ENABLED |
        RIN_WEBCONTENT_STATE_FLAG_HAS_DOWNLOAD_STATUS |
        RIN_WEBCONTENT_STATE_FLAG_HAS_FILE_PICKER_REQUEST;

    if (state == NULL || expected_page_id == 0u ||
        state->page_id != expected_page_id ||
        (state->flags & ~known_flags) != 0u ||
        ((state->flags & RIN_WEBCONTENT_STATE_FLAG_LOADING) != 0u &&
         (state->flags & RIN_WEBCONTENT_STATE_FLAG_CRASHED) != 0u) ||
        state->progress_percent > 100u ||
        state->load_phase > RIN_WEBCONTENT_LOAD_PHASE_COMPLETE ||
        state->download_status > RIN_WEBCONTENT_DOWNLOAD_STATUS_TLS_FAILED ||
        ((state->flags & RIN_WEBCONTENT_STATE_FLAG_HAS_FILE_PICKER_REQUEST) == 0u &&
         (state->file_picker_request_id != 0u ||
          state->file_picker_allow_multiple != 0u ||
          state->file_picker_reserved0 != 0u)) ||
        ((state->flags & RIN_WEBCONTENT_STATE_FLAG_HAS_FILE_PICKER_REQUEST) != 0u &&
         (state->file_picker_request_id == 0u ||
          state->file_picker_allow_multiple > 1u ||
          state->file_picker_reserved0 != 0u)) ||
        ((state->flags & RIN_WEBCONTENT_STATE_FLAG_SUSPECTED_STALL) != 0u &&
         (state->flags & RIN_WEBCONTENT_STATE_FLAG_HAS_LOAD_PHASE) == 0u) ||
        state->text_input_content_type > RIN_TEXT_INPUT_CONTENT_NUMBER) {
        return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
    }

    if (state->viewport_width == 0u || state->viewport_height == 0u ||
        state->viewport_width > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
        state->viewport_height > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
        state->content_width < state->viewport_width ||
        state->content_height < state->viewport_height ||
        state->content_width > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
        state->content_height > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
        state->max_scroll_x < 0 || state->max_scroll_y < 0 ||
        state->scroll_x < 0 || state->scroll_y < 0 ||
        state->scroll_x > state->max_scroll_x ||
        state->scroll_y > state->max_scroll_y) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }

    if (!rin_webcontent_client_fixed_cstr_valid(
            state->committed_url, sizeof(state->committed_url)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            state->pending_url, sizeof(state->pending_url)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            state->title, sizeof(state->title)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            state->crash_reason, sizeof(state->crash_reason)) ||
        !rin_webcontent_client_fixed_cstr_valid(
            state->load_current_url, sizeof(state->load_current_url))) {
        return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
    }

    if ((state->load_bytes_total != 0u &&
         state->load_bytes_received > state->load_bytes_total) ||
        (state->load_scripts_total != 0u &&
         state->load_scripts_pending > state->load_scripts_total)) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }

    if ((state->flags & RIN_WEBCONTENT_STATE_FLAG_TEXT_INPUT_ENABLED) != 0u &&
        (state->text_input_width <= 0 || state->text_input_height <= 0 ||
         (uint32_t)state->text_input_width >
             RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
         (uint32_t)state->text_input_height >
             RIN_WEBCONTENT_CLIENT_DIMENSION_MAX)) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }

    if ((state->flags & RIN_WEBCONTENT_STATE_FLAG_HAS_DOWNLOAD_STATUS) != 0u) {
        if (state->download_status == RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE ||
            state->download_status_revision == 0u ||
            state->download_status_timestamp_ms == 0u) {
            return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
        }
    } else if (state->download_status != RIN_WEBCONTENT_DOWNLOAD_STATUS_NONE ||
               state->download_status_revision != 0u ||
               state->download_status_timestamp_ms != 0u) {
        return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
    }

    return RIN_WEBCONTENT_CLIENT_VALID;
}

static inline RinWebContentClientValidation
rin_webcontent_client_paint_validate(
    const RinWebContentPaintResponse* response)
{
    uint64_t expected_size;
    if (response == NULL ||
        response->pixel_storage_kind != RIN_WEBCONTENT_STORAGE_SHM ||
        !rin_webcontent_client_fixed_cstr_valid(
            response->pixel_region.name,
            sizeof(response->pixel_region.name)) ||
        response->pixel_region.name[0] == '\0') {
        return RIN_WEBCONTENT_CLIENT_INVALID_PROTOCOL;
    }
    if (response->width == 0u || response->height == 0u ||
        response->width > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX ||
        response->height > RIN_WEBCONTENT_CLIENT_DIMENSION_MAX) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }

    expected_size = (uint64_t)response->width *
                    (uint64_t)response->height * sizeof(uint32_t);
    if (expected_size == 0u ||
        expected_size > RIN_WEBCONTENT_CLIENT_PAINT_BYTES_MAX ||
        response->pixel_region.size != expected_size) {
        return RIN_WEBCONTENT_CLIENT_INVALID_SIZE;
    }
    return RIN_WEBCONTENT_CLIENT_VALID;
}

#endif /* RIN_SHARED_WEBCONTENT_CLIENT_POLICY_H */
