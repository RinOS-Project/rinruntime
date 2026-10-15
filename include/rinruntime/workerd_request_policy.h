/* SPDX-License-Identifier: MIT */
/* Fail-closed admission rules for the workerd wire protocol. */
#ifndef RIN_SHARED_WORKERD_REQUEST_POLICY_H
#define RIN_SHARED_WORKERD_REQUEST_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include <rinhttp/http.h>
#include <rin/web/request_body_capability.h>
#include "workerd_service_abi.h"

#define RIN_WORKERD_MAX_CONTROL_PAYLOAD (1024u * 1024u)
#define RIN_WORKERD_MAX_HEADERS 256u
#define RIN_WORKERD_MAX_METHOD_LENGTH 4096u
#define RIN_WORKERD_MAX_URL_LENGTH 32768u
/* Service-local admission ceilings.  Kernel rlimit/cgroup enforcement is a
 * separate product boundary; these values prevent the daemon from accepting
 * more explicitly-owned memory/SHM state than it can account for. */
#define RIN_WORKERD_MAX_RESIDENT_BYTES (256u * 1024u * 1024u)
#define RIN_WORKERD_MAX_RESIDENT_HANDLES 64u
#define RIN_WORKERD_MAX_CLIENT_RESIDENT_BYTES (64u * 1024u * 1024u)
#define RIN_WORKERD_MAX_CLIENT_RESIDENT_HANDLES 16u

static inline int rin_workerd_resource_reservation_valid(
    uint64_t bytes, uint32_t handles) {
    return bytes <= (uint64_t)RIN_WORKERD_MAX_RESIDENT_BYTES &&
           handles <= (uint32_t)RIN_WORKERD_MAX_RESIDENT_HANDLES;
}

static inline int rin_workerd_client_resource_reservation_valid(
    uint64_t bytes, uint32_t handles) {
    return bytes <= (uint64_t)RIN_WORKERD_MAX_CLIENT_RESIDENT_BYTES &&
           handles <= (uint32_t)RIN_WORKERD_MAX_CLIENT_RESIDENT_HANDLES;
}

static inline int rin_workerd_command_valid(uint32_t command) {
    return command == RIN_WORKERD_CMD_FETCH_V1 ||
           command == RIN_WORKERD_CMD_DECODE_IMAGE_V1 ||
           command == RIN_WORKERD_CMD_CANCEL_V1 ||
           command == RIN_WORKERD_CMD_FETCH_REVOCATION_V1;
}

static inline int rin_workerd_message_header_valid(
    const RinWorkerdMsgHeader* header) {
    return header != NULL && header->magic == RIN_WORKERD_MAGIC &&
           header->version == RIN_WORKERD_VERSION &&
           rin_workerd_command_valid(header->command) &&
           header->status == 0 && header->request_id != 0u &&
           header->request_id != UINT32_MAX &&
           header->payload_len <= RIN_WORKERD_MAX_CONTROL_PAYLOAD &&
           header->reserved0 == 0u && header->reserved1 == 0u;
}

static inline int rin_workerd_shm_region_name_valid(
    const RinWorkerdShmRegion* region) {
    size_t length = 0u;
    if (region == NULL || region->size == 0u) return 0;
    while (length < sizeof(region->name) && region->name[length] != '\0') {
        unsigned char value = (unsigned char)region->name[length];
        if (value < 0x21u || value > 0x7eu || value == '/') return 0;
        ++length;
    }
    return length > 0u && length < sizeof(region->name);
}

/* This validator only checks the wire descriptor and service-local bounds.
 * Resolver registration remains a private owner step; workerd must still
 * reject capability bodies when that authenticated owner is absent. */
static inline int rin_workerd_body_capability_valid(
    const RinWorkerdBodyCapability* capability, uint32_t request_id,
    uint64_t connection_generation) {
    return rin_request_body_capability_bound_to(
        capability, (uint64_t)request_id, connection_generation);
}

/* A capability reservation is charged to one client-owned resident handle.
 * This is only service-local admission; the kernel quota owner and the
 * authenticated RequestServer token resolver remain separate boundaries. */
static inline int rin_workerd_body_capability_reservation_valid(
    const RinWorkerdBodyCapability* capability) {
    return rin_request_body_capability_valid(capability) &&
           rin_workerd_client_resource_reservation_valid(
               capability->byte_length, 1u);
}

static inline int rin_workerd_body_capability_zero(
    const RinWorkerdBodyCapability* capability) {
    const uint8_t* bytes = (const uint8_t*)capability;
    size_t index;
    uint8_t aggregate = 0u;
    if (!bytes || capability == NULL) return 0;
    for (index = 0u; index < sizeof(*capability); ++index)
        aggregate |= bytes[index];
    return aggregate == 0u;
}

static inline int rin_workerd_shm_region_zero(
    const RinWorkerdShmRegion* region) {
    const uint8_t* bytes = (const uint8_t*)region;
    size_t index;
    uint8_t aggregate = 0u;
    if (!bytes || region == NULL) return 0;
    for (index = 0u; index < sizeof(*region); ++index)
        aggregate |= bytes[index];
    return aggregate == 0u;
}

static inline int rin_workerd_fetch_request_fields_valid(
    const RinWorkerdFetchRequest* request) {
    const uint32_t known_flags =
        RIN_WORKERD_FETCH_FLAG_FORCE_CONNECTION_CLOSE |
        RIN_WORKERD_FETCH_FLAG_FORCE_IDENTITY_ENCODING;
    if (request == NULL || request->method_len > RIN_WORKERD_MAX_METHOD_LENGTH ||
        request->url_len > RIN_WORKERD_MAX_URL_LENGTH ||
        request->header_count > RIN_WORKERD_MAX_HEADERS ||
        ((request->body_storage_kind != RIN_WORKERD_PAYLOAD_CAPABILITY) &&
         request->body_len > RIN_WORKERD_MAX_CONTROL_PAYLOAD) ||
        ((request->body_storage_kind == RIN_WORKERD_PAYLOAD_CAPABILITY) &&
         request->body_len > RIN_WORKERD_MAX_CLIENT_RESIDENT_BYTES) ||
        request->follow_redirects > 1u ||
        (request->options_flags & ~known_flags) != 0u) {
        return 0;
    }
    if (request->request_class != RIN_WORKERD_FETCH_CLASS_DEFAULT &&
        request->request_class != RIN_WORKERD_FETCH_CLASS_SCRIPT &&
        request->request_class != RIN_WORKERD_FETCH_CLASS_STYLESHEET &&
        request->request_class != RIN_WORKERD_FETCH_CLASS_IMAGE) {
        return 0;
    }
    if (request->body_storage_kind == RIN_WORKERD_PAYLOAD_INLINE) {
        return rin_workerd_body_capability_zero(&request->body_capability) &&
               rin_workerd_shm_region_zero(&request->body_region);
    }
    if (request->body_storage_kind == RIN_WORKERD_PAYLOAD_CAPABILITY) {
        return request->body_len != 0u &&
               request->body_len == request->body_capability.byte_length &&
               rin_workerd_body_capability_reservation_valid(
                   &request->body_capability) &&
               rin_workerd_shm_region_zero(&request->body_region);
    }
    /* A caller-selected SHM name is not an authority.  The v3 fetch ABI has
     * no authenticated handle/owner binding for request input, and the
     * private service parser therefore rejects this mode.  SHM remains valid
     * for service-produced responses and decode output descriptors. */
    return 0;
}

/* Keep control-channel header admission aligned with the HTTP field grammar.
 * Values are intentionally checked here as raw bytes: this boundary must not
 * allow a later HTTP serializer to reinterpret control characters. */
static inline int rin_workerd_fetch_header_field_valid(
    const uint8_t* key, size_t key_size,
    const uint8_t* value, size_t value_size) {
    size_t index;
    if (rin_http_field_name_valid(key, key_size) != RIN_HTTP_OK ||
        (value == NULL && value_size != 0u)) {
        return 0;
    }
    for (index = 0u; index < value_size; ++index) {
        if (value[index] == 0u || value[index] == '\r' ||
            value[index] == '\n' ||
            (value[index] < 0x20u && value[index] != '\t') ||
            value[index] == 0x7fu) {
            return 0;
        }
    }
    return 1;
}

static inline int rin_workerd_decode_request_fields_valid(
    const RinWorkerdDecodeImageRequest* request) {
    if (request == NULL || request->url_len > RIN_WORKERD_MAX_URL_LENGTH ||
        request->body_len > RIN_WORKERD_MAX_CONTROL_PAYLOAD) {
        return 0;
    }
    if (request->body_storage_kind == RIN_WORKERD_PAYLOAD_INLINE) {
        return rin_workerd_shm_region_zero(&request->body_region);
    }
    /* Decode input has the same public boundary as fetch input: a shared
     * memory name is not an authenticated transfer owner.  Service-produced
     * pixel SHM remains valid on the response side. */
    return 0;
}

static inline int rin_workerd_cancel_request_valid(
    const RinWorkerdCancelRequest* request) {
    return request != NULL && request->request_id != 0u &&
           request->request_id != UINT32_MAX;
}

static inline int rin_workerd_revocation_fetch_request_valid(
    const RinWorkerdRevocationFetchRequest* request) {
    return request != NULL && request->timeout_ms != 0u &&
           (request->source == RIN_WORKERD_REVOCATION_SOURCE_OCSP ||
            request->source == RIN_WORKERD_REVOCATION_SOURCE_CRL) &&
           request->url_len != 0u &&
           request->url_len <= RIN_WORKERD_MAX_URL_LENGTH &&
           request->reserved == 0u;
}

static inline int rin_workerd_revocation_fetch_response_valid(
    const RinWorkerdRevocationFetchResponse* response,
    uint32_t payload_len) {
    return response != NULL && response->transfer_complete == 1u &&
           response->success == 1u && response->status_code >= 200 &&
           response->status_code < 300 &&
           response->body_len != 0u &&
           response->body_len <= RIN_WORKERD_REVOCATION_MAX_RESPONSE_BYTES &&
           payload_len == sizeof(*response) + response->body_len;
}

#endif /* RIN_SHARED_WORKERD_REQUEST_POLICY_H */
