// SPDX-License-Identifier: MIT
#ifndef RIN_SHARED_WEBCONTENT_SERVICE_POLICY_H
#define RIN_SHARED_WEBCONTENT_SERVICE_POLICY_H

#include "webcontent_client_policy.h"
#include "webcontent_service_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Validate the fields common to every client-to-WebContent request. */
static inline int rin_webcontent_service_request_header_valid(
    const RinWebContentMsgHeader* header)
{
    return header != 0 &&
           header->magic == RIN_WEBCONTENT_MAGIC &&
           header->version == RIN_WEBCONTENT_VERSION &&
           header->status == 0 &&
           header->reserved0 == 0u &&
           header->reserved1 == 0u;
}

/* Admit a request size before the bridge allocates or receives its payload.
 * Large markup travels in a shared-memory region; only its descriptor or a
 * bounded inline body is ever carried by this socket. */
static inline int rin_webcontent_service_request_payload_length_valid(
    const RinWebContentMsgHeader* header)
{
    if (!rin_webcontent_service_request_header_valid(header) ||
        !rin_webcontent_client_command_valid(header->command) ||
        ((header->command == RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1 ||
          header->command == RIN_WEBCONTENT_CMD_OPEN_SERVICE_WORKER_OWNER_V1 ||
          header->command == RIN_WEBCONTENT_CMD_SERIAL_PORTAL_V1 ||
          header->command == RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1) !=
         (header->page_id == 0u)))
        return 0;

    switch (header->command) {
    case RIN_WEBCONTENT_CMD_CREATE_PAGE_V1:
        return header->payload_len == sizeof(RinWebContentCreatePageRequest);
    case RIN_WEBCONTENT_CMD_DESTROY_PAGE_V1:
    case RIN_WEBCONTENT_CMD_PUMP_EVENTS_V1:
    case RIN_WEBCONTENT_CMD_PAINT_V1:
    case RIN_WEBCONTENT_CMD_GET_PAGE_STATE_V1:
    case RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1:
        return header->payload_len == 0u;
    case RIN_WEBCONTENT_CMD_OPEN_SERVICE_WORKER_OWNER_V1:
        return header->payload_len == 0u ||
               header->payload_len == sizeof(RinWebContentOwnerChannelSessionV1);
    case RIN_WEBCONTENT_CMD_SERIAL_PORTAL_V1:
        return header->payload_len >= 36u &&
               header->payload_len <= RIN_WEBCONTENT_INLINE_THRESHOLD;
    case RIN_WEBCONTENT_CMD_NAVIGATE_V1:
        return header->payload_len == sizeof(RinWebContentNavigateRequest);
    case RIN_WEBCONTENT_CMD_LOAD_MARKUP_V1:
        return header->payload_len >= sizeof(RinWebContentLoadMarkupRequest) &&
               header->payload_len <=
                   sizeof(RinWebContentLoadMarkupRequest) +
                       RIN_WEBCONTENT_INLINE_THRESHOLD;
    case RIN_WEBCONTENT_CMD_RESIZE_V1:
        return header->payload_len == sizeof(RinWebContentResizeRequest);
    case RIN_WEBCONTENT_CMD_DISPATCH_POINTER_V1:
        return header->payload_len == sizeof(RinWebContentPointerRequest);
    case RIN_WEBCONTENT_CMD_DISPATCH_KEY_OR_TEXT_V1:
        return header->payload_len == sizeof(RinWebContentKeyOrTextRequest);
    case RIN_WEBCONTENT_CMD_SCROLL_TO_V1:
        return header->payload_len == sizeof(RinWebContentScrollRequest);
    case RIN_WEBCONTENT_CMD_POLL_WEBAUTHN_V1:
        return header->payload_len == sizeof(RinWebContentWebAuthnPollV1);
    case RIN_WEBCONTENT_CMD_COMPLETE_WEBAUTHN_V1:
        return header->payload_len == sizeof(RinWebContentWebAuthnCompleteV1);
    case RIN_WEBCONTENT_CMD_COMPLETE_FILE_PICKER_V1:
        return header->payload_len == sizeof(RinWebContentFilePickerCompleteV1);
    case RIN_WEBCONTENT_CMD_COMPLETE_FILE_PICKER_V2:
        return header->payload_len == sizeof(RinWebContentFilePickerCompleteV2);
    case RIN_WEBCONTENT_CMD_GET_ACCESSIBILITY_TREE_V1:
        return header->payload_len ==
               sizeof(RinWebContentAccessibilityRequestV1);
    case RIN_WEBCONTENT_CMD_PERFORM_ACCESSIBILITY_ACTION_V1:
        return header->payload_len ==
               sizeof(RinWebContentAccessibilityActionV1);
    case RIN_WEBCONTENT_CMD_GET_DOWNLOAD_EVENT_V1:
        return header->payload_len ==
               sizeof(RinWebContentDownloadEventRequestV1);
    case RIN_WEBCONTENT_CMD_POLL_PERMISSION_V1:
        return header->payload_len == sizeof(RinWebContentPermissionPollV1);
    case RIN_WEBCONTENT_CMD_COMPLETE_PERMISSION_V1:
        return header->payload_len == sizeof(RinWebContentPermissionCompleteV1);
    case RIN_WEBCONTENT_CMD_COMPLETE_LOCATION_V1:
        return header->payload_len ==
            sizeof(RinWebContentLocationPermissionCompleteV1);
    case RIN_WEBCONTENT_CMD_REVOKE_MICROPHONE_V1:
        return header->payload_len == sizeof(RinWebContentMicrophoneRevokeV1);
    case RIN_WEBCONTENT_CMD_REVOKE_CAMERA_V1:
        return header->payload_len == sizeof(RinWebContentCameraRevokeV1);
    case RIN_WEBCONTENT_CMD_REVOKE_LOCATION_V1:
        return header->payload_len == sizeof(RinWebContentLocationRevokeV1);
    case RIN_WEBCONTENT_CMD_SERVICE_WORKER_OWNER_V1:
        return header->payload_len == sizeof(RinWebContentServiceWorkerOwnerRequestV1);
    case RIN_WEBCONTENT_CMD_CACHE_STORAGE_OWNER_V1:
        return header->payload_len >= sizeof(RinWebContentCacheStorageOwnerRequestV1) &&
               header->payload_len <= sizeof(RinWebContentCacheStorageOwnerRequestV1) +
                   RIN_WEBCONTENT_URL_MAX +
                   RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_KEY_BYTES +
                   RIN_WEBCONTENT_CACHE_STORAGE_OWNER_MAX_VALUE_BYTES;
    case RIN_WEBCONTENT_CMD_HTTP_COOKIE_OWNER_V1:
        return header->payload_len >= sizeof(RinWebContentHttpCookieOwnerRequestV1) &&
               header->payload_len <= sizeof(RinWebContentHttpCookieOwnerRequestV1) +
                   (2u * RIN_WEBCONTENT_URL_MAX) +
                   RIN_WEBCONTENT_HTTP_COOKIE_OWNER_MAX_DATA_BYTES;
    case RIN_WEBCONTENT_CMD_CAMERA_CAPTURE_OWNER_V1:
        return header->payload_len ==
               sizeof(RinWebContentCameraCaptureOwnerRequestV1);
    case RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1:
        return header->payload_len >=
                   sizeof(RinWebContentTlsIdentityOwnerRequestV1) &&
               header->payload_len <=
                   sizeof(RinWebContentTlsIdentityOwnerRequestV1) +
                   RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_URL +
                   (2u * RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_SCHEMES) +
                   RIN_WEBCONTENT_TLS_IDENTITY_OWNER_MAX_AUTHORITIES +
                   RIN_REQUESTSERVER_TLS_CLIENT_CERTIFICATE_MAX_TRANSCRIPT_BYTES;
    default:
        return 0;
    }
}

/* Reuse the client-side schema after the bounded payload has arrived.  A
 * non-null marker is sufficient: the schema only needs response shape here,
 * not a response body. */
static inline int rin_webcontent_service_request_valid(
    const RinWebContentMsgHeader* header, const void* payload)
{
    uint8_t response_marker = 0u;
    uint32_t response_len = 0u;

    if (!rin_webcontent_service_request_payload_length_valid(header) ||
        (header->payload_len != 0u && payload == NULL))
        return 0;

    switch (header->command) {
    case RIN_WEBCONTENT_CMD_PUMP_EVENTS_V1:
    case RIN_WEBCONTENT_CMD_GET_PAGE_STATE_V1:
        response_len = sizeof(RinWebContentPageState);
        break;
    case RIN_WEBCONTENT_CMD_PAINT_V1:
        response_len = sizeof(RinWebContentPaintResponse);
        break;
    case RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1:
        response_len = sizeof(RinWebContentCapabilitiesV1);
        break;
    case RIN_WEBCONTENT_CMD_POLL_WEBAUTHN_V1:
        response_len = sizeof(RinWebContentWebAuthnEventV1);
        break;
    case RIN_WEBCONTENT_CMD_GET_ACCESSIBILITY_TREE_V1:
        response_len = sizeof(RinWebContentAccessibilitySnapshotV1);
        break;
    case RIN_WEBCONTENT_CMD_GET_DOWNLOAD_EVENT_V1:
        response_len = sizeof(RinWebContentDownloadEventV1);
        break;
    case RIN_WEBCONTENT_CMD_POLL_PERMISSION_V1:
        response_len = sizeof(RinWebContentPermissionEventV1);
        break;
    case RIN_WEBCONTENT_CMD_SERVICE_WORKER_OWNER_V1:
        response_len = sizeof(RinWebContentServiceWorkerOwnerResponseV1);
        break;
    case RIN_WEBCONTENT_CMD_CACHE_STORAGE_OWNER_V1:
        response_len = sizeof(RinWebContentCacheStorageOwnerResponseV1);
        break;
    case RIN_WEBCONTENT_CMD_HTTP_COOKIE_OWNER_V1:
        response_len = sizeof(RinWebContentHttpCookieOwnerResponseV1);
        break;
    case RIN_WEBCONTENT_CMD_CAMERA_CAPTURE_OWNER_V1:
        response_len = sizeof(RinWebContentCameraCaptureOwnerResponseV1);
        break;
    case RIN_WEBCONTENT_CMD_TLS_IDENTITY_OWNER_V1:
        response_len = sizeof(RinWebContentTlsIdentityOwnerResponseV1);
        break;
    default:
        break;
    }

    return rin_webcontent_client_call_valid(
        header->command, header->page_id, payload, header->payload_len,
        response_len == 0u ? NULL : &response_marker, response_len);
}

/*
 * Build the extension discovery response. Optional service capabilities stay
 * disabled until their complete producer and TCB completion paths are linked.
 * The output is always cleared, including on invalid input.
 */
static inline int rin_webcontent_service_capabilities_build(
    const RinWebContentMsgHeader* request,
    RinWebContentCapabilitiesV1* capabilities)
{
    if (capabilities == 0) return 0;

    capabilities->struct_size = 0u;
    capabilities->version = 0u;
    capabilities->reserved0 = 0u;
    capabilities->capabilities = 0u;
    capabilities->webauthn_min_version = 0u;
    capabilities->webauthn_max_version = 0u;
    capabilities->reserved[0] = 0u;

    if (!rin_webcontent_service_request_header_valid(request) ||
        request->command != RIN_WEBCONTENT_CMD_GET_CAPABILITIES_V1 ||
        request->page_id != 0u || request->payload_len != 0u)
        return 0;

    capabilities->struct_size = (uint32_t)sizeof(*capabilities);
    capabilities->version = RIN_WEBCONTENT_EXTENSION_ABI_VERSION;
    return 1;
}

#ifdef __cplusplus
}
#endif

#endif
