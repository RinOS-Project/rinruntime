/* SPDX-License-Identifier: MIT */
/* Public, path-free client contract for File Manager's chooser portal. */

#ifndef RINRUNTIME_FILE_CHOOSER_PORTAL_H
#define RINRUNTIME_FILE_CHOOSER_PORTAL_H

#include <stddef.h>
#include <stdint.h>

#include "file_portal.h"
#include <rin/net/socket_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_FILE_CHOOSER_MAGIC UINT32_C(0x50434652) /* "RFCP" */
#define RINRUNTIME_FILE_CHOOSER_VERSION UINT16_C(1)
#define RINRUNTIME_FILE_CHOOSER_SERVICE_PATH "/run/rin/file-chooser.portal"
#define RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME UINT32_C(255)
#define RINRUNTIME_FILE_CHOOSER_ATOMIC_SAVE_MAX_BYTES (UINT64_C(256) * 1024u * 1024u)
#define RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS UINT32_C(8)

typedef enum RinRuntimeFileChooserKind {
    RINRUNTIME_FILE_CHOOSER_OPEN = 1,
    RINRUNTIME_FILE_CHOOSER_SAVE = 2,
    RINRUNTIME_FILE_CHOOSER_FOLDER = 3
} RinRuntimeFileChooserKind;

typedef enum RinRuntimeFileChooserResult {
    RINRUNTIME_FILE_CHOOSER_OK = 0,
    /* Returned by the non-blocking poll API while the authenticated File
     * Manager surface is still waiting for user input.  This value is local
     * client state and is never encoded on the wire. */
    RINRUNTIME_FILE_CHOOSER_IN_PROGRESS = 1,
    RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT = -1,
    RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY = -2,
    RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED = -3,
    RINRUNTIME_FILE_CHOOSER_IO_FAILED = -4,
    RINRUNTIME_FILE_CHOOSER_DENIED = -5,
    RINRUNTIME_FILE_CHOOSER_CANCELLED = -6,
    RINRUNTIME_FILE_CHOOSER_SERVER_FAILED = -7,
    /* The replacement is visible, but a parent-directory sync did not
     * complete. Callers must not blindly retry this outcome. */
    RINRUNTIME_FILE_CHOOSER_COMMITTED_UNSYNCED = -8
} RinRuntimeFileChooserResult;

typedef struct __attribute__((packed)) RinRuntimeFileChooserFrameV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t frame_size;
    uint64_t request_id;
} RinRuntimeFileChooserFrameV1;

#define RINRUNTIME_FILE_CHOOSER_OPERATION_REQUEST UINT16_C(1)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_GRANT UINT16_C(2)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_GRANT UINT16_C(3)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_REQUEST UINT16_C(4)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY UINT16_C(5)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_COMPLETE UINT16_C(6)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE UINT16_C(7)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE_COMPLETE UINT16_C(8)
#define RINRUNTIME_FILE_CHOOSER_OPERATION_MULTIPLE_GRANT UINT16_C(9)
/* Only the signed system archived service may use this operation.  The
 * origin peer in the request is checked against the broker's capability
 * record; it is not accepted as a replacement for peer authentication. */
#define RINRUNTIME_FILE_CHOOSER_OPERATION_DELEGATED_ATOMIC_SAVE_REQUEST UINT16_C(10)

/* A Save request with this flag asks File Manager to retain the user-approved
 * destination as an opaque, peer-bound capability. It intentionally does not
 * issue a writable filesystem descriptor. */
#define RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ATOMIC_SAVE_DESTINATION UINT32_C(0x00000001)
/* Open-only request flag: return up to MAX_SELECTIONS regular files. */
#define RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ALLOW_MULTIPLE UINT32_C(0x00000002)

/* REQUEST is followed by exactly suggested_name_size non-NUL bytes.  It never
 * accepts a path or initial directory: selection remains entirely inside the
 * user-visible File Manager broker. */
typedef struct __attribute__((packed)) RinRuntimeFileChooserRequestV1 {
    RinRuntimeFileChooserFrameV1 frame;
    uint32_t kind;
    uint32_t requested_rights;
    uint32_t suggested_name_size;
    uint32_t flags;
    uint64_t reserved;
} RinRuntimeFileChooserRequestV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserGrantV1 {
    RinRuntimeFileChooserFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinFilePortalTokenV1 token;
} RinRuntimeFileChooserGrantV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserSelectionV1 {
    RinFilePortalTokenV1 token;
    uint32_t display_name_size;
    uint32_t reserved;
    char display_name[RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME + 1u];
} RinRuntimeFileChooserSelectionV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserMultipleGrantV1 {
    RinRuntimeFileChooserFrameV1 frame;
    int32_t result;
    uint32_t selection_count;
    RinRuntimeFileChooserSelectionV1 selections[RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS];
    uint64_t reserved[2];
} RinRuntimeFileChooserMultipleGrantV1;

/* This value is opaque to applications. File Manager binds it to the
 * authenticated process identity that selected the destination; it is not a
 * pathname and cannot be used after broker restart or explicit release. */
typedef struct __attribute__((packed)) RinRuntimeFileChooserSaveCapabilityV1 {
    uint8_t bytes[32];
} RinRuntimeFileChooserSaveCapabilityV1;

/* Stable, opaque identity for the object selected by an Open/Folder chooser.
 * It is derived from the broker-issued token, never from a pathname. The
 * bytes are only for a trusted recent-item broker; clients must not parse
 * them or use them as filesystem authority. */
#define RINRUNTIME_FILE_CHOOSER_DOCUMENT_ID_SIZE UINT32_C(32)
typedef struct __attribute__((packed)) RinRuntimeFileChooserDocumentIdentityV1 {
    uint8_t bytes[RINRUNTIME_FILE_CHOOSER_DOCUMENT_ID_SIZE];
} RinRuntimeFileChooserDocumentIdentityV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserSaveDestinationGrantV1 {
    RinRuntimeFileChooserFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinRuntimeFileChooserSaveCapabilityV1 capability;
} RinRuntimeFileChooserSaveDestinationGrantV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserAtomicSaveRequestV1 {
    RinRuntimeFileChooserFrameV1 frame;
    RinRuntimeFileChooserSaveCapabilityV1 capability;
    uint64_t data_size;
    uint64_t reserved;
} RinRuntimeFileChooserAtomicSaveRequestV1;

/* A path-free archive publication request.  archived connects as the
 * authenticated service, while origin_peer identifies the application that
 * received the user-approved save capability.  File Manager requires both
 * identities and never trusts a caller-provided pathname. */
typedef struct __attribute__((packed)) RinRuntimeFileChooserDelegatedAtomicSaveRequestV1 {
    RinRuntimeFileChooserFrameV1 frame;
    RinRuntimeFileChooserSaveCapabilityV1 capability;
    rin_unix_peer_app_identity_v1 origin_peer;
    uint64_t data_size;
    uint64_t reserved;
} RinRuntimeFileChooserDelegatedAtomicSaveRequestV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserStatusV1 {
    RinRuntimeFileChooserFrameV1 frame;
    int32_t result;
    uint32_t reserved;
} RinRuntimeFileChooserStatusV1;

typedef struct __attribute__((packed)) RinRuntimeFileChooserSaveDestinationReleaseV1 {
    RinRuntimeFileChooserFrameV1 frame;
    RinRuntimeFileChooserSaveCapabilityV1 capability;
} RinRuntimeFileChooserSaveDestinationReleaseV1;

typedef struct RinRuntimeFileChooserRequestViewV1 {
    uint64_t request_id;
    RinRuntimeFileChooserKind kind;
    uint32_t requested_rights;
    const char* suggested_name;
    size_t suggested_name_size;
    uint32_t flags;
} RinRuntimeFileChooserRequestViewV1;

typedef struct RinRuntimeFileChooserRequestV1Input {
    RinRuntimeFileChooserKind kind;
    uint32_t requested_rights;
    const char* suggested_name;
    size_t suggested_name_size;
    uint32_t flags;
} RinRuntimeFileChooserRequestV1Input;

/* The async client owns one authenticated chooser connection.  The request
 * and reply buffers are inline so external SDK clients need no allocator and
 * can keep the object in application state.  A reply is one complete
 * Open/Folder grant, bounded multiple-file grant, or Save-destination grant;
 * no pathname crosses this API. */
#define RINRUNTIME_FILE_CHOOSER_ASYNC_REQUEST_MAX UINT32_C(512)
#define RINRUNTIME_FILE_CHOOSER_ASYNC_REPLY_MAX \
    ((sizeof(RinRuntimeFileChooserMultipleGrantV1) > \
      sizeof(RinRuntimeFileChooserSaveDestinationGrantV1)) \
         ? sizeof(RinRuntimeFileChooserMultipleGrantV1) \
         : sizeof(RinRuntimeFileChooserSaveDestinationGrantV1))

typedef enum RinRuntimeFileChooserAsyncState {
    RINRUNTIME_FILE_CHOOSER_ASYNC_IDLE = 0,
    RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING = 1,
    RINRUNTIME_FILE_CHOOSER_ASYNC_WAITING = 2,
    RINRUNTIME_FILE_CHOOSER_ASYNC_COMPLETE = 3,
    RINRUNTIME_FILE_CHOOSER_ASYNC_FAILED = 4
} RinRuntimeFileChooserAsyncState;

typedef struct RinRuntimeFileChooserAsyncV1 {
    int32_t socket_fd;
    uint32_t state;
    uint32_t kind;
    uint32_t allow_multiple;
    uint32_t request_size;
    uint32_t request_offset;
    uint32_t reply_size;
    uint32_t reply_offset;
    uint64_t request_id;
    RinRuntimeFileChooserResult terminal_result;
    uint32_t reserved;
    uint8_t request[RINRUNTIME_FILE_CHOOSER_ASYNC_REQUEST_MAX];
    uint8_t reply[RINRUNTIME_FILE_CHOOSER_ASYNC_REPLY_MAX];
} RinRuntimeFileChooserAsyncV1;

void rinruntime_file_chooser_async_init(
    RinRuntimeFileChooserAsyncV1* async_client);

/* Starts an authenticated Open/Folder or Save-destination chooser request.
 * The function never waits for user input.  Call poll() from the application
 * loop until it returns a terminal result; cancel() closes the sole socket
 * owner and zeroes all pending wire material. */
RinRuntimeFileChooserResult rinruntime_file_chooser_begin(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinRuntimeFileChooserAsyncV1* async_client);
RinRuntimeFileChooserResult rinruntime_file_chooser_poll(
    RinRuntimeFileChooserAsyncV1* async_client,
    RinRuntimeFileChooserResult* result_out,
    RinFilePortalTokenV1* token_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out);
void rinruntime_file_chooser_cancel(RinRuntimeFileChooserAsyncV1* async_client);

RinRuntimeFileChooserResult rinruntime_file_chooser_poll_multiple(
    RinRuntimeFileChooserAsyncV1* async_client,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSelectionV1* selections_out,
    uint32_t* selection_count_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out);

/* Open and Folder requests return an authenticated single-use token. Save is
 * deliberately excluded: use save_destination_request() and atomic_save() so
 * the broker, rather than an application descriptor, owns replacement. Call
 * rinruntime_file_portal_open() to install an Open/Folder descriptor. */
RinRuntimeFileChooserResult rinruntime_file_chooser_request(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinFilePortalTokenV1* token_out);

/* Requests a user-approved, process-bound atomic-save destination. `request`
 * must be a SAVE request with REQUEST_FLAG_ATOMIC_SAVE_DESTINATION set. */
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_request(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out);

/* Streams `data_size` bytes to the trusted broker. It writes an exclusive
 * same-directory temporary, syncs it, atomically replaces the selected target,
 * then syncs the parent directory. No application pathname is accepted. */
RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save(
    const RinRuntimeFileChooserSaveCapabilityV1* capability,
    const void* data, uint64_t data_size);

/* Discards the broker-side destination record. Failure is safe to ignore on
 * process shutdown because the broker also drops records on restart. */
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release(
    const RinRuntimeFileChooserSaveCapabilityV1* capability);

/* These codec functions let a trusted chooser implementation share the exact
 * public wire validation with external SDK clients. */
RinRuntimeFileChooserResult rinruntime_file_chooser_request_encode(
    uint64_t request_id, const RinRuntimeFileChooserRequestV1Input* request,
    void* frame_out, size_t frame_capacity, size_t* frame_size_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_request_decode(
    const void* frame, size_t frame_size,
    RinRuntimeFileChooserRequestViewV1* request_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinFilePortalTokenV1* token,
    RinRuntimeFileChooserGrantV1* grant_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_grant_decode(
    const RinRuntimeFileChooserGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out, RinFilePortalTokenV1* token_out,
    uint64_t* request_id_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_multiple_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinRuntimeFileChooserSelectionV1* selections, uint32_t selection_count,
    RinRuntimeFileChooserMultipleGrantV1* grant_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_multiple_grant_decode(
    const RinRuntimeFileChooserMultipleGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSelectionV1* selections_out,
    uint32_t* selection_count_out, uint64_t* request_id_out);
int rinruntime_file_chooser_save_capability_valid(
    const RinRuntimeFileChooserSaveCapabilityV1* capability);
int rinruntime_file_chooser_document_identity_valid(
    const RinRuntimeFileChooserDocumentIdentityV1* identity);
RinRuntimeFileChooserResult rinruntime_file_chooser_document_identity_from_token(
    const RinFilePortalTokenV1* token,
    RinRuntimeFileChooserDocumentIdentityV1* identity_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinRuntimeFileChooserSaveCapabilityV1* capability,
    RinRuntimeFileChooserSaveDestinationGrantV1* grant_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_grant_decode(
    const RinRuntimeFileChooserSaveDestinationGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* request_id_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save_request_encode(
    uint64_t request_id, const RinRuntimeFileChooserSaveCapabilityV1* capability,
    uint64_t data_size, RinRuntimeFileChooserAtomicSaveRequestV1* request_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save_request_decode(
    const RinRuntimeFileChooserAtomicSaveRequestV1* request, size_t frame_size,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* data_size_out, uint64_t* request_id_out);
RinRuntimeFileChooserResult
rinruntime_file_chooser_delegated_atomic_save_request_encode(
    uint64_t request_id,
    const RinRuntimeFileChooserSaveCapabilityV1* capability,
    const rin_unix_peer_app_identity_v1* origin_peer, uint64_t data_size,
    RinRuntimeFileChooserDelegatedAtomicSaveRequestV1* request_out);
RinRuntimeFileChooserResult
rinruntime_file_chooser_delegated_atomic_save_request_decode(
    const RinRuntimeFileChooserDelegatedAtomicSaveRequestV1* request,
    size_t frame_size,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    rin_unix_peer_app_identity_v1* origin_peer_out, uint64_t* data_size_out,
    uint64_t* request_id_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_status_encode(
    uint16_t operation, uint64_t request_id, RinRuntimeFileChooserResult result,
    RinRuntimeFileChooserStatusV1* status_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_status_decode(
    const RinRuntimeFileChooserStatusV1* status, size_t frame_size,
    uint16_t expected_operation, RinRuntimeFileChooserResult* result_out,
    uint64_t* request_id_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release_encode(
    uint64_t request_id, const RinRuntimeFileChooserSaveCapabilityV1* capability,
    RinRuntimeFileChooserSaveDestinationReleaseV1* release_out);
RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release_decode(
    const RinRuntimeFileChooserSaveDestinationReleaseV1* release,
    size_t frame_size, RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* request_id_out);

#if defined(__cplusplus)
static_assert(sizeof(RinRuntimeFileChooserFrameV1) == 20u,
              "RinRuntimeFileChooserFrameV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserRequestV1) == 44u,
              "RinRuntimeFileChooserRequestV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserGrantV1) == 236u,
              "RinRuntimeFileChooserGrantV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserSelectionV1) == 472u,
              "RinRuntimeFileChooserSelectionV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserMultipleGrantV1) == 3820u,
              "RinRuntimeFileChooserMultipleGrantV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserSaveCapabilityV1) == 32u,
              "RinRuntimeFileChooserSaveCapabilityV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserDocumentIdentityV1) == 32u,
              "RinRuntimeFileChooserDocumentIdentityV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserSaveDestinationGrantV1) == 60u,
              "RinRuntimeFileChooserSaveDestinationGrantV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserAtomicSaveRequestV1) == 68u,
              "RinRuntimeFileChooserAtomicSaveRequestV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserDelegatedAtomicSaveRequestV1) == 148u,
              "RinRuntimeFileChooserDelegatedAtomicSaveRequestV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserStatusV1) == 28u,
              "RinRuntimeFileChooserStatusV1 ABI drift");
static_assert(sizeof(RinRuntimeFileChooserSaveDestinationReleaseV1) == 52u,
              "RinRuntimeFileChooserSaveDestinationReleaseV1 ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeFileChooserFrameV1) == 20u,
               "RinRuntimeFileChooserFrameV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserRequestV1) == 44u,
               "RinRuntimeFileChooserRequestV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserGrantV1) == 236u,
               "RinRuntimeFileChooserGrantV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserSelectionV1) == 472u,
               "RinRuntimeFileChooserSelectionV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserMultipleGrantV1) == 3820u,
               "RinRuntimeFileChooserMultipleGrantV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserSaveCapabilityV1) == 32u,
               "RinRuntimeFileChooserSaveCapabilityV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserDocumentIdentityV1) == 32u,
               "RinRuntimeFileChooserDocumentIdentityV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserSaveDestinationGrantV1) == 60u,
               "RinRuntimeFileChooserSaveDestinationGrantV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserAtomicSaveRequestV1) == 68u,
               "RinRuntimeFileChooserAtomicSaveRequestV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserDelegatedAtomicSaveRequestV1) == 148u,
               "RinRuntimeFileChooserDelegatedAtomicSaveRequestV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserStatusV1) == 28u,
               "RinRuntimeFileChooserStatusV1 ABI drift");
_Static_assert(sizeof(RinRuntimeFileChooserSaveDestinationReleaseV1) == 52u,
               "RinRuntimeFileChooserSaveDestinationReleaseV1 ABI drift");
#endif

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FILE_CHOOSER_PORTAL_H */

