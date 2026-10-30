/* SPDX-License-Identifier: MIT */
/* RinRuntime client for the compositor's authenticated native D&D path. */

#ifndef RINRUNTIME_DRAG_DROP_CLIENT_H
#define RINRUNTIME_DRAG_DROP_CLIENT_H

#include <stdint.h>
#include "window.h"
#include <rin/file_portal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_DRAG_DROP_VERSION UINT16_C(1)
#define RINRUNTIME_DRAG_DROP_MAX_PAYLOADS UINT32_C(16)
#define RINRUNTIME_DRAG_DROP_MAX_TEXT_BYTES UINT32_C(65536)
#define RINRUNTIME_DRAG_DROP_MAX_MIME_BYTES UINT32_C(127)
#define RINRUNTIME_DRAG_DROP_MAX_LABEL_BYTES UINT32_C(255)

enum {
    RINRUNTIME_DRAG_DROP_COPY = UINT32_C(1),
    RINRUNTIME_DRAG_DROP_MOVE = UINT32_C(2),
    RINRUNTIME_DRAG_DROP_LINK = UINT32_C(4)
};

enum {
    RINRUNTIME_DRAG_DROP_STATE_NONE = UINT32_C(0),
    RINRUNTIME_DRAG_DROP_STATE_OFFERED = UINT32_C(1),
    RINRUNTIME_DRAG_DROP_STATE_ACCEPTED = UINT32_C(2),
    RINRUNTIME_DRAG_DROP_STATE_DROPPED = UINT32_C(3)
};

enum {
    RINRUNTIME_DRAG_DROP_PAYLOAD_TEXT = UINT32_C(1),
    RINRUNTIME_DRAG_DROP_PAYLOAD_FILE = UINT32_C(2)
};

/* A payload reference is an opaque File Portal capability produced by an
 * authenticated owner. The public ABI carries no file path or descriptor. */
typedef struct RinRuntimeDragDropPayloadV1 {
    uint32_t mime_size;
    uint32_t label_size;
    uint32_t payload_size;
    uint32_t reserved0;
    uint64_t payload_capability;
    char mime[RINRUNTIME_DRAG_DROP_MAX_MIME_BYTES + 1u];
    char label[RINRUNTIME_DRAG_DROP_MAX_LABEL_BYTES + 1u];
} RinRuntimeDragDropPayloadV1;

typedef struct RinRuntimeDragDropOfferV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint64_t offer_token;
    uint64_t generation;
    uint64_t origin_peer;
    uint64_t target_handle;
    uint32_t action;
    uint32_t state;
    uint32_t payload_count;
    uint32_t reserved0;
    RinRuntimeDragDropPayloadV1
        payloads[RINRUNTIME_DRAG_DROP_MAX_PAYLOADS];
} RinRuntimeDragDropOfferV1;

/* Begins an offer for a live window. session_id and generation are caller
 * lifecycle identifiers; offer_token is issued by Compositor. Payload
 * capabilities remain opaque and are resolved only by the File Portal owner. */
int rinruntime_drag_drop_begin_v1(
    RinRuntimeGuiHandle source, uint64_t session_id, uint64_t generation,
    uint32_t actions, const RinRuntimeDragDropPayloadV1* payloads,
    uint32_t payload_count, uint64_t* offer_token_out);

/* Re-targets an active source offer to the surface under the compositor's
 * current physical pointer. The target app learns of the offer through poll. */
int rinruntime_drag_drop_update_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation,
    uint32_t action, uint64_t* target_handle_out, uint32_t* state_out);

/* A target can accept only an offer currently addressed to its own window. */
int rinruntime_drag_drop_accept_v1(
    RinRuntimeGuiHandle target, uint64_t offer_token, uint64_t generation,
    uint32_t action);

int rinruntime_drag_drop_drop_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation);
int rinruntime_drag_drop_cancel_v1(
    RinRuntimeGuiHandle source, uint64_t offer_token, uint64_t generation);

/* Returns RIN_RESULT_OK with state NONE when no offer is pending. A live offer
 * is not consumed by polling; final DROPPED publications are consumed once. */
int rinruntime_drag_drop_poll_v1(
    RinRuntimeGuiHandle target, RinRuntimeDragDropOfferV1* offer_out);

/* Registers text bytes or a regular file descriptor with the authenticated
 * desktopd owner. File registration returns only an opaque capability; the
 * descriptor is converted to a target-bound File Portal token internally. */
int rinruntime_drag_drop_payload_register_text_v1(
    const char* mime, const char* label, const void* bytes,
    uint32_t byte_count, uint64_t* payload_capability_out);
int rinruntime_drag_drop_payload_register_file_v1(
    int32_t source_fd, const char* mime, const char* label,
    uint64_t* payload_capability_out);
int rinruntime_drag_drop_payload_release_v1(uint64_t payload_capability);

/* Receives a completed, accepted offer payload. Text is copied into the
 * supplied bounded buffer; files return a one-use token for the caller. */
int rinruntime_drag_drop_receive_v1(
    uint64_t offer_token, uint64_t generation, uint64_t payload_capability,
    void* text_bytes, uint32_t text_capacity, uint32_t* text_size_out,
    RinFilePortalTokenV1* file_token_out, uint32_t* payload_type_out);
int rinruntime_drag_drop_complete_v1(
    uint64_t offer_token, uint64_t generation, uint32_t result);
int rinruntime_drag_drop_source_result_v1(
    uint64_t offer_token, uint64_t generation, uint32_t* result_out);
int rinruntime_drag_drop_release_v1(uint64_t offer_token,
                                    uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_DRAG_DROP_CLIENT_H */
