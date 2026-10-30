/* SPDX-License-Identifier: MIT */
/* Private bounded RPC between RinRuntime clients and desktopd's D&D owner. */
#ifndef RINRUNTIME_DETAIL_DRAG_DROP_OWNER_PROTOCOL_H
#define RINRUNTIME_DETAIL_DRAG_DROP_OWNER_PROTOCOL_H

#include <stdint.h>
#include <rinruntime/drag_drop_client.h>
#include <rinruntime/clipboard.h>
#include <rin/file_portal.h>

#define RINRUNTIME_DRAG_DROP_OWNER_MAGIC UINT32_C(0x314f4452)
#define RINRUNTIME_DRAG_DROP_OWNER_VERSION UINT16_C(2)
#define RINRUNTIME_DRAG_DROP_OWNER_MAX_TEXT_BYTES \
    RINRUNTIME_DRAG_DROP_MAX_TEXT_BYTES
#define RINRUNTIME_DRAG_DROP_OWNER_MAX_MIME_BYTES UINT32_C(127)
#define RINRUNTIME_DRAG_DROP_OWNER_MAX_LABEL_BYTES UINT32_C(255)

enum {
    RINRUNTIME_DRAG_DROP_OWNER_REGISTER_TEXT = UINT16_C(1),
    RINRUNTIME_DRAG_DROP_OWNER_REGISTER_FILE = UINT16_C(2),
    RINRUNTIME_DRAG_DROP_OWNER_BIND_OFFER = UINT16_C(3),
    RINRUNTIME_DRAG_DROP_OWNER_RECEIVE = UINT16_C(4),
    RINRUNTIME_DRAG_DROP_OWNER_COMPLETE = UINT16_C(5),
    RINRUNTIME_DRAG_DROP_OWNER_SOURCE_RESULT = UINT16_C(6),
    RINRUNTIME_DRAG_DROP_OWNER_RELEASE = UINT16_C(7),
    RINRUNTIME_DRAG_DROP_OWNER_RELEASE_PAYLOAD = UINT16_C(8),
    RINRUNTIME_CLIPBOARD_OWNER_SET_BEGIN = UINT16_C(9),
    RINRUNTIME_CLIPBOARD_OWNER_SET_CHUNK = UINT16_C(10),
    RINRUNTIME_CLIPBOARD_OWNER_SET_FILE = UINT16_C(11),
    RINRUNTIME_CLIPBOARD_OWNER_SET_COMMIT = UINT16_C(12),
    RINRUNTIME_CLIPBOARD_OWNER_SET_ABORT = UINT16_C(13),
    RINRUNTIME_CLIPBOARD_OWNER_QUERY = UINT16_C(14),
    RINRUNTIME_CLIPBOARD_OWNER_READ_CHUNK = UINT16_C(15),
    RINRUNTIME_CLIPBOARD_OWNER_GET_FILE = UINT16_C(16)
};

enum {
    RINRUNTIME_DRAG_DROP_OWNER_PAYLOAD_NONE = UINT32_C(0),
    RINRUNTIME_DRAG_DROP_OWNER_PAYLOAD_TEXT = UINT32_C(1),
    RINRUNTIME_DRAG_DROP_OWNER_PAYLOAD_FILE = UINT32_C(2)
};

typedef struct RinRuntimeDragDropOwnerRequestV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t struct_size;
    uint32_t body_size;
    uint64_t offer_token;
    uint64_t generation;
    uint64_t capability;
    uint32_t action;
    uint32_t result;
    uint32_t mime_size;
    uint32_t label_size;
    RinFilePortalTokenV1 file_token;
    uint64_t offset;
    uint64_t data_size;
} RinRuntimeDragDropOwnerRequestV1;

typedef struct RinRuntimeDragDropOwnerResponseV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t struct_size;
    uint32_t result;
    uint32_t payload_type;
    uint32_t body_size;
    uint64_t capability;
    uint32_t completion;
    uint32_t reserved0;
    RinFilePortalTokenV1 file_token;
    uint64_t generation;
    uint64_t data_size;
    uint32_t format_count;
    uint32_t label_size;
    char label[RINRUNTIME_CLIPBOARD_MAX_LABEL_BYTES + 1u];
} RinRuntimeDragDropOwnerResponseV1;

#endif /* RINRUNTIME_DETAIL_DRAG_DROP_OWNER_PROTOCOL_H */
