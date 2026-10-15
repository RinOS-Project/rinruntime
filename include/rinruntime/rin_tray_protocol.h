/* SPDX-License-Identifier: MIT */
/*
 * Versioned userspace system-tray ABI.  The desktop shell is the only
 * consumer of this protocol; applications never get a callback pointer or a
 * path to execute.  Identity and ownership are supplied by the authenticated
 * UNIX peer and are deliberately absent from the wire descriptor.
 */
#ifndef RINOS_SHARED_RIN_TRAY_PROTOCOL_H
#define RINOS_SHARED_RIN_TRAY_PROTOCOL_H

#include <stdint.h>

#include <rin/contract_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_TRAY_PROTOCOL_VERSION 1u
#define RIN_TRAY_FRAME_MAGIC 0x31594152u /* "RAY1" */
#define RIN_TRAY_SOCKET_PATH "/run/rin/desktop-tray.sock"
#define RIN_TRAY_MAX_FRAME 4096u
#define RIN_TRAY_MAX_MENU_ITEMS 16u
#define RIN_TRAY_MAX_ITEMS_PER_APP 8u

enum RinTrayOperationV1 {
    RIN_TRAY_OP_REGISTER = 1u,
    RIN_TRAY_OP_UPDATE = 2u,
    RIN_TRAY_OP_UNREGISTER = 3u,
    RIN_TRAY_OP_PING = 4u,
};

enum RinTrayMenuFlagsV1 {
    RIN_TRAY_MENU_ENABLED = 1u << 0,
    RIN_TRAY_MENU_CHECKED = 1u << 1,
    RIN_TRAY_MENU_SEPARATOR = 1u << 2,
    RIN_TRAY_MENU_DESTRUCTIVE = 1u << 3,
    RIN_TRAY_MENU_SUBMENU = 1u << 4,
};

enum RinTrayItemFlagsV1 {
    RIN_TRAY_ITEM_ATTENTION = 1u << 0,
};

enum RinTrayEventKindV1 {
    RIN_TRAY_EVENT_ACTIVATED = 1u,
    RIN_TRAY_EVENT_CONTEXT_MENU = 2u,
};

typedef struct RinTrayFrameHeaderV1 {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
    uint32_t payload_size;
    uint32_t request_id;
    uint32_t flags;
} RinTrayFrameHeaderV1;

typedef struct RinTrayMenuItemV1 {
    uint64_t item_id;
    uint64_t parent_id;
    uint32_t flags;
    uint32_t reserved;
    char label[64];
    char accessibility_label[64];
} RinTrayMenuItemV1;

typedef struct RinTrayItemDescriptorV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t flags;
    uint32_t badge;
    uint32_t menu_count;
    uint32_t reserved;
    char label[64];
    char tooltip[96];
    /* Empty means “use the authenticated application's embedded icon”. */
    char icon_resource[160];
    /* Opaque action number delivered back to the owning client. */
    uint32_t activation_action_id;
    uint32_t reserved_action;
    RinTrayMenuItemV1 menu[RIN_TRAY_MAX_MENU_ITEMS];
} RinTrayItemDescriptorV1;

typedef struct RinTrayRequestV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t operation;
    uint32_t flags;
    uint64_t item_id;
    RinTrayItemDescriptorV1 descriptor;
} RinTrayRequestV1;

typedef struct RinTrayReplyV1 {
    uint32_t struct_size;
    uint32_t version;
    int32_t status;
    uint32_t flags;
    uint32_t request_id;
    uint32_t reserved;
    uint64_t item_id;
    uint64_t generation;
} RinTrayReplyV1;

typedef struct RinTrayEventV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t kind;
    uint32_t flags;
    uint64_t item_id;
    uint64_t menu_id;
    uint32_t activation_action_id;
    uint32_t reserved;
} RinTrayEventV1;

static inline int rin_tray_text_valid(const char* text, uint32_t capacity,
                                      int allow_empty)
{
    uint32_t i;
    if (!text || !capacity) return 0;
    for (i = 0u; i < capacity; ++i) {
        unsigned char value = (unsigned char)text[i];
        if (value == 0u) return allow_empty || i != 0u;
        if (value < 0x20u || value == 0x7fu) return 0;
    }
    return 0;
}

static inline int rin_tray_resource_valid(const char* path)
{
    uint32_t i;
    const char* prefix = 0;
    if (!path) return 0;
    if (path[0] == 0) return 1;
    if (path[0] != '/' || path[1] == '/') return 0;
    if (path[1] == 'r') prefix = "/res/";
    else if (path[1] == 'a') prefix = "/apps/";
    else if (path[1] == 's') prefix = "/sys/apps/";
    else return 0;
    for (i = 0u; prefix[i] != 0; ++i)
        if (path[i] == 0 || path[i] != prefix[i]) return 0;
    for (i = 0u; i < 160u; ++i) {
        unsigned char value = (unsigned char)path[i];
        if (value == 0u) return 1;
        if (value < 0x20u || value == 0x7fu || value == '\\') return 0;
        if (value == '.' && i + 1u < 160u && path[i + 1u] == '.') return 0;
    }
    return 0;
}

static inline int rin_tray_descriptor_valid(const RinTrayItemDescriptorV1* item)
{
    uint32_t i, j, parent;
    if (!item || item->struct_size != sizeof(*item) ||
        item->version != RIN_TRAY_PROTOCOL_VERSION ||
        (item->flags & ~RIN_TRAY_ITEM_ATTENTION) != 0u ||
        item->reserved != 0u || item->reserved_action != 0u ||
        item->menu_count > RIN_TRAY_MAX_MENU_ITEMS ||
        !rin_tray_text_valid(item->label, sizeof(item->label), 0) ||
        !rin_tray_text_valid(item->tooltip, sizeof(item->tooltip), 1) ||
        !rin_tray_resource_valid(item->icon_resource)) return 0;
    for (i = 0u; i < item->menu_count; ++i) {
        const RinTrayMenuItemV1* menu = &item->menu[i];
        if (!menu->item_id || menu->reserved != 0u ||
            (menu->flags & ~(RIN_TRAY_MENU_ENABLED | RIN_TRAY_MENU_CHECKED |
                             RIN_TRAY_MENU_SEPARATOR | RIN_TRAY_MENU_DESTRUCTIVE |
                             RIN_TRAY_MENU_SUBMENU)) != 0u ||
            !rin_tray_text_valid(menu->label, sizeof(menu->label),
                                 (menu->flags & RIN_TRAY_MENU_SEPARATOR) != 0u) ||
            !rin_tray_text_valid(menu->accessibility_label,
                                 sizeof(menu->accessibility_label), 1)) return 0;
        for (j = 0u; j < i; ++j)
            if (item->menu[j].item_id == menu->item_id) return 0;
        parent = 0u;
        for (j = 0u; j < item->menu_count; ++j)
            if (item->menu[j].item_id == menu->parent_id) {
                parent = j + 1u;
                break;
            }
        if (menu->parent_id != 0u && parent == 0u) return 0;
        if (menu->parent_id != 0u) {
            uint64_t ancestor = menu->parent_id;
            for (uint32_t depth = 0u; depth < 4u && ancestor != 0u; ++depth) {
                uint32_t parent_index = item->menu_count;
                for (uint32_t candidate = 0u; candidate < item->menu_count; ++candidate)
                    if (item->menu[candidate].item_id == ancestor) {
                        parent_index = candidate;
                        break;
                    }
                if (parent_index == item->menu_count) return 0;
                if (item->menu[parent_index].parent_id == menu->item_id) return 0;
                ancestor = item->menu[parent_index].parent_id;
                if (depth == 3u && ancestor != 0u) return 0;
            }
        }
    }
    return 1;
}

#if defined(__cplusplus)
static_assert(sizeof(RinTrayFrameHeaderV1) == 24, "tray frame ABI drift");
static_assert(sizeof(RinTrayMenuItemV1) == 152, "tray menu ABI drift");
static_assert(sizeof(RinTrayEventV1) == 40, "tray event ABI drift");
#else
_Static_assert(sizeof(RinTrayFrameHeaderV1) == 24, "tray frame ABI drift");
_Static_assert(sizeof(RinTrayMenuItemV1) == 152, "tray menu ABI drift");
_Static_assert(sizeof(RinTrayEventV1) == 40, "tray event ABI drift");
#endif

#ifdef __cplusplus
}
#endif

#endif
