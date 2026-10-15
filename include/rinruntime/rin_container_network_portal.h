/* SPDX-License-Identifier: MIT */
/*
 * User-space request/result contract for the privileged container-network
 * portal.  This is intentionally not the kernel adapter ABI: portal clients
 * can describe one native veth attachment but never receive kernel owner,
 * bridge, or namespace implementation records.
 */
#ifndef RIN_SHARED_RIN_CONTAINER_NETWORK_PORTAL_H
#define RIN_SHARED_RIN_CONTAINER_NETWORK_PORTAL_H

#include <stdint.h>

#define RIN_CONTAINER_NETWORK_PORTAL_VERSION UINT16_C(1)
#define RIN_CONTAINER_NETWORK_PORTAL_CALL_VERSION UINT16_C(1)
#define RIN_CONTAINER_NETWORK_PORTAL_MIN_MTU UINT32_C(576)
#define RIN_CONTAINER_NETWORK_PORTAL_MAX_MTU UINT32_C(1500)
#define RIN_CONTAINER_NETWORK_PORTAL_MAX_EXPECTED_HANDLES UINT32_C(8)
#define RIN_CONTAINER_NETWORK_PORTAL_CLEANUP_VERSION UINT16_C(1)

typedef uint64_t RinContainerNetworkPortalHandle;
typedef uint64_t RinContainerNetworkNamespaceHandle;

typedef enum RinContainerNetworkPortalStatus {
    RIN_CONTAINER_NETWORK_PORTAL_OK = 0,
    RIN_CONTAINER_NETWORK_PORTAL_INVALID_ARGUMENT = -1,
    RIN_CONTAINER_NETWORK_PORTAL_DENIED = -2,
    RIN_CONTAINER_NETWORK_PORTAL_STALE_HANDLE = -3,
    RIN_CONTAINER_NETWORK_PORTAL_CAPACITY = -4,
    RIN_CONTAINER_NETWORK_PORTAL_ALREADY_EXISTS = -5,
    RIN_CONTAINER_NETWORK_PORTAL_BUSY = -6,
    RIN_CONTAINER_NETWORK_PORTAL_RECONCILIATION_REQUIRED = -7,
    RIN_CONTAINER_NETWORK_PORTAL_DATAPATH_UNAVAILABLE = -8
} RinContainerNetworkPortalStatus;

typedef enum RinContainerNetworkPortalOperationV1 {
    RIN_CONTAINER_NETWORK_PORTAL_CREATE = 1,
    RIN_CONTAINER_NETWORK_PORTAL_QUERY = 2,
    RIN_CONTAINER_NETWORK_PORTAL_MOVE = 3,
    RIN_CONTAINER_NETWORK_PORTAL_DESTROY = 4,
    RIN_CONTAINER_NETWORK_PORTAL_RECONCILE = 5,
    RIN_CONTAINER_NETWORK_PORTAL_CLEANUP_ORPHANS = 6
} RinContainerNetworkPortalOperationV1;

/* The portal applies its fixed transaction policy: create the veth pair with
 * both endpoints down, configure IPv4 on the container endpoint, attach the
 * host endpoint to the selected bridge, then publish the link.  Namespace
 * handles are opaque generation handles; numeric kernel namespace IDs and
 * kernel implementation records never cross this boundary. */
typedef struct RinContainerNetworkPortalCreateRequestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    RinContainerNetworkNamespaceHandle host_namespace_handle;
    RinContainerNetworkNamespaceHandle container_namespace_handle;
    uint64_t interface_owner_uid;
    uint32_t mtu;
    uint32_t bridge_endpoint;
    char host_ifname[16];
    char container_ifname[16];
    uint8_t host_mac[6];
    uint8_t container_mac[6];
    uint8_t address[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t reserved0[2];
    uint64_t reserved[4];
} RinContainerNetworkPortalCreateRequestV1;

/* A client gets only an opaque attachment handle and the reconciliation bit.
 * Endpoint, bridge, interface, and namespace records remain portal-private. */
typedef struct RinContainerNetworkPortalBindingV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    RinContainerNetworkPortalHandle handle;
    uint32_t bridge_endpoint;
    uint32_t reconciliation_required;
    uint64_t reserved[4];
} RinContainerNetworkPortalBindingV1;

/* Endpoint migration replaces the container-side IPv4 state atomically.  The
 * call header carries the opaque attachment handle; this record carries only
 * the new namespace generation handle and address tuple. */
typedef struct RinContainerNetworkPortalMoveRequestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    RinContainerNetworkNamespaceHandle target_namespace_handle;
    uint8_t address[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t reserved0[4];
    uint64_t reserved[4];
} RinContainerNetworkPortalMoveRequestV1;

/* Admin-only startup sweep. The trusted runtime supplies its durable live
 * handle set; every kernel binding outside that set is destroyed or
 * reconciled once. The fixed bound matches the kernel adapter capacity. */
typedef struct RinContainerNetworkPortalCleanupRequestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint32_t expected_count;
    uint32_t reserved0;
    RinContainerNetworkPortalHandle expected_handles[
        RIN_CONTAINER_NETWORK_PORTAL_MAX_EXPECTED_HANDLES];
    uint64_t reserved[4];
} RinContainerNetworkPortalCleanupRequestV1;

typedef struct RinContainerNetworkPortalCleanupResultV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint32_t inspected;
    uint32_t cleaned;
    uint32_t remaining;
    uint32_t retryable;
    uint64_t reserved[4];
} RinContainerNetworkPortalCleanupResultV1;

typedef union RinContainerNetworkPortalResponseV1 {
    RinContainerNetworkPortalBindingV1 binding;
    RinContainerNetworkPortalCleanupResultV1 cleanup;
    uint8_t reserved[56];
} RinContainerNetworkPortalResponseV1;

/* One fixed-size portal transaction.  User space supplies opaque generation
 * handles only; kernel-owned veth, bridge, interface, and numeric namespace
 * records never cross this boundary. */
typedef struct RinContainerNetworkPortalCallV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint32_t flags;
    uint32_t reserved0;
    RinContainerNetworkPortalHandle handle;
    union {
        RinContainerNetworkPortalCreateRequestV1 create;
        RinContainerNetworkPortalMoveRequestV1 move;
        RinContainerNetworkPortalCleanupRequestV1 cleanup;
        uint8_t reserved_payload[136];
    } payload;
    uint64_t reserved[2];
} RinContainerNetworkPortalCallV1;

#if defined(__cplusplus)
static_assert(sizeof(RinContainerNetworkPortalBindingV1) == 56u,
              "RinContainerNetworkPortalBindingV1 ABI drift");
#else
_Static_assert(sizeof(RinContainerNetworkPortalBindingV1) == 56u,
               "RinContainerNetworkPortalBindingV1 ABI drift");
#endif

#if defined(__cplusplus)
static_assert(sizeof(RinContainerNetworkPortalMoveRequestV1) == 64u,
              "RinContainerNetworkPortalMoveRequestV1 ABI drift");
static_assert(sizeof(RinContainerNetworkPortalCallV1) == 176u,
              "RinContainerNetworkPortalCallV1 ABI drift");
static_assert(sizeof(RinContainerNetworkPortalCleanupRequestV1) == 112u,
              "RinContainerNetworkPortalCleanupRequestV1 ABI drift");
static_assert(sizeof(RinContainerNetworkPortalCleanupResultV1) == 56u,
              "RinContainerNetworkPortalCleanupResultV1 ABI drift");
static_assert(sizeof(RinContainerNetworkPortalResponseV1) == 56u,
              "RinContainerNetworkPortalResponseV1 ABI drift");
#else
_Static_assert(sizeof(RinContainerNetworkPortalMoveRequestV1) == 64u,
               "RinContainerNetworkPortalMoveRequestV1 ABI drift");
_Static_assert(sizeof(RinContainerNetworkPortalCallV1) == 176u,
               "RinContainerNetworkPortalCallV1 ABI drift");
_Static_assert(sizeof(RinContainerNetworkPortalCleanupRequestV1) == 112u,
               "RinContainerNetworkPortalCleanupRequestV1 ABI drift");
_Static_assert(sizeof(RinContainerNetworkPortalCleanupResultV1) == 56u,
               "RinContainerNetworkPortalCleanupResultV1 ABI drift");
_Static_assert(sizeof(RinContainerNetworkPortalResponseV1) == 56u,
               "RinContainerNetworkPortalResponseV1 ABI drift");
#endif

#endif /* RIN_SHARED_RIN_CONTAINER_NETWORK_PORTAL_H */
