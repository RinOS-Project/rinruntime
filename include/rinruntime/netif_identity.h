// SPDX-License-Identifier: MIT
#ifndef RIN_SHARED_NETIF_IDENTITY_H
#define RIN_SHARED_NETIF_IDENTITY_H

#include <stdint.h>

#include <rin/net/netif_abi.h>

#define RIN_NETIF_IDENTITY_OK           0
#define RIN_NETIF_IDENTITY_INVALID     -1
#define RIN_NETIF_IDENTITY_UNAVAILABLE -2
#define RIN_NETIF_IDENTITY_RETIRED     -3
#define RIN_NETIF_IDENTITY_BUSY        -4

typedef struct RinNetifIdentity {
    uint32_t sequence;
    uint16_t generation;
    uint8_t ready;
    uint8_t retired;
    char name[RIN_NETINFO_IFNAME_MAX];
} RinNetifIdentity;

int rin_netif_identity_prepare_name(
    const char* name, char output[RIN_NETINFO_IFNAME_MAX]);
int rin_netif_identity_publish(RinNetifIdentity* identity, const char* name,
                               uint16_t* index_out);
int rin_netif_identity_revoke(RinNetifIdentity* identity);
int rin_netif_identity_snapshot(
    const RinNetifIdentity* identity,
    char name_out[RIN_NETINFO_IFNAME_MAX], uint16_t* index_out);

#if defined(__cplusplus)
static_assert(sizeof(RinNetifIdentity) == 24u,
              "RinNetifIdentity ABI drift");
#else
_Static_assert(sizeof(RinNetifIdentity) == 24u,
               "RinNetifIdentity ABI drift");
#endif

#endif
