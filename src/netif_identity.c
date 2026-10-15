// SPDX-License-Identifier: MIT
#include "netif_identity.h"

#include <stddef.h>
#include <string.h>

static int identity_begin_write(RinNetifIdentity* identity,
                                uint32_t* sequence_out)
{
    uint32_t sequence;
    if (!identity || !sequence_out)
        return RIN_NETIF_IDENTITY_INVALID;
    sequence = __atomic_load_n(&identity->sequence, __ATOMIC_ACQUIRE);
    if ((sequence & 1u) != 0u || sequence > UINT32_MAX - 2u)
        return RIN_NETIF_IDENTITY_BUSY;
    if (!__atomic_compare_exchange_n(&identity->sequence, &sequence,
                                     sequence + 1u, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE))
        return RIN_NETIF_IDENTITY_BUSY;
    *sequence_out = sequence;
    return RIN_NETIF_IDENTITY_OK;
}

static void identity_end_write(RinNetifIdentity* identity, uint32_t sequence)
{
    __atomic_store_n(&identity->sequence, sequence + 2u, __ATOMIC_RELEASE);
}

int rin_netif_identity_prepare_name(
    const char* name, char output[RIN_NETINFO_IFNAME_MAX])
{
    uint32_t index;
    if (output != NULL)
        memset(output, 0, RIN_NETINFO_IFNAME_MAX);
    if (!name || !output)
        return RIN_NETIF_IDENTITY_INVALID;
    for (index = 0u; index < RIN_NETINFO_IFNAME_MAX; ++index) {
        unsigned char ch = (unsigned char)name[index];
        if (ch == 0u) {
            if (index == 0u)
                return RIN_NETIF_IDENTITY_INVALID;
            while (index < RIN_NETINFO_IFNAME_MAX)
                output[index++] = '\0';
            return RIN_NETIF_IDENTITY_OK;
        }
        if (!((ch >= 'a' && ch <= 'z') ||
              (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' ||
              ch == '.'))
        {
            memset(output, 0, RIN_NETINFO_IFNAME_MAX);
            return RIN_NETIF_IDENTITY_INVALID;
        }
        output[index] = (char)ch;
    }
    memset(output, 0, RIN_NETINFO_IFNAME_MAX);
    return RIN_NETIF_IDENTITY_INVALID;
}

int rin_netif_identity_publish(RinNetifIdentity* identity, const char* name,
                               uint16_t* index_out)
{
    char candidate[RIN_NETINFO_IFNAME_MAX];
    uint32_t sequence;
    uint16_t generation;
    int status;
    if (index_out != NULL) *index_out = 0u;
    if (!index_out ||
        rin_netif_identity_prepare_name(name, candidate) !=
            RIN_NETIF_IDENTITY_OK)
        return RIN_NETIF_IDENTITY_INVALID;
    status = identity_begin_write(identity, &sequence);
    if (status != RIN_NETIF_IDENTITY_OK)
        return status;
    generation = __atomic_load_n(&identity->generation, __ATOMIC_RELAXED);
    if (__atomic_load_n(&identity->retired, __ATOMIC_RELAXED) != 0u ||
        generation == UINT16_MAX) {
        __atomic_store_n(&identity->ready, 0u, __ATOMIC_RELAXED);
        __atomic_store_n(&identity->retired, 1u, __ATOMIC_RELAXED);
        identity_end_write(identity, sequence);
        return RIN_NETIF_IDENTITY_RETIRED;
    }
    __atomic_store_n(&identity->ready, 0u, __ATOMIC_RELAXED);
    for (uint32_t index = 0u; index < RIN_NETINFO_IFNAME_MAX; ++index)
        __atomic_store_n(&identity->name[index], candidate[index],
                         __ATOMIC_RELAXED);
    ++generation;
    __atomic_store_n(&identity->generation, generation, __ATOMIC_RELAXED);
    __atomic_store_n(&identity->ready, 1u, __ATOMIC_RELAXED);
    identity_end_write(identity, sequence);
    *index_out = generation;
    return RIN_NETIF_IDENTITY_OK;
}

int rin_netif_identity_revoke(RinNetifIdentity* identity)
{
    uint32_t sequence;
    int status = identity_begin_write(identity, &sequence);
    if (status != RIN_NETIF_IDENTITY_OK)
        return status;
    __atomic_store_n(&identity->ready, 0u, __ATOMIC_RELAXED);
    identity_end_write(identity, sequence);
    return RIN_NETIF_IDENTITY_OK;
}

int rin_netif_identity_snapshot(
    const RinNetifIdentity* identity,
    char name_out[RIN_NETINFO_IFNAME_MAX], uint16_t* index_out)
{
    uint32_t attempt;
    if (name_out != NULL)
        memset(name_out, 0, RIN_NETINFO_IFNAME_MAX);
    if (index_out != NULL) *index_out = 0u;
    if (!identity || !name_out || !index_out)
        return RIN_NETIF_IDENTITY_INVALID;
    for (attempt = 0u; attempt < 4u; ++attempt) {
        char candidate[RIN_NETINFO_IFNAME_MAX];
        uint32_t before = __atomic_load_n(&identity->sequence,
                                          __ATOMIC_ACQUIRE);
        uint8_t ready;
        uint16_t generation;
        uint32_t after;
        if ((before & 1u) != 0u)
            continue;
        ready = __atomic_load_n(&identity->ready, __ATOMIC_RELAXED);
        generation = __atomic_load_n(&identity->generation,
                                      __ATOMIC_RELAXED);
        for (uint32_t index = 0u; index < RIN_NETINFO_IFNAME_MAX; ++index)
            candidate[index] = __atomic_load_n(&identity->name[index],
                                               __ATOMIC_RELAXED);
        after = __atomic_load_n(&identity->sequence, __ATOMIC_ACQUIRE);
        if (before != after || (after & 1u) != 0u)
            continue;
        if (ready == 0u || generation == 0u)
            return RIN_NETIF_IDENTITY_UNAVAILABLE;
        for (uint32_t index = 0u; index < RIN_NETINFO_IFNAME_MAX; ++index)
            name_out[index] = candidate[index];
        *index_out = generation;
        return RIN_NETIF_IDENTITY_OK;
    }
    return RIN_NETIF_IDENTITY_BUSY;
}
