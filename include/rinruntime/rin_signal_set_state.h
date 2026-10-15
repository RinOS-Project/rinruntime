/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_RIN_SIGNAL_SET_STATE_H
#define RIN_SHARED_RIN_SIGNAL_SET_STATE_H

#include <stdint.h>

#define RIN_SIGNAL_SET_BYTES32 UINT32_C(4)
#define RIN_SIGNAL_SET_BYTES64 UINT32_C(8)
#define RIN_SIGNAL_BLOCK       0
#define RIN_SIGNAL_UNBLOCK     1
#define RIN_SIGNAL_SETMASK     2

#define RIN_SIGNAL_UNBLOCKABLE32 \
    ((UINT32_C(1) << 9) | (UINT32_C(1) << 19))
#define RIN_SIGNAL_UNBLOCKABLE64 \
    ((UINT64_C(1) << 9) | (UINT64_C(1) << 19))

static inline int rin_signal_mask_next32(uint32_t current, int how,
                                         uint32_t requested,
                                         uint32_t* next)
{
    uint32_t value;
    if (!next) return -1;
    switch (how) {
    case RIN_SIGNAL_BLOCK:
        value = current | requested;
        break;
    case RIN_SIGNAL_UNBLOCK:
        value = current & ~requested;
        break;
    case RIN_SIGNAL_SETMASK:
        value = requested;
        break;
    default:
        return -1;
    }
    *next = value & ~RIN_SIGNAL_UNBLOCKABLE32;
    return 0;
}

static inline int rin_signal_mask_next64(uint64_t current, int how,
                                         uint64_t requested,
                                         uint64_t* next)
{
    uint64_t value;
    if (!next) return -1;
    switch (how) {
    case RIN_SIGNAL_BLOCK:
        value = current | requested;
        break;
    case RIN_SIGNAL_UNBLOCK:
        value = current & ~requested;
        break;
    case RIN_SIGNAL_SETMASK:
        value = requested;
        break;
    default:
        return -1;
    }
    *next = value & ~RIN_SIGNAL_UNBLOCKABLE64;
    return 0;
}

static inline uint32_t rin_signal_pending_blocked32(uint32_t pending,
                                                    uint32_t blocked)
{
    return pending & blocked;
}

static inline uint64_t rin_signal_pending_blocked64(uint64_t pending,
                                                    uint64_t blocked)
{
    return pending & blocked;
}

#endif
