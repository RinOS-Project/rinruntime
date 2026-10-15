/* SPDX-License-Identifier: MIT */
/*
 * Generation owner for resolver transport changes.
 *
 * The value is deliberately caller-owned and lock-free at this layer.  The
 * resolved cache serializes these operations with its cache mutex, while
 * linked tests can exercise the exact rollover/fail-closed contract without
 * importing the daemon's socket and session machinery.
 */

#ifndef RIN_RESOLVED_NETWORK_GENERATION_H
#define RIN_RESOLVED_NETWORK_GENERATION_H

#include <stdint.h>

#define RIN_RESOLVED_NETWORK_GENERATION_INITIAL UINT64_C(1)

typedef struct RinResolvedNetworkGenerationV1 {
    uint64_t value;
} RinResolvedNetworkGenerationV1;

/* Zero is never a usable generation. */
static inline int rin_resolved_network_generation_init(
    RinResolvedNetworkGenerationV1* state)
{
    if (state == NULL) return 0;
    state->value = RIN_RESOLVED_NETWORK_GENERATION_INITIAL;
    return 1;
}

static inline int rin_resolved_network_generation_read(
    const RinResolvedNetworkGenerationV1* state, uint64_t* value_out)
{
    if (state == NULL || value_out == NULL || state->value == 0u) return 0;
    *value_out = state->value;
    return 1;
}

/*
 * Advance after a carrier/network disconnect.  Rollover is terminal: the
 * state is poisoned to zero and callers must fail closed until a fresh
 * process/service owner is initialized.
 */
static inline int rin_resolved_network_generation_disconnect(
    RinResolvedNetworkGenerationV1* state)
{
    if (state == NULL || state->value == 0u || state->value == UINT64_MAX) {
        if (state != NULL) state->value = 0u;
        return 0;
    }
    ++state->value;
    return 1;
}

#endif /* RIN_RESOLVED_NETWORK_GENERATION_H */
