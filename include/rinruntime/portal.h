/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_PORTAL_H
#define RINRUNTIME_PORTAL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_API_VERSION 1u
#define RINRUNTIME_PORTAL_TOKEN_VERSION 1u
#define RINRUNTIME_PORTAL_TOKEN_BYTES 32u
#define RINRUNTIME_PORTAL_RIGHT_READ UINT32_C(0x00000001)
#define RINRUNTIME_PORTAL_RIGHT_WRITE UINT32_C(0x00000002)
#define RINRUNTIME_PORTAL_RIGHT_LIST UINT32_C(0x00000004)
#define RINRUNTIME_PORTAL_RIGHT_KNOWN \
    (RINRUNTIME_PORTAL_RIGHT_READ | RINRUNTIME_PORTAL_RIGHT_WRITE | \
     RINRUNTIME_PORTAL_RIGHT_LIST)

typedef enum RinRuntimePortalResult {
    RINRUNTIME_PORTAL_OK = 0,
    RINRUNTIME_PORTAL_INVALID_ARGUMENT = -1,
    RINRUNTIME_PORTAL_MALFORMED = -2,
    RINRUNTIME_PORTAL_STALE = -3,
    RINRUNTIME_PORTAL_DENIED = -4
} RinRuntimePortalResult;

/* The token is an opaque capability copied from an authenticated OS owner.
 * It intentionally has no path, pointer, PID, native handle, or secret. */
typedef struct RinRuntimePortalTokenV1 {
    uint32_t struct_size;
    uint32_t version;
    uint64_t owner_id;
    uint64_t generation;
    uint32_t rights;
    uint32_t reserved;
    uint8_t opaque[RINRUNTIME_PORTAL_TOKEN_BYTES];
} RinRuntimePortalTokenV1;

int rinruntime_portal_token_validate(
    const RinRuntimePortalTokenV1* token, uint64_t expected_owner,
    uint64_t expected_generation, uint32_t required_rights);

/* Validates a bounded UTF-8 display label.  The label is metadata only and
 * is never interpreted as a filesystem path. */
int rinruntime_portal_label_validate(const char* label, size_t length,
                                     size_t maximum_length);

#ifdef __cplusplus
}
#endif

#endif
