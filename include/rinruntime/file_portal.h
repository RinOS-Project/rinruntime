/* SPDX-License-Identifier: MIT */
/* Small, renderer-independent client for an already user-approved file token. */

#ifndef RINRUNTIME_FILE_PORTAL_H
#define RINRUNTIME_FILE_PORTAL_H

#include <stdint.h>

/* The syscall ABI is deliberately kept separate from the UI toolkit.  An SDK
 * consumer installs the public RinOS API headers alongside this header. */
#include <rin/file_portal_call.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RinRuntimeFilePortalResult {
    RINRUNTIME_FILE_PORTAL_OK = 0,
    RINRUNTIME_FILE_PORTAL_INVALID_ARGUMENT = -1,
    RINRUNTIME_FILE_PORTAL_KERNEL_REJECTED = -2,
    RINRUNTIME_FILE_PORTAL_MALFORMED_REPLY = -3
} RinRuntimeFilePortalResult;

/* Consumes exactly one authenticated token in the current sandbox process.
 * `requested_rights` may only reduce the grant. `minimum_fd` is the lowest
 * acceptable process descriptor; the resulting descriptor is always returned
 * with CLOEXEC unless the caller explicitly passes zero flags.  Failure never
 * exposes an output descriptor. */
RinRuntimeFilePortalResult rinruntime_file_portal_open(
    const RinFilePortalTokenV1* token, uint32_t requested_rights,
    int32_t minimum_fd, uint32_t descriptor_flags, int32_t* descriptor_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FILE_PORTAL_H */


