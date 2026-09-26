/* SPDX-License-Identifier: MIT */
/* Public, one-shot File Portal consumer for descriptor-only app handoff. */

#ifndef RINRUNTIME_FILE_PORTAL_STARTUP_H
#define RINRUNTIME_FILE_PORTAL_STARTUP_H

#include <stddef.h>
#include <stdint.h>

#include <rinruntime/file_chooser_portal.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_FILE_PORTAL_STARTUP_VERSION 1u
#define RINRUNTIME_FILE_PORTAL_STARTUP_FD 198
#define RINRUNTIME_FILE_PORTAL_STARTUP_NAME_MAX 255u

/* Fixed v1 record sent over the child-only socket at STARTUP_FD. The grant
 * carries an authenticated opaque token and a display label, never a path. */
typedef struct RinRuntimeFilePortalStartupRequestV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    uint32_t display_name_size;
    uint32_t reserved0;
    RinFilePortalTokenV1 token;
    char display_name[RINRUNTIME_FILE_PORTAL_STARTUP_NAME_MAX + 1u];
    uint64_t reserved[2];
} RinRuntimeFilePortalStartupRequestV1;

typedef struct RinRuntimeFilePortalStartupOpenV1 {
    int32_t descriptor;
    uint32_t display_name_size;
    char display_name[RINRUNTIME_FILE_PORTAL_STARTUP_NAME_MAX + 1u];
    RinRuntimeFileChooserDocumentIdentityV1 document_identity;
} RinRuntimeFilePortalStartupOpenV1;

typedef enum RinRuntimeFilePortalStartupResult {
    RINRUNTIME_FILE_PORTAL_STARTUP_ERROR = -1,
    RINRUNTIME_FILE_PORTAL_STARTUP_NOT_PRESENT = 0,
    RINRUNTIME_FILE_PORTAL_STARTUP_OPENED = 1
} RinRuntimeFilePortalStartupResult;

#if defined(__cplusplus)
static_assert(sizeof(RinRuntimeFilePortalStartupRequestV1) ==
                  sizeof(RinFilePortalTokenV1) + 288u,
              "File Portal startup request ABI drift");
static_assert(sizeof(RinRuntimeFilePortalStartupOpenV1) == 296u,
              "File Portal startup result ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeFilePortalStartupRequestV1) ==
                   sizeof(RinFilePortalTokenV1) + 288u,
               "File Portal startup request ABI drift");
_Static_assert(sizeof(RinRuntimeFilePortalStartupOpenV1) == 296u,
               "File Portal startup result ABI drift");
#endif

/* Clear token-bearing records without allowing the write to be optimized away. */
static inline void rinruntime_file_portal_startup_clear(
    void* value, size_t size)
{
    volatile unsigned char* cursor = (volatile unsigned char*)value;
    while (size-- != 0u) *cursor++ = 0u;
}

/* Call during process startup. NOT_PRESENT means STARTUP_FD was not inherited.
 * OPENED transfers ownership of opened->descriptor to the caller while the
 * parent handshake remains open. Any malformed or rejected grant is reported
 * to the parent and closes the startup channel. */
RinRuntimeFilePortalStartupResult rinruntime_file_portal_startup_take(
    RinRuntimeFilePortalStartupOpenV1* opened);

/* Complete the parent handshake after the app accepted or rejected the open.
 * This always closes STARTUP_FD. The caller retains ownership of the opened
 * file descriptor and must close it after use. */
int rinruntime_file_portal_startup_acknowledge(int accepted);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FILE_PORTAL_STARTUP_H */
