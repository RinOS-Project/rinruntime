/* SPDX-License-Identifier: MIT */
/* Public client for identity-bound durable File Portal permissions. */

#ifndef RINRUNTIME_DURABLE_FILE_PORTAL_H
#define RINRUNTIME_DURABLE_FILE_PORTAL_H

#include <stdint.h>

#include <rin/file_portal_call.h>
#include "file_chooser_portal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RinRuntimeDurableFilePortalResult {
    RINRUNTIME_DURABLE_FILE_PORTAL_OK = 0,
    RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT = -1,
    RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED = -2,
    RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY = -3,
    /* A well-formed listing reached its end.  This is not a kernel failure. */
    RINRUNTIME_DURABLE_FILE_PORTAL_NOT_FOUND = -4,
    /* SETTINGS_REVOKE_STATUS is still waiting for the physical prompt. */
    RINRUNTIME_DURABLE_FILE_PORTAL_PENDING = -5
} RinRuntimeDurableFilePortalResult;

/* Recent-item reopen is deliberately bounded. The helper scans only the
 * current sandbox's durable grants and never turns the opaque identity into a
 * pathname or a caller-selected object. */
#define RINRUNTIME_DURABLE_FILE_PORTAL_REOPEN_MAX_SCAN 64u

/* Reauthorizes a grant owned by the current sandbox identity.  The grant ID
 * is not a pathname, descriptor, object cookie, or reusable portal token. */
RinRuntimeDurableFilePortalResult rinruntime_file_portal_durable_open(
    uint64_t grant_id, uint32_t requested_rights, int32_t minimum_fd,
    uint32_t descriptor_flags, int32_t* descriptor_out);

/* Reauthorizes a recent Open identity through a matching current-sandbox
 * durable grant. A successful call returns a CLOEXEC descriptor; no token,
 * object cookie, or pathname is exposed. */
RinRuntimeDurableFilePortalResult
rinruntime_file_portal_reopen_document_identity(
    const RinRuntimeFileChooserDocumentIdentityV1* document_identity,
    uint32_t requested_rights, int32_t minimum_fd, uint32_t descriptor_flags,
    int32_t* descriptor_out);

/* Lists one current-sandbox grant.  `cursor` is zero for the first entry and
 * the returned next_cursor is opaque; no path or identity is disclosed. */
RinRuntimeDurableFilePortalResult rinruntime_file_portal_durable_list(
    uint64_t cursor, RinFilePortalDurableEntryV1* entry_out,
    uint64_t* next_cursor_out);

/* Lists one durable grant for the privileged Settings model.  The kernel
 * authenticates the Settings identity and returns identity plus stable
 * metadata, but never a path, descriptor, object cookie, or portal token. */
RinRuntimeDurableFilePortalResult rinruntime_file_portal_settings_list(
    uint64_t cursor, RinFilePortalSettingsEntryV1* entry_out,
    uint64_t* next_cursor_out);

/* Starts, observes, and retires a Settings durable-grant revoke request. The
 * request remains pending until the kernel-owned physical prompt is
 * approved; callers never receive the RFPG identity or a decision secret. */
RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_request(
    uint64_t grant_id, uint64_t* request_id_out,
    uint64_t* expires_at_epoch_out);
RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_status(
    uint64_t request_id, int32_t* permission_status_out,
    uint64_t* new_generation_out);
RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_finish(uint64_t request_id);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_DURABLE_FILE_PORTAL_H */


