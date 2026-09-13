/* SPDX-License-Identifier: MIT */

#include <rinruntime/file_portal.h>

#include <string.h>
#include <unistd.h>

#include <rin/contract_abi.h>

static int rinruntime_nonzero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    if (bytes == NULL) return 0;
    while (size-- != 0u) value |= *bytes++;
    return value != 0u;
}

static int rinruntime_all_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t value = 0u;
    if (bytes == NULL) return 0;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

/* This is intentionally only a structural check. The kernel verifies the
 * HMAC, target sandbox identity, expiry, policy generation and one-time use;
 * a library must not duplicate or weaken those scheduler-owned checks. */
static int rinruntime_token_well_formed(const RinFilePortalTokenV1* token)
{
    return token != NULL &&
           token->magic == RIN_FILE_PORTAL_TOKEN_MAGIC &&
           token->version == RIN_FILE_PORTAL_TOKEN_VERSION &&
           token->token_size == RIN_FILE_PORTAL_TOKEN_SIZE &&
           token->flags == 0u && token->rights != 0u &&
           (token->rights & ~RIN_FILE_PORTAL_RIGHT_ALL) == 0u &&
           token->file_object_id != 0u && token->not_before_epoch != 0u &&
           token->expires_at_epoch > token->not_before_epoch &&
           token->policy_generation != 0u &&
           rinruntime_nonzero(token->nonce, sizeof(token->nonce)) &&
           rinruntime_all_zero(token->reserved, sizeof(token->reserved)) &&
           rinruntime_nonzero(token->authentication_tag,
                              sizeof(token->authentication_tag));
}

RinRuntimeFilePortalResult rinruntime_file_portal_open(
    const RinFilePortalTokenV1* token, uint32_t requested_rights,
    int32_t minimum_fd, uint32_t descriptor_flags, int32_t* descriptor_out)
{
    RinFilePortalCallV1 call;
    int result;
    int32_t installed = -1;

    if (descriptor_out != NULL) *descriptor_out = -1;
    if (descriptor_out == NULL || !rinruntime_token_well_formed(token) ||
        requested_rights == 0u ||
        (requested_rights & ~RIN_FILE_PORTAL_RIGHT_ALL) != 0u ||
        (requested_rights & ~token->rights) != 0u || minimum_fd < 0 ||
        (descriptor_flags & ~RIN_FILE_PORTAL_CALL_FD_CLOEXEC) != 0u) {
        return RINRUNTIME_FILE_PORTAL_INVALID_ARGUMENT;
    }

    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_OPEN;
    call.descriptor = minimum_fd;
    call.requested_rights = requested_rights;
    call.descriptor_flags = descriptor_flags;
    call.token = *token;
    call.process_fd = -1;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_OK && call.granted_rights == requested_rights &&
        call.process_fd >= minimum_fd && call.file_object_id != 0u &&
        call.expires_at_epoch != 0u) {
        installed = call.process_fd;
    } else if (result == RIN_RESULT_OK && call.process_fd >= minimum_fd) {
        /* A successful syscall with a malformed output must not leave a
         * usable descriptor behind for a caller that received an error. */
        (void)close(call.process_fd);
    }
    memset(&call, 0, sizeof(call));

    if (installed < 0) {
        return result == RIN_RESULT_OK
            ? RINRUNTIME_FILE_PORTAL_MALFORMED_REPLY
            : RINRUNTIME_FILE_PORTAL_KERNEL_REJECTED;
    }
    *descriptor_out = installed;
    return RINRUNTIME_FILE_PORTAL_OK;
}


