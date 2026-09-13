/* SPDX-License-Identifier: MIT */
#include <rinruntime/portal.h>
#include <rinruntime/unicode.h>

#include <string.h>

int rinruntime_portal_token_validate(
    const RinRuntimePortalTokenV1* token, uint64_t expected_owner,
    uint64_t expected_generation, uint32_t required_rights)
{
    size_t index;
    int nonzero = 0;
    if (!token || token->struct_size < sizeof(*token) ||
        token->version != RINRUNTIME_PORTAL_TOKEN_VERSION ||
        token->owner_id != expected_owner ||
        token->generation != expected_generation ||
        (required_rights & ~RINRUNTIME_PORTAL_RIGHT_KNOWN) != 0u ||
        (token->rights & ~RINRUNTIME_PORTAL_RIGHT_KNOWN) != 0u ||
        (token->rights & required_rights) != required_rights ||
        token->reserved != 0u) return RINRUNTIME_PORTAL_MALFORMED;
    for (index = 0u; index < sizeof(token->opaque); ++index)
        if (token->opaque[index] != 0u) { nonzero = 1; break; }
    return nonzero ? RINRUNTIME_PORTAL_OK : RINRUNTIME_PORTAL_DENIED;
}

int rinruntime_portal_request_validate(
    const RinRuntimePortalRequestV1* request, uint64_t expected_owner,
    uint64_t expected_generation)
{
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RINRUNTIME_PORTAL_IPC_PROTOCOL_VERSION ||
        request->operation == 0u || request->request_id == 0u ||
        request->timeout_ns == 0u ||
        request->timeout_ns > RINRUNTIME_PORTAL_MAX_TIMEOUT_NS ||
        (request->flags & ~RINRUNTIME_PORTAL_REQUEST_FLAG_CANCELABLE) != 0u ||
        request->reserved[0] != 0u || request->reserved[1] != 0u)
        return RINRUNTIME_PORTAL_INVALID_ARGUMENT;
    return rinruntime_portal_token_validate(&request->token, expected_owner,
                                            expected_generation,
                                            request->requested_rights);
}

int rinruntime_portal_label_validate(const char* label, size_t length,
                                     size_t maximum_length)
{
    size_t valid = 0u;
    size_t index;
    if (!label || length == 0u || length > maximum_length || maximum_length == 0u)
        return RINRUNTIME_PORTAL_INVALID_ARGUMENT;
    if (!rinruntime_utf8_validate(label, length, &valid) || valid != length)
        return RINRUNTIME_PORTAL_MALFORMED;
    for (index = 0u; index < length; ++index)
        if ((unsigned char)label[index] < 0x20u ||
            (unsigned char)label[index] == 0x7fu)
            return RINRUNTIME_PORTAL_MALFORMED;
    return RINRUNTIME_PORTAL_OK;
}
