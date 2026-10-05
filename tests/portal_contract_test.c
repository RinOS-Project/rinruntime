/* SPDX-License-Identifier: MIT */
#include <rinruntime/portal.h>

#include <string.h>

int main(void) {
    RinRuntimePortalTokenV1 token = {0};
    token.struct_size = sizeof(token);
    token.version = RINRUNTIME_PORTAL_TOKEN_VERSION;
    token.owner_id = 7u;
    token.generation = 3u;
    token.rights = RINRUNTIME_PORTAL_RIGHT_READ;
    token.opaque[0] = 1u;
    if (rinruntime_portal_token_validate(&token, 7u, 3u,
                                         RINRUNTIME_PORTAL_RIGHT_READ) != 0)
        return 1;
    token.generation = UINT64_MAX;
    if (rinruntime_portal_token_validate(&token, 7u, UINT64_MAX,
                                         RINRUNTIME_PORTAL_RIGHT_READ) == 0)
        return 1;
    token.generation = 3u;
    token.owner_id = UINT64_MAX;
    if (rinruntime_portal_token_validate(&token, UINT64_MAX, 3u,
                                         RINRUNTIME_PORTAL_RIGHT_READ) == 0)
        return 1;
    token.owner_id = 7u;
    RinRuntimePortalRequestV1 request = {0};
    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_PORTAL_IPC_PROTOCOL_VERSION;
    request.operation = 1u;
    request.token = token;
    request.requested_rights = RINRUNTIME_PORTAL_RIGHT_READ;
    request.request_id = UINT64_MAX;
    request.timeout_ns = 1000000u;
    if (rinruntime_portal_request_validate(&request, 7u, 3u) == 0)
        return 1;
    token.generation++;
    if (rinruntime_portal_token_validate(&token, 7u, 3u,
                                         RINRUNTIME_PORTAL_RIGHT_READ) == 0)
        return 1;
    return rinruntime_portal_label_validate("RinOS", 5u, 64u) == 0 ? 0 : 1;
}
