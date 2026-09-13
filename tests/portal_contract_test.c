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
    token.generation++;
    if (rinruntime_portal_token_validate(&token, 7u, 3u,
                                         RINRUNTIME_PORTAL_RIGHT_READ) == 0)
        return 1;
    return rinruntime_portal_label_validate("RinOS", 5u, 64u) == 0 ? 0 : 1;
}
