/* SPDX-License-Identifier: MIT */
/* Private Browser-to-WebContent completion carrying one approved location fix. */

#ifndef RIN_SHARED_WEBCONTENT_LOCATION_PERMISSION_H
#define RIN_SHARED_WEBCONTENT_LOCATION_PERMISSION_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <rin/location.h>
#include "../../public-base/RinOS-SDK/include/rin/web/webcontent_protocol.h"

#define RIN_WEBCONTENT_CMD_COMPLETE_LOCATION_V1 UINT32_C(38)
#define RIN_WEBCONTENT_LOCATION_PERMISSION_VERSION UINT16_C(1)

typedef struct RinWebContentLocationPermissionCompleteV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t fix_valid;
    RinWebContentPermissionCompleteV1 permission;
    RinLocationFixV1 fix;
    uint64_t reserved[2];
} RinWebContentLocationPermissionCompleteV1;

#if defined(__cplusplus)
static_assert(sizeof(RinWebContentLocationPermissionCompleteV1) == 136u,
              "location permission completion ABI size changed");
#else
_Static_assert(sizeof(RinWebContentLocationPermissionCompleteV1) == 136u,
               "location permission completion ABI size changed");
#endif

static inline int rin_webcontent_location_permission_complete_valid(
    const RinWebContentLocationPermissionCompleteV1* completion)
{
    const RinWebContentPermissionCompleteV1* permission;
    if (completion == 0 || completion->struct_size != sizeof(*completion) ||
        completion->version != RIN_WEBCONTENT_LOCATION_PERMISSION_VERSION ||
        completion->fix_valid > 1u || completion->reserved[0] != 0u ||
        completion->reserved[1] != 0u)
        return 0;
    permission = &completion->permission;
    if (permission->struct_size != sizeof(*permission) ||
        permission->version != RIN_WEBCONTENT_EXTENSION_ABI_VERSION ||
        permission->reserved0 != 0u || permission->reserved1 != 0u ||
        permission->reserved2 != 0u || permission->request_id == 0u ||
        permission->navigation_generation == 0u ||
        permission->result < RIN_WEBCONTENT_PERMISSION_RESULT_DENIED ||
        permission->result > RIN_WEBCONTENT_PERMISSION_RESULT_CANCELLED ||
        permission->reserved[0] != 0u || permission->reserved[1] != 0u)
        return 0;
    if (permission->result !=
            RIN_WEBCONTENT_PERMISSION_RESULT_ALLOW &&
        completion->fix_valid != 0u)
        return 0;
    if (completion->fix_valid != 0u)
        return rin_location_fix_v1_is_valid(&completion->fix);
    {
        const uint8_t* bytes = (const uint8_t*)&completion->fix;
        size_t index;
        for (index = 0u; index < sizeof(completion->fix); ++index) {
            if (bytes[index] != 0u) return 0;
        }
    }
    return 1;
}

#endif /* RIN_SHARED_WEBCONTENT_LOCATION_PERMISSION_H */
