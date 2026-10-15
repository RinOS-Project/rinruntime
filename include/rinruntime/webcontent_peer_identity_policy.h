/* SPDX-License-Identifier: MIT */
/* Browser admission policy for a kernel-authenticated WebContent peer. */

#ifndef RIN_SHARED_WEBCONTENT_PEER_IDENTITY_POLICY_H
#define RIN_SHARED_WEBCONTENT_PEER_IDENTITY_POLICY_H

#include <rin/abi.h>
#include "rin_socket_abi.h"
#include "webcontent_service_abi.h"

#define RIN_WEBCONTENT_CLIENT_REQUIRED_CAPABILITIES \
    (RIN_CAP_RIN_PASS | RIN_CAP_NETWORK_ACCESS | RIN_CAP_CLIPBOARD | \
     RIN_CAP_NOTIFICATION)

/* The socket kernel fills this record only for a verified signed RIN v3
 * image.  A pathname is not an identity claim: Browser combines this record
 * with the kernel-captured service slot of the unique running webcontent
 * system service before exchanging browser state, page pixels, or input. */
static inline int rin_webcontent_peer_identity_valid(
    const rin_unix_peer_app_identity_v1* identity)
{
    return rin_unix_peer_app_identity_valid(identity);
}

/* WebContent only accepts the signed Browser privilege profile.  The kernel
 * supplies both the image digest and effective capability snapshot, so a
 * pathname or client-provided request header cannot claim this authority. */
static inline int rin_webcontent_authenticated_client_peer_valid(
    const rin_unix_peer_app_identity_v1* identity)
{
    return rin_webcontent_peer_identity_valid(identity) &&
           (identity->capabilities &
            RIN_WEBCONTENT_CLIENT_REQUIRED_CAPABILITIES) ==
               RIN_WEBCONTENT_CLIENT_REQUIRED_CAPABILITIES;
}

static inline int rin_webcontent_service_identity_valid(
    const rin_unix_service_identity_v1* identity, uint32_t expected_slot_id)
{
    return identity != NULL && expected_slot_id != 0u &&
           expected_slot_id != UINT32_MAX &&
           identity->slot_id == expected_slot_id &&
           identity->slot_id != UINT32_MAX &&
           identity->owner_uid == RIN_WEBCONTENT_SERVICE_OWNER_UID &&
           identity->scope == RIN_WEBCONTENT_SERVICE_SCOPE &&
           identity->flags == RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED;
}

/* The resolver is sampled before and after socket identity inspection. A
 * service-manager restart must not turn a connection to an old service slot
 * into an authenticated WebContent transport. */
static inline int rin_webcontent_service_slot_stable(uint32_t first_slot_id,
                                                      uint32_t second_slot_id)
{
    return first_slot_id != 0u && first_slot_id != UINT32_MAX &&
           first_slot_id == second_slot_id;
}

static inline int rin_webcontent_authenticated_service_peer_valid(
    const rin_unix_service_identity_v1* service_identity,
    uint32_t expected_slot_id,
    const rin_unix_peer_app_identity_v1* application_identity)
{
    return rin_webcontent_service_identity_valid(service_identity,
                                                  expected_slot_id) &&
           rin_webcontent_peer_identity_valid(application_identity);
}

#endif /* RIN_SHARED_WEBCONTENT_PEER_IDENTITY_POLICY_H */
