/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_RIN_DHCPV6_RECONFIGURE_H
#define RIN_SHARED_RIN_DHCPV6_RECONFIGURE_H

#include <stdint.h>

#include "rin_dhcpv6_client.h"

#define RIN_DHCPV6_RECONFIGURE_VERSION 1u
#define RIN_DHCPV6_RECONFIGURE_KEY_SIZE 16u

typedef enum RinDhcpv6ReconfigureStatus {
    RIN_DHCPV6_RECONFIGURE_OK = 0,
    RIN_DHCPV6_RECONFIGURE_KEY_CAPTURED = 1,
    RIN_DHCPV6_RECONFIGURE_ACCEPTED = 2,
    RIN_DHCPV6_RECONFIGURE_INVALID_ARGUMENT = -1,
    RIN_DHCPV6_RECONFIGURE_MALFORMED = -2,
    RIN_DHCPV6_RECONFIGURE_NOT_FOR_US = -3,
    RIN_DHCPV6_RECONFIGURE_AUTH_FAILED = -4,
    RIN_DHCPV6_RECONFIGURE_REPLAY = -5,
    RIN_DHCPV6_RECONFIGURE_BUSY = -6
} RinDhcpv6ReconfigureStatus;

/* This owner intentionally stays outside the stable DHCPv6 v1 client and
 * transport records.  It has no allocation, can be reset on link loss, and
 * binds an RKAP key to one accepted lease generation. */
typedef struct RinDhcpv6ReconfigureStateV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t initialized;
    uint32_t key_present;
    uint64_t interface_generation;
    uint64_t lease_generation;
    uint64_t highest_replay;
    uint32_t server_duid_size;
    uint32_t reserved0;
    uint8_t server_duid[RIN_DHCPV6_MAX_DUID_SIZE];
    uint8_t key[RIN_DHCPV6_RECONFIGURE_KEY_SIZE];
} RinDhcpv6ReconfigureStateV1;

/* Validate a live reconfigure snapshot without changing it. */
int rin_dhcpv6_reconfigure_state_valid(
    const RinDhcpv6ReconfigureStateV1* state);

int rin_dhcpv6_reconfigure_init(RinDhcpv6ReconfigureStateV1* state);
/* Capture only an RKAP key carried by an already accepted Reply.  A Reply
 * without a well-formed key withdraws a prior key instead of retaining stale
 * authority across a changed lease. */
int rin_dhcpv6_reconfigure_capture_reply(
    RinDhcpv6ReconfigureStateV1* state, const RinDhcpv6ClientV1* client,
    const uint8_t* message, uint32_t message_size);
/* Verify a unicast Reconfigure's RKAP HMAC-MD5 and monotonic replay value,
 * then schedule the requested Renew, Rebind, or Information-request through
 * the normal DHCPv6 client transaction owner. */
int rin_dhcpv6_reconfigure_receive(
    RinDhcpv6ReconfigureStateV1* state, RinDhcpv6ClientV1* client,
    const uint8_t* message, uint32_t message_size, uint64_t now_ms);
void rin_dhcpv6_reconfigure_destroy(RinDhcpv6ReconfigureStateV1* state);

#endif /* RIN_SHARED_RIN_DHCPV6_RECONFIGURE_H */
