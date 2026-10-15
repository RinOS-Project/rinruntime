/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_RIN_DHCPV6_CLIENT_H
#define RIN_SHARED_RIN_DHCPV6_CLIENT_H

#include <stdint.h>

#define RIN_DHCPV6_CLIENT_VERSION 1u
#define RIN_DHCPV6_MAX_MESSAGE_SIZE 512u
#define RIN_DHCPV6_MAX_DUID_SIZE 32u
#define RIN_DHCPV6_MAX_DNS_SERVERS 3u

typedef enum RinDhcpv6Status {
    RIN_DHCPV6_OK = 0,
    RIN_DHCPV6_PACKET_READY = 1,
    RIN_DHCPV6_OFFER_READY = 2,
    RIN_DHCPV6_LEASE_READY = 3,
    RIN_DHCPV6_LEASE_EXPIRED = 4,
    RIN_DHCPV6_INVALID_ARGUMENT = -1,
    RIN_DHCPV6_INVALID_STATE = -2,
    RIN_DHCPV6_MALFORMED_PACKET = -3,
    RIN_DHCPV6_NOT_FOR_US = -4,
    RIN_DHCPV6_SERVER_REJECTED = -5,
    RIN_DHCPV6_CLOCK_ROLLBACK = -6,
    RIN_DHCPV6_BUSY = -7,
    RIN_DHCPV6_RANGE_EXHAUSTED = -8,
    RIN_DHCPV6_NOT_FOUND = -9
} RinDhcpv6Status;

typedef enum RinDhcpv6ClientState {
    RIN_DHCPV6_STATE_IDLE = 0,
    RIN_DHCPV6_STATE_SOLICITING = 1,
    RIN_DHCPV6_STATE_ADVERTISED = 2,
    RIN_DHCPV6_STATE_REQUESTING = 3,
    RIN_DHCPV6_STATE_BOUND = 4,
    RIN_DHCPV6_STATE_RENEWING = 5,
    RIN_DHCPV6_STATE_REBINDING = 6,
    /* RFC 8415 Information-request has no IA_NA and only publishes
     * configuration such as DNS servers. */
    RIN_DHCPV6_STATE_INFORMATION_REQUESTING = 7,
    RIN_DHCPV6_STATE_INFORMATION_BOUND = 8,
    /* A stateful client can be asked to refresh configuration only.  It keeps
     * its IA_NA and lifetimes while an Information-request is in flight. */
    RIN_DHCPV6_STATE_RECONFIGURE_INFORMATION_REQUESTING = 9,
    /* Reconfigure-requested Rebind keeps normal T1/T2 ordering intact until
     * the fresh exchange completes. */
    RIN_DHCPV6_STATE_RECONFIGURE_REBINDING = 10
} RinDhcpv6ClientState;

typedef enum RinDhcpv6TransmitKind {
    RIN_DHCPV6_TRANSMIT_NONE = 0,
    RIN_DHCPV6_TRANSMIT_SOLICIT = 1,
    RIN_DHCPV6_TRANSMIT_REQUEST = 3,
    RIN_DHCPV6_TRANSMIT_RENEW = 5,
    RIN_DHCPV6_TRANSMIT_REBIND = 6,
    RIN_DHCPV6_TRANSMIT_INFORMATION_REQUEST = 11
} RinDhcpv6TransmitKind;

typedef enum RinDhcpv6ClientMode {
    /* Default preserves the existing IA_NA stateful-client behavior. */
    RIN_DHCPV6_CLIENT_MODE_STATEFUL = 0,
    RIN_DHCPV6_CLIENT_MODE_INFORMATION = 1
} RinDhcpv6ClientMode;

typedef struct RinDhcpv6TransmitV1 {
    uint32_t version;
    uint32_t struct_size;
    uint64_t owner_generation;
    uint32_t sequence;
    uint32_t reserved;
    uint64_t prepared_at_ms;
    uint32_t kind;
    uint32_t message_size;
    uint8_t message[RIN_DHCPV6_MAX_MESSAGE_SIZE];
} RinDhcpv6TransmitV1;

typedef struct RinDhcpv6LeaseV1 {
    uint32_t version;
    uint32_t struct_size;
    uint64_t interface_generation;
    uint64_t lease_generation;
    uint64_t preferred_until_ms;
    uint64_t renew_at_ms;
    uint64_t rebind_at_ms;
    uint64_t expires_at_ms;
    uint32_t dns_server_count;
    uint32_t state;
    uint8_t address[16];
    uint8_t dns_servers[RIN_DHCPV6_MAX_DNS_SERVERS][16];
} RinDhcpv6LeaseV1;

typedef struct RinDhcpv6ClientV1 {
    uint32_t version;
    uint32_t struct_size;
    uint32_t initialized;
    uint32_t state;
    uint64_t interface_generation;
    uint64_t generation;
    uint64_t last_now_ms;
    uint64_t transaction_started_ms;
    uint64_t next_transmit_ms;
    uint64_t retry_ms;
    uint64_t lease_generation;
    uint64_t next_lease_generation;
    uint64_t preferred_until_ms;
    uint64_t renew_at_ms;
    uint64_t rebind_at_ms;
    uint64_t expires_at_ms;
    uint32_t iaid;
    uint32_t transaction_id;
    uint32_t duid_size;
    uint32_t server_duid_size;
    uint32_t dns_server_count;
    uint32_t offer_preferred_seconds;
    uint32_t offer_valid_seconds;
    uint32_t offer_t1_seconds;
    uint32_t offer_t2_seconds;
    uint32_t next_transmit_sequence;
    uint32_t pending_present;
    uint8_t duid[RIN_DHCPV6_MAX_DUID_SIZE];
    uint8_t server_duid[RIN_DHCPV6_MAX_DUID_SIZE];
    uint8_t address[16];
    uint8_t dns_servers[RIN_DHCPV6_MAX_DNS_SERVERS][16];
    uint32_t reserved;
    RinDhcpv6TransmitV1 pending;
} RinDhcpv6ClientV1;

int rin_dhcpv6_client_init(
    RinDhcpv6ClientV1* client, const uint8_t* duid, uint32_t duid_size,
    uint32_t iaid, uint64_t interface_generation);
/* Validate a live client snapshot without changing it.  Private transport
 * owners use this before consuming a restored or delegated state record. */
int rin_dhcpv6_client_state_valid(const RinDhcpv6ClientV1* client);
/* Select the RFC 8415 exchange after initialisation and before the first
 * transmission.  The mode is stored in the existing ABI-reserved field so
 * RinDhcpv6ClientV1 remains binary-size stable. */
int rin_dhcpv6_client_set_mode(RinDhcpv6ClientV1* client,
                               RinDhcpv6ClientMode mode);
/* Accept an already-authenticated DHCPv6 Reconfigure instruction.  The
 * transport owner remains responsible for RFC 3315 Authentication-option
 * verification and replay protection; this routine merely turns a valid
 * RENEW or Information-request instruction into the next normal client
 * transaction. */
int rin_dhcpv6_client_request_reconfigure(
    RinDhcpv6ClientV1* client, RinDhcpv6TransmitKind requested_kind,
    uint64_t now_ms);
int rin_dhcpv6_client_prepare(
    RinDhcpv6ClientV1* client, uint32_t new_transaction_id,
    uint64_t now_ms, RinDhcpv6TransmitV1* transmit_out);
int rin_dhcpv6_client_complete_transmit(
    RinDhcpv6ClientV1* client, const RinDhcpv6TransmitV1* transmit,
    int sent_successfully);
int rin_dhcpv6_client_receive(
    RinDhcpv6ClientV1* client, const uint8_t* message,
    uint32_t message_size, uint64_t now_ms);
int rin_dhcpv6_client_get_lease(
    RinDhcpv6ClientV1* client, uint64_t now_ms,
    RinDhcpv6LeaseV1* lease_out);
int rin_dhcpv6_client_stop(RinDhcpv6ClientV1* client);
void rin_dhcpv6_client_destroy(RinDhcpv6ClientV1* client);

#endif /* RIN_SHARED_RIN_DHCPV6_CLIENT_H */
