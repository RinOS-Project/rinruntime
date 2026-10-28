/* SPDX-License-Identifier: MIT */
/* Strict decoder for the primary-interface address-configuration snapshot. */

#ifndef RIN_SHARED_NETIF_ADDRCONFIG_POLICY_H
#define RIN_SHARED_NETIF_ADDRCONFIG_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include <rin/net/netif_abi.h>

static inline int rin_netif_addrconfig_bytes_are_zero(const void* value,
                                                       size_t size)
{
    const uint8_t* bytes = (const uint8_t*)value;
    size_t index;
    if (!bytes) return 0;
    for (index = 0u; index < size; ++index) {
        if (bytes[index] != 0u) return 0;
    }
    return 1;
}

static inline int rin_netif_addrconfig_name_valid(
    const char name[RIN_NETINFO_IFNAME_MAX])
{
    size_t index;
    if (!name || name[0] == '\0') return 0;
    for (index = 1u; index < RIN_NETINFO_IFNAME_MAX; ++index) {
        if (name[index] != '\0') continue;
        while (++index < RIN_NETINFO_IFNAME_MAX) {
            if (name[index] != '\0') return 0;
        }
        return 1;
    }
    return 0;
}

static inline int rin_netif_addrconfig_decode(
    const RinNetPrimaryInfo* info,
    int* ipv4_configured,
    int* ipv6_configured)
{
    int has_ipv4;
    if (ipv4_configured) *ipv4_configured = 0;
    if (ipv6_configured) *ipv6_configured = 0;
    if (!info || !ipv4_configured || !ipv6_configured) return -1;
    if ((info->flags & ~RIN_NETINFO_KNOWN_FLAGS) != 0u) return -1;
    if (info->flags == 0u)
        return rin_netif_addrconfig_bytes_are_zero(info, sizeof(*info))
            ? 0 : -1;
    if (info->link_type > RIN_NET_LINK_TYPE_MAX ||
        (info->signal_percent > 100u &&
         info->signal_percent != RIN_NET_SIGNAL_UNKNOWN) ||
        ((info->flags & RIN_NETINFO_FLAG_LINK_UP) != 0u &&
         (info->flags & RIN_NETINFO_FLAG_LINK_KNOWN) == 0u) ||
        ((info->flags & RIN_NETINFO_FLAG_LINK_KNOWN) == 0u &&
         info->link_type != RIN_NET_LINK_TYPE_UNKNOWN) ||
        ((info->flags & RIN_NETINFO_FLAG_SIGNAL_VALID) != 0u &&
         (info->link_type != RIN_NET_LINK_TYPE_WIFI ||
          info->signal_percent > 100u)) ||
        ((info->flags & RIN_NETINFO_FLAG_SIGNAL_VALID) == 0u &&
         info->signal_percent != 0u))
        return -1;
    if ((info->flags & RIN_NETINFO_FLAG_DEVICE_READY) == 0u ||
        info->device_generation == 0u ||
        !rin_netif_addrconfig_name_valid(info->ifname))
        return -1;
    has_ipv4 = !rin_netif_addrconfig_bytes_are_zero(info->ip,
                                                     sizeof(info->ip));
    if (has_ipv4 !=
        ((info->flags & RIN_NETINFO_FLAG_IPV4_CONFIGURED) != 0u))
        return -1;
    /* RFC 3493's AI_ADDRCONFIG policy does not count IPv4 loopback as a
     * configured address, even when the primary snapshot carries 127/8. */
    *ipv4_configured = has_ipv4 && info->ip[0] != 127u;
    *ipv6_configured =
        (info->flags & RIN_NETINFO_FLAG_IPV6_CONFIGURED) != 0u;
    return 0;
}

static inline int rin_net_wifi_info_mac_valid(const uint8_t mac[6])
{
    size_t index;
    int all_zero = 1;
    int all_ff = 1;
    if (!mac || (mac[0] & 1u) != 0u) return 0;
    for (index = 0u; index < 6u; ++index) {
        if (mac[index] != 0u) all_zero = 0;
        if (mac[index] != UINT8_MAX) all_ff = 0;
    }
    return !all_zero && !all_ff;
}

/* Decode the separate Wi-Fi telemetry ABI without inventing values for an
 * absent provider.  This accepts a disconnected snapshot with only its
 * device generation; associated identity and signal fields are all-or-none. */
static inline int rin_net_wifi_info_valid(const RinNetWifiInfoV1* info)
{
    uint16_t flags;
    size_t index;
    if (!info || info->struct_size != sizeof(*info) ||
        info->version != RIN_NET_WIFI_INFO_VERSION ||
        info->device_generation == 0u ||
        (info->flags & ~RIN_NET_WIFI_INFO_KNOWN_FLAGS) != 0u ||
        info->reserved0 != 0u || info->reserved != 0u)
        return 0;
    flags = info->flags;
    if ((flags & (RIN_NET_WIFI_INFO_FLAG_SSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_BSSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_RSSI_VALID)) != 0u &&
        (flags & (RIN_NET_WIFI_INFO_FLAG_SSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_BSSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_RSSI_VALID)) !=
            (RIN_NET_WIFI_INFO_FLAG_SSID_VALID |
             RIN_NET_WIFI_INFO_FLAG_BSSID_VALID |
             RIN_NET_WIFI_INFO_FLAG_RSSI_VALID))
        return 0;
    if ((flags & RIN_NET_WIFI_INFO_FLAG_SSID_VALID) != 0u) {
        if (info->ssid_length == 0u || info->ssid_length > 32u)
            return 0;
    } else {
        if (info->ssid_length != 0u) return 0;
        for (index = 0u; index < sizeof(info->ssid); ++index)
            if (info->ssid[index] != 0u) return 0;
    }
    if ((flags & RIN_NET_WIFI_INFO_FLAG_BSSID_VALID) != 0u) {
        if (!rin_net_wifi_info_mac_valid(info->bssid)) return 0;
    } else {
        for (index = 0u; index < sizeof(info->bssid); ++index)
            if (info->bssid[index] != 0u) return 0;
    }
    if ((flags & RIN_NET_WIFI_INFO_FLAG_RSSI_VALID) != 0u) {
        if (info->signal_dbm > 0 || info->signal_dbm < -127)
            return 0;
    } else if (info->signal_dbm != 0) {
        return 0;
    }
    if ((flags & RIN_NET_WIFI_INFO_FLAG_SIGNAL_VALID) != 0u) {
        if (info->signal_percent > 100u ||
            (flags & RIN_NET_WIFI_INFO_FLAG_RSSI_VALID) == 0u)
            return 0;
    } else if (info->signal_percent != RIN_NET_SIGNAL_UNKNOWN) {
        return 0;
    }
    if ((flags & RIN_NET_WIFI_INFO_FLAG_CONNECTED) != 0u &&
        (flags & (RIN_NET_WIFI_INFO_FLAG_SSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_BSSID_VALID |
                  RIN_NET_WIFI_INFO_FLAG_RSSI_VALID)) !=
            (RIN_NET_WIFI_INFO_FLAG_SSID_VALID |
             RIN_NET_WIFI_INFO_FLAG_BSSID_VALID |
             RIN_NET_WIFI_INFO_FLAG_RSSI_VALID))
        return 0;
    return 1;
}

#endif /* RIN_SHARED_NETIF_ADDRCONFIG_POLICY_H */
