/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_NETIF_POLICY_H
#define RIN_SHARED_NETIF_POLICY_H

#include <rin/net/netif_abi.h>

#include <stddef.h>
#include <stdint.h>

static inline uint32_t rin_netif_ipv4_value(const uint8_t address[4]) {
    return ((uint32_t)address[0] << 24u) |
           ((uint32_t)address[1] << 16u) |
           ((uint32_t)address[2] << 8u) | (uint32_t)address[3];
}

static inline int rin_netif_ipv4_zero(const uint8_t address[4]) {
    return (address[0] | address[1] | address[2] | address[3]) == 0u;
}

static inline int rin_netif_ipv4_unicast(const uint8_t address[4]) {
    return address[0] != 0u && address[0] != 127u && address[0] < 224u &&
           !(address[0] == 255u && address[1] == 255u &&
             address[2] == 255u && address[3] == 255u);
}

static inline int rin_netif_mask_valid(const uint8_t mask[4]) {
    uint32_t value = rin_netif_ipv4_value(mask);
    uint32_t inverse;
    if (value == 0u) return 0;
    inverse = ~value;
    return (inverse & (inverse + 1u)) == 0u;
}

static inline int rin_netif_host_address_valid(const uint8_t address[4],
                                                const uint8_t mask[4]) {
    uint32_t host_mask;
    uint32_t host;
    if (!rin_netif_ipv4_unicast(address) || !rin_netif_mask_valid(mask))
        return 0;
    host_mask = ~rin_netif_ipv4_value(mask);
    if (host_mask <= 1u) return 1;
    host = rin_netif_ipv4_value(address) & host_mask;
    return host != 0u && host != host_mask;
}

static inline int rin_netif_ipv4_config_valid(const RinIPv4Config* config) {
    uint32_t mask;
    if (!config) return 0;
    if (config->source == RIN_NETCFG_SOURCE_CLEAR) {
        return config->dns_count == 0u && rin_netif_ipv4_zero(config->ip) &&
               rin_netif_ipv4_zero(config->netmask) &&
               rin_netif_ipv4_zero(config->gateway) &&
               rin_netif_ipv4_zero(config->dns);
    }
    if (config->source != RIN_NETCFG_SOURCE_DHCP || config->dns_count > 1u ||
        !rin_netif_host_address_valid(config->ip, config->netmask))
        return 0;
    mask = rin_netif_ipv4_value(config->netmask);
    if (!rin_netif_ipv4_zero(config->gateway) &&
        (!rin_netif_host_address_valid(config->gateway, config->netmask) ||
         (rin_netif_ipv4_value(config->gateway) & mask) !=
             (rin_netif_ipv4_value(config->ip) & mask)))
        return 0;
    if (config->dns_count == 0u) return rin_netif_ipv4_zero(config->dns);
    return rin_netif_ipv4_unicast(config->dns);
}

static inline int rin_netif_ipv6_zero(const uint8_t address[16]) {
    uint8_t value = 0u;
    uint32_t index;
    if (!address) return 1;
    for (index = 0u; index < 16u; ++index) value |= address[index];
    return value == 0u;
}

static inline int rin_netif_ipv6_unicast(const uint8_t address[16]) {
    return address != NULL && !rin_netif_ipv6_zero(address) &&
           address[0] != 0xffu;
}

static inline int rin_netif_ipv6_link_local(const uint8_t address[16]) {
    return rin_netif_ipv6_unicast(address) && address[0] == 0xfeu &&
           (address[1] & 0xc0u) == 0x80u;
}

static inline int rin_netif_ipv6_equal(const uint8_t left[16],
                                       const uint8_t right[16]) {
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < 16u; ++index) difference |= left[index] ^ right[index];
    return difference == 0u;
}

static inline int rin_netif_ipv6_config_valid(const RinIPv6Config* config) {
    uint32_t index;
    uint32_t previous;
    if (!config || config->version != RIN_IPV6_CONFIG_VERSION ||
        config->struct_size != sizeof(*config) ||
        config->reserved0 != 0u || config->reserved1 != 0u ||
        config->reserved2 != 0u ||
        (config->flags & ~RIN_IPV6_CONFIG_KNOWN_FLAGS) != 0u ||
        config->dns_count > RIN_IPV6_CONFIG_MAX_DNS_SERVERS)
        return 0;
    if (config->source == RIN_NETCFG_SOURCE_CLEAR) {
        return config->flags == 0u && config->device_generation == 0u &&
               config->lease_generation == 0u &&
               config->preferred_lifetime_ms == 0u &&
               config->valid_lifetime_ms == 0u && config->dns_count == 0u &&
               rin_netif_ipv6_zero(config->address) &&
               rin_netif_ipv6_zero(config->dns[0]) &&
               rin_netif_ipv6_zero(config->dns[1]) &&
               rin_netif_ipv6_zero(config->dns[2]);
    }
    if (config->source != RIN_NETCFG_SOURCE_DHCPV6 ||
        config->device_generation == 0u || config->lease_generation == 0u ||
        config->valid_lifetime_ms < UINT64_C(60000) ||
        config->valid_lifetime_ms > UINT64_C(2592000000) ||
        config->preferred_lifetime_ms > config->valid_lifetime_ms)
        return 0;
    if ((config->flags & RIN_IPV6_CONFIG_FLAG_HAS_ADDRESS) != 0u) {
        if (!rin_netif_ipv6_unicast(config->address) ||
            rin_netif_ipv6_link_local(config->address))
            return 0;
    } else if (!rin_netif_ipv6_zero(config->address) ||
               config->preferred_lifetime_ms != 0u) {
        return 0;
    }
    for (index = 0u; index < config->dns_count; ++index) {
        if (!rin_netif_ipv6_unicast(config->dns[index])) return 0;
        for (previous = 0u; previous < index; ++previous) {
            if (rin_netif_ipv6_equal(config->dns[index], config->dns[previous]))
                return 0;
        }
    }
    for (; index < RIN_IPV6_CONFIG_MAX_DNS_SERVERS; ++index) {
        if (!rin_netif_ipv6_zero(config->dns[index])) return 0;
    }
    return 1;
}

#endif
