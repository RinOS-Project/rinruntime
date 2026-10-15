/* SPDX-License-Identifier: MIT */
/*
 * Shared EDNS0 client-option policy and wire builder.
 *
 * The policy is deliberately a fixed, caller-owned value.  A zero/default
 * policy emits the mandatory root OPT record but no identifying data.  A
 * client cookie can be provisioned from the platform CSPRNG; ECS requires an
 * explicit privacy opt-in and is never enabled by default.
 */

#ifndef RIN_SHARED_DNS_CLIENT_POLICY_H
#define RIN_SHARED_DNS_CLIENT_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define RIN_DNS_CLIENT_EDNS_POLICY_VERSION 1u
#define RIN_DNS_CLIENT_EDNS_FLAG_COOKIE UINT32_C(0x00000001)
#define RIN_DNS_CLIENT_EDNS_FLAG_ECS UINT32_C(0x00000002)
#define RIN_DNS_CLIENT_EDNS_FLAG_PADDING UINT32_C(0x00000004)
/* ECS is a privacy-sensitive disclosure and requires this second gate. */
#define RIN_DNS_CLIENT_EDNS_FLAG_ALLOW_ECS UINT32_C(0x00000008)
#define RIN_DNS_CLIENT_EDNS_KNOWN_FLAGS \
    (RIN_DNS_CLIENT_EDNS_FLAG_COOKIE | RIN_DNS_CLIENT_EDNS_FLAG_ECS | \
     RIN_DNS_CLIENT_EDNS_FLAG_PADDING | RIN_DNS_CLIENT_EDNS_FLAG_ALLOW_ECS)

#define RIN_DNS_CLIENT_EDNS_COOKIE_SIZE 8u
#define RIN_DNS_CLIENT_EDNS_MIN_PADDING_BLOCK 64u
#define RIN_DNS_CLIENT_EDNS_MAX_PADDING_BLOCK 512u

typedef struct RinDnsClientEdnsPolicyV1 {
    uint16_t struct_size;
    uint16_t version;
    uint32_t flags;
    uint8_t client_cookie[RIN_DNS_CLIENT_EDNS_COOKIE_SIZE];
    uint8_t ecs_family;          /* 1 = IPv4, 2 = IPv6 */
    uint8_t ecs_source_prefix;
    uint8_t ecs_scope_prefix;    /* clients must send scope 0 */
    uint8_t reserved0;
    uint8_t ecs_address[16];     /* only ceil(source_prefix / 8) bytes used */
    uint16_t padding_block_size; /* zero disables padding; otherwise power of 2 */
    uint16_t reserved1;
} RinDnsClientEdnsPolicyV1;

typedef int (*RinDnsClientRandomBytesFn)(void* context,
                                         uint8_t* output,
                                         uint32_t size);

static inline void rin_dns_client_policy_zero(void* data, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)data;
    size_t index;
    if (!bytes) return;
    for (index = 0u; index < size; ++index) bytes[index] = 0u;
}

static inline int rin_dns_client_edns_policy_init(
    RinDnsClientEdnsPolicyV1* policy)
{
    if (!policy) return 0;
    rin_dns_client_policy_zero(policy, sizeof(*policy));
    policy->struct_size = (uint16_t)sizeof(*policy);
    policy->version = RIN_DNS_CLIENT_EDNS_POLICY_VERSION;
    return 1;
}

static inline size_t rin_dns_client_ecs_address_size(uint8_t family,
                                                     uint8_t source_prefix)
{
    uint8_t maximum = family == 1u ? 32u : 128u;
    if ((family != 1u && family != 2u) || source_prefix > maximum) return 0u;
    return ((size_t)source_prefix + 7u) / 8u;
}

static inline int rin_dns_client_edns_policy_validate(
    const RinDnsClientEdnsPolicyV1* policy)
{
    size_t address_size;
    size_t index;
    uint8_t mask;
    uint8_t cookie_nonzero = 0u;
    uint16_t block;
    if (!policy || policy->struct_size != sizeof(*policy) ||
        policy->version != RIN_DNS_CLIENT_EDNS_POLICY_VERSION ||
        (policy->flags & ~RIN_DNS_CLIENT_EDNS_KNOWN_FLAGS) != 0u ||
        policy->reserved0 != 0u || policy->reserved1 != 0u ||
        policy->ecs_scope_prefix != 0u) {
        return 0;
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_ECS) != 0u &&
        (policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_ALLOW_ECS) == 0u) {
        return 0;
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_COOKIE) != 0u) {
        for (index = 0u; index < sizeof(policy->client_cookie); ++index) {
            cookie_nonzero |= policy->client_cookie[index];
        }
        if (cookie_nonzero == 0u) return 0;
    } else {
        for (index = 0u; index < sizeof(policy->client_cookie); ++index) {
            if (policy->client_cookie[index] != 0u) return 0;
        }
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_ECS) != 0u) {
        address_size = rin_dns_client_ecs_address_size(
            policy->ecs_family, policy->ecs_source_prefix);
        if (address_size == 0u && policy->ecs_source_prefix != 0u) return 0;
        for (index = address_size; index < sizeof(policy->ecs_address); ++index) {
            if (policy->ecs_address[index] != 0u) return 0;
        }
        if (address_size != 0u && (policy->ecs_source_prefix & 7u) != 0u) {
            mask = (uint8_t)(0xffu >> (policy->ecs_source_prefix & 7u));
            if ((policy->ecs_address[address_size - 1u] & mask) != 0u) return 0;
        }
    } else {
        if (policy->ecs_family != 0u || policy->ecs_source_prefix != 0u ||
            policy->ecs_scope_prefix != 0u) return 0;
        for (index = 0u; index < sizeof(policy->ecs_address); ++index) {
            if (policy->ecs_address[index] != 0u) return 0;
        }
    }
    block = policy->padding_block_size;
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_PADDING) == 0u) {
        if (block != 0u) return 0;
    } else {
        if (block < RIN_DNS_CLIENT_EDNS_MIN_PADDING_BLOCK ||
            block > RIN_DNS_CLIENT_EDNS_MAX_PADDING_BLOCK ||
            (block & (uint16_t)(block - 1u)) != 0u) {
            return 0;
        }
    }
    return 1;
}

static inline int rin_dns_client_edns_policy_provision_cookie(
    RinDnsClientEdnsPolicyV1* policy,
    RinDnsClientRandomBytesFn random_bytes,
    void* context)
{
    uint8_t cookie[RIN_DNS_CLIENT_EDNS_COOKIE_SIZE];
    size_t index;
    uint8_t nonzero = 0u;
    if (!policy || !random_bytes ||
        !rin_dns_client_edns_policy_validate(policy) ||
        random_bytes(context, cookie, (uint32_t)sizeof(cookie)) != 0) {
        rin_dns_client_policy_zero(cookie, sizeof(cookie));
        return 0;
    }
    for (index = 0u; index < sizeof(cookie); ++index) {
        nonzero |= cookie[index];
    }
    if (nonzero == 0u) {
        rin_dns_client_policy_zero(cookie, sizeof(cookie));
        return 0;
    }
    for (index = 0u; index < sizeof(cookie); ++index) {
        policy->client_cookie[index] = cookie[index];
    }
    policy->flags |= RIN_DNS_CLIENT_EDNS_FLAG_COOKIE;
    rin_dns_client_policy_zero(cookie, sizeof(cookie));
    return 1;
}

static inline size_t rin_dns_client_edns_options_size(
    const RinDnsClientEdnsPolicyV1* policy,
    size_t message_length_before_opt)
{
    size_t rdata_size = 0u;
    size_t address_size = 0u;
    size_t padding = 0u;
    uint16_t block;
    if (!rin_dns_client_edns_policy_validate(policy)) return 0u;
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_COOKIE) != 0u) {
        rdata_size += 4u + RIN_DNS_CLIENT_EDNS_COOKIE_SIZE;
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_ECS) != 0u) {
        address_size = rin_dns_client_ecs_address_size(
            policy->ecs_family, policy->ecs_source_prefix);
        rdata_size += 4u + 4u + address_size;
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_PADDING) != 0u) {
        block = policy->padding_block_size;
        padding = (size_t)block -
                  ((message_length_before_opt + 11u + rdata_size + 4u) %
                   (size_t)block);
        if (padding == (size_t)block) padding = 0u;
        rdata_size += 4u + padding;
    }
    if (rdata_size > UINT16_MAX) return 0u;
    return 11u + rdata_size;
}

static inline void rin_dns_client_put_u16(uint8_t* output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

/* Write the complete root OPT RR.  message_length_before_opt includes the
 * DNS header and question, but not this RR. */
static inline int rin_dns_client_edns_write_opt(
    const RinDnsClientEdnsPolicyV1* policy,
    size_t message_length_before_opt,
    uint16_t udp_payload_size,
    uint8_t* output,
    size_t output_capacity,
    size_t* output_size)
{
    size_t expected;
    size_t position = 11u;
    size_t address_size = 0u;
    size_t padding = 0u;
    size_t index;
    uint16_t block;
    if (!output || !output_size || udp_payload_size < 512u ||
        !rin_dns_client_edns_policy_validate(policy)) return 0;
    expected = rin_dns_client_edns_options_size(policy,
                                                message_length_before_opt);
    if (expected == 0u || output_capacity < expected) return 0;
    output[0] = 0u;
    rin_dns_client_put_u16(output + 1u, 41u);
    rin_dns_client_put_u16(output + 3u, udp_payload_size);
    output[5] = 0u;
    output[6] = 0u;
    output[7] = 0u;
    output[8] = 0u;
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_COOKIE) != 0u) {
        rin_dns_client_put_u16(output + position, 10u);
        rin_dns_client_put_u16(output + position + 2u,
                               RIN_DNS_CLIENT_EDNS_COOKIE_SIZE);
        position += 4u;
        for (index = 0u; index < RIN_DNS_CLIENT_EDNS_COOKIE_SIZE; ++index) {
            output[position++] = policy->client_cookie[index];
        }
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_ECS) != 0u) {
        address_size = rin_dns_client_ecs_address_size(
            policy->ecs_family, policy->ecs_source_prefix);
        rin_dns_client_put_u16(output + position, 8u);
        rin_dns_client_put_u16(output + position + 2u,
                               (uint16_t)(4u + address_size));
        position += 4u;
        rin_dns_client_put_u16(output + position,
                               policy->ecs_family == 1u ? 1u : 2u);
        output[position + 2u] = policy->ecs_source_prefix;
        output[position + 3u] = 0u;
        position += 4u;
        for (index = 0u; index < address_size; ++index) {
            output[position++] = policy->ecs_address[index];
        }
    }
    if ((policy->flags & RIN_DNS_CLIENT_EDNS_FLAG_PADDING) != 0u) {
        block = policy->padding_block_size;
        padding = (size_t)block -
                  ((message_length_before_opt + 11u + position - 11u + 4u) %
                   (size_t)block);
        if (padding == (size_t)block) padding = 0u;
        rin_dns_client_put_u16(output + position, 12u);
        rin_dns_client_put_u16(output + position + 2u, (uint16_t)padding);
        position += 4u;
        for (index = 0u; index < padding; ++index) output[position++] = 0u;
    }
    rin_dns_client_put_u16(output + 9u, (uint16_t)(position - 11u));
    if (position != expected) return 0;
    *output_size = position;
    return 1;
}

#endif /* RIN_SHARED_DNS_CLIENT_POLICY_H */
