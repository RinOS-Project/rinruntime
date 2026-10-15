// SPDX-License-Identifier: MIT

#ifndef RIN_SHARED_RESOLVED_SEARCH_POLICY_H
#define RIN_SHARED_RESOLVED_SEARCH_POLICY_H

#include <stddef.h>

#include <rin/net/resolved_nameinfo_policy.h>

/* Build one search-list candidate without allocation.  Only a single-label
 * hostname is eligible: qualified names are already explicit and must never
 * be redirected through DHCP-provided suffixes. */
static inline int rin_resolved_search_candidate_build(
    const char* hostname, size_t hostname_length,
    const char* search_domain, size_t search_domain_length,
    char output[RIN_RESOLVED_LOCAL_DOMAIN_MAX + 1u],
    size_t* output_length)
{
    size_t index;
    size_t total_length;
    if (output_length) *output_length = 0u;
    if (!hostname || !search_domain || !output || !output_length ||
        !rin_resolved_dns_name_valid(hostname, hostname_length) ||
        !rin_resolved_dns_name_valid(search_domain, search_domain_length))
        return -1;
    for (index = 0u; index < hostname_length; ++index) {
        if (hostname[index] == '.') return -1;
    }
    if (hostname_length + 1u >
        RIN_RESOLVED_LOCAL_DOMAIN_MAX - search_domain_length)
        return -1;
    total_length = hostname_length + 1u + search_domain_length;
    for (index = 0u; index < hostname_length; ++index)
        output[index] = (char)rin_resolved_ascii_lower(
            (uint8_t)hostname[index]);
    output[hostname_length] = '.';
    for (index = 0u; index < search_domain_length; ++index)
        output[hostname_length + 1u + index] =
            (char)rin_resolved_ascii_lower((uint8_t)search_domain[index]);
    output[total_length] = '\0';
    *output_length = total_length;
    return 0;
}

#endif
