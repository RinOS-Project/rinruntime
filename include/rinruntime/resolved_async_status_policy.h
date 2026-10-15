/* SPDX-License-Identifier: MIT */

#ifndef RIN_SHARED_RESOLVED_ASYNC_STATUS_POLICY_H
#define RIN_SHARED_RESOLVED_ASYNC_STATUS_POLICY_H

#include "dns_abi.h"
#include "resolved_service_abi.h"

static inline uint32_t rin_resolved_getaddrinfo_async_status(int32_t status)
{
    if (status == 0) return RIN_DNS_STATUS_DONE;
    if (status == RIN_RESOLVED_EAI_NONAME) return RIN_DNS_STATUS_NOT_FOUND;
    return RIN_DNS_STATUS_FAILED;
}

#endif
