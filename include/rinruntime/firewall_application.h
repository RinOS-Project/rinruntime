/* SPDX-License-Identifier: MIT */
/* Authenticated package/process identity boundary for Firewall rules. */
#ifndef RIN_FIREWALL_APPLICATION_H
#define RIN_FIREWALL_APPLICATION_H

#include <rin/firewall/abi.h>
#include <rin/firewall/application_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_firewall_application_context_valid(
    const RinFirewallApplicationContextV1* context);
int rin_firewall_application_context_apply(
    const RinFirewallPacketV1* packet,
    const RinFirewallApplicationContextV1* context,
    RinFirewallPacketV1* output);

#ifdef __cplusplus
}
#endif

#endif /* RIN_FIREWALL_APPLICATION_H */
