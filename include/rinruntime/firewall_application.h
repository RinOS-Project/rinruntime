/* SPDX-License-Identifier: MIT */
/* Authenticated package/process identity model for Firewall rules.
 * package_generation may be zero only when SYSTEM_PROCESS is set. That flag
 * describes the kernel-issued identity source; it does not authenticate an
 * untrusted caller by itself. */
#ifndef RIN_FIREWALL_APPLICATION_H
#define RIN_FIREWALL_APPLICATION_H

#include <rin/firewall/abi.h>
#include <rin/firewall/application_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

int rin_firewall_application_context_valid(
    const RinFirewallApplicationContextV2* context);
int rin_firewall_application_context_apply(
    const RinFirewallPacketV1* packet,
    const RinFirewallApplicationContextV2* context,
    RinFirewallPacketV1* output);

#ifdef __cplusplus
}
#endif

#endif /* RIN_FIREWALL_APPLICATION_H */
