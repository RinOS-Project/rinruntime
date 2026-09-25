/* SPDX-License-Identifier: MIT */

#include <rinruntime/firewall_application.h>

#include <stddef.h>

static void application_zero(void* memory, size_t size)
{
    volatile uint8_t* bytes = (volatile uint8_t*)memory;
    if (memory == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int application_nonzero(const uint8_t* bytes, size_t size)
{
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index)
        if (bytes[index] != 0u) return 1;
    return 0;
}

int rin_firewall_application_context_valid(
    const RinFirewallApplicationContextV2* context)
{
    size_t index;
    if (context == NULL || context->struct_size != sizeof(*context) ||
        context->version != RIN_FIREWALL_APPLICATION_CONTEXT_VERSION ||
        (context->flags & ~RIN_FIREWALL_APPLICATION_KNOWN_FLAGS) != 0u ||
        context->process_id == 0u || context->process_instance_cookie == 0u ||
        (context->package_generation == 0u &&
         (context->flags &
          RIN_FIREWALL_APPLICATION_FLAG_SYSTEM_PROCESS) == 0u) ||
        context->namespace_id == 0u || !application_nonzero(
            context->application_id, sizeof(context->application_id)) ||
        !application_nonzero(context->package_digest,
                             sizeof(context->package_digest)))
        return 0;
    for (index = 0u; index < sizeof(context->reserved1) / sizeof(uint64_t);
         ++index)
        if (context->reserved1[index] != 0u) return 0;
    return 1;
}

int rin_firewall_application_context_apply(
    const RinFirewallPacketV1* packet,
    const RinFirewallApplicationContextV2* context,
    RinFirewallPacketV1* output)
{
    uint32_t index;
    if (output == NULL) return RIN_FIREWALL_INVALID_ARGUMENT;
    application_zero(output, sizeof(*output));
    if (packet == NULL || context == NULL)
        return RIN_FIREWALL_INVALID_ARGUMENT;
    if (!rin_firewall_application_context_valid(context) ||
        rin_firewall_packet_validate(packet) != RIN_FIREWALL_OK ||
        packet->namespace_id != context->namespace_id)
        return RIN_FIREWALL_MALFORMED;
    *output = *packet;
    for (index = 0u; index < RIN_FIREWALL_APPLICATION_ID_SIZE; ++index)
        output->application_id[index] = context->application_id[index];
    /* Process identity is kernel-derived from the authenticated context, not
     * from caller packet metadata.  Keep the fixed packet ABI and publish the
     * pair only after all input validation succeeds. */
    output->flags |= RIN_FIREWALL_PACKET_FLAG_PROCESS_IDENTITY;
    output->reserved[0] = context->process_id;
    output->reserved[1] = context->process_instance_cookie;
    output->reserved[2] = 0u;
    return RIN_FIREWALL_OK;
}
