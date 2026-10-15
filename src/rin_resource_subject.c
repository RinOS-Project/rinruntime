/* SPDX-License-Identifier: MIT */

#include <rin/resource/subject.h>

#include <rin/resource/capability.h>

#include <stddef.h>

static int application_id_is_nonzero(const uint8_t application_id[32])
{
    uint8_t observed = 0u;
    uint32_t index;

    for (index = 0u; index < 32u; ++index) observed |= application_id[index];
    return observed != 0u;
}

RinResourceSubjectStatus rin_resource_subject_validate(
    const RinResourceSubjectV1* subject)
{
    if (subject == NULL || subject->struct_size != sizeof(*subject) ||
        subject->version != RIN_RESOURCE_SUBJECT_VERSION ||
        subject->flags != 0u || subject->process_id == 0u ||
        subject->process_instance_cookie == 0u ||
        (subject->current_capabilities & ~RIN_CAP_ALL) != 0u ||
        !application_id_is_nonzero(subject->application_id) ||
        subject->reserved[0] != 0u || subject->reserved[1] != 0u) {
        return RIN_RESOURCE_SUBJECT_INVALID_ARGUMENT;
    }
    return RIN_RESOURCE_SUBJECT_OK;
}

RinResourceSubjectStatus rin_resource_subject_authorize(
    const RinResourceSubjectV1* subject,
    uint32_t resource)
{
    RinResourceCapabilityRequestV1 request = {0};
    RinResourceCapabilityResultV1 result;
    RinResourceCapabilityStatus status;

    if (rin_resource_subject_validate(subject) != RIN_RESOURCE_SUBJECT_OK) {
        return RIN_RESOURCE_SUBJECT_INVALID_ARGUMENT;
    }

    request.struct_size = sizeof(request);
    request.version = RIN_RESOURCE_CAPABILITY_VERSION;
    request.granted_capabilities = subject->current_capabilities;
    request.resource = resource;
    status = rin_resource_capability_authorize(&request, &result);
    if (status == RIN_RESOURCE_CAPABILITY_DENIED) {
        return RIN_RESOURCE_SUBJECT_DENIED;
    }
    if (status != RIN_RESOURCE_CAPABILITY_OK || result.allowed != 1u) {
        return RIN_RESOURCE_SUBJECT_INVALID_ARGUMENT;
    }
    return RIN_RESOURCE_SUBJECT_OK;
}
