/* SPDX-License-Identifier: MIT */

#include <rin/resource/capability.h>

#include <stddef.h>

static RinDeviceCapabilityBrokerV1 g_product_device_capability_broker;

static void bytes_zero(void* destination, uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    while (size-- != 0u) *output++ = 0u;
}

static void bytes_copy(void* destination, const void* source, uint32_t size)
{
    uint8_t* output = (uint8_t*)destination;
    const uint8_t* input = (const uint8_t*)source;
    while (size-- != 0u) *output++ = *input++;
}

static int bytes_equal(const void* left, const void* right, uint32_t size)
{
    const uint8_t* a = (const uint8_t*)left;
    const uint8_t* b = (const uint8_t*)right;
    uint8_t difference = 0u;
    while (size-- != 0u) difference |= (uint8_t)(*a++ ^ *b++);
    return difference == 0u;
}

static void broker_lock(RinDeviceCapabilityBrokerV1* broker)
{
    while (__atomic_exchange_n(&broker->lock, 1u, __ATOMIC_ACQUIRE) != 0u) {
        while (__atomic_load_n(&broker->lock, __ATOMIC_RELAXED) != 0u) {
        }
    }
}

static void broker_unlock(RinDeviceCapabilityBrokerV1* broker)
{
    __atomic_store_n(&broker->lock, 0u, __ATOMIC_RELEASE);
}

static RinCapabilitySet resource_required_capability(uint32_t resource)
{
    switch (resource) {
        case RIN_APP_RESOURCE_NETWORK:
            return RIN_CAP_NETWORK_ACCESS;
        case RIN_APP_RESOURCE_CLIPBOARD:
            return RIN_CAP_CLIPBOARD;
        case RIN_APP_RESOURCE_NOTIFICATION:
            return RIN_CAP_NOTIFICATION;
        case RIN_APP_RESOURCE_GPU:
            return RIN_CAP_GPU_ACCESS;
        case RIN_APP_RESOURCE_MICROPHONE:
            return RIN_CAP_MICROPHONE;
        case RIN_APP_RESOURCE_CAMERA:
            return RIN_CAP_CAMERA;
        case RIN_APP_RESOURCE_MIDI:
            return RIN_CAP_MIDI;
        case RIN_APP_RESOURCE_LOCATION:
            return RIN_CAP_LOCATION;
        default:
            return 0u;
    }
}

static uint32_t device_resource_rights(uint32_t resource)
{
    switch (resource) {
        case RIN_APP_RESOURCE_GPU:
            return RIN_DEVICE_RIGHT_ALL;
        case RIN_APP_RESOURCE_MICROPHONE:
        case RIN_APP_RESOURCE_CAMERA:
            return RIN_DEVICE_RIGHT_READ | RIN_DEVICE_RIGHT_CONTROL;
        case RIN_APP_RESOURCE_MIDI:
            return RIN_DEVICE_RIGHT_READ | RIN_DEVICE_RIGHT_WRITE |
                   RIN_DEVICE_RIGHT_CONTROL;
        case RIN_APP_RESOURCE_LOCATION:
            return RIN_DEVICE_RIGHT_READ;
        default:
            return 0u;
    }
}

static int subject_is_well_formed(
    const RinDeviceCapabilitySubjectV1* subject)
{
    return rin_resource_subject_validate(subject) == RIN_RESOURCE_SUBJECT_OK;
}

static int subject_has_resource(
    const RinDeviceCapabilitySubjectV1* subject, uint32_t resource)
{
    return rin_resource_subject_authorize(subject, resource) ==
           RIN_RESOURCE_SUBJECT_OK;
}

static int subject_owns_record(
    const RinDeviceCapabilitySubjectV1* subject,
    const RinDeviceCapabilityHandleRecordV1* record)
{
    return record->owner_uid == subject->owner_uid &&
           record->owner_process_id == subject->process_id &&
           record->owner_instance_cookie == subject->process_instance_cookie &&
           bytes_equal(record->owner_application_id, subject->application_id,
                       RIN_DEVICE_CAPABILITY_APPLICATION_ID_SIZE);
}

static uint64_t make_handle(uint32_t slot, uint64_t generation)
{
    return (generation << RIN_DEVICE_CAPABILITY_HANDLE_SLOT_BITS) |
           (uint64_t)(slot + 1u);
}

static int decode_handle(uint64_t handle, uint32_t* slot_out,
                         uint64_t* generation_out)
{
    uint32_t slot_code = (uint32_t)(handle & UINT64_C(0xff));
    uint64_t generation =
        handle >> RIN_DEVICE_CAPABILITY_HANDLE_SLOT_BITS;
    if (slot_code == 0u || slot_code > RIN_DEVICE_CAPABILITY_MAX_HANDLES ||
        generation == 0u) {
        return 0;
    }
    *slot_out = slot_code - 1u;
    *generation_out = generation;
    return 1;
}

static void clear_record_preserving_generation(
    RinDeviceCapabilityHandleRecordV1* record)
{
    uint64_t generation = record->generation;
    bytes_zero(record, (uint32_t)sizeof(*record));
    record->generation = generation;
}

static RinDeviceCapabilityHandleRecordV1* lookup_record_locked(
    RinDeviceCapabilityBrokerV1* broker, uint64_t handle,
    const RinDeviceCapabilitySubjectV1* subject)
{
    RinDeviceCapabilityHandleRecordV1* record;
    uint64_t generation;
    uint32_t slot;

    if (!decode_handle(handle, &slot, &generation)) return NULL;
    record = &broker->handles[slot];
    if (!record->active || record->generation != generation ||
        !subject_owns_record(subject, record)) {
        return NULL;
    }
    return record;
}

static void resource_initialize_result(RinResourceCapabilityResultV1* result)
{
    result->struct_size = (uint32_t)sizeof(*result);
    result->version = RIN_RESOURCE_CAPABILITY_VERSION;
    result->required_capability = 0u;
    result->allowed = 0u;
    result->reserved0 = 0u;
    result->reserved[0] = 0u;
}

RinResourceCapabilityStatus rin_resource_capability_authorize(
    const RinResourceCapabilityRequestV1* request,
    RinResourceCapabilityResultV1* result)
{
    RinCapabilitySet required;

    if (result == NULL) return RIN_RESOURCE_CAPABILITY_INVALID_ARGUMENT;
    resource_initialize_result(result);
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RIN_RESOURCE_CAPABILITY_VERSION ||
        (request->granted_capabilities & ~RIN_CAP_ALL) != 0u ||
        request->flags != 0u || request->reserved[0] != 0u ||
        request->reserved[1] != 0u || request->reserved[2] != 0u) {
        return RIN_RESOURCE_CAPABILITY_INVALID_ARGUMENT;
    }

    required = resource_required_capability(request->resource);
    if (required == 0u) return RIN_RESOURCE_CAPABILITY_INVALID_ARGUMENT;
    result->required_capability = required;
    if ((request->granted_capabilities & required) == 0u) {
        return RIN_RESOURCE_CAPABILITY_DENIED;
    }
    result->allowed = 1u;
    return RIN_RESOURCE_CAPABILITY_OK;
}

void rin_device_capability_broker_reset(RinDeviceCapabilityBrokerV1* broker)
{
    if (broker) bytes_zero(broker, (uint32_t)sizeof(*broker));
}

RinDeviceCapabilityStatus rin_device_capability_handle_open(
    RinDeviceCapabilityBrokerV1* broker,
    const RinDeviceCapabilitySubjectV1* subject,
    uint32_t resource,
    uint32_t rights,
    uint64_t* handle_out)
{
    uint32_t allowed_rights = device_resource_rights(resource);
    uint32_t slot;

    if (handle_out) *handle_out = 0u;
    if (!broker || !handle_out || !subject_is_well_formed(subject) ||
        allowed_rights == 0u || rights == 0u ||
        (rights & ~allowed_rights) != 0u) {
        return RIN_DEVICE_CAPABILITY_INVALID_ARGUMENT;
    }
    if (!subject_has_resource(subject, resource)) {
        return RIN_DEVICE_CAPABILITY_DENIED;
    }

    broker_lock(broker);
    for (slot = 0u; slot < RIN_DEVICE_CAPABILITY_MAX_HANDLES; ++slot) {
        RinDeviceCapabilityHandleRecordV1* record = &broker->handles[slot];
        if (!record->active &&
            record->generation <
                RIN_DEVICE_CAPABILITY_HANDLE_GENERATION_MAX - UINT64_C(1)) {
            /* The packed generation's terminal value must never become a
             * live handle identity. Retire the slot one step before it so a
             * later close/reopen cannot create an ambiguous terminal handle. */
            uint64_t generation = record->generation + 1u;
            clear_record_preserving_generation(record);
            record->generation = generation;
            record->owner_instance_cookie =
                subject->process_instance_cookie;
            bytes_copy(record->owner_application_id, subject->application_id,
                       RIN_DEVICE_CAPABILITY_APPLICATION_ID_SIZE);
            record->owner_uid = subject->owner_uid;
            record->owner_process_id = subject->process_id;
            record->resource = resource;
            record->rights = rights;
            record->active = 1u;
            *handle_out = make_handle(slot, generation);
            broker_unlock(broker);
            return RIN_DEVICE_CAPABILITY_OK;
        }
    }
    broker_unlock(broker);
    return RIN_DEVICE_CAPABILITY_LIMIT_EXCEEDED;
}

RinDeviceCapabilityStatus rin_device_capability_handle_acquire(
    RinDeviceCapabilityBrokerV1* broker,
    const RinDeviceCapabilitySubjectV1* subject,
    uint64_t handle,
    uint32_t resource,
    uint32_t rights,
    RinDeviceCapabilityLeaseV1* lease_out)
{
    RinDeviceCapabilityHandleRecordV1* record;

    if (lease_out) bytes_zero(lease_out, (uint32_t)sizeof(*lease_out));
    if (!broker || !lease_out || !subject_is_well_formed(subject) ||
        rights == 0u || (rights & ~RIN_DEVICE_RIGHT_ALL) != 0u ||
        device_resource_rights(resource) == 0u) {
        return RIN_DEVICE_CAPABILITY_INVALID_ARGUMENT;
    }
    if (!subject_has_resource(subject, resource)) {
        return RIN_DEVICE_CAPABILITY_DENIED;
    }

    broker_lock(broker);
    record = lookup_record_locked(broker, handle, subject);
    if (!record || record->closing) {
        broker_unlock(broker);
        return RIN_DEVICE_CAPABILITY_NOT_FOUND;
    }
    if (record->resource != resource || (rights & ~record->rights) != 0u) {
        broker_unlock(broker);
        return RIN_DEVICE_CAPABILITY_DENIED;
    }
    if (record->use_count == UINT32_MAX) {
        broker_unlock(broker);
        return RIN_DEVICE_CAPABILITY_LIMIT_EXCEEDED;
    }
    ++record->use_count;
    lease_out->struct_size = (uint32_t)sizeof(*lease_out);
    lease_out->version = RIN_DEVICE_CAPABILITY_BROKER_VERSION;
    lease_out->handle = handle;
    lease_out->resource = resource;
    lease_out->rights = rights;
    broker_unlock(broker);
    return RIN_DEVICE_CAPABILITY_OK;
}

RinDeviceCapabilityStatus rin_device_capability_handle_release(
    RinDeviceCapabilityBrokerV1* broker,
    const RinDeviceCapabilitySubjectV1* subject,
    const RinDeviceCapabilityLeaseV1* lease)
{
    RinDeviceCapabilityHandleRecordV1* record;

    if (!broker || !subject_is_well_formed(subject) || !lease ||
        lease->struct_size != sizeof(*lease) ||
        lease->version != RIN_DEVICE_CAPABILITY_BROKER_VERSION ||
        lease->flags != 0u || lease->rights == 0u ||
        (lease->rights & ~RIN_DEVICE_RIGHT_ALL) != 0u ||
        device_resource_rights(lease->resource) == 0u) {
        return RIN_DEVICE_CAPABILITY_INVALID_ARGUMENT;
    }

    broker_lock(broker);
    record = lookup_record_locked(broker, lease->handle, subject);
    if (!record || record->resource != lease->resource ||
        (lease->rights & ~record->rights) != 0u || record->use_count == 0u) {
        broker_unlock(broker);
        return RIN_DEVICE_CAPABILITY_NOT_FOUND;
    }
    --record->use_count;
    if (record->closing && record->use_count == 0u) {
        clear_record_preserving_generation(record);
    }
    broker_unlock(broker);
    return RIN_DEVICE_CAPABILITY_OK;
}

RinDeviceCapabilityStatus rin_device_capability_handle_close(
    RinDeviceCapabilityBrokerV1* broker,
    const RinDeviceCapabilitySubjectV1* subject,
    uint64_t handle)
{
    RinDeviceCapabilityHandleRecordV1* record;

    if (!broker || !subject_is_well_formed(subject)) {
        return RIN_DEVICE_CAPABILITY_INVALID_ARGUMENT;
    }
    broker_lock(broker);
    record = lookup_record_locked(broker, handle, subject);
    if (!record || record->closing) {
        broker_unlock(broker);
        return RIN_DEVICE_CAPABILITY_NOT_FOUND;
    }
    record->closing = 1u;
    if (record->use_count == 0u) {
        clear_record_preserving_generation(record);
    }
    broker_unlock(broker);
    return RIN_DEVICE_CAPABILITY_OK;
}

uint32_t rin_device_capability_revoke_process(
    RinDeviceCapabilityBrokerV1* broker,
    uint32_t owner_uid,
    uint32_t process_id,
    uint64_t process_instance_cookie)
{
    uint32_t revoked = 0u;
    uint32_t slot;

    if (!broker || process_id == 0u || process_instance_cookie == 0u) {
        return 0u;
    }
    broker_lock(broker);
    for (slot = 0u; slot < RIN_DEVICE_CAPABILITY_MAX_HANDLES; ++slot) {
        RinDeviceCapabilityHandleRecordV1* record = &broker->handles[slot];
        if (record->active && !record->closing &&
            record->owner_uid == owner_uid &&
            record->owner_process_id == process_id &&
            record->owner_instance_cookie == process_instance_cookie) {
            record->closing = 1u;
            ++revoked;
            if (record->use_count == 0u) {
                clear_record_preserving_generation(record);
            }
        }
    }
    broker_unlock(broker);
    return revoked;
}

RinDeviceCapabilityBrokerV1* rin_device_capability_product_broker(void)
{
    return &g_product_device_capability_broker;
}
