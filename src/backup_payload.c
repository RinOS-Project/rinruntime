/* SPDX-License-Identifier: MIT */

#include <rinruntime/backup_restore.h>

#include <rin/file_portal_call.h>
#include <rin/contract_abi.h>

#include <string.h>

static int backup_payload_ranges_overlap(const void* left, size_t left_size,
                                         const void* right, size_t right_size)
{
    uintptr_t left_address;
    uintptr_t right_address;
    if (left == NULL || right == NULL || left_size == 0u ||
        right_size == 0u)
        return 0;
    left_address = (uintptr_t)left;
    right_address = (uintptr_t)right;
    if (left_address > UINTPTR_MAX - (uintptr_t)left_size ||
        right_address > UINTPTR_MAX - (uintptr_t)right_size)
        return 1;
    return left_address < right_address + (uintptr_t)right_size &&
           right_address < left_address + (uintptr_t)left_size;
}

static int backup_payload_reply_header_valid(
    const RinFilePortalCallV1* call, uint16_t operation, int32_t descriptor,
    uint64_t offset, uint32_t payload_size)
{
    uint32_t index;
    if (call == NULL || call->struct_size != sizeof(*call) ||
        call->version != RIN_FILE_PORTAL_CALL_VERSION ||
        call->operation != operation || call->descriptor != descriptor ||
        call->requested_rights != 0u || call->target_process_id != 0u ||
        call->target_process_cookie != 0u || call->descriptor_flags != 0u ||
        call->granted_rights != 0u || call->process_fd != -1 ||
        call->file_object_id != 0u || call->expires_at_epoch != 0u ||
        call->request_id != 0u || call->new_generation != 0u ||
        call->request_status != 0 || call->reserved_status != 0u ||
        call->reserved[0] != 0u ||
        call->payload.struct_size != sizeof(call->payload) ||
        call->payload.version != RIN_FILE_PORTAL_PAYLOAD_VERSION ||
        call->payload.flags != 0u || call->payload.reserved0 != 0u ||
        call->payload.offset != offset ||
        call->payload.payload_size != payload_size ||
        call->payload.result_size > payload_size)
        return 0;
    for (index = (uint32_t)call->payload.result_size;
         index < RIN_FILE_PORTAL_PAYLOAD_DATA_SIZE; ++index) {
        if (call->payload.bytes[index] != 0u) return 0;
    }
    return 1;
}

static RinRuntimeBackupResult backup_payload_call(
    int32_t descriptor, uint16_t operation, uint64_t offset,
    const uint8_t* input, uint32_t input_size,
    uint8_t* output, uint32_t output_capacity, uint32_t* transferred)
{
    RinFilePortalCallV1 call;
    int result;

    if (transferred == NULL ||
        backup_payload_ranges_overlap(input, input_size, transferred,
                                      sizeof(*transferred)) ||
        backup_payload_ranges_overlap(output, output_capacity, transferred,
                                      sizeof(*transferred)))
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    *transferred = 0u;
    if (output != NULL && output_capacity != 0u)
        memset(output, 0, output_capacity);
    if (descriptor < 0 || input_size > RIN_FILE_PORTAL_PAYLOAD_DATA_SIZE ||
        output_capacity > RIN_FILE_PORTAL_PAYLOAD_DATA_SIZE ||
        (input_size != 0u && input == NULL) ||
        (output_capacity != 0u && output == NULL) ||
        (operation != RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ &&
         operation != RIN_FILE_PORTAL_OPERATION_PAYLOAD_WRITE &&
         operation != RIN_FILE_PORTAL_OPERATION_PAYLOAD_SYNC &&
         operation != RIN_FILE_PORTAL_OPERATION_PAYLOAD_TRUNCATE)) {
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    }
    if (operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ &&
        input_size != 0u)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    if (operation != RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ &&
        output_capacity != 0u)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;

    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = operation;
    call.descriptor = descriptor;
    call.process_fd = -1;
    call.payload.struct_size = sizeof(call.payload);
    call.payload.version = RIN_FILE_PORTAL_PAYLOAD_VERSION;
    call.payload.offset = offset;
    call.payload.payload_size = input_size != 0u ? input_size : output_capacity;
    if (input_size != 0u)
        memcpy(call.payload.bytes, input, input_size);
    result = rin_file_portal_call(&call);
    if (result != RIN_RESULT_OK) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_BACKUP_TRANSPORT_FAILED;
    }
    if (!backup_payload_reply_header_valid(
            &call, operation, descriptor, offset,
            input_size != 0u ? input_size : output_capacity) ||
        call.payload.result_size > call.payload.payload_size ||
        (operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ &&
         call.payload.result_size > output_capacity) ||
        (operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_WRITE &&
         call.payload.result_size != input_size) ||
        ((operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_SYNC ||
          operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_TRUNCATE) &&
         call.payload.result_size != 0u)) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_BACKUP_TRANSPORT_FAILED;
    }
    if (operation == RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ &&
        call.payload.result_size != 0u)
        memcpy(output, call.payload.bytes,
               (size_t)call.payload.result_size);
    *transferred = (uint32_t)call.payload.result_size;
    memset(&call, 0, sizeof(call));
    return RINRUNTIME_BACKUP_OK;
}

RinRuntimeBackupResult rinruntime_backup_payload_read(
    int32_t descriptor, uint64_t offset, uint8_t* bytes, uint32_t capacity,
    uint32_t* bytes_read)
{
    return backup_payload_call(
        descriptor, RIN_FILE_PORTAL_OPERATION_PAYLOAD_READ, offset, NULL, 0u,
        bytes, capacity, bytes_read);
}

RinRuntimeBackupResult rinruntime_backup_payload_write(
    int32_t descriptor, uint64_t offset, const uint8_t* bytes, uint32_t size,
    uint32_t* bytes_written)
{
    return backup_payload_call(
        descriptor, RIN_FILE_PORTAL_OPERATION_PAYLOAD_WRITE, offset, bytes,
        size, NULL, 0u, bytes_written);
}

RinRuntimeBackupResult rinruntime_backup_payload_sync(int32_t descriptor)
{
    uint32_t ignored = 0u;
    return backup_payload_call(
        descriptor, RIN_FILE_PORTAL_OPERATION_PAYLOAD_SYNC, 0u, NULL, 0u,
        NULL, 0u, &ignored);
}

RinRuntimeBackupResult rinruntime_backup_payload_truncate(
    int32_t descriptor, uint64_t size)
{
    uint32_t ignored = 0u;
    return backup_payload_call(
        descriptor, RIN_FILE_PORTAL_OPERATION_PAYLOAD_TRUNCATE, size, NULL,
        0u, NULL, 0u, &ignored);
}
