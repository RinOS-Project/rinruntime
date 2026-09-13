/* SPDX-License-Identifier: MIT */

#include <rinruntime/durable_file_portal.h>

#include <string.h>
#include <unistd.h>

#include <rin/contract_abi.h>

static uint64_t durable_read_u64_le(const uint8_t* bytes)
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index)
        value |= ((uint64_t)bytes[index]) << (index * 8u);
    return value;
}

static int durable_document_identity_valid(
    const RinRuntimeFileChooserDocumentIdentityV1* identity,
    uint64_t* object_id_out)
{
    static const uint8_t tag[8] = {'R', 'I', 'N', '-', 'D', 'O', 'C', '1'};
    uint32_t index;
    uint8_t nonzero = 0u;
    if (object_id_out != NULL) *object_id_out = 0u;
    if (identity == NULL || object_id_out == NULL) return 0;
    for (index = 0u; index < sizeof(identity->bytes); ++index)
        nonzero |= identity->bytes[index];
    if (nonzero == 0u || durable_read_u64_le(identity->bytes) == 0u)
        return 0;
    for (index = 0u; index < sizeof(tag); ++index) {
        if (identity->bytes[8u + index] != tag[index]) return 0;
    }
    for (index = 16u; index < sizeof(identity->bytes); ++index) {
        if (identity->bytes[index] != 0u) return 0;
    }
    *object_id_out = durable_read_u64_le(identity->bytes);
    return 1;
}

static int durable_all_zero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    if (bytes == NULL) return 0;
    while (size-- != 0u) combined |= *bytes++;
    return combined == 0u;
}

static int durable_package_name_valid(
    const char name[RIN_FILE_PORTAL_PACKAGE_NAME_SIZE])
{
    uint32_t length = 0u;
    while (length < RIN_FILE_PORTAL_PACKAGE_NAME_SIZE &&
           name[length] != '\0') {
        uint8_t value = (uint8_t)name[length];
        if (value < 0x20u || value == 0x7fu || value == '/' ||
            value == '\\' || value == ':')
            return 0;
        ++length;
    }
    if (length == 0u || length == RIN_FILE_PORTAL_PACKAGE_NAME_SIZE ||
        (length == 1u && name[0] == '.') ||
        (length == 2u && name[0] == '.' && name[1] == '.'))
        return 0;
    while (++length < RIN_FILE_PORTAL_PACKAGE_NAME_SIZE) {
        if (name[length] != '\0') return 0;
    }
    return 1;
}

static int durable_identity_valid(const RinFilePortalIdentityV1* identity)
{
    uint8_t nonzero = 0u;
    uint32_t index;
    if (!identity || !durable_package_name_valid(identity->package_name) ||
        identity->publisher_key_generation == 0u)
        return 0;
    for (index = 0u; index < sizeof(identity->publisher_key_id); ++index)
        nonzero |= identity->publisher_key_id[index];
    return nonzero != 0u;
}

static int durable_entry_valid(const RinFilePortalDurableEntryV1* entry)
{
    if (entry == NULL || entry->grant_id == 0u ||
        entry->database_generation == 0u || entry->mount_id == 0u ||
        entry->namespace_id == 0u || entry->object_id == 0u ||
        entry->object_generation == 0u ||
        (entry->object_type != RIN_FILE_PORTAL_DURABLE_OBJECT_REGULAR &&
         entry->object_type != RIN_FILE_PORTAL_DURABLE_OBJECT_DIRECTORY) ||
        (entry->scope != RIN_FILE_PORTAL_DURABLE_SCOPE_EXACT &&
         entry->scope != RIN_FILE_PORTAL_DURABLE_SCOPE_DESCENDANTS) ||
        (entry->rights & ~RIN_FILE_PORTAL_RIGHT_ALL) != 0u ||
        entry->rights == 0u ||
        (entry->state != RIN_FILE_PORTAL_DURABLE_STATE_ACTIVE &&
         entry->state != RIN_FILE_PORTAL_DURABLE_STATE_EXPIRED) ||
        !durable_all_zero(entry->reserved, sizeof(entry->reserved)))
        return 0;
    return 1;
}

static int settings_entry_valid(const RinFilePortalSettingsEntryV1* entry)
{
    if (entry == NULL || entry->grant_id == 0u ||
        entry->database_generation == 0u || entry->mount_id == 0u ||
        entry->namespace_id == 0u || entry->object_id == 0u ||
        entry->object_generation == 0u ||
        (entry->object_type != RIN_FILE_PORTAL_DURABLE_OBJECT_REGULAR &&
         entry->object_type != RIN_FILE_PORTAL_DURABLE_OBJECT_DIRECTORY) ||
        (entry->scope != RIN_FILE_PORTAL_DURABLE_SCOPE_EXACT &&
         entry->scope != RIN_FILE_PORTAL_DURABLE_SCOPE_DESCENDANTS) ||
        (entry->rights & ~RIN_FILE_PORTAL_RIGHT_ALL) != 0u ||
        entry->rights == 0u ||
        (entry->state != RIN_FILE_PORTAL_DURABLE_STATE_ACTIVE &&
         entry->state != RIN_FILE_PORTAL_DURABLE_STATE_EXPIRED) ||
        !durable_identity_valid(&entry->identity) ||
        !durable_all_zero(entry->reserved, sizeof(entry->reserved)))
        return 0;
    return 1;
}

static int durable_call_header_valid(const RinFilePortalCallV1* call,
                                     uint16_t operation,
                                     int allow_expiry)
{
    return call != NULL && call->struct_size == sizeof(*call) &&
           call->version == RIN_FILE_PORTAL_CALL_VERSION &&
           call->operation == operation && call->descriptor == -1 &&
           call->requested_rights == 0u && call->target_process_id == 0u &&
           call->descriptor_flags == 0u && call->target_process_cookie == 0u &&
           call->granted_rights == 0u && call->process_fd == -1 &&
           call->request_id == 0u && call->new_generation == 0u &&
           call->request_status == 0 && call->reserved_status == 0u &&
           (allow_expiry || call->expires_at_epoch == 0u) &&
           durable_all_zero(
               (const uint8_t*)call->reserved, sizeof(call->reserved));
}

static int durable_revoke_call_empty(const RinFilePortalCallV1* call)
{
    return call != NULL && call->descriptor == -1 &&
           call->requested_rights == 0u && call->target_process_id == 0u &&
           call->descriptor_flags == 0u && call->target_process_cookie == 0u &&
           durable_all_zero((const uint8_t*)&call->token, sizeof(call->token)) &&
           durable_all_zero((const uint8_t*)&call->settings_entry,
                            sizeof(call->settings_entry)) &&
           call->granted_rights == 0u && call->process_fd == -1 &&
           call->new_generation == 0u && call->request_status == 0 &&
           call->reserved_status == 0u &&
           durable_all_zero((const uint8_t*)call->reserved,
                            sizeof(call->reserved));
}

static int durable_revoke_status_shape_valid(const RinFilePortalCallV1* call)
{
    return call != NULL && call->descriptor == -1 &&
           call->requested_rights == 0u && call->target_process_id == 0u &&
           call->descriptor_flags == 0u && call->target_process_cookie == 0u &&
           durable_all_zero((const uint8_t*)&call->token, sizeof(call->token)) &&
           durable_all_zero((const uint8_t*)&call->settings_entry,
                            sizeof(call->settings_entry)) &&
           call->granted_rights == 0u && call->process_fd == -1 &&
           call->file_object_id == 0u && call->expires_at_epoch == 0u &&
           call->reserved_status == 0u &&
           durable_all_zero((const uint8_t*)call->reserved,
                            sizeof(call->reserved));
}

RinRuntimeDurableFilePortalResult rinruntime_file_portal_durable_open(
    uint64_t grant_id, uint32_t requested_rights, int32_t minimum_fd,
    uint32_t descriptor_flags, int32_t* descriptor_out)
{
    RinFilePortalCallV1 call;
    int result;

    if (descriptor_out != NULL) *descriptor_out = -1;
    if (descriptor_out == NULL || grant_id == 0u || requested_rights == 0u ||
        (requested_rights & ~RIN_FILE_PORTAL_RIGHT_ALL) != 0u ||
        minimum_fd < 0 ||
        (descriptor_flags & ~RIN_FILE_PORTAL_CALL_FD_CLOEXEC) != 0u)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;

    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_DURABLE_OPEN;
    call.descriptor = minimum_fd;
    call.requested_rights = requested_rights;
    call.process_fd = -1;
    call.file_object_id = grant_id;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_OK && call.granted_rights == requested_rights &&
        call.file_object_id == grant_id && call.process_fd >= minimum_fd) {
        *descriptor_out = call.process_fd;
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
    }
    if (result == RIN_RESULT_OK && call.process_fd >= minimum_fd)
        (void)close(call.process_fd);
    memset(&call, 0, sizeof(call));
    return result == RIN_RESULT_OK
        ? RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY
        : RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
}

RinRuntimeDurableFilePortalResult
rinruntime_file_portal_reopen_document_identity(
    const RinRuntimeFileChooserDocumentIdentityV1* document_identity,
    uint32_t requested_rights, int32_t minimum_fd, uint32_t descriptor_flags,
    int32_t* descriptor_out)
{
    RinFilePortalDurableEntryV1 entry;
    uint64_t object_id = 0u;
    uint64_t cursor = 0u;
    uint64_t next_cursor = 0u;
    uint32_t scan_count;
    int matched = 0;
    RinRuntimeDurableFilePortalResult result;

    if (descriptor_out != NULL) *descriptor_out = -1;
    if (!durable_document_identity_valid(document_identity, &object_id) ||
        descriptor_out == NULL || requested_rights == 0u ||
        (requested_rights & ~RIN_FILE_PORTAL_RIGHT_ALL) != 0u ||
        minimum_fd < 0 ||
        (descriptor_flags & ~RIN_FILE_PORTAL_CALL_FD_CLOEXEC) != 0u)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;

    for (scan_count = 0u;
         scan_count < RINRUNTIME_DURABLE_FILE_PORTAL_REOPEN_MAX_SCAN;
         ++scan_count) {
        memset(&entry, 0, sizeof(entry));
        next_cursor = 0u;
        result = rinruntime_file_portal_durable_list(
            cursor, &entry, &next_cursor);
        if (result == RINRUNTIME_DURABLE_FILE_PORTAL_NOT_FOUND)
            return matched ? RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED
                            : RINRUNTIME_DURABLE_FILE_PORTAL_NOT_FOUND;
        if (result != RINRUNTIME_DURABLE_FILE_PORTAL_OK)
            return result;
        if (entry.object_type == RIN_FILE_PORTAL_DURABLE_OBJECT_REGULAR &&
            entry.object_id == object_id) {
            matched = 1;
            result = rinruntime_file_portal_durable_open(
                entry.grant_id, requested_rights, minimum_fd,
                descriptor_flags, descriptor_out);
            if (result == RINRUNTIME_DURABLE_FILE_PORTAL_OK ||
                result == RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY)
                return result;
            *descriptor_out = -1;
        }
        if (next_cursor == 0u || next_cursor == cursor)
            return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
        cursor = next_cursor;
    }
    return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
}

RinRuntimeDurableFilePortalResult rinruntime_file_portal_durable_list(
    uint64_t cursor, RinFilePortalDurableEntryV1* entry_out,
    uint64_t* next_cursor_out)
{
    RinFilePortalCallV1 call;
    int result;

    if (entry_out != NULL) memset(entry_out, 0, sizeof(*entry_out));
    if (next_cursor_out != NULL) *next_cursor_out = 0u;
    if (entry_out == NULL || next_cursor_out == NULL)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;

    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_DURABLE_LIST;
    call.descriptor = -1;
    call.process_fd = -1;
    call.file_object_id = cursor;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_NOT_FOUND) {
        if (!durable_call_header_valid(
                &call, RIN_FILE_PORTAL_OPERATION_DURABLE_LIST, 0) ||
            call.file_object_id != cursor ||
            !durable_all_zero((const uint8_t*)&call.durable_entry,
                              sizeof(call.durable_entry))) {
            memset(&call, 0, sizeof(call));
            return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
        }
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_NOT_FOUND;
    }
    if (result != RIN_RESULT_OK) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
    }
    if (!durable_call_header_valid(
            &call, RIN_FILE_PORTAL_OPERATION_DURABLE_LIST, 1) ||
        call.expires_at_epoch != call.durable_entry.expires_at_epoch ||
        !durable_entry_valid(&call.durable_entry) ||
        call.file_object_id == 0u || call.file_object_id == cursor) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
    }
    *entry_out = call.durable_entry;
    *next_cursor_out = call.file_object_id;
    memset(&call, 0, sizeof(call));
    return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
}

RinRuntimeDurableFilePortalResult rinruntime_file_portal_settings_list(
    uint64_t cursor, RinFilePortalSettingsEntryV1* entry_out,
    uint64_t* next_cursor_out)
{
    RinFilePortalCallV1 call;
    int result;

    if (entry_out != NULL) memset(entry_out, 0, sizeof(*entry_out));
    if (next_cursor_out != NULL) *next_cursor_out = 0u;
    if (entry_out == NULL || next_cursor_out == NULL)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;

    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_SETTINGS_LIST;
    call.descriptor = -1;
    call.process_fd = -1;
    call.file_object_id = cursor;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_NOT_FOUND) {
        if (!durable_call_header_valid(
                &call, RIN_FILE_PORTAL_OPERATION_SETTINGS_LIST, 0) ||
            call.file_object_id != cursor ||
            !durable_all_zero((const uint8_t*)&call.settings_entry,
                              sizeof(call.settings_entry))) {
            memset(&call, 0, sizeof(call));
            return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
        }
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_NOT_FOUND;
    }
    if (result != RIN_RESULT_OK) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
    }
    if (!durable_call_header_valid(
            &call, RIN_FILE_PORTAL_OPERATION_SETTINGS_LIST, 1) ||
        !settings_entry_valid(&call.settings_entry) ||
        call.expires_at_epoch != call.settings_entry.expires_at_epoch ||
        call.file_object_id == 0u || call.file_object_id == cursor) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY;
    }
    *entry_out = call.settings_entry;
    *next_cursor_out = call.file_object_id;
    memset(&call, 0, sizeof(call));
    return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
}

RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_request(
    uint64_t grant_id, uint64_t* request_id_out,
    uint64_t* expires_at_epoch_out)
{
    RinFilePortalCallV1 call;
    int result;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (expires_at_epoch_out != NULL) *expires_at_epoch_out = 0u;
    if (grant_id == 0u || request_id_out == NULL || expires_at_epoch_out == NULL)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;
    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_SETTINGS_REVOKE_REQUEST;
    call.descriptor = -1;
    call.process_fd = -1;
    call.file_object_id = grant_id;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_OK && durable_revoke_call_empty(&call) != 0 &&
        call.file_object_id == grant_id && call.request_id != 0u &&
        call.expires_at_epoch != 0u) {
        *request_id_out = call.request_id;
        *expires_at_epoch_out = call.expires_at_epoch;
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
    }
    memset(&call, 0, sizeof(call));
    return result == RIN_RESULT_OK
        ? RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY
        : RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
}

RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_status(
    uint64_t request_id, int32_t* permission_status_out,
    uint64_t* new_generation_out)
{
    RinFilePortalCallV1 call;
    int result;
    if (permission_status_out != NULL) *permission_status_out = 0;
    if (new_generation_out != NULL) *new_generation_out = 0u;
    if (request_id == 0u || permission_status_out == NULL ||
        new_generation_out == NULL)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;
    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_SETTINGS_REVOKE_STATUS;
    call.descriptor = -1;
    call.process_fd = -1;
    call.request_id = request_id;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_BUSY) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_PENDING;
    }
    if (result == RIN_RESULT_OK && call.request_id == request_id &&
        call.file_object_id == 0u && call.expires_at_epoch == 0u &&
        durable_revoke_status_shape_valid(&call) &&
        call.request_status <= 0 && call.request_status >= -12) {
        *permission_status_out = call.request_status;
        *new_generation_out = call.new_generation;
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
    }
    memset(&call, 0, sizeof(call));
    return result == RIN_RESULT_OK
        ? RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY
        : RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
}

RinRuntimeDurableFilePortalResult
rinruntime_file_portal_settings_revoke_finish(uint64_t request_id)
{
    RinFilePortalCallV1 call;
    int result;
    if (request_id == 0u)
        return RINRUNTIME_DURABLE_FILE_PORTAL_INVALID_ARGUMENT;
    memset(&call, 0, sizeof(call));
    call.struct_size = sizeof(call);
    call.version = RIN_FILE_PORTAL_CALL_VERSION;
    call.operation = RIN_FILE_PORTAL_OPERATION_SETTINGS_REVOKE_FINISH;
    call.descriptor = -1;
    call.process_fd = -1;
    call.request_id = request_id;
    result = rin_file_portal_call(&call);
    if (result == RIN_RESULT_OK && call.request_id == request_id &&
        call.file_object_id == 0u && call.expires_at_epoch == 0u &&
        durable_revoke_call_empty(&call) != 0) {
        memset(&call, 0, sizeof(call));
        return RINRUNTIME_DURABLE_FILE_PORTAL_OK;
    }
    memset(&call, 0, sizeof(call));
    return result == RIN_RESULT_OK
        ? RINRUNTIME_DURABLE_FILE_PORTAL_MALFORMED_REPLY
        : RINRUNTIME_DURABLE_FILE_PORTAL_KERNEL_REJECTED;
}


