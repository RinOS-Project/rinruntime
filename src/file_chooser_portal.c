/* SPDX-License-Identifier: MIT */

#include <rinruntime/file_chooser_portal.h>
#include <rinruntime/text_codec.h>
#include <rinruntime/path.h>
#include <rin/capability.h>

#include <errno.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <rin/contract_abi.h>
#include <rin/socket_abi.h>
#include "../../../../src/api/rin_abi.h"
#endif

#if !defined(_WIN32)
static uint64_t g_file_chooser_request_id;
#endif

static void chooser_zero(void* output, size_t size)
{
    if (output != NULL) memset(output, 0, size);
}

static int chooser_rights_valid(uint32_t rights)
{
    return rights != 0u &&
           (rights & ~RIN_FILE_PORTAL_RIGHT_ALL) == 0u;
}

static int chooser_suggested_name_valid(const char* name, size_t size)
{
    if (size == 0u)
        return 1;
    return name != NULL && rin_path_filename_valid(name, size) != 0;
}

static int chooser_request_valid(
    const RinRuntimeFileChooserRequestV1Input* request)
{
    if (request == NULL || !chooser_rights_valid(request->requested_rights) ||
        request->suggested_name_size >
            RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME ||
        (request->suggested_name_size != 0u && request->suggested_name == NULL) ||
        !chooser_suggested_name_valid(request->suggested_name,
                                      request->suggested_name_size)) {
        return 0;
    }
    switch (request->kind) {
    case RINRUNTIME_FILE_CHOOSER_OPEN:
        return (request->flags & ~RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ALLOW_MULTIPLE) == 0u &&
               request->suggested_name_size == 0u &&
               (request->requested_rights &
                ~(RIN_FILE_PORTAL_RIGHT_READ | RIN_FILE_PORTAL_RIGHT_METADATA)) == 0u;
    case RINRUNTIME_FILE_CHOOSER_SAVE:
        return request->suggested_name_size != 0u &&
               request->flags ==
                   RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ATOMIC_SAVE_DESTINATION &&
               (request->requested_rights &
                ~(RIN_FILE_PORTAL_RIGHT_WRITE | RIN_FILE_PORTAL_RIGHT_METADATA)) == 0u &&
               (request->requested_rights & RIN_FILE_PORTAL_RIGHT_WRITE) != 0u;
    case RINRUNTIME_FILE_CHOOSER_FOLDER:
        return request->flags == 0u && request->suggested_name_size == 0u;
    default:
        return 0;
    }
}

static int chooser_result_valid(RinRuntimeFileChooserResult result)
{
    return result == RINRUNTIME_FILE_CHOOSER_OK ||
           result == RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT ||
           result == RINRUNTIME_FILE_CHOOSER_DENIED ||
           result == RINRUNTIME_FILE_CHOOSER_CANCELLED ||
           result == RINRUNTIME_FILE_CHOOSER_SERVER_FAILED ||
           result == RINRUNTIME_FILE_CHOOSER_COMMITTED_UNSYNCED;
}

int rinruntime_file_chooser_save_capability_valid(
    const RinRuntimeFileChooserSaveCapabilityV1* capability)
{
    if (capability == NULL) return 0;
    return rin_wire_capability_token_valid(
               capability->bytes, sizeof(capability->bytes),
               sizeof(capability->bytes), sizeof(capability->bytes)) ==
           RIN_WIRE_CAPABILITY_OK;
}

static int chooser_token_structural_valid(const RinFilePortalTokenV1* token)
{
    if (token == NULL || token->magic != RIN_FILE_PORTAL_TOKEN_MAGIC ||
        token->version != RIN_FILE_PORTAL_TOKEN_VERSION ||
        token->token_size != RIN_FILE_PORTAL_TOKEN_SIZE || token->flags != 0u ||
        !chooser_rights_valid(token->rights) || token->file_object_id == 0u ||
        token->policy_generation == 0u ||
        rin_wire_capability_generation_valid(token->policy_generation) !=
            RIN_WIRE_CAPABILITY_OK ||
        rin_wire_capability_expiry_shape_valid(
            token->not_before_epoch, token->expires_at_epoch) !=
            RIN_WIRE_CAPABILITY_OK ||
        rin_wire_capability_token_valid(
            token->nonce, sizeof(token->nonce), sizeof(token->nonce),
            sizeof(token->nonce)) != RIN_WIRE_CAPABILITY_OK ||
        rin_wire_capability_token_valid(
            token->authentication_tag, sizeof(token->authentication_tag),
            sizeof(token->authentication_tag), sizeof(token->authentication_tag)) !=
            RIN_WIRE_CAPABILITY_OK)
        return 0;
    return rin_wire_reserved_zero(token->reserved, sizeof(token->reserved));
}

static int chooser_token_structural_valid(const RinFilePortalTokenV1* token);

static int chooser_selection_valid(
    const RinRuntimeFileChooserSelectionV1* selection)
{
    if (selection == NULL || selection->reserved != 0u ||
        selection->display_name_size == 0u ||
        selection->display_name_size > RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME ||
        !chooser_token_structural_valid(&selection->token) ||
        rinruntime_text_utf8_validate((const uint8_t*)selection->display_name,
                                      selection->display_name_size) !=
            RINRUNTIME_TEXT_CODEC_OK)
        return 0;
    for (size_t index = 0u; index < selection->display_name_size; ++index) {
        unsigned char byte = (unsigned char)selection->display_name[index];
        if (byte < 0x20u || byte == 0x7fu || byte == '/' || byte == '\\')
            return 0;
    }
    for (size_t index = selection->display_name_size;
         index < sizeof(selection->display_name); ++index)
        if (selection->display_name[index] != '\0') return 0;
    return 1;
}

int rinruntime_file_chooser_document_identity_valid(
    const RinRuntimeFileChooserDocumentIdentityV1* identity)
{
    if (identity == NULL) return 0;
    return rin_wire_capability_token_valid(
               identity->bytes, sizeof(identity->bytes),
               sizeof(identity->bytes), sizeof(identity->bytes)) ==
           RIN_WIRE_CAPABILITY_OK;
}

static void chooser_put_u64_le(uint8_t* output, uint64_t value)
{
    size_t index;
    for (index = 0u; index < 8u; ++index) {
        output[index] = (uint8_t)(value & 0xffu);
        value >>= 8u;
    }
}

RinRuntimeFileChooserResult rinruntime_file_chooser_document_identity_from_token(
    const RinFilePortalTokenV1* token,
    RinRuntimeFileChooserDocumentIdentityV1* identity_out)
{
    if (identity_out != NULL) chooser_zero(identity_out, sizeof(*identity_out));
    if (token == NULL || identity_out == NULL ||
        !chooser_token_structural_valid(token))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;

    /* The object id is stable across chooser tokens. A fixed domain tag keeps
     * this value distinct from other opaque IDs without copying policy,
     * package, or pathname data into the recent-item contract. */
    chooser_put_u64_le(identity_out->bytes, token->file_object_id);
    memcpy(identity_out->bytes + 8u, "RIN-DOC1", 8u);
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_request_encode(
    uint64_t request_id, const RinRuntimeFileChooserRequestV1Input* request,
    void* frame_out, size_t frame_capacity, size_t* frame_size_out)
{
    RinRuntimeFileChooserRequestV1 header;
    size_t frame_size;
    if (frame_size_out != NULL) *frame_size_out = 0u;
    chooser_zero(frame_out, frame_capacity);
    if (request_id == 0u || !chooser_request_valid(request) ||
        frame_out == NULL || frame_size_out == NULL ||
        request->suggested_name_size > SIZE_MAX - sizeof(header)) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    frame_size = sizeof(header) + request->suggested_name_size;
    if (frame_capacity < frame_size || frame_size > UINT32_MAX)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    chooser_zero(&header, sizeof(header));
    header.frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    header.frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    header.frame.operation = RINRUNTIME_FILE_CHOOSER_OPERATION_REQUEST;
    header.frame.frame_size = (uint32_t)frame_size;
    header.frame.request_id = request_id;
    header.kind = (uint32_t)request->kind;
    header.requested_rights = request->requested_rights;
    header.suggested_name_size = (uint32_t)request->suggested_name_size;
    header.flags = request->flags;
    memcpy(frame_out, &header, sizeof(header));
    if (request->suggested_name_size != 0u) {
        memcpy((uint8_t*)frame_out + sizeof(header), request->suggested_name,
               request->suggested_name_size);
    }
    *frame_size_out = frame_size;
    chooser_zero(&header, sizeof(header));
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_request_decode(
    const void* frame, size_t frame_size,
    RinRuntimeFileChooserRequestViewV1* request_out)
{
    RinRuntimeFileChooserRequestV1 header;
    RinRuntimeFileChooserRequestV1Input input;
    if (request_out != NULL) chooser_zero(request_out, sizeof(*request_out));
    if (frame == NULL || request_out == NULL || frame_size < sizeof(header))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    memcpy(&header, frame, sizeof(header));
    if (header.frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        header.frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        header.frame.operation != RINRUNTIME_FILE_CHOOSER_OPERATION_REQUEST ||
        header.frame.request_id == 0u || header.frame.frame_size != frame_size ||
        header.reserved != 0u ||
        header.suggested_name_size > RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME ||
        header.suggested_name_size != frame_size - sizeof(header)) {
        chooser_zero(&header, sizeof(header));
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    input.kind = (RinRuntimeFileChooserKind)header.kind;
    input.requested_rights = header.requested_rights;
    input.suggested_name = (const char*)frame + sizeof(header);
    input.suggested_name_size = header.suggested_name_size;
    input.flags = header.flags;
    if (!chooser_request_valid(&input)) {
        chooser_zero(&header, sizeof(header));
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    request_out->request_id = header.frame.request_id;
    request_out->kind = input.kind;
    request_out->requested_rights = input.requested_rights;
    request_out->suggested_name = input.suggested_name;
    request_out->suggested_name_size = input.suggested_name_size;
    request_out->flags = input.flags;
    chooser_zero(&header, sizeof(header));
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinFilePortalTokenV1* token, RinRuntimeFileChooserGrantV1* grant_out)
{
    if (grant_out != NULL) chooser_zero(grant_out, sizeof(*grant_out));
    if (grant_out == NULL || request_id == 0u || !chooser_result_valid(result) ||
        (result == RINRUNTIME_FILE_CHOOSER_OK &&
         !chooser_token_structural_valid(token)) ||
        (result != RINRUNTIME_FILE_CHOOSER_OK && token != NULL)) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    grant_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    grant_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    grant_out->frame.operation = RINRUNTIME_FILE_CHOOSER_OPERATION_GRANT;
    grant_out->frame.frame_size = sizeof(*grant_out);
    grant_out->frame.request_id = request_id;
    grant_out->result = result;
    if (token != NULL) grant_out->token = *token;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_grant_decode(
    const RinRuntimeFileChooserGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out, RinFilePortalTokenV1* token_out,
    uint64_t* request_id_out)
{
    RinRuntimeFileChooserResult result;
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    if (token_out != NULL) chooser_zero(token_out, sizeof(*token_out));
    if (request_id_out != NULL) *request_id_out = 0u;
    if (grant == NULL || result_out == NULL || token_out == NULL ||
        request_id_out == NULL || frame_size != sizeof(*grant) ||
        grant->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        grant->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        grant->frame.operation != RINRUNTIME_FILE_CHOOSER_OPERATION_GRANT ||
        grant->frame.frame_size != sizeof(*grant) || grant->frame.request_id == 0u ||
        grant->reserved != 0u) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    result = (RinRuntimeFileChooserResult)grant->result;
    if (!chooser_result_valid(result) ||
        (result == RINRUNTIME_FILE_CHOOSER_OK &&
         !chooser_token_structural_valid(&grant->token))) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (result != RINRUNTIME_FILE_CHOOSER_OK) {
        uint8_t zero = 0u;
        size_t index;
        for (index = 0u; index < sizeof(grant->token); ++index)
            zero |= ((const uint8_t*)&grant->token)[index];
        if (zero != 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    } else {
        *token_out = grant->token;
    }
    *result_out = result;
    *request_id_out = grant->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

static int chooser_capability_zero(
    const RinRuntimeFileChooserSaveCapabilityV1* capability)
{
    uint8_t observed = 0u;
    size_t index;
    if (capability == NULL) return 1;
    for (index = 0u; index < sizeof(capability->bytes); ++index)
        observed |= capability->bytes[index];
    return observed == 0u;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinRuntimeFileChooserSaveCapabilityV1* capability,
    RinRuntimeFileChooserSaveDestinationGrantV1* grant_out)
{
    if (grant_out != NULL) chooser_zero(grant_out, sizeof(*grant_out));
    if (grant_out == NULL || request_id == 0u || !chooser_result_valid(result) ||
        (result == RINRUNTIME_FILE_CHOOSER_OK &&
         !rinruntime_file_chooser_save_capability_valid(capability)) ||
        (result != RINRUNTIME_FILE_CHOOSER_OK && capability != NULL)) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    grant_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    grant_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    grant_out->frame.operation =
        RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_GRANT;
    grant_out->frame.frame_size = sizeof(*grant_out);
    grant_out->frame.request_id = request_id;
    grant_out->result = result;
    if (capability != NULL) grant_out->capability = *capability;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_grant_decode(
    const RinRuntimeFileChooserSaveDestinationGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* request_id_out)
{
    RinRuntimeFileChooserResult result;
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    if (capability_out != NULL) chooser_zero(capability_out, sizeof(*capability_out));
    if (request_id_out != NULL) *request_id_out = 0u;
    if (grant == NULL || result_out == NULL || capability_out == NULL ||
        request_id_out == NULL || frame_size != sizeof(*grant) ||
        grant->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        grant->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        grant->frame.operation !=
            RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_GRANT ||
        grant->frame.frame_size != sizeof(*grant) || grant->frame.request_id == 0u ||
        grant->reserved != 0u) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    result = (RinRuntimeFileChooserResult)grant->result;
    if (!chooser_result_valid(result) ||
        (result == RINRUNTIME_FILE_CHOOSER_OK &&
         !rinruntime_file_chooser_save_capability_valid(&grant->capability)) ||
        (result != RINRUNTIME_FILE_CHOOSER_OK &&
         !chooser_capability_zero(&grant->capability))) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (result == RINRUNTIME_FILE_CHOOSER_OK) *capability_out = grant->capability;
    *result_out = result;
    *request_id_out = grant->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save_request_encode(
    uint64_t request_id, const RinRuntimeFileChooserSaveCapabilityV1* capability,
    uint64_t data_size, RinRuntimeFileChooserAtomicSaveRequestV1* request_out)
{
    if (request_out != NULL) chooser_zero(request_out, sizeof(*request_out));
    if (request_out == NULL || request_id == 0u ||
        !rinruntime_file_chooser_save_capability_valid(capability) ||
        data_size > RINRUNTIME_FILE_CHOOSER_ATOMIC_SAVE_MAX_BYTES) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    request_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    request_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    request_out->frame.operation = RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_REQUEST;
    request_out->frame.frame_size = sizeof(*request_out);
    request_out->frame.request_id = request_id;
    request_out->capability = *capability;
    request_out->data_size = data_size;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save_request_decode(
    const RinRuntimeFileChooserAtomicSaveRequestV1* request, size_t frame_size,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* data_size_out, uint64_t* request_id_out)
{
    if (capability_out != NULL) chooser_zero(capability_out, sizeof(*capability_out));
    if (data_size_out != NULL) *data_size_out = 0u;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (request == NULL || capability_out == NULL || data_size_out == NULL ||
        request_id_out == NULL || frame_size != sizeof(*request) ||
        request->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        request->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        request->frame.operation != RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_REQUEST ||
        request->frame.frame_size != sizeof(*request) || request->frame.request_id == 0u ||
        request->reserved != 0u ||
        !rinruntime_file_chooser_save_capability_valid(&request->capability) ||
        request->data_size > RINRUNTIME_FILE_CHOOSER_ATOMIC_SAVE_MAX_BYTES) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    *capability_out = request->capability;
    *data_size_out = request->data_size;
    *request_id_out = request->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

static int chooser_status_operation_valid(uint16_t operation)
{
    return operation == RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY ||
           operation == RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_COMPLETE ||
           operation ==
               RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE_COMPLETE;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_status_encode(
    uint16_t operation, uint64_t request_id, RinRuntimeFileChooserResult result,
    RinRuntimeFileChooserStatusV1* status_out)
{
    if (status_out != NULL) chooser_zero(status_out, sizeof(*status_out));
    if (status_out == NULL || request_id == 0u ||
        !chooser_status_operation_valid(operation) || !chooser_result_valid(result)) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    status_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    status_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    status_out->frame.operation = operation;
    status_out->frame.frame_size = sizeof(*status_out);
    status_out->frame.request_id = request_id;
    status_out->result = result;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_status_decode(
    const RinRuntimeFileChooserStatusV1* status, size_t frame_size,
    uint16_t expected_operation, RinRuntimeFileChooserResult* result_out,
    uint64_t* request_id_out)
{
    RinRuntimeFileChooserResult result;
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (status == NULL || result_out == NULL || request_id_out == NULL ||
        frame_size != sizeof(*status) ||
        !chooser_status_operation_valid(expected_operation) ||
        status->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        status->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        status->frame.operation != expected_operation ||
        status->frame.frame_size != sizeof(*status) || status->frame.request_id == 0u ||
        status->reserved != 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    result = (RinRuntimeFileChooserResult)status->result;
    if (!chooser_result_valid(result)) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    *result_out = result;
    *request_id_out = status->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release_encode(
    uint64_t request_id, const RinRuntimeFileChooserSaveCapabilityV1* capability,
    RinRuntimeFileChooserSaveDestinationReleaseV1* release_out)
{
    if (release_out != NULL) chooser_zero(release_out, sizeof(*release_out));
    if (release_out == NULL || request_id == 0u ||
        !rinruntime_file_chooser_save_capability_valid(capability)) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    release_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    release_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    release_out->frame.operation =
        RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE;
    release_out->frame.frame_size = sizeof(*release_out);
    release_out->frame.request_id = request_id;
    release_out->capability = *capability;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release_decode(
    const RinRuntimeFileChooserSaveDestinationReleaseV1* release,
    size_t frame_size, RinRuntimeFileChooserSaveCapabilityV1* capability_out,
    uint64_t* request_id_out)
{
    if (capability_out != NULL) chooser_zero(capability_out, sizeof(*capability_out));
    if (request_id_out != NULL) *request_id_out = 0u;
    if (release == NULL || capability_out == NULL || request_id_out == NULL ||
        frame_size != sizeof(*release) ||
        release->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        release->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        release->frame.operation !=
            RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE ||
        release->frame.frame_size != sizeof(*release) ||
        release->frame.request_id == 0u ||
        !rinruntime_file_chooser_save_capability_valid(&release->capability)) {
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    *capability_out = release->capability;
    *request_id_out = release->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

#if !defined(_WIN32)
static int chooser_write_all(int descriptor, const void* bytes, size_t size)
{
    const uint8_t* cursor = (const uint8_t*)bytes;
    while (size != 0u) {
        ssize_t written = send(descriptor, cursor, size, MSG_NOSIGNAL);
        if (written > 0) {
            if ((size_t)written > size) return 0;
            cursor += (size_t)written;
            size -= (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static int chooser_read_all(int descriptor, void* bytes, size_t size)
{
    uint8_t* cursor = (uint8_t*)bytes;
    while (size != 0u) {
        ssize_t received = recv(descriptor, cursor, size, 0);
        if (received > 0) {
            if ((size_t)received > size) return 0;
            cursor += (size_t)received;
            size -= (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) continue;
        return 0;
    }
    return 1;
}

static uint64_t chooser_next_request_id(void)
{
    uint64_t request_id = __atomic_add_fetch(&g_file_chooser_request_id, 1u,
                                             __ATOMIC_RELAXED);
    if (request_id == 0u) request_id = __atomic_add_fetch(
        &g_file_chooser_request_id, 1u, __ATOMIC_RELAXED);
    return request_id;
}

static int chooser_connect(void)
{
    struct sockaddr_un address;
    rin_unix_service_identity_v1 service_identity;
    rin_unix_peer_app_identity_v1 peer_identity;
    socklen_t identity_size;
    int descriptor;
    chooser_zero(&address, sizeof(address));
    address.sun_family = AF_UNIX;
    if (sizeof(RINRUNTIME_FILE_CHOOSER_SERVICE_PATH) > sizeof(address.sun_path))
        return -1;
    memcpy(address.sun_path, RINRUNTIME_FILE_CHOOSER_SERVICE_PATH,
           sizeof(RINRUNTIME_FILE_CHOOSER_SERVICE_PATH));
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0) return -1;
    if (connect(descriptor, (const struct sockaddr*)&address, sizeof(address)) != 0) {
        (void)close(descriptor);
        return -1;
    }
    chooser_zero(&service_identity, sizeof(service_identity));
    identity_size = sizeof(service_identity);
    if (getsockopt(descriptor, SOL_SOCKET, SO_RIN_UNIX_SERVICE_IDENTITY,
                   &service_identity, &identity_size) != 0 ||
        identity_size != sizeof(service_identity)) {
        (void)close(descriptor);
        return -1;
    }
    chooser_zero(&peer_identity, sizeof(peer_identity));
    identity_size = sizeof(peer_identity);
    if (getsockopt(descriptor, SOL_SOCKET, SO_RIN_UNIX_PEER_APP_IDENTITY,
                   &peer_identity, &identity_size) != 0 ||
        identity_size != sizeof(peer_identity) ||
        service_identity.owner_uid == 0u ||
        service_identity.owner_uid != peer_identity.owner_uid ||
        service_identity.scope != peer_identity.scope ||
        service_identity.flags != RIN_UNIX_SERVICE_IDENTITY_FLAG_PUBLISHED ||
        !rin_unix_peer_app_identity_valid(&peer_identity) ||
        peer_identity.capabilities !=
            (RIN_CAP_CLIPBOARD | RIN_CAP_FILE_PORTAL)) {
        chooser_zero(&service_identity, sizeof(service_identity));
        chooser_zero(&peer_identity, sizeof(peer_identity));
        (void)close(descriptor);
        return -1;
    }
    chooser_zero(&service_identity, sizeof(service_identity));
    chooser_zero(&peer_identity, sizeof(peer_identity));
    return descriptor;
}

#endif

RinRuntimeFileChooserResult rinruntime_file_chooser_multiple_grant_encode(
    uint64_t request_id, RinRuntimeFileChooserResult result,
    const RinRuntimeFileChooserSelectionV1* selections, uint32_t selection_count,
    RinRuntimeFileChooserMultipleGrantV1* grant_out)
{
    if (grant_out != NULL) chooser_zero(grant_out, sizeof(*grant_out));
    if (grant_out == NULL || request_id == 0u || !chooser_result_valid(result) ||
        selection_count > RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS ||
        (result == RINRUNTIME_FILE_CHOOSER_OK &&
         (selection_count == 0u || selections == NULL)) ||
        (result != RINRUNTIME_FILE_CHOOSER_OK &&
         (selection_count != 0u || selections != NULL)))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    for (uint32_t index = 0u; index < selection_count; ++index)
        if (!chooser_selection_valid(&selections[index]))
            return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    grant_out->frame.magic = RINRUNTIME_FILE_CHOOSER_MAGIC;
    grant_out->frame.version = RINRUNTIME_FILE_CHOOSER_VERSION;
    grant_out->frame.operation = RINRUNTIME_FILE_CHOOSER_OPERATION_MULTIPLE_GRANT;
    grant_out->frame.frame_size = sizeof(*grant_out);
    grant_out->frame.request_id = request_id;
    grant_out->result = result;
    grant_out->selection_count = selection_count;
    if (selection_count != 0u)
        memcpy(grant_out->selections, selections,
               sizeof(*selections) * selection_count);
    return RINRUNTIME_FILE_CHOOSER_OK;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_multiple_grant_decode(
    const RinRuntimeFileChooserMultipleGrantV1* grant, size_t frame_size,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSelectionV1* selections_out,
    uint32_t* selection_count_out, uint64_t* request_id_out)
{
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    if (selection_count_out != NULL) *selection_count_out = 0u;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (selections_out != NULL)
        chooser_zero(selections_out,
                     sizeof(*selections_out) * RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS);
    if (grant == NULL || result_out == NULL || selections_out == NULL ||
        selection_count_out == NULL || request_id_out == NULL ||
        frame_size != sizeof(*grant) || grant->frame.magic != RINRUNTIME_FILE_CHOOSER_MAGIC ||
        grant->frame.version != RINRUNTIME_FILE_CHOOSER_VERSION ||
        grant->frame.operation != RINRUNTIME_FILE_CHOOSER_OPERATION_MULTIPLE_GRANT ||
        grant->frame.frame_size != sizeof(*grant) || grant->frame.request_id == 0u ||
        grant->selection_count > RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS ||
        !chooser_result_valid((RinRuntimeFileChooserResult)grant->result))
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    RinRuntimeFileChooserResult result = (RinRuntimeFileChooserResult)grant->result;
    if (result == RINRUNTIME_FILE_CHOOSER_OK) {
        if (grant->selection_count == 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
        for (uint32_t index = 0u; index < grant->selection_count; ++index)
            if (!chooser_selection_valid(&grant->selections[index]))
                return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
        for (uint32_t index = grant->selection_count;
             index < RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS; ++index)
        {
            uint8_t observed = 0u;
            for (size_t byte = 0u; byte < sizeof(grant->selections[index]); ++byte)
                observed |= ((const uint8_t*)&grant->selections[index])[byte];
            if (observed != 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
        }
        memcpy(selections_out, grant->selections,
               sizeof(*selections_out) * grant->selection_count);
    } else if (grant->selection_count != 0u) {
        /* Error replies must not carry selection material. */
        uint8_t observed = 0u;
        for (size_t index = 0u; index < sizeof(grant->selections); ++index)
            observed |= ((const uint8_t*)grant->selections)[index];
        if (observed != 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    uint8_t reserved_zero = 0u;
    for (size_t index = 0u; index < sizeof(grant->reserved); ++index)
        reserved_zero |= ((const uint8_t*)grant->reserved)[index];
    if (reserved_zero != 0u) return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    *result_out = result;
    *selection_count_out = grant->selection_count;
    *request_id_out = grant->frame.request_id;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

#if !defined(_WIN32)

static int chooser_async_set_nonblocking(int descriptor)
{
    int flags;
    if (descriptor < 0) return 0;
    flags = fcntl(descriptor, F_GETFL, 0);
    if (flags < 0) return 0;
    if ((flags & O_NONBLOCK) != 0) return 1;
    return fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static RinRuntimeFileChooserResult chooser_async_fail(
    RinRuntimeFileChooserAsyncV1* async_client,
    RinRuntimeFileChooserResult result)
{
    if (async_client == NULL) return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    if (async_client->socket_fd >= 0) (void)close(async_client->socket_fd);
    async_client->socket_fd = -1;
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_FAILED;
    async_client->terminal_result = result;
    chooser_zero(async_client->request, sizeof(async_client->request));
    chooser_zero(async_client->reply, sizeof(async_client->reply));
    return result;
}

static RinRuntimeFileChooserResult chooser_async_flush_request(
    RinRuntimeFileChooserAsyncV1* async_client)
{
    while (async_client->request_offset < async_client->request_size) {
        ssize_t written = send(
            async_client->socket_fd,
            async_client->request + async_client->request_offset,
            async_client->request_size - async_client->request_offset,
            MSG_NOSIGNAL);
        if (written > 0) {
            async_client->request_offset += (uint32_t)written;
            continue;
        }
        if (written < 0 && (errno == EINTR || errno == EAGAIN ||
                            errno == EWOULDBLOCK))
            return RINRUNTIME_FILE_CHOOSER_IN_PROGRESS;
        return chooser_async_fail(async_client,
                                  RINRUNTIME_FILE_CHOOSER_IO_FAILED);
    }
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_WAITING;
    return RINRUNTIME_FILE_CHOOSER_OK;
}

static RinRuntimeFileChooserResult chooser_async_read_reply(
    RinRuntimeFileChooserAsyncV1* async_client)
{
    while (async_client->reply_offset < async_client->reply_size) {
        ssize_t received = recv(
            async_client->socket_fd,
            async_client->reply + async_client->reply_offset,
            async_client->reply_size - async_client->reply_offset,
            MSG_DONTWAIT);
        if (received > 0) {
            async_client->reply_offset += (uint32_t)received;
            continue;
        }
        if (received < 0 && (errno == EINTR || errno == EAGAIN ||
                             errno == EWOULDBLOCK))
            return RINRUNTIME_FILE_CHOOSER_IN_PROGRESS;
        return chooser_async_fail(async_client,
                                  RINRUNTIME_FILE_CHOOSER_IO_FAILED);
    }
    return RINRUNTIME_FILE_CHOOSER_OK;
}
#endif

static void chooser_async_zero(RinRuntimeFileChooserAsyncV1* async_client)
{
    if (async_client != NULL) {
#if !defined(_WIN32)
        if (async_client->state != RINRUNTIME_FILE_CHOOSER_ASYNC_IDLE &&
            async_client->socket_fd >= 0)
            (void)close(async_client->socket_fd);
#endif
        chooser_zero(async_client, sizeof(*async_client));
        async_client->socket_fd = -1;
        async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_IDLE;
    }
}

void rinruntime_file_chooser_async_init(
    RinRuntimeFileChooserAsyncV1* async_client)
{
    if (async_client == NULL) return;
    chooser_zero(async_client, sizeof(*async_client));
    async_client->socket_fd = -1;
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_IDLE;
}

RinRuntimeFileChooserResult rinruntime_file_chooser_begin(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinRuntimeFileChooserAsyncV1* async_client)
{
#if defined(_WIN32)
    if (async_client != NULL) chooser_async_zero(async_client);
    if (async_client == NULL || !chooser_request_valid(request))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    size_t frame_size = 0u;
    uint64_t request_id;
    RinRuntimeFileChooserResult result;
    int descriptor;

    if (async_client == NULL || !chooser_request_valid(request))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    chooser_async_zero(async_client);
    request_id = chooser_next_request_id();
    result = rinruntime_file_chooser_request_encode(
        request_id, request, async_client->request,
        sizeof(async_client->request), &frame_size);
    if (result != RINRUNTIME_FILE_CHOOSER_OK)
        return result;
    descriptor = chooser_connect();
    if (descriptor < 0)
        return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    if (!chooser_async_set_nonblocking(descriptor)) {
        (void)close(descriptor);
        return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    }
    async_client->socket_fd = descriptor;
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING;
    async_client->kind = (uint32_t)request->kind;
    async_client->allow_multiple =
        (request->flags & RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ALLOW_MULTIPLE) != 0u;
    async_client->request_size = (uint32_t)frame_size;
    async_client->request_offset = 0u;
    async_client->reply_size = request->kind == RINRUNTIME_FILE_CHOOSER_SAVE
        ? (uint32_t)sizeof(RinRuntimeFileChooserSaveDestinationGrantV1)
        : async_client->allow_multiple
            ? (uint32_t)sizeof(RinRuntimeFileChooserMultipleGrantV1)
            : (uint32_t)sizeof(RinRuntimeFileChooserGrantV1);
    async_client->reply_offset = 0u;
    async_client->request_id = request_id;
    async_client->terminal_result = RINRUNTIME_FILE_CHOOSER_IN_PROGRESS;
    result = chooser_async_flush_request(async_client);
    if (result != RINRUNTIME_FILE_CHOOSER_OK &&
        result != RINRUNTIME_FILE_CHOOSER_IN_PROGRESS)
        return result;
    return RINRUNTIME_FILE_CHOOSER_OK;
#endif
}

RinRuntimeFileChooserResult rinruntime_file_chooser_poll(
    RinRuntimeFileChooserAsyncV1* async_client,
    RinRuntimeFileChooserResult* result_out,
    RinFilePortalTokenV1* token_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out)
{
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_IN_PROGRESS;
    if (token_out != NULL) chooser_zero(token_out, sizeof(*token_out));
    if (capability_out != NULL)
        chooser_zero(capability_out, sizeof(*capability_out));
    if (async_client == NULL)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    if (async_client->allow_multiple)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    if (async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_COMPLETE ||
        async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_FAILED) {
        if (result_out != NULL) *result_out = async_client->terminal_result;
        return async_client->terminal_result;
    }
    if (async_client->state != RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING &&
        async_client->state != RINRUNTIME_FILE_CHOOSER_ASYNC_WAITING)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    RinRuntimeFileChooserResult result;
    RinRuntimeFileChooserResult decoded_result =
        RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    uint64_t response_id = 0u;

    if (async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING) {
        result = chooser_async_flush_request(async_client);
        if (result != RINRUNTIME_FILE_CHOOSER_OK) {
            if (result_out != NULL) *result_out = result;
            return result;
        }
    }
    result = chooser_async_read_reply(async_client);
    if (result != RINRUNTIME_FILE_CHOOSER_OK) {
        if (result_out != NULL) *result_out = result;
        return result;
    }
    if (async_client->kind == RINRUNTIME_FILE_CHOOSER_SAVE) {
        result = rinruntime_file_chooser_save_destination_grant_decode(
            (const RinRuntimeFileChooserSaveDestinationGrantV1*)
                async_client->reply,
            async_client->reply_size, &decoded_result, capability_out,
            &response_id);
    } else {
        result = rinruntime_file_chooser_grant_decode(
            (const RinRuntimeFileChooserGrantV1*)async_client->reply,
            async_client->reply_size, &decoded_result, token_out,
            &response_id);
    }
    if (result != RINRUNTIME_FILE_CHOOSER_OK ||
        response_id != async_client->request_id) {
        chooser_async_fail(async_client,
                           RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY);
        if (result_out != NULL)
            *result_out = RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (async_client->socket_fd >= 0) (void)close(async_client->socket_fd);
    async_client->socket_fd = -1;
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_COMPLETE;
    async_client->terminal_result = decoded_result;
    chooser_zero(async_client->request, sizeof(async_client->request));
    chooser_zero(async_client->reply, sizeof(async_client->reply));
    if (result_out != NULL) *result_out = decoded_result;
    if (decoded_result != RINRUNTIME_FILE_CHOOSER_OK) {
        if (token_out != NULL) chooser_zero(token_out, sizeof(*token_out));
        if (capability_out != NULL)
            chooser_zero(capability_out, sizeof(*capability_out));
    }
    return decoded_result;
#endif
}

void rinruntime_file_chooser_cancel(RinRuntimeFileChooserAsyncV1* async_client)
{
    chooser_async_zero(async_client);
}

RinRuntimeFileChooserResult rinruntime_file_chooser_poll_multiple(
    RinRuntimeFileChooserAsyncV1* async_client,
    RinRuntimeFileChooserResult* result_out,
    RinRuntimeFileChooserSelectionV1* selections_out,
    uint32_t* selection_count_out,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out)
{
    if (result_out != NULL) *result_out = RINRUNTIME_FILE_CHOOSER_IN_PROGRESS;
    if (selection_count_out != NULL) *selection_count_out = 0u;
    if (selections_out != NULL)
        chooser_zero(selections_out, sizeof(*selections_out) *
                     RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS);
    if (capability_out != NULL)
        chooser_zero(capability_out, sizeof(*capability_out));
    if (async_client == NULL || !async_client->allow_multiple ||
        selections_out == NULL || selection_count_out == NULL)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    if (async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_COMPLETE ||
        async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_FAILED) {
        if (result_out != NULL) *result_out = async_client->terminal_result;
        return async_client->terminal_result;
    }
    if (async_client->state != RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING &&
        async_client->state != RINRUNTIME_FILE_CHOOSER_ASYNC_WAITING)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
#if defined(_WIN32)
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    RinRuntimeFileChooserResult result;
    RinRuntimeFileChooserResult decoded_result =
        RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    uint64_t response_id = 0u;
    if (async_client->state == RINRUNTIME_FILE_CHOOSER_ASYNC_SENDING) {
        result = chooser_async_flush_request(async_client);
        if (result != RINRUNTIME_FILE_CHOOSER_OK) {
            if (result_out != NULL) *result_out = result;
            return result;
        }
    }
    result = chooser_async_read_reply(async_client);
    if (result != RINRUNTIME_FILE_CHOOSER_OK) {
        if (result_out != NULL) *result_out = result;
        return result;
    }
    result = rinruntime_file_chooser_multiple_grant_decode(
        (const RinRuntimeFileChooserMultipleGrantV1*)async_client->reply,
        async_client->reply_size, &decoded_result, selections_out,
        selection_count_out, &response_id);
    if (result != RINRUNTIME_FILE_CHOOSER_OK ||
        response_id != async_client->request_id) {
        chooser_async_fail(async_client,
                           RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY);
        if (result_out != NULL)
            *result_out = RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (async_client->socket_fd >= 0) (void)close(async_client->socket_fd);
    async_client->socket_fd = -1;
    async_client->state = RINRUNTIME_FILE_CHOOSER_ASYNC_COMPLETE;
    async_client->terminal_result = decoded_result;
    chooser_zero(async_client->request, sizeof(async_client->request));
    chooser_zero(async_client->reply, sizeof(async_client->reply));
    if (result_out != NULL) *result_out = decoded_result;
    if (decoded_result != RINRUNTIME_FILE_CHOOSER_OK)
        chooser_zero(selections_out, sizeof(*selections_out) *
                     RINRUNTIME_FILE_CHOOSER_MAX_SELECTIONS);
    return decoded_result;
#endif
}

RinRuntimeFileChooserResult rinruntime_file_chooser_request(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinFilePortalTokenV1* token_out)
{
#if defined(_WIN32)
    if (token_out != NULL) chooser_zero(token_out, sizeof(*token_out));
    if (token_out == NULL || !chooser_request_valid(request) ||
        request->flags != 0u || request->kind == RINRUNTIME_FILE_CHOOSER_SAVE)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    /* The authenticated File Manager transport is an AF_UNIX RinOS service.
     * Host tools can still exercise the public codec, but cannot mint a
     * capability or fall back to a host pathname. */
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    uint8_t frame[sizeof(RinRuntimeFileChooserRequestV1) +
                  RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME];
    RinRuntimeFileChooserGrantV1 grant;
    RinRuntimeFileChooserResult portal_result;
    RinRuntimeFileChooserResult response_result;
    size_t frame_size = 0u;
    uint64_t request_id;
    uint64_t response_id = 0u;
    int descriptor = -1;

    if (token_out != NULL) chooser_zero(token_out, sizeof(*token_out));
    if (token_out == NULL || !chooser_request_valid(request) ||
        request->flags != 0u || request->kind == RINRUNTIME_FILE_CHOOSER_SAVE)
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    request_id = chooser_next_request_id();
    portal_result = rinruntime_file_chooser_request_encode(
        request_id, request, frame, sizeof(frame), &frame_size);
    if (portal_result != RINRUNTIME_FILE_CHOOSER_OK) return portal_result;
    descriptor = chooser_connect();
    if (descriptor < 0) return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    if (!chooser_write_all(descriptor, frame, frame_size) ||
        !chooser_read_all(descriptor, &grant, sizeof(grant))) {
        (void)close(descriptor);
        chooser_zero(&grant, sizeof(grant));
        return RINRUNTIME_FILE_CHOOSER_IO_FAILED;
    }
    (void)close(descriptor);
    portal_result = rinruntime_file_chooser_grant_decode(
        &grant, sizeof(grant), &response_result, token_out, &response_id);
    chooser_zero(&grant, sizeof(grant));
    if (portal_result != RINRUNTIME_FILE_CHOOSER_OK || response_id != request_id) {
        chooser_zero(token_out, sizeof(*token_out));
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (response_result != RINRUNTIME_FILE_CHOOSER_OK) {
        chooser_zero(token_out, sizeof(*token_out));
        return response_result;
    }
    return RINRUNTIME_FILE_CHOOSER_OK;
#endif
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_request(
    const RinRuntimeFileChooserRequestV1Input* request,
    RinRuntimeFileChooserSaveCapabilityV1* capability_out)
{
#if defined(_WIN32)
    if (capability_out != NULL) chooser_zero(capability_out, sizeof(*capability_out));
    if (capability_out == NULL || !chooser_request_valid(request) ||
        request->kind != RINRUNTIME_FILE_CHOOSER_SAVE ||
        request->flags !=
            RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ATOMIC_SAVE_DESTINATION) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    uint8_t frame[sizeof(RinRuntimeFileChooserRequestV1) +
                  RINRUNTIME_FILE_CHOOSER_MAX_SUGGESTED_NAME];
    RinRuntimeFileChooserSaveDestinationGrantV1 grant;
    RinRuntimeFileChooserResult codec_result;
    RinRuntimeFileChooserResult response_result;
    size_t frame_size = 0u;
    uint64_t request_id;
    uint64_t response_id = 0u;
    int descriptor;

    if (capability_out != NULL) chooser_zero(capability_out, sizeof(*capability_out));
    if (capability_out == NULL || !chooser_request_valid(request) ||
        request->kind != RINRUNTIME_FILE_CHOOSER_SAVE ||
        request->flags !=
            RINRUNTIME_FILE_CHOOSER_REQUEST_FLAG_ATOMIC_SAVE_DESTINATION) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    request_id = chooser_next_request_id();
    codec_result = rinruntime_file_chooser_request_encode(
        request_id, request, frame, sizeof(frame), &frame_size);
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK) return codec_result;
    descriptor = chooser_connect();
    if (descriptor < 0) return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    if (!chooser_write_all(descriptor, frame, frame_size) ||
        !chooser_read_all(descriptor, &grant, sizeof(grant))) {
        (void)close(descriptor);
        chooser_zero(&grant, sizeof(grant));
        return RINRUNTIME_FILE_CHOOSER_IO_FAILED;
    }
    (void)close(descriptor);
    codec_result = rinruntime_file_chooser_save_destination_grant_decode(
        &grant, sizeof(grant), &response_result, capability_out, &response_id);
    chooser_zero(&grant, sizeof(grant));
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK || response_id != request_id) {
        chooser_zero(capability_out, sizeof(*capability_out));
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (response_result != RINRUNTIME_FILE_CHOOSER_OK) {
        chooser_zero(capability_out, sizeof(*capability_out));
        return response_result;
    }
    return RINRUNTIME_FILE_CHOOSER_OK;
#endif
}

RinRuntimeFileChooserResult rinruntime_file_chooser_atomic_save(
    const RinRuntimeFileChooserSaveCapabilityV1* capability,
    const void* data, uint64_t data_size)
{
#if defined(_WIN32)
    if (!rinruntime_file_chooser_save_capability_valid(capability) ||
        (data == NULL && data_size != 0u) ||
        data_size > RINRUNTIME_FILE_CHOOSER_ATOMIC_SAVE_MAX_BYTES) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    RinRuntimeFileChooserAtomicSaveRequestV1 request;
    RinRuntimeFileChooserStatusV1 status;
    RinRuntimeFileChooserResult codec_result;
    RinRuntimeFileChooserResult response_result;
    uint64_t request_id;
    uint64_t response_id = 0u;
    int descriptor;

    if (!rinruntime_file_chooser_save_capability_valid(capability) ||
        (data == NULL && data_size != 0u) ||
        data_size > RINRUNTIME_FILE_CHOOSER_ATOMIC_SAVE_MAX_BYTES ||
        data_size > (uint64_t)SIZE_MAX) {
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    }
    request_id = chooser_next_request_id();
    codec_result = rinruntime_file_chooser_atomic_save_request_encode(
        request_id, capability, data_size, &request);
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK) return codec_result;
    descriptor = chooser_connect();
    if (descriptor < 0) return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    if (!chooser_write_all(descriptor, &request, sizeof(request)) ||
        !chooser_read_all(descriptor, &status, sizeof(status))) {
        (void)close(descriptor);
        chooser_zero(&request, sizeof(request));
        chooser_zero(&status, sizeof(status));
        return RINRUNTIME_FILE_CHOOSER_IO_FAILED;
    }
    codec_result = rinruntime_file_chooser_status_decode(
        &status, sizeof(status), RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY,
        &response_result, &response_id);
    chooser_zero(&status, sizeof(status));
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK || response_id != request_id) {
        (void)close(descriptor);
        chooser_zero(&request, sizeof(request));
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    }
    if (response_result != RINRUNTIME_FILE_CHOOSER_OK) {
        (void)close(descriptor);
        chooser_zero(&request, sizeof(request));
        return response_result;
    }
    if ((data_size != 0u &&
         !chooser_write_all(descriptor, data, (size_t)data_size)) ||
        !chooser_read_all(descriptor, &status, sizeof(status))) {
        (void)close(descriptor);
        chooser_zero(&request, sizeof(request));
        chooser_zero(&status, sizeof(status));
        return RINRUNTIME_FILE_CHOOSER_IO_FAILED;
    }
    (void)close(descriptor);
    codec_result = rinruntime_file_chooser_status_decode(
        &status, sizeof(status), RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_COMPLETE,
        &response_result, &response_id);
    chooser_zero(&request, sizeof(request));
    chooser_zero(&status, sizeof(status));
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK || response_id != request_id)
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    return response_result;
#endif
}

RinRuntimeFileChooserResult rinruntime_file_chooser_save_destination_release(
    const RinRuntimeFileChooserSaveCapabilityV1* capability)
{
#if defined(_WIN32)
    if (!rinruntime_file_chooser_save_capability_valid(capability))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
#else
    RinRuntimeFileChooserSaveDestinationReleaseV1 release;
    RinRuntimeFileChooserStatusV1 status;
    RinRuntimeFileChooserResult codec_result;
    RinRuntimeFileChooserResult response_result;
    uint64_t request_id;
    uint64_t response_id = 0u;
    int descriptor;

    if (!rinruntime_file_chooser_save_capability_valid(capability))
        return RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT;
    request_id = chooser_next_request_id();
    codec_result = rinruntime_file_chooser_save_destination_release_encode(
        request_id, capability, &release);
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK) return codec_result;
    descriptor = chooser_connect();
    if (descriptor < 0) return RINRUNTIME_FILE_CHOOSER_CONNECT_FAILED;
    if (!chooser_write_all(descriptor, &release, sizeof(release)) ||
        !chooser_read_all(descriptor, &status, sizeof(status))) {
        (void)close(descriptor);
        chooser_zero(&release, sizeof(release));
        chooser_zero(&status, sizeof(status));
        return RINRUNTIME_FILE_CHOOSER_IO_FAILED;
    }
    (void)close(descriptor);
    codec_result = rinruntime_file_chooser_status_decode(
        &status, sizeof(status),
        RINRUNTIME_FILE_CHOOSER_OPERATION_SAVE_DESTINATION_RELEASE_COMPLETE,
        &response_result, &response_id);
    chooser_zero(&release, sizeof(release));
    chooser_zero(&status, sizeof(status));
    if (codec_result != RINRUNTIME_FILE_CHOOSER_OK || response_id != request_id)
        return RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY;
    return response_result;
#endif
}

