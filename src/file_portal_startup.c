/* SPDX-License-Identifier: MIT */
/* Public, fail-closed consumer for a one-shot child File Portal handoff. */

#include <rinruntime/file_portal_startup.h>

#include <rinruntime/file_portal.h>
#include <rinruntime/text_codec.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define RINRUNTIME_FILE_PORTAL_STARTUP_IO_INTERRUPTION_LIMIT 32u

static int startup_receive_exact(int descriptor, void* output, size_t size)
{
    unsigned char* cursor = (unsigned char*)output;
    uint32_t interrupted = 0u;
    while (size != 0u) {
        ssize_t count = recv(descriptor, cursor, size, 0);
        if (count > 0) interrupted = 0u;
        if (count < 0 && errno == EINTR) {
            if (++interrupted >=
                RINRUNTIME_FILE_PORTAL_STARTUP_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (count <= 0 || (size_t)count > size) return 0;
        cursor += (size_t)count;
        size -= (size_t)count;
    }
    return 1;
}

static int startup_send_exact(int descriptor, const void* input, size_t size)
{
    const unsigned char* cursor = (const unsigned char*)input;
    uint32_t interrupted = 0u;
    while (size != 0u) {
        ssize_t count = send(descriptor, cursor, size, MSG_NOSIGNAL);
        if (count > 0) interrupted = 0u;
        if (count < 0 && errno == EINTR) {
            if (++interrupted >=
                RINRUNTIME_FILE_PORTAL_STARTUP_IO_INTERRUPTION_LIMIT)
                return 0;
            continue;
        }
        if (count <= 0 || (size_t)count > size) return 0;
        cursor += (size_t)count;
        size -= (size_t)count;
    }
    return 1;
}

static int startup_request_valid(
    const RinRuntimeFilePortalStartupRequestV1* request)
{
    uint32_t index;
    if (request == NULL || request->struct_size != sizeof(*request) ||
        request->version != RINRUNTIME_FILE_PORTAL_STARTUP_VERSION ||
        request->flags != 0u || request->reserved0 != 0u ||
        request->display_name_size == 0u ||
        request->display_name_size > RINRUNTIME_FILE_PORTAL_STARTUP_NAME_MAX ||
        request->token.magic != RIN_FILE_PORTAL_TOKEN_MAGIC ||
        request->token.version != RIN_FILE_PORTAL_TOKEN_VERSION ||
        request->token.token_size != RIN_FILE_PORTAL_TOKEN_SIZE ||
        request->token.file_object_id == 0u ||
        request->token.rights !=
            (RIN_FILE_PORTAL_RIGHT_READ | RIN_FILE_PORTAL_RIGHT_METADATA) ||
        rinruntime_text_utf8_validate(
            (const uint8_t*)request->display_name,
            request->display_name_size) != RINRUNTIME_TEXT_CODEC_OK)
        return 0;
    for (index = 0u; index < request->display_name_size; ++index) {
        unsigned char byte = (unsigned char)request->display_name[index];
        if (byte < 0x20u || byte == 0x7fu || byte == '/' || byte == '\\')
            return 0;
    }
    for (index = request->display_name_size;
         index < sizeof(request->display_name); ++index)
        if (request->display_name[index] != '\0') return 0;
    for (index = 0u; index < sizeof(request->reserved) /
                                  sizeof(request->reserved[0]); ++index)
        if (request->reserved[index] != 0u) return 0;
    return 1;
}

static void startup_identity_from_token(
    const RinFilePortalTokenV1* token,
    RinRuntimeFileChooserDocumentIdentityV1* identity)
{
    uint64_t object_id = token->file_object_id;
    uint32_t index;
    memset(identity, 0, sizeof(*identity));
    for (index = 0u; index < 8u; ++index) {
        identity->bytes[index] = (uint8_t)(object_id & 0xffu);
        object_id >>= 8u;
    }
    /* Keep the canonical opaque identity derivation used by the chooser API. */
    memcpy(identity->bytes + 8u, "RIN-DOC1", 8u);
}

RinRuntimeFilePortalStartupResult rinruntime_file_portal_startup_take(
    RinRuntimeFilePortalStartupOpenV1* opened)
{
    RinRuntimeFilePortalStartupRequestV1 request;
    RinRuntimeFilePortalStartupResult result =
        RINRUNTIME_FILE_PORTAL_STARTUP_ERROR;
    int descriptor_flags;
    int opened_fd = -1;
    int channel_open = 0;

    if (opened == NULL) return RINRUNTIME_FILE_PORTAL_STARTUP_ERROR;
    memset(opened, 0, sizeof(*opened));
    opened->descriptor = -1;
    memset(&request, 0, sizeof(request));

    descriptor_flags = fcntl(RINRUNTIME_FILE_PORTAL_STARTUP_FD, F_GETFD);
    if (descriptor_flags < 0) {
        if (errno == EBADF)
            result = RINRUNTIME_FILE_PORTAL_STARTUP_NOT_PRESENT;
        goto done;
    }
    channel_open = 1;
    if (fcntl(RINRUNTIME_FILE_PORTAL_STARTUP_FD, F_SETFD,
              descriptor_flags | FD_CLOEXEC) != 0 ||
        !startup_receive_exact(RINRUNTIME_FILE_PORTAL_STARTUP_FD, &request,
                               sizeof(request)) ||
        !startup_request_valid(&request))
        goto done;

    if (rinruntime_file_portal_open(
            &request.token, request.token.rights, 0,
            RIN_FILE_PORTAL_CALL_FD_CLOEXEC, &opened_fd) !=
        RINRUNTIME_FILE_PORTAL_OK)
        goto done;

    startup_identity_from_token(&request.token, &opened->document_identity);
    opened->descriptor = opened_fd;
    opened_fd = -1;
    opened->display_name_size = request.display_name_size;
    memcpy(opened->display_name, request.display_name,
           request.display_name_size);
    result = RINRUNTIME_FILE_PORTAL_STARTUP_OPENED;

done:
    if (opened_fd >= 0) (void)close(opened_fd);
    if (channel_open && result != RINRUNTIME_FILE_PORTAL_STARTUP_OPENED) {
        int32_t acknowledgement = RINRUNTIME_FILE_PORTAL_STARTUP_ERROR;
        (void)startup_send_exact(RINRUNTIME_FILE_PORTAL_STARTUP_FD,
                                 &acknowledgement,
                                 sizeof(acknowledgement));
        (void)close(RINRUNTIME_FILE_PORTAL_STARTUP_FD);
    }
    rinruntime_file_portal_startup_clear(&request, sizeof(request));
    if (result != RINRUNTIME_FILE_PORTAL_STARTUP_OPENED) {
        opened->descriptor = -1;
        opened->display_name_size = 0u;
        rinruntime_file_portal_startup_clear(
            opened->display_name, sizeof(opened->display_name));
        rinruntime_file_portal_startup_clear(
            &opened->document_identity, sizeof(opened->document_identity));
    }
    return result;
}

int rinruntime_file_portal_startup_acknowledge(int accepted)
{
    int32_t acknowledgement = accepted
        ? RINRUNTIME_FILE_PORTAL_STARTUP_OPENED
        : RINRUNTIME_FILE_PORTAL_STARTUP_ERROR;
    const int sent = startup_send_exact(
        RINRUNTIME_FILE_PORTAL_STARTUP_FD, &acknowledgement,
        sizeof(acknowledgement));
    (void)close(RINRUNTIME_FILE_PORTAL_STARTUP_FD);
    return sent && accepted != 0;
}
