/* SPDX-License-Identifier: MIT */

#include <assert.h>
#include <stdint.h>

#include <rinruntime/file_chooser_portal.h>

int main(void)
{
    const RinRuntimeFileChooserRequestV1Input request = {
        RINRUNTIME_FILE_CHOOSER_OPEN,
        RIN_FILE_PORTAL_RIGHT_READ | RIN_FILE_PORTAL_RIGHT_METADATA,
        NULL,
        0u,
        0u
    };
    uint8_t request_frame[sizeof(RinRuntimeFileChooserRequestV1)] = {0};
    size_t request_frame_size = 0u;
    RinRuntimeFileChooserRequestViewV1 request_view = {0};
    RinRuntimeFileChooserStatusV1 status = {0};
    RinRuntimeFileChooserResult result = RINRUNTIME_FILE_CHOOSER_SERVER_FAILED;
    uint64_t request_id = 0u;

    assert(rinruntime_file_chooser_request_encode(
               UINT64_MAX, &request, request_frame, sizeof(request_frame),
               &request_frame_size) == RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT);
    assert(request_frame_size == 0u);
    assert(rinruntime_file_chooser_request_encode(
               1u, &request, request_frame, sizeof(request_frame),
               &request_frame_size) == RINRUNTIME_FILE_CHOOSER_OK);
    ((RinRuntimeFileChooserRequestV1*)request_frame)->frame.request_id = UINT64_MAX;
    assert(rinruntime_file_chooser_request_decode(
               request_frame, request_frame_size, &request_view) ==
           RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY);

    assert(rinruntime_file_chooser_status_encode(
               RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY, UINT64_MAX,
               RINRUNTIME_FILE_CHOOSER_OK, &status) ==
           RINRUNTIME_FILE_CHOOSER_INVALID_ARGUMENT);
    assert(rinruntime_file_chooser_status_encode(
               RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY, 1u,
               RINRUNTIME_FILE_CHOOSER_OK, &status) == RINRUNTIME_FILE_CHOOSER_OK);
    status.frame.request_id = UINT64_MAX;
    assert(rinruntime_file_chooser_status_decode(
               &status, sizeof(status),
               RINRUNTIME_FILE_CHOOSER_OPERATION_ATOMIC_SAVE_READY, &result,
               &request_id) == RINRUNTIME_FILE_CHOOSER_MALFORMED_REPLY);

    return 0;
}
