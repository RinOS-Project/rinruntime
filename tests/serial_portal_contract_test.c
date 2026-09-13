/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_serial_portal_protocol.h>

#include <assert.h>
#include <string.h>

int main(void)
{
    RinSerialPortalFrameV1 frame;
    uint64_t request_id = 0u;
    uint64_t session_id = 0u;
    uint64_t session_generation = 0u;

    memset(&frame, 0, sizeof(frame));
    assert(rin_serial_portal_request_encode(
               1u, 2u, 3u, RIN_SERIAL_PORTAL_ENUMERATE_REQUEST, &frame) ==
           RIN_SERIAL_PORTAL_OK);
    assert(rin_serial_portal_frame_decode(
               &frame, sizeof(frame), RIN_SERIAL_PORTAL_ENUMERATE_REQUEST,
               &request_id, &session_id, &session_generation) ==
           RIN_SERIAL_PORTAL_OK);
    assert(request_id == 1u && session_id == 2u && session_generation == 3u);
    frame.session_generation = 0u;
    assert(rin_serial_portal_frame_decode(
               &frame, sizeof(frame), RIN_SERIAL_PORTAL_ENUMERATE_REQUEST,
               NULL, NULL, NULL) == RIN_SERIAL_PORTAL_MALFORMED);
    return 0;
}
