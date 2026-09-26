/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_serial_portal_protocol.h>

#include <assert.h>
#include <string.h>

int main(void)
{
    RinSerialPortalFrameV1 frame;
    RinSerialPortalRequestPortRequestV1 request_port;
    RinSerialPortalGetPortsRequestV1 get_ports;
    RinSerialPortalFilterV1 filter = { 1u, 2u, 1u, 1u, 0u };
    char origin[RIN_SERIAL_PORTAL_ORIGIN_MAX];
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
    memset(origin, 'a', sizeof(origin));
    origin[sizeof(origin) - 1u] = '\0';
    assert(rin_serial_portal_request_port_encode(
               4u, 5u, 6u, origin, 1u, &filter, 1u, 7u, &request_port) ==
           RIN_SERIAL_PORTAL_OK);
    assert(request_port.origin[sizeof(request_port.origin) - 2u] == 'a' &&
           request_port.origin[sizeof(request_port.origin) - 1u] == '\0');
    assert(rin_serial_portal_get_ports_request_encode(
               4u, 5u, 6u, origin, &get_ports) == RIN_SERIAL_PORTAL_OK);
    assert(get_ports.origin[sizeof(get_ports.origin) - 2u] == 'a' &&
           get_ports.origin[sizeof(get_ports.origin) - 1u] == '\0');
    origin[sizeof(origin) - 1u] = 'b';
    assert(rin_serial_portal_request_port_encode(
               4u, 5u, 6u, origin, 1u, &filter, 1u, 7u, &request_port) ==
           RIN_SERIAL_PORTAL_INVALID_ARGUMENT);
    assert(rin_serial_portal_get_ports_request_encode(
               4u, 5u, 6u, origin, &get_ports) ==
           RIN_SERIAL_PORTAL_INVALID_ARGUMENT);
    return 0;
}
