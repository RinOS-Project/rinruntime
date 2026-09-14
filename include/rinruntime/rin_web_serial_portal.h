/* SPDX-License-Identifier: MIT */
/* WebContent-side bounded Serial portal client contract. */

#ifndef RINRUNTIME_WEB_SERIAL_PORTAL_H
#define RINRUNTIME_WEB_SERIAL_PORTAL_H

#include <stddef.h>
#include <stdint.h>

#include <rin/serial_abi.h>
#include <rinruntime/rin_serial_portal_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_WEB_SERIAL_MAX_DEVICES UINT32_C(16)

typedef struct RinWebSerialDeviceV1 {
    RinSerialDeviceInfoV1 info;
    RinSerialCapabilityV1 capability;
} RinWebSerialDeviceV1;

/* The default operations are supplied by the OS-Core VFS adapter. Tests and
 * alternate WebContent hosts may install an equivalent bounded file owner;
 * a missing callback is reported as an error, never as readiness/success. */
typedef struct RinWebSerialFileOpsV1 {
    uint32_t (*open)(void* context, const char* path, uint32_t flags);
    int (*close)(void* context, uint32_t handle);
    int (*read)(void* context, uint32_t handle, void* bytes, size_t capacity);
    int (*write)(void* context, uint32_t handle, const void* bytes, size_t count);
    int (*configure)(void* context, uint32_t handle,
                     const RinSerialConfigV1* config);
    int (*set_signals)(void* context, uint32_t handle, uint8_t dtr,
                       uint8_t rts, uint8_t break_signal);
    int (*get_signals)(void* context, uint32_t handle,
                       RinSerialStatusV1* status);
    void* context;
    int (*wait)(void* context, uint32_t handle, uint32_t events,
                RinSerialWaitResultV1* result);
} RinWebSerialFileOpsV1;

typedef int (*RinWebSerialPortalExchangeV1)(
    void* context, const void* request, size_t request_size,
    void* response, size_t response_capacity, size_t* response_size);

/* Authenticated Browser portal transport. Session values are captured by
 * every frame and are never caller-selected per operation. */
typedef struct RinWebSerialPortalTransportV1 {
    RinWebSerialPortalExchangeV1 exchange;
    void* context;
    uint64_t session_id;
    uint64_t session_generation;
} RinWebSerialPortalTransportV1;

void rin_web_serial_set_file_ops(const RinWebSerialFileOpsV1* ops);
void rin_web_serial_set_portal_transport(
    const RinWebSerialPortalTransportV1* transport);

int rin_web_serial_enumerate(RinWebSerialDeviceV1* output, uint32_t capacity,
                             uint32_t* count_out);
int rin_web_serial_request_port(const char* origin, uint32_t user_activation,
                                const RinSerialPortalFilterV1* filters,
                                uint32_t filter_count,
                                uint64_t selected_object_id,
                                RinWebSerialDeviceV1* output);
int rin_web_serial_get_ports(const char* origin, RinWebSerialDeviceV1* output,
                             uint32_t capacity, uint32_t* count_out);
int rin_web_serial_open(RinSerialCapabilityV1 capability, uint32_t baud_rate,
                        uint8_t data_bits, uint8_t stop_bits, uint8_t parity,
                        uint8_t flow_control, uint32_t buffer_size,
                        uint32_t* handle_out);
int rin_web_serial_close(uint32_t handle);
int rin_web_serial_read(uint32_t handle, uint8_t* bytes, size_t capacity,
                        size_t* count_out);
int rin_web_serial_write(uint32_t handle, const uint8_t* bytes, size_t count,
                         size_t* count_out);
int rin_web_serial_set_signals(uint32_t handle, uint8_t dtr, uint8_t rts,
                               uint8_t break_signal);
int rin_web_serial_get_signals(uint32_t handle, RinSerialStatusV1* status_out);
int rin_web_serial_wait(uint32_t handle, uint32_t events,
                        RinSerialWaitResultV1* result_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_WEB_SERIAL_PORTAL_H */
