/* SPDX-License-Identifier: MIT */
/* Authenticated Browser-to-generic Serial Device Portal wire contract. */

#ifndef RIN_RUNTIME_SERIAL_PORTAL_PROTOCOL_H
#define RIN_RUNTIME_SERIAL_PORTAL_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include <rin/serial_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_SERIAL_PORTAL_MAGIC UINT32_C(0x31505352) /* "RSP1" */
#define RIN_SERIAL_PORTAL_VERSION UINT16_C(1)
#define RIN_SERIAL_PORTAL_MAX_DEVICES UINT32_C(32)
#define RIN_SERIAL_PORTAL_MAX_FILTERS UINT32_C(16)
#define RIN_SERIAL_PORTAL_ORIGIN_MAX UINT32_C(1024)

typedef enum RinSerialPortalOperationV1 {
    RIN_SERIAL_PORTAL_ENUMERATE_REQUEST = 1,
    RIN_SERIAL_PORTAL_ENUMERATE_RESPONSE = 2,
    RIN_SERIAL_PORTAL_OPEN_REQUEST = 3,
    RIN_SERIAL_PORTAL_OPEN_RESPONSE = 4,
    RIN_SERIAL_PORTAL_CLOSE_REQUEST = 5,
    RIN_SERIAL_PORTAL_CLOSE_RESPONSE = 6,
    RIN_SERIAL_PORTAL_READ_REQUEST = 7,
    RIN_SERIAL_PORTAL_READ_RESPONSE = 8,
    RIN_SERIAL_PORTAL_WRITE_REQUEST = 9,
    RIN_SERIAL_PORTAL_WRITE_RESPONSE = 10,
    RIN_SERIAL_PORTAL_CONNECT_EVENT = 11,
    RIN_SERIAL_PORTAL_DISCONNECT_EVENT = 12,
    RIN_SERIAL_PORTAL_SET_SIGNALS_REQUEST = 13,
    RIN_SERIAL_PORTAL_SET_SIGNALS_RESPONSE = 14,
    RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST = 15,
    RIN_SERIAL_PORTAL_GET_SIGNALS_RESPONSE = 16,
    RIN_SERIAL_PORTAL_WAIT_REQUEST = 17,
    RIN_SERIAL_PORTAL_WAIT_RESPONSE = 18,
    RIN_SERIAL_PORTAL_REQUEST_PORT_REQUEST = 19,
    RIN_SERIAL_PORTAL_REQUEST_PORT_RESPONSE = 20,
    RIN_SERIAL_PORTAL_GET_PORTS_REQUEST = 21,
    RIN_SERIAL_PORTAL_GET_PORTS_RESPONSE = 22
} RinSerialPortalOperationV1;

typedef enum RinSerialPortalResultV1 {
    RIN_SERIAL_PORTAL_OK = 0,
    RIN_SERIAL_PORTAL_INVALID_ARGUMENT = -1,
    RIN_SERIAL_PORTAL_MALFORMED = -2,
    RIN_SERIAL_PORTAL_LIMIT = -3,
    RIN_SERIAL_PORTAL_DENIED = -4,
    RIN_SERIAL_PORTAL_STALE = -5,
    RIN_SERIAL_PORTAL_DISCONNECTED = -6,
    RIN_SERIAL_PORTAL_IO_FAILED = -7
} RinSerialPortalResultV1;

/* The portal service authenticates the local connection before accepting a
 * frame.  session_id and session_generation bind every frame to that
 * authenticated connection; they are not a substitute for transport
 * authentication. */
typedef struct __attribute__((packed)) RinSerialPortalFrameV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t frame_size;
    uint64_t request_id;
    uint64_t session_id;
    uint64_t session_generation;
} RinSerialPortalFrameV1;

typedef struct __attribute__((packed)) RinSerialPortalDeviceV1 {
    RinSerialDeviceInfoV1 info;
    RinSerialCapabilityV1 capability;
} RinSerialPortalDeviceV1;

typedef struct __attribute__((packed)) RinSerialPortalEnumerateResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t device_count;
    RinSerialPortalDeviceV1 devices[RIN_SERIAL_PORTAL_MAX_DEVICES];
} RinSerialPortalEnumerateResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalOpenRequestV1 {
    RinSerialPortalFrameV1 frame;
    RinSerialCapabilityV1 capability;
    RinSerialConfigV1 config;
    uint32_t flags;
    uint32_t reserved;
} RinSerialPortalOpenRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalOpenResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinSerialCapabilityV1 capability;
} RinSerialPortalOpenResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalCloseRequestV1 {
    RinSerialPortalFrameV1 frame;
    RinSerialCapabilityV1 capability;
} RinSerialPortalCloseRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalTransferV1 {
    RinSerialPortalFrameV1 frame;
    RinSerialCapabilityV1 capability;
    uint32_t byte_count;
    uint32_t reserved;
} RinSerialPortalTransferV1;

typedef struct __attribute__((packed)) RinSerialPortalTransferResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t byte_count;
    RinSerialCapabilityV1 capability;
    uint8_t bytes[RIN_SERIAL_BUFFER_MAX];
} RinSerialPortalTransferResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalSignalsRequestV1 {
    RinSerialPortalFrameV1 frame;
    RinSerialCapabilityV1 capability;
    RinSerialSignalsV1 signals;
    uint32_t reserved;
} RinSerialPortalSignalsRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalStatusResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinSerialCapabilityV1 capability;
    RinSerialStatusV1 status;
} RinSerialPortalStatusResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalWaitRequestV1 {
    RinSerialPortalFrameV1 frame;
    RinSerialCapabilityV1 capability;
    uint32_t events;
    uint32_t reserved;
} RinSerialPortalWaitRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalWaitResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinSerialCapabilityV1 capability;
    RinSerialWaitResultV1 wait;
} RinSerialPortalWaitResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalFilterV1 {
    uint16_t vendor_id;
    uint16_t product_id;
    uint8_t has_vendor_id;
    uint8_t has_product_id;
    uint16_t reserved;
} RinSerialPortalFilterV1;

typedef struct __attribute__((packed)) RinSerialPortalRequestPortRequestV1 {
    RinSerialPortalFrameV1 frame;
    uint32_t user_activation;
    uint32_t filter_count;
    uint64_t selected_object_id;
    char origin[RIN_SERIAL_PORTAL_ORIGIN_MAX];
    RinSerialPortalFilterV1 filters[RIN_SERIAL_PORTAL_MAX_FILTERS];
} RinSerialPortalRequestPortRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalRequestPortResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t reserved;
    RinSerialPortalDeviceV1 device;
} RinSerialPortalRequestPortResponseV1;

typedef struct __attribute__((packed)) RinSerialPortalGetPortsRequestV1 {
    RinSerialPortalFrameV1 frame;
    char origin[RIN_SERIAL_PORTAL_ORIGIN_MAX];
} RinSerialPortalGetPortsRequestV1;

typedef struct __attribute__((packed)) RinSerialPortalGetPortsResponseV1 {
    RinSerialPortalFrameV1 frame;
    int32_t result;
    uint32_t device_count;
    RinSerialPortalDeviceV1 devices[RIN_SERIAL_PORTAL_MAX_DEVICES];
} RinSerialPortalGetPortsResponseV1;

typedef struct RinSerialPortalDeviceViewV1 {
    RinSerialDeviceInfoV1 info;
    RinSerialCapabilityV1 capability;
    uint32_t connected;
} RinSerialPortalDeviceViewV1;

RinSerialPortalResultV1 rin_serial_portal_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialPortalFrameV1* frame_out);
RinSerialPortalResultV1 rin_serial_portal_frame_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out);

RinSerialPortalResultV1 rin_serial_portal_enumerate_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* devices,
    size_t device_count, RinSerialPortalEnumerateResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_enumerate_response_decode(
    const RinSerialPortalEnumerateResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out,
    const RinSerialPortalDeviceV1** devices_out, size_t* device_count_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out);

RinSerialPortalResultV1 rin_serial_portal_open_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, RinSerialConfigV1 config, uint32_t flags,
    RinSerialPortalOpenRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_open_request_decode(
    const RinSerialPortalOpenRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out, RinSerialConfigV1* config_out,
    uint32_t* flags_out);
RinSerialPortalResultV1 rin_serial_portal_open_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    RinSerialPortalOpenResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_open_response_decode(
    const RinSerialPortalOpenResponseV1* response, size_t frame_size,
    RinSerialPortalOperationV1 operation, RinSerialPortalResultV1* result_out,
    RinSerialCapabilityV1* capability_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out);
RinSerialPortalResultV1 rin_serial_portal_close_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, RinSerialPortalCloseRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_close_request_decode(
    const RinSerialPortalCloseRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out);

RinSerialPortalResultV1 rin_serial_portal_transfer_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1 capability,
    const uint8_t* bytes, size_t byte_count, void* frame_out,
    size_t frame_capacity, size_t* frame_size_out);
RinSerialPortalResultV1 rin_serial_portal_transfer_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialCapabilityV1* capability_out, const uint8_t** bytes_out,
    size_t* byte_count_out);

RinSerialPortalResultV1 rin_serial_portal_transfer_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialPortalResultV1 result,
    RinSerialCapabilityV1 capability, size_t byte_count,
    RinSerialPortalTransferResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_transfer_response_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    const uint8_t** bytes_out, size_t* byte_count_out);

RinSerialPortalResultV1 rin_serial_portal_signals_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1 capability,
    RinSerialSignalsV1 signals, RinSerialPortalSignalsRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_signals_request_decode(
    const RinSerialPortalSignalsRequestV1* request, size_t frame_size,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1* capability_out,
    RinSerialSignalsV1* signals_out);
RinSerialPortalResultV1 rin_serial_portal_status_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    const RinSerialStatusV1* status,
    RinSerialPortalStatusResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_status_response_decode(
    const RinSerialPortalStatusResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    RinSerialStatusV1* status_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out);

RinSerialPortalResultV1 rin_serial_portal_wait_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, uint32_t events,
    RinSerialPortalWaitRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_wait_request_decode(
    const RinSerialPortalWaitRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out, uint32_t* events_out);
RinSerialPortalResultV1 rin_serial_portal_wait_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    const RinSerialWaitResultV1* wait, RinSerialPortalWaitResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_wait_response_decode(
    const RinSerialPortalWaitResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    RinSerialWaitResultV1* wait_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out);

RinSerialPortalResultV1 rin_serial_portal_request_port_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    const char* origin, uint32_t user_activation,
    const RinSerialPortalFilterV1* filters, size_t filter_count,
    uint64_t selected_object_id,
    RinSerialPortalRequestPortRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_request_port_decode(
    const RinSerialPortalRequestPortRequestV1* request, size_t frame_size,
    const char** origin_out, uint32_t* user_activation_out,
    const RinSerialPortalFilterV1** filters_out, size_t* filter_count_out,
    uint64_t* selected_object_id_out);
RinSerialPortalResultV1 rin_serial_portal_request_port_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* device,
    RinSerialPortalRequestPortResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_request_port_response_decode(
    const RinSerialPortalRequestPortResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialPortalDeviceV1* device_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out);
RinSerialPortalResultV1 rin_serial_portal_get_ports_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    const char* origin, RinSerialPortalGetPortsRequestV1* request_out);
RinSerialPortalResultV1 rin_serial_portal_get_ports_request_decode(
    const RinSerialPortalGetPortsRequestV1* request, size_t frame_size,
    const char** origin_out);
RinSerialPortalResultV1 rin_serial_portal_get_ports_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* devices,
    size_t device_count, RinSerialPortalGetPortsResponseV1* response_out);
RinSerialPortalResultV1 rin_serial_portal_get_ports_response_decode(
    const RinSerialPortalGetPortsResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out,
    const RinSerialPortalDeviceV1** devices_out, size_t* device_count_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out);

RinSerialPortalResultV1 rin_serial_portal_event_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, const RinSerialPortalDeviceV1* device,
    RinSerialPortalFrameV1* frame_out, size_t frame_capacity,
    size_t* frame_size_out);
RinSerialPortalResultV1 rin_serial_portal_event_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialPortalDeviceViewV1* device_out);

#if defined(__cplusplus)
static_assert(sizeof(RinSerialPortalFrameV1) == 36u,
              "RinSerialPortalFrameV1 ABI drift");
static_assert(sizeof(RinSerialPortalDeviceV1) == 344u,
              "RinSerialPortalDeviceV1 ABI drift");
static_assert(sizeof(RinSerialPortalOpenRequestV1) == 76u,
              "RinSerialPortalOpenRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalOpenResponseV1) == 60u,
              "RinSerialPortalOpenResponseV1 ABI drift");
static_assert(sizeof(RinSerialPortalCloseRequestV1) == 52u,
              "RinSerialPortalCloseRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalSignalsRequestV1) == 60u,
              "RinSerialPortalSignalsRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalStatusResponseV1) == 116u,
              "RinSerialPortalStatusResponseV1 ABI drift");
static_assert(sizeof(RinSerialPortalWaitRequestV1) == 60u,
              "RinSerialPortalWaitRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalWaitResponseV1) == 76u,
              "RinSerialPortalWaitResponseV1 ABI drift");
static_assert(sizeof(RinSerialPortalFilterV1) == 8u,
              "RinSerialPortalFilterV1 ABI drift");
static_assert(sizeof(RinSerialPortalRequestPortRequestV1) == 1204u,
              "RinSerialPortalRequestPortRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalRequestPortResponseV1) == 388u,
              "RinSerialPortalRequestPortResponseV1 ABI drift");
static_assert(sizeof(RinSerialPortalGetPortsRequestV1) == 1060u,
              "RinSerialPortalGetPortsRequestV1 ABI drift");
static_assert(sizeof(RinSerialPortalGetPortsResponseV1) == 11052u,
              "RinSerialPortalGetPortsResponseV1 ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinSerialPortalFrameV1) == 36u,
               "RinSerialPortalFrameV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalDeviceV1) == 344u,
               "RinSerialPortalDeviceV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalOpenRequestV1) == 76u,
               "RinSerialPortalOpenRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalOpenResponseV1) == 60u,
               "RinSerialPortalOpenResponseV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalCloseRequestV1) == 52u,
               "RinSerialPortalCloseRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalSignalsRequestV1) == 60u,
               "RinSerialPortalSignalsRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalStatusResponseV1) == 116u,
               "RinSerialPortalStatusResponseV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalWaitRequestV1) == 60u,
               "RinSerialPortalWaitRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalWaitResponseV1) == 76u,
               "RinSerialPortalWaitResponseV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalFilterV1) == 8u,
               "RinSerialPortalFilterV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalRequestPortRequestV1) == 1204u,
               "RinSerialPortalRequestPortRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalRequestPortResponseV1) == 388u,
               "RinSerialPortalRequestPortResponseV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalGetPortsRequestV1) == 1060u,
               "RinSerialPortalGetPortsRequestV1 ABI drift");
_Static_assert(sizeof(RinSerialPortalGetPortsResponseV1) == 11052u,
               "RinSerialPortalGetPortsResponseV1 ABI drift");
#endif

#ifdef __cplusplus
}
#endif

#endif /* RIN_APPS_COMMON_SERIAL_PORTAL_PROTOCOL_H */
