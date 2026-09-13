/* SPDX-License-Identifier: MIT */

#include <rinruntime/rin_serial_portal_protocol.h>

#include <string.h>

static void zero(void* value, size_t size)
{
    if (value != NULL) memset(value, 0, size);
}

static int capability_valid(RinSerialCapabilityV1 capability)
{
    return capability.object_id != 0u && capability.generation != 0u;
}

static int wait_events_mask_valid(uint32_t events)
{
    const uint32_t allowed = RIN_SERIAL_WAIT_READABLE |
                             RIN_SERIAL_WAIT_WRITABLE |
                             RIN_SERIAL_WAIT_HANGUP |
                             RIN_SERIAL_WAIT_ERROR;
    return (events & ~allowed) == 0u;
}

static int wait_events_valid(uint32_t events)
{
    return events != 0u && wait_events_mask_valid(events);
}

static int frame_valid(const RinSerialPortalFrameV1* frame, size_t frame_size,
                       RinSerialPortalOperationV1 operation, size_t exact_size)
{
    return frame != NULL && frame_size == exact_size &&
           frame->magic == RIN_SERIAL_PORTAL_MAGIC &&
           frame->version == RIN_SERIAL_PORTAL_VERSION &&
           frame->operation == (uint16_t)operation &&
           frame->frame_size == exact_size && frame->request_id != 0u &&
           frame->session_id != 0u && frame->session_generation != 0u;
}

RinSerialPortalResultV1 rin_serial_portal_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialPortalFrameV1* frame_out)
{
    if (frame_out == NULL || request_id == 0u || session_id == 0u ||
        session_generation == 0u || operation < RIN_SERIAL_PORTAL_ENUMERATE_REQUEST ||
        operation > RIN_SERIAL_PORTAL_GET_PORTS_RESPONSE)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(frame_out, sizeof(*frame_out));
    frame_out->magic = RIN_SERIAL_PORTAL_MAGIC;
    frame_out->version = RIN_SERIAL_PORTAL_VERSION;
    frame_out->operation = (uint16_t)operation;
    frame_out->frame_size = (uint32_t)sizeof(*frame_out);
    frame_out->request_id = request_id;
    frame_out->session_id = session_id;
    frame_out->session_generation = session_generation;
    return RIN_SERIAL_PORTAL_OK;
}
RinSerialPortalResultV1 rin_serial_portal_frame_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out)
{
    const RinSerialPortalFrameV1* header = (const RinSerialPortalFrameV1*)frame;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (session_id_out != NULL) *session_id_out = 0u;
    if (session_generation_out != NULL) *session_generation_out = 0u;
    if (!frame_valid(header, frame_size, operation, sizeof(*header)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = header->request_id;
    if (session_id_out != NULL) *session_id_out = header->session_id;
    if (session_generation_out != NULL)
        *session_generation_out = header->session_generation;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_enumerate_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* devices,
    size_t device_count, RinSerialPortalEnumerateResponseV1* response_out)
{
    if (response_out == NULL || device_count > RIN_SERIAL_PORTAL_MAX_DEVICES ||
        (device_count != 0u && devices == NULL) || request_id == 0u ||
        session_id == 0u || session_generation == 0u)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_ENUMERATE_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    response_out->device_count = (uint32_t)device_count;
    if (device_count != 0u)
        memcpy(response_out->devices, devices,
               device_count * sizeof(response_out->devices[0]));
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_enumerate_response_decode(
    const RinSerialPortalEnumerateResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out,
    const RinSerialPortalDeviceV1** devices_out, size_t* device_count_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (devices_out != NULL) *devices_out = NULL;
    if (device_count_out != NULL) *device_count_out = 0u;
    if (response == NULL || !frame_valid(&response->frame, frame_size,
                                         RIN_SERIAL_PORTAL_ENUMERATE_RESPONSE,
                                         sizeof(*response)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (response->device_count > RIN_SERIAL_PORTAL_MAX_DEVICES)
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (devices_out != NULL) *devices_out = response->devices;
    if (device_count_out != NULL) *device_count_out = response->device_count;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_open_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, RinSerialConfigV1 config, uint32_t flags,
    RinSerialPortalOpenRequestV1* request_out)
{
    if (request_out == NULL || !capability_valid(capability))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_OPEN_REQUEST, &request_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    request_out->capability = capability;
    request_out->config = config;
    request_out->flags = flags;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_open_request_decode(
    const RinSerialPortalOpenRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out, RinSerialConfigV1* config_out,
    uint32_t* flags_out)
{
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (config_out != NULL) zero(config_out, sizeof(*config_out));
    if (flags_out != NULL) *flags_out = 0u;
    if (request == NULL || !frame_valid(&request->frame, frame_size,
                                        RIN_SERIAL_PORTAL_OPEN_REQUEST,
                                        sizeof(*request)) ||
        !capability_valid(request->capability) || request->reserved != 0u)
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) *capability_out = request->capability;
    if (config_out != NULL) *config_out = request->config;
    if (flags_out != NULL) *flags_out = request->flags;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_close_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, RinSerialPortalCloseRequestV1* request_out)
{
    if (request_out == NULL || !capability_valid(capability))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_CLOSE_REQUEST, &request_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    request_out->capability = capability;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_close_request_decode(
    const RinSerialPortalCloseRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out)
{
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (request == NULL ||
        !frame_valid(&request->frame, frame_size, RIN_SERIAL_PORTAL_CLOSE_REQUEST,
                     sizeof(*request)) || !capability_valid(request->capability))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) *capability_out = request->capability;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_open_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    RinSerialPortalOpenResponseV1* response_out)
{
    if (response_out == NULL || (result == RIN_SERIAL_PORTAL_OK &&
                                 !capability_valid(capability)))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_OPEN_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    response_out->capability = capability;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_open_response_decode(
    const RinSerialPortalOpenResponseV1* response, size_t frame_size,
    RinSerialPortalOperationV1 operation, RinSerialPortalResultV1* result_out,
    RinSerialCapabilityV1* capability_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (response == NULL ||
        !frame_valid(&response->frame, frame_size, operation, sizeof(*response)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (capability_out != NULL) *capability_out = response->capability;
    if (response->result == RIN_SERIAL_PORTAL_OK &&
        !capability_valid(response->capability))
        return RIN_SERIAL_PORTAL_MALFORMED;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_transfer_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1 capability,
    const uint8_t* bytes, size_t byte_count, void* frame_out,
    size_t frame_capacity, size_t* frame_size_out)
{
    RinSerialPortalTransferV1* transfer = (RinSerialPortalTransferV1*)frame_out;
    size_t frame_size;
    if (frame_size_out != NULL) *frame_size_out = 0u;
    if (frame_out != NULL) zero(frame_out, frame_capacity);
    if (transfer == NULL || frame_size_out == NULL || !capability_valid(capability) ||
        (operation != RIN_SERIAL_PORTAL_READ_REQUEST &&
         operation != RIN_SERIAL_PORTAL_WRITE_REQUEST &&
         operation != RIN_SERIAL_PORTAL_READ_RESPONSE) ||
        (byte_count != 0u && bytes == NULL) || byte_count > RIN_SERIAL_BUFFER_MAX)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    if (rin_serial_portal_request_encode(request_id, session_id,
                                         session_generation, operation,
                                         &transfer->frame) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    frame_size = sizeof(*transfer) + byte_count;
    if (frame_capacity < frame_size || frame_size > UINT32_MAX)
        return RIN_SERIAL_PORTAL_LIMIT;
    transfer->frame.frame_size = (uint32_t)frame_size;
    transfer->capability = capability;
    transfer->byte_count = (uint32_t)byte_count;
    if (byte_count != 0u) memcpy((uint8_t*)transfer + sizeof(*transfer), bytes, byte_count);
    *frame_size_out = frame_size;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_transfer_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialCapabilityV1* capability_out, const uint8_t** bytes_out,
    size_t* byte_count_out)
{
    const RinSerialPortalTransferV1* transfer = (const RinSerialPortalTransferV1*)frame;
    size_t expected;
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (bytes_out != NULL) *bytes_out = NULL;
    if (byte_count_out != NULL) *byte_count_out = 0u;
    if (transfer == NULL || (operation != RIN_SERIAL_PORTAL_READ_REQUEST &&
                             operation != RIN_SERIAL_PORTAL_WRITE_REQUEST &&
                             operation != RIN_SERIAL_PORTAL_READ_RESPONSE) ||
        transfer->byte_count > RIN_SERIAL_BUFFER_MAX)
        return RIN_SERIAL_PORTAL_MALFORMED;
    expected = sizeof(*transfer) + (size_t)transfer->byte_count;
    if (!frame_valid(&transfer->frame, frame_size, operation, expected) ||
        !capability_valid(transfer->capability))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) *capability_out = transfer->capability;
    if (bytes_out != NULL) *bytes_out = (const uint8_t*)transfer + sizeof(*transfer);
    if (byte_count_out != NULL) *byte_count_out = transfer->byte_count;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_transfer_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialPortalResultV1 result,
    RinSerialCapabilityV1 capability, size_t byte_count,
    RinSerialPortalTransferResponseV1* response_out)
{
    if (response_out == NULL ||
        (operation != RIN_SERIAL_PORTAL_READ_RESPONSE &&
         operation != RIN_SERIAL_PORTAL_WRITE_RESPONSE) ||
        byte_count > RIN_SERIAL_BUFFER_MAX ||
        (result == RIN_SERIAL_PORTAL_OK && !capability_valid(capability)))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(request_id, session_id,
                                         session_generation, operation,
                                         &response_out->frame) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)(offsetof(
        RinSerialPortalTransferResponseV1, bytes) + byte_count);
    response_out->result = result;
    response_out->byte_count = (uint32_t)byte_count;
    response_out->capability = capability;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_transfer_response_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    const uint8_t** bytes_out, size_t* byte_count_out)
{
    const RinSerialPortalTransferResponseV1* response =
        (const RinSerialPortalTransferResponseV1*)frame;
    size_t expected;
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (bytes_out != NULL) *bytes_out = NULL;
    if (byte_count_out != NULL) *byte_count_out = 0u;
    if (response == NULL ||
        (operation != RIN_SERIAL_PORTAL_READ_RESPONSE &&
         operation != RIN_SERIAL_PORTAL_WRITE_RESPONSE) ||
        response->byte_count > RIN_SERIAL_BUFFER_MAX)
        return RIN_SERIAL_PORTAL_MALFORMED;
    expected = offsetof(RinSerialPortalTransferResponseV1, bytes) +
               (size_t)response->byte_count;
    if (!frame_valid(&response->frame, frame_size, operation, expected) ||
        (response->result == RIN_SERIAL_PORTAL_OK &&
         !capability_valid(response->capability)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (capability_out != NULL) *capability_out = response->capability;
    if (bytes_out != NULL) *bytes_out = response->bytes;
    if (byte_count_out != NULL) *byte_count_out = response->byte_count;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_signals_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1 capability,
    RinSerialSignalsV1 signals, RinSerialPortalSignalsRequestV1* request_out)
{
    if (request_out == NULL ||
        (operation != RIN_SERIAL_PORTAL_SET_SIGNALS_REQUEST &&
         operation != RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST) ||
        !capability_valid(capability) || signals.dtr > 1u || signals.rts > 1u ||
        signals.break_signal > 1u || signals.reserved0 != 0u ||
        (operation == RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST &&
         (signals.dtr != 0u || signals.rts != 0u || signals.break_signal != 0u)))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation, operation,
            &request_out->frame) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    request_out->capability = capability;
    request_out->signals = signals;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_signals_request_decode(
    const RinSerialPortalSignalsRequestV1* request, size_t frame_size,
    RinSerialPortalOperationV1 operation, RinSerialCapabilityV1* capability_out,
    RinSerialSignalsV1* signals_out)
{
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (signals_out != NULL) zero(signals_out, sizeof(*signals_out));
    if (request == NULL ||
        (operation != RIN_SERIAL_PORTAL_SET_SIGNALS_REQUEST &&
         operation != RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST) ||
        !frame_valid(&request->frame, frame_size, operation, sizeof(*request)) ||
        !capability_valid(request->capability) || request->reserved != 0u ||
        request->signals.dtr > 1u || request->signals.rts > 1u ||
        request->signals.break_signal > 1u || request->signals.reserved0 != 0u ||
        (operation == RIN_SERIAL_PORTAL_GET_SIGNALS_REQUEST &&
         (request->signals.dtr != 0u || request->signals.rts != 0u ||
          request->signals.break_signal != 0u)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) *capability_out = request->capability;
    if (signals_out != NULL) *signals_out = request->signals;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_status_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    const RinSerialStatusV1* status,
    RinSerialPortalStatusResponseV1* response_out)
{
    if (response_out == NULL ||
        (result == RIN_SERIAL_PORTAL_OK &&
         (!capability_valid(capability) || status == NULL)))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_GET_SIGNALS_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    response_out->capability = capability;
    if (status != NULL) response_out->status = *status;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_status_response_decode(
    const RinSerialPortalStatusResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    RinSerialStatusV1* status_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (status_out != NULL) zero(status_out, sizeof(*status_out));
    if (response == NULL ||
        !frame_valid(&response->frame, frame_size,
                     RIN_SERIAL_PORTAL_GET_SIGNALS_RESPONSE, sizeof(*response)) ||
        response->reserved != 0u)
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (capability_out != NULL) *capability_out = response->capability;
    if (status_out != NULL) *status_out = response->status;
    if (response->result == RIN_SERIAL_PORTAL_OK &&
        !capability_valid(response->capability))
        return RIN_SERIAL_PORTAL_MALFORMED;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_wait_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialCapabilityV1 capability, uint32_t events,
    RinSerialPortalWaitRequestV1* request_out)
{
    if (request_out == NULL || !capability_valid(capability) ||
        !wait_events_valid(events))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_WAIT_REQUEST, &request_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    request_out->capability = capability;
    request_out->events = events;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_wait_request_decode(
    const RinSerialPortalWaitRequestV1* request, size_t frame_size,
    RinSerialCapabilityV1* capability_out, uint32_t* events_out)
{
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (events_out != NULL) *events_out = 0u;
    if (request == NULL || !frame_valid(&request->frame, frame_size,
                                        RIN_SERIAL_PORTAL_WAIT_REQUEST,
                                        sizeof(*request)) ||
        !capability_valid(request->capability) || request->reserved != 0u ||
        !wait_events_valid(request->events))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) *capability_out = request->capability;
    if (events_out != NULL) *events_out = request->events;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_wait_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, RinSerialCapabilityV1 capability,
    const RinSerialWaitResultV1* wait, RinSerialPortalWaitResponseV1* response_out)
{
    if (response_out == NULL ||
        (result == RIN_SERIAL_PORTAL_OK &&
         (!capability_valid(capability) || wait == NULL ||
          wait->reserved0 != 0u || !wait_events_mask_valid(wait->events))))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_WAIT_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    response_out->capability = capability;
    if (wait != NULL) response_out->wait = *wait;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_wait_response_decode(
    const RinSerialPortalWaitResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialCapabilityV1* capability_out,
    RinSerialWaitResultV1* wait_out, uint64_t* request_id_out,
    uint64_t* session_id_out, uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (capability_out != NULL) zero(capability_out, sizeof(*capability_out));
    if (wait_out != NULL) zero(wait_out, sizeof(*wait_out));
    if (response == NULL ||
        !frame_valid(&response->frame, frame_size,
                     RIN_SERIAL_PORTAL_WAIT_RESPONSE, sizeof(*response)) ||
        response->reserved != 0u || response->wait.reserved0 != 0u ||
        !wait_events_mask_valid(response->wait.events) ||
        (response->result == RIN_SERIAL_PORTAL_OK &&
         (!capability_valid(response->capability) ||
          !wait_events_valid(response->wait.events))))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (capability_out != NULL) *capability_out = response->capability;
    if (wait_out != NULL) *wait_out = response->wait;
    return RIN_SERIAL_PORTAL_OK;
}

static int origin_valid(const char* origin)
{
    size_t index;
    if (origin == NULL || origin[0] == '\0') return 0;
    for (index = 0u; index < RIN_SERIAL_PORTAL_ORIGIN_MAX; ++index) {
        unsigned char byte = (unsigned char)origin[index];
        if (byte == 0u) return index != 0u;
        if (byte < 0x20u || byte == 0x7fu) return 0;
    }
    return 0;
}

static int filters_valid(const RinSerialPortalFilterV1* filters, size_t count)
{
    size_t index;
    if (count > RIN_SERIAL_PORTAL_MAX_FILTERS ||
        (count != 0u && filters == NULL)) return 0;
    for (index = 0u; index < count; ++index) {
        if ((!filters[index].has_vendor_id && !filters[index].has_product_id) ||
            filters[index].has_vendor_id > 1u || filters[index].has_product_id > 1u ||
            filters[index].reserved != 0u)
            return 0;
    }
    return 1;
}

RinSerialPortalResultV1 rin_serial_portal_request_port_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    const char* origin, uint32_t user_activation,
    const RinSerialPortalFilterV1* filters, size_t filter_count,
    uint64_t selected_object_id,
    RinSerialPortalRequestPortRequestV1* request_out)
{
    if (request_out == NULL || !origin_valid(origin) ||
        user_activation > 1u || !filters_valid(filters, filter_count))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_REQUEST_PORT_REQUEST, &request_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    request_out->user_activation = user_activation;
    request_out->filter_count = (uint32_t)filter_count;
    request_out->selected_object_id = selected_object_id;
    memcpy(request_out->origin, origin, strlen(origin));
    if (filter_count != 0u)
        memcpy(request_out->filters, filters,
               filter_count * sizeof(request_out->filters[0]));
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_request_port_decode(
    const RinSerialPortalRequestPortRequestV1* request, size_t frame_size,
    const char** origin_out, uint32_t* user_activation_out,
    const RinSerialPortalFilterV1** filters_out, size_t* filter_count_out,
    uint64_t* selected_object_id_out)
{
    if (origin_out != NULL) *origin_out = NULL;
    if (user_activation_out != NULL) *user_activation_out = 0u;
    if (filters_out != NULL) *filters_out = NULL;
    if (filter_count_out != NULL) *filter_count_out = 0u;
    if (selected_object_id_out != NULL) *selected_object_id_out = 0u;
    if (request == NULL || !frame_valid(&request->frame, frame_size,
                                        RIN_SERIAL_PORTAL_REQUEST_PORT_REQUEST,
                                        sizeof(*request)) ||
        request->user_activation > 1u ||
        request->filter_count > RIN_SERIAL_PORTAL_MAX_FILTERS ||
        !origin_valid(request->origin) ||
        !filters_valid(request->filters, request->filter_count))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (origin_out != NULL) *origin_out = request->origin;
    if (user_activation_out != NULL) *user_activation_out = request->user_activation;
    if (filters_out != NULL) *filters_out = request->filters;
    if (filter_count_out != NULL) *filter_count_out = request->filter_count;
    if (selected_object_id_out != NULL) *selected_object_id_out = request->selected_object_id;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_request_port_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* device,
    RinSerialPortalRequestPortResponseV1* response_out)
{
    if (response_out == NULL ||
        (result == RIN_SERIAL_PORTAL_OK &&
         (device == NULL || !capability_valid(device->capability))))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_REQUEST_PORT_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    if (device != NULL) response_out->device = *device;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_request_port_response_decode(
    const RinSerialPortalRequestPortResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out, RinSerialPortalDeviceV1* device_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (device_out != NULL) zero(device_out, sizeof(*device_out));
    if (response == NULL || !frame_valid(&response->frame, frame_size,
                                         RIN_SERIAL_PORTAL_REQUEST_PORT_RESPONSE,
                                         sizeof(*response)) ||
        response->reserved != 0u ||
        (response->result == RIN_SERIAL_PORTAL_OK &&
         !capability_valid(response->device.capability)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (device_out != NULL) *device_out = response->device;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_get_ports_request_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    const char* origin, RinSerialPortalGetPortsRequestV1* request_out)
{
    if (request_out == NULL || !origin_valid(origin))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(request_out, sizeof(*request_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_GET_PORTS_REQUEST, &request_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    request_out->frame.frame_size = (uint32_t)sizeof(*request_out);
    memcpy(request_out->origin, origin, strlen(origin));
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_get_ports_request_decode(
    const RinSerialPortalGetPortsRequestV1* request, size_t frame_size,
    const char** origin_out)
{
    if (origin_out != NULL) *origin_out = NULL;
    if (request == NULL || !frame_valid(&request->frame, frame_size,
                                        RIN_SERIAL_PORTAL_GET_PORTS_REQUEST,
                                        sizeof(*request)) ||
        !origin_valid(request->origin))
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (origin_out != NULL) *origin_out = request->origin;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_get_ports_response_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalResultV1 result, const RinSerialPortalDeviceV1* devices,
    size_t device_count, RinSerialPortalGetPortsResponseV1* response_out)
{
    if (response_out == NULL || device_count > RIN_SERIAL_PORTAL_MAX_DEVICES ||
        (device_count != 0u && devices == NULL))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    zero(response_out, sizeof(*response_out));
    if (rin_serial_portal_request_encode(
            request_id, session_id, session_generation,
            RIN_SERIAL_PORTAL_GET_PORTS_RESPONSE, &response_out->frame) !=
        RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    response_out->frame.frame_size = (uint32_t)sizeof(*response_out);
    response_out->result = result;
    response_out->device_count = (uint32_t)device_count;
    if (device_count != 0u)
        memcpy(response_out->devices, devices,
               device_count * sizeof(response_out->devices[0]));
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_get_ports_response_decode(
    const RinSerialPortalGetPortsResponseV1* response, size_t frame_size,
    RinSerialPortalResultV1* result_out,
    const RinSerialPortalDeviceV1** devices_out, size_t* device_count_out,
    uint64_t* request_id_out, uint64_t* session_id_out,
    uint64_t* session_generation_out)
{
    if (result_out != NULL) *result_out = RIN_SERIAL_PORTAL_MALFORMED;
    if (devices_out != NULL) *devices_out = NULL;
    if (device_count_out != NULL) *device_count_out = 0u;
    if (response == NULL || !frame_valid(&response->frame, frame_size,
                                         RIN_SERIAL_PORTAL_GET_PORTS_RESPONSE,
                                         sizeof(*response)) ||
        response->device_count > RIN_SERIAL_PORTAL_MAX_DEVICES)
        return RIN_SERIAL_PORTAL_MALFORMED;
    if (request_id_out != NULL) *request_id_out = response->frame.request_id;
    if (session_id_out != NULL) *session_id_out = response->frame.session_id;
    if (session_generation_out != NULL)
        *session_generation_out = response->frame.session_generation;
    if (result_out != NULL) *result_out = (RinSerialPortalResultV1)response->result;
    if (devices_out != NULL) *devices_out = response->devices;
    if (device_count_out != NULL) *device_count_out = response->device_count;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_event_encode(
    uint64_t request_id, uint64_t session_id, uint64_t session_generation,
    RinSerialPortalOperationV1 operation, const RinSerialPortalDeviceV1* device,
    RinSerialPortalFrameV1* frame_out, size_t frame_capacity,
    size_t* frame_size_out)
{
    size_t size = sizeof(RinSerialPortalFrameV1) + sizeof(RinSerialPortalDeviceV1);
    if (frame_size_out != NULL) *frame_size_out = 0u;
    if (frame_out != NULL) zero(frame_out, frame_capacity);
    if (frame_out == NULL || frame_size_out == NULL || device == NULL ||
        frame_capacity < size || (operation != RIN_SERIAL_PORTAL_CONNECT_EVENT &&
                                  operation != RIN_SERIAL_PORTAL_DISCONNECT_EVENT) ||
        !capability_valid(device->capability))
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    if (rin_serial_portal_request_encode(request_id, session_id,
                                         session_generation, operation,
                                         frame_out) != RIN_SERIAL_PORTAL_OK)
        return RIN_SERIAL_PORTAL_INVALID_ARGUMENT;
    frame_out->frame_size = (uint32_t)size;
    memcpy((uint8_t*)frame_out + sizeof(*frame_out), device, sizeof(*device));
    *frame_size_out = size;
    return RIN_SERIAL_PORTAL_OK;
}

RinSerialPortalResultV1 rin_serial_portal_event_decode(
    const void* frame, size_t frame_size, RinSerialPortalOperationV1 operation,
    RinSerialPortalDeviceViewV1* device_out)
{
    const RinSerialPortalFrameV1* header = (const RinSerialPortalFrameV1*)frame;
    const RinSerialPortalDeviceV1* device;
    if (device_out != NULL) zero(device_out, sizeof(*device_out));
    if (frame == NULL || device_out == NULL ||
        (operation != RIN_SERIAL_PORTAL_CONNECT_EVENT &&
         operation != RIN_SERIAL_PORTAL_DISCONNECT_EVENT) ||
        !frame_valid(header, frame_size, operation,
                     sizeof(*header) + sizeof(RinSerialPortalDeviceV1)))
        return RIN_SERIAL_PORTAL_MALFORMED;
    device = (const RinSerialPortalDeviceV1*)((const uint8_t*)frame + sizeof(*header));
    if (!capability_valid(device->capability)) return RIN_SERIAL_PORTAL_MALFORMED;
    device_out->info = device->info;
    device_out->capability = device->capability;
    device_out->connected = operation == RIN_SERIAL_PORTAL_CONNECT_EVENT ? 1u : 0u;
    return RIN_SERIAL_PORTAL_OK;
}

