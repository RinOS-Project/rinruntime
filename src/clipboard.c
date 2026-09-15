/* SPDX-License-Identifier: MIT */
/* Public GUI-syscall adapter for the application clipboard contract. */

#include <rinruntime/clipboard.h>

#include "../../libc/sys/syscall.h"

#include <rin/contract_abi.h>
#include <rin/syscall_abi.h>

#include <string.h>

static void clipboard_zero(void* value, uint64_t size)
{
    unsigned char* bytes = (unsigned char*)value;
    if (bytes == NULL) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static RinRuntimeClipboardResult clipboard_call(
    RinGuiRequestV2* request)
{
    intptr_t raw_result;
    if (request == NULL) return RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT;
    raw_result = _syscall1((uintptr_t)RIN_SYS_GUI_V2_CALL,
                           (uintptr_t)request);
    if (raw_result < INT32_MIN || raw_result > INT32_MAX)
        return RINRUNTIME_CLIPBOARD_MALFORMED_REPLY;
    return (RinRuntimeClipboardResult)(RinResultCode)raw_result;
}

static int clipboard_request_valid(uint32_t format, uint64_t data_size,
                                   const void* data)
{
    return format == RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT &&
           data_size <= RINRUNTIME_CLIPBOARD_MAX_BYTES &&
           (data_size == 0u || data != NULL);
}

static int clipboard_reply_reserved_zero(const RinGuiRequestV2* request)
{
    return request != NULL && request->reserved[0] == 0u &&
           request->reserved[1] == 0u;
}

RinRuntimeClipboardResult rinruntime_clipboard_set(
    uint32_t format, const void* data, uint64_t data_size,
    uint64_t* generation_out)
{
    RinGuiRequestV2 request;
    RinRuntimeClipboardResult result;

    if (generation_out != NULL) *generation_out = 0u;
    if (!clipboard_request_valid(format, data_size, data))
        return RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_GUI_V2_VERSION;
    request.operation = RIN_GUI_V2_OPERATION_CLIPBOARD_SET;
    request.value = format;
    request.data = data_size == 0u ? 0u : (uint64_t)(uintptr_t)data;
    request.data_size = data_size;
    result = clipboard_call(&request);
    if (result != RINRUNTIME_CLIPBOARD_OK ||
        !clipboard_reply_reserved_zero(&request) || request.result0 == 0u ||
        request.result1 != 0u) {
        memset(&request, 0, sizeof(request));
        return result == RINRUNTIME_CLIPBOARD_OK
            ? RINRUNTIME_CLIPBOARD_MALFORMED_REPLY : result;
    }
    if (generation_out != NULL) *generation_out = request.result0;
    memset(&request, 0, sizeof(request));
    return RINRUNTIME_CLIPBOARD_OK;
}

RinRuntimeClipboardResult rinruntime_clipboard_get(
    uint32_t format, void* data, uint64_t data_capacity,
    uint64_t* required_out, uint64_t* generation_out)
{
    RinGuiRequestV2 request;
    RinRuntimeClipboardResult result;
    const int request_valid = clipboard_request_valid(
        format, data_capacity, data);

    if (required_out != NULL) *required_out = 0u;
    if (generation_out != NULL) *generation_out = 0u;
    if (!request_valid) return RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT;

    memset(&request, 0, sizeof(request));
    request.struct_size = sizeof(request);
    request.version = RIN_GUI_V2_VERSION;
    request.operation = RIN_GUI_V2_OPERATION_CLIPBOARD_GET;
    request.value = format;
    request.data = data_capacity == 0u ? 0u : (uint64_t)(uintptr_t)data;
    request.data_size = data_capacity;
    result = clipboard_call(&request);
    if ((result != RINRUNTIME_CLIPBOARD_OK &&
         result != RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL) ||
        !clipboard_reply_reserved_zero(&request) || request.result0 == 0u ||
        request.result0 > RINRUNTIME_CLIPBOARD_MAX_BYTES ||
        request.result1 == 0u ||
        (result == RINRUNTIME_CLIPBOARD_OK &&
         request.result0 > data_capacity) ||
        (result == RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL &&
         request.result0 <= data_capacity)) {
        if (data != NULL) clipboard_zero(data, data_capacity);
        memset(&request, 0, sizeof(request));
        return result == RINRUNTIME_CLIPBOARD_OK ||
                       result == RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL
            ? RINRUNTIME_CLIPBOARD_MALFORMED_REPLY : result;
    }
    if (result == RINRUNTIME_CLIPBOARD_OK) {
        if (required_out != NULL) *required_out = request.result0;
        if (generation_out != NULL) *generation_out = request.result1;
    } else {
        if (data != NULL) clipboard_zero(data, data_capacity);
        if (required_out != NULL) *required_out = request.result0;
        if (generation_out != NULL) *generation_out = request.result1;
    }
    memset(&request, 0, sizeof(request));
    return result;
}
