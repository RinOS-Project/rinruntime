/* SPDX-License-Identifier: MIT */
/* Public application clipboard client. */
#ifndef RINRUNTIME_CLIPBOARD_H
#define RINRUNTIME_CLIPBOARD_H

#include <stdint.h>

#include <rin/contract_abi.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The public application surface intentionally exposes text only.  Locale
 * metadata and ownership transactions belong to the private compatibility
 * broker and are not part of this general application contract. */
#define RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT UINT32_C(1)
#define RINRUNTIME_CLIPBOARD_MAX_BYTES UINT64_C(4096)

typedef enum RinRuntimeClipboardResult {
    RINRUNTIME_CLIPBOARD_OK = RIN_RESULT_OK,
    RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT = RIN_RESULT_INVALID_ARGUMENT,
    RINRUNTIME_CLIPBOARD_NOT_FOUND = RIN_RESULT_NOT_FOUND,
    RINRUNTIME_CLIPBOARD_KERNEL_REJECTED = RIN_RESULT_ACCESS_DENIED,
    RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL = RIN_RESULT_BUFFER_TOO_SMALL,
    RINRUNTIME_CLIPBOARD_MALFORMED_REPLY = RIN_RESULT_CORRUPT_DATA
} RinRuntimeClipboardResult;

/* Store one caller-owned UTF-8 byte sequence through the public GUI syscall.
 * The private broker remains responsible for capability checks, per-user
 * ownership, generations, and the actual clipboard store. */
RinRuntimeClipboardResult rinruntime_clipboard_set(
    uint32_t format, const void* data, uint64_t data_size,
    uint64_t* generation_out);

/* Read one caller-owned UTF-8 byte sequence.  On BUFFER_TOO_SMALL, required
 * and generation are still returned and the destination is not valid.  On
 * every other failure, all output values are cleared. */
RinRuntimeClipboardResult rinruntime_clipboard_get(
    uint32_t format, void* data, uint64_t data_capacity,
    uint64_t* required_out, uint64_t* generation_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CLIPBOARD_H */
