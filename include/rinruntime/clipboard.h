/* SPDX-License-Identifier: MIT */
/* Public application clipboard client. */
#ifndef RINRUNTIME_CLIPBOARD_H
#define RINRUNTIME_CLIPBOARD_H

#include <stddef.h>
#include <stdint.h>

#include <rin/contract_abi.h>
#include <rin/file_portal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy text clipboard format retained for source compatibility. New native
 * clients should use the multi-format owner API below. */
#define RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT UINT32_C(1)
#define RINRUNTIME_CLIPBOARD_MAX_BYTES UINT64_C(4096)
#define RINRUNTIME_CLIPBOARD_MAX_FORMATS UINT32_C(16)
#define RINRUNTIME_CLIPBOARD_MAX_DATA_BYTES UINT64_C(16777216)
#define RINRUNTIME_CLIPBOARD_MAX_CHUNK_BYTES UINT32_C(32768)
#define RINRUNTIME_CLIPBOARD_MAX_MIME_BYTES UINT32_C(127)
#define RINRUNTIME_CLIPBOARD_MAX_LABEL_BYTES UINT32_C(255)
#define RINRUNTIME_CLIPBOARD_MAX_FILES UINT32_C(16)
#define RINRUNTIME_CLIPBOARD_FILE_LIST_MIME "application/x-rinos-file-list"

/* Source-compatible application names live in the public base as well. */
#define RIN_APP_CLIPBOARD_FORMAT_UTF8_TEXT \
    RINRUNTIME_CLIPBOARD_FORMAT_UTF8_TEXT
#define RIN_APP_CLIPBOARD_MAX_BYTES RINRUNTIME_CLIPBOARD_MAX_BYTES

typedef enum RinRuntimeClipboardResult {
    RINRUNTIME_CLIPBOARD_OK = RIN_RESULT_OK,
    RINRUNTIME_CLIPBOARD_INVALID_ARGUMENT = RIN_RESULT_INVALID_ARGUMENT,
    RINRUNTIME_CLIPBOARD_NOT_FOUND = RIN_RESULT_NOT_FOUND,
    RINRUNTIME_CLIPBOARD_KERNEL_REJECTED = RIN_RESULT_ACCESS_DENIED,
    RINRUNTIME_CLIPBOARD_BUFFER_TOO_SMALL = RIN_RESULT_BUFFER_TOO_SMALL,
    RINRUNTIME_CLIPBOARD_MALFORMED_REPLY = RIN_RESULT_CORRUPT_DATA,
    RINRUNTIME_CLIPBOARD_IO = RIN_RESULT_IO,
    RINRUNTIME_CLIPBOARD_NO_MEMORY = RIN_RESULT_NO_MEMORY,
    RINRUNTIME_CLIPBOARD_BUSY = RIN_RESULT_BUSY,
    RINRUNTIME_CLIPBOARD_NOT_SUPPORTED = RIN_RESULT_NOT_SUPPORTED,
    RINRUNTIME_CLIPBOARD_LIMIT_EXCEEDED = RIN_RESULT_LIMIT_EXCEEDED
} RinRuntimeClipboardResult;

enum {
    RINRUNTIME_CLIPBOARD_TYPE_BYTES = UINT32_C(1),
    RINRUNTIME_CLIPBOARD_TYPE_FILE_LIST = UINT32_C(2)
};

#define RINRUNTIME_CLIPBOARD_FORMAT_FLAG_SENSITIVE UINT32_C(1)

typedef struct RinRuntimeClipboardFormatInfoV1 {
    uint32_t struct_size;
    uint32_t type;
    uint32_t mime_size;
    uint32_t label_size;
    uint32_t priority;
    uint32_t flags;
    uint64_t data_size;
    uint32_t file_count;
    uint32_t reserved0;
    char mime[RINRUNTIME_CLIPBOARD_MAX_MIME_BYTES + 1u];
    char label[RINRUNTIME_CLIPBOARD_MAX_LABEL_BYTES + 1u];
} RinRuntimeClipboardFormatInfoV1;

typedef struct RinRuntimeClipboardFileInputV1 {
    int32_t descriptor;
    uint32_t reserved0;
    const char* label;
} RinRuntimeClipboardFileInputV1;

typedef struct RinRuntimeClipboardFormatInputV1 {
    uint32_t struct_size;
    uint32_t type;
    uint32_t priority;
    uint32_t flags;
    const char* mime;
    const char* label;
    const void* data;
    uint64_t data_size;
    const RinRuntimeClipboardFileInputV1* files;
    uint32_t file_count;
    uint32_t reserved0;
} RinRuntimeClipboardFormatInputV1;

/* Offers are committed atomically. Byte payloads are streamed in bounded
 * chunks; file-list entries are held by the per-user clipboard owner as
 * File Portal capabilities and re-issued for each receiving process.
 * Generations are opaque nonzero tokens for rejecting stale reads. */
RinRuntimeClipboardResult rinruntime_clipboard_set_formats_v1(
    const RinRuntimeClipboardFormatInputV1* formats, uint32_t format_count,
    uint64_t* generation_out);
RinRuntimeClipboardResult rinruntime_clipboard_query_v1(
    RinRuntimeClipboardFormatInfoV1* formats, uint32_t format_capacity,
    uint32_t* format_count_out, uint64_t* generation_out);
RinRuntimeClipboardResult rinruntime_clipboard_read_chunk_v1(
    uint64_t generation, uint32_t format_index, uint64_t offset,
    void* data, uint32_t data_capacity, uint32_t* bytes_read_out);
RinRuntimeClipboardResult rinruntime_clipboard_get_file_v1(
    uint64_t generation, uint32_t format_index, uint32_t file_index,
    RinFilePortalTokenV1* token_out, char* label_out,
    uint32_t label_capacity, uint32_t* label_size_out);
/* Polling compares the active session generation; callers can turn a changed
 * value into their normal UI notification without exposing clipboard data. */
RinRuntimeClipboardResult rinruntime_clipboard_poll_change_v1(
    uint64_t previous_generation, uint64_t* generation_out,
    int* changed_out);

/* Store one caller-owned UTF-8 byte sequence through the session clipboard
 * owner. This compatibility entry point keeps the historical 4 KiB limit. */
RinRuntimeClipboardResult rinruntime_clipboard_set(
    uint32_t format, const void* data, uint64_t data_size,
    uint64_t* generation_out);

/* Read one caller-owned UTF-8 byte sequence. On BUFFER_TOO_SMALL, required
 * and generation are still returned and the destination is not valid.  On
 * every other failure, all output values are cleared. */
RinRuntimeClipboardResult rinruntime_clipboard_get(
    uint32_t format, void* data, uint64_t data_capacity,
    uint64_t* required_out, uint64_t* generation_out);

/* Compatibility names used by existing native applications.  These are
 * implemented by this public-base client and share the same ABI contract. */
int rin_app_clipboard_set(uint32_t format, const void* data,
                          size_t data_size, uint64_t* generation_out);
int rin_app_clipboard_get(uint32_t format, void* data, size_t data_capacity,
                          uint64_t* required_out,
                          uint64_t* generation_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CLIPBOARD_H */
