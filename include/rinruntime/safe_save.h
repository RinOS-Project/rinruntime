/* SPDX-License-Identifier: MIT */
/* Crash-aware, backend-neutral document replacement helper. */

#ifndef RINRUNTIME_SAFE_SAVE_H
#define RINRUNTIME_SAFE_SAVE_H

#include <stdint.h>

#include "file_operation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_SAFE_SAVE_VERSION 1u

typedef enum RinRuntimeSafeSaveResult {
    /* The replacement and its parent directory have been synchronized. */
    RINRUNTIME_SAFE_SAVE_COMPLETED = 0,
    /* The replacement was committed, but parent-directory durability is
     * unknown. The caller must not retry the write blindly. */
    RINRUNTIME_SAFE_SAVE_COMMITTED_UNSYNCED = 1,
    RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT = -1,
    /* No replacement was published. The old target remains authoritative. */
    RINRUNTIME_SAFE_SAVE_IO_FAILED = -2,
    /* No replacement was published, but a private temporary object could not
     * be removed and/or its directory could not be synchronized. */
    RINRUNTIME_SAFE_SAVE_CLEANUP_FAILED = -3
} RinRuntimeSafeSaveResult;

typedef struct RinRuntimeSafeSaveBackendV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    void* context;
    /* Create an exclusive private temporary in target_path's parent. On
     * success, write its absolute canonical path and return its open handle. */
    int (*open_temporary)(void* context, const char* target_path,
                          char* temporary_path_out,
                          uint32_t temporary_path_capacity,
                          uintptr_t* handle_out);
    /* Return zero only when bytes_written_out is within [0, size]. */
    int (*write)(void* context, uintptr_t handle, const uint8_t* bytes,
                 uint32_t size, uint32_t* bytes_written_out);
    int (*sync_file)(void* context, uintptr_t handle);
    int (*close)(void* context, uintptr_t handle);
    /* Atomically replace target_path with temporary_path. On failure it must
     * leave the old target and temporary object intact. */
    int (*publish_replace)(void* context, const char* temporary_path,
                           const char* target_path);
    /* Remove only a helper-created private temporary. */
    int (*remove_temporary)(void* context, const char* temporary_path);
    int (*sync_directory)(void* context, const char* directory_path);
    uint64_t reserved[3];
} RinRuntimeSafeSaveBackendV1;

/* Writes one bounded caller-owned byte span without exposing a partial target.
 * target_path must be absolute and canonical; data may be NULL only if size is
 * zero. A COMMITTED_UNSYNCED result means that the new document is visible and
 * must be resolved by inspecting the target, not by an automatic retry. */
RinRuntimeSafeSaveResult rinruntime_safe_save(
    const RinRuntimeSafeSaveBackendV1* backend, const char* target_path,
    const uint8_t* data, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_SAFE_SAVE_H */


