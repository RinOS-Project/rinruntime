/* SPDX-License-Identifier: MIT */
/* Bounded, backend-neutral FileOperation service core. */

#ifndef RINRUNTIME_FILE_OPERATION_H
#define RINRUNTIME_FILE_OPERATION_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Metadata, link, and sparse-copy callbacks extend the backend layout; reject
 * clients compiled against an older layout instead of reading beyond it. */
#define RINRUNTIME_FILE_OPERATION_VERSION 5u
#define RINRUNTIME_FILE_OPERATION_PATH_MAX 512u
#define RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT 4096u
#define RINRUNTIME_FILE_OPERATION_COPY_CHUNK_SIZE (64u * 1024u)

/* Backends return these values for failures which need a user-visible,
 * portable diagnosis. All other nonzero results are treated as I/O failure. */
#define RINRUNTIME_FILE_OPERATION_BACKEND_NO_SPACE (-2)
#define RINRUNTIME_FILE_OPERATION_BACKEND_DEVICE_REMOVED (-3)
/* The source has no data at or after a sparse SEEK_DATA probe. */
#define RINRUNTIME_FILE_OPERATION_BACKEND_NO_DATA (-4)
/* The filesystem cannot report sparse extents. The core copies dense bytes. */
#define RINRUNTIME_FILE_OPERATION_BACKEND_SPARSE_UNSUPPORTED (-5)

typedef enum RinRuntimeFileOperationSeekWhence {
    RINRUNTIME_FILE_OPERATION_SEEK_SET = 0,
    RINRUNTIME_FILE_OPERATION_SEEK_END = 2,
    RINRUNTIME_FILE_OPERATION_SEEK_DATA = 3,
    RINRUNTIME_FILE_OPERATION_SEEK_HOLE = 4
} RinRuntimeFileOperationSeekWhence;

typedef enum RinRuntimeFileOperationEntryKind {
    RINRUNTIME_FILE_OPERATION_ENTRY_FILE = 1,
    RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY = 2,
    RINRUNTIME_FILE_OPERATION_ENTRY_SYMLINK = 3,
    /* link_source_index identifies an earlier FILE/HARDLINK copy entry whose
     * destination becomes the source of this no-replace hardlink. */
    RINRUNTIME_FILE_OPERATION_ENTRY_HARDLINK = 4
} RinRuntimeFileOperationEntryKind;

typedef enum RinRuntimeFileOperationKind {
    RINRUNTIME_FILE_OPERATION_COPY = 1,
    RINRUNTIME_FILE_OPERATION_MOVE = 2,
    RINRUNTIME_FILE_OPERATION_RENAME = 3,
    RINRUNTIME_FILE_OPERATION_DELETE = 4,
    RINRUNTIME_FILE_OPERATION_TRASH = 5,
    RINRUNTIME_FILE_OPERATION_RESTORE = 6
} RinRuntimeFileOperationKind;

typedef enum RinRuntimeFileOperationConflictPolicy {
    RINRUNTIME_FILE_OPERATION_CONFLICT_FAIL = 1,
    RINRUNTIME_FILE_OPERATION_CONFLICT_SKIP = 2,
    RINRUNTIME_FILE_OPERATION_CONFLICT_REPLACE = 3,
    RINRUNTIME_FILE_OPERATION_CONFLICT_RENAME = 4
} RinRuntimeFileOperationConflictPolicy;

typedef enum RinRuntimeFileOperationResult {
    RINRUNTIME_FILE_OPERATION_OK = 0,
    RINRUNTIME_FILE_OPERATION_IN_PROGRESS = 1,
    RINRUNTIME_FILE_OPERATION_COMPLETED = 2,
    RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT = -1,
    RINRUNTIME_FILE_OPERATION_BUSY = -2,
    RINRUNTIME_FILE_OPERATION_CONFLICT = -3,
    RINRUNTIME_FILE_OPERATION_IO_FAILED = -4,
    RINRUNTIME_FILE_OPERATION_NO_SPACE = -5,
    RINRUNTIME_FILE_OPERATION_DEVICE_REMOVED = -6,
    RINRUNTIME_FILE_OPERATION_CANCELLED = -7,
    RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED = -8,
    RINRUNTIME_FILE_OPERATION_UNSUPPORTED = -9
} RinRuntimeFileOperationResult;

enum {
    RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP = 0x00000001u,
    RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED = 0x00000002u,
    RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED = 0x00000004u
};

typedef struct RinRuntimeFileOperationEntryV1 {
    const char* source_path;
    char destination_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    uint64_t size_bytes;
    uint32_t kind;
    uint32_t flags;
    uint32_t link_source_index;
} RinRuntimeFileOperationEntryV1;

typedef struct RinRuntimeFileOperationBackendV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    void* context;
    /* Returns 1 for exists, 0 for missing, -1 for unknown/error. */
    int (*path_state)(void* context, const char* path);
    int (*open_read)(void* context, const char* path, uintptr_t* handle_out);
    int (*open_create_exclusive)(void* context, const char* path,
                                 uintptr_t* handle_out);
    int (*read)(void* context, uintptr_t handle, uint8_t* bytes,
                uint32_t capacity, uint32_t* bytes_read_out);
    int (*write)(void* context, uintptr_t handle, const uint8_t* bytes,
                 uint32_t size, uint32_t* bytes_written_out);
    int (*sync_file)(void* context, uintptr_t handle);
    int (*close)(void* context, uintptr_t handle);
    int (*mkdir)(void* context, const char* path);
    /* Must publish without replacing an existing destination (for example,
     * a same-filesystem hard-link publication), then leave source cleanup to
     * remove_file. */
    int (*publish_no_replace)(void* context, const char* temporary_path,
                              const char* destination_path);
    /* Must fail if destination exists. This is the no-replace primitive for
     * move/rename/trash/restore; a preflight check alone is not sufficient. */
    int (*rename_no_replace)(void* context, const char* source_path,
                             const char* destination_path);
    int (*remove_file)(void* context, const char* path);
    int (*remove_directory)(void* context, const char* path);
    int (*sync_directory)(void* context, const char* path);
    /* Optional: copy best-effort metadata. Files are passed while their copy
     * target is private, before its sync/publish; symlinks are passed after
     * no-replace creation and before parent sync. Directories are passed after
     * their descendants finish, before their final sync. A failure aborts and
     * rolls back created entries. Moving/renaming retains inode metadata and
     * does not invoke this callback. */
    int (*copy_metadata)(void* context, const char* source_path,
                         const char* destination_path,
                         uint32_t entry_kind);
    /* Reads a symlink's exact, non-NUL target into target_out and writes its
     * byte count. The target must fit within capacity - 1. */
    int (*read_symlink)(void* context, const char* source_path,
                        char* target_out, uint32_t capacity,
                        uint32_t* target_size_out);
    /* Creates the supplied symlink target without replacing destination. */
    int (*create_symlink)(void* context, const char* target,
                          const char* destination_path);
    /* Creates a hardlink without replacing destination. */
    int (*link_no_replace)(void* context, const char* source_path,
                           const char* destination_path);
    /* Optional sparse-copy support. seek returns the resulting absolute
     * offset through result_offset_out. SEEK_DATA reports NO_DATA when no
     * later data exists, or SPARSE_UNSUPPORTED to select dense copying.
     * A backend provides all three callbacks or none. */
    int (*seek)(void* context, uintptr_t handle, uint64_t offset,
                uint32_t whence, uint64_t* result_offset_out);
    int (*truncate)(void* context, uintptr_t handle, uint64_t size);
    /* Returns the source logical size used to reject mutation between plan
     * capture and sparse extent copying. */
    int (*file_size)(void* context, uintptr_t handle, uint64_t* size_out);
    /* REPLACE is explicitly destructive. The backend must remove only the
     * already-authorized existing destination, return after it is absent, and
     * preserve a separate undo record if its product contract requires one. */
    int (*replace_destination)(void* context, const char* path,
                               uint32_t entry_kind);
    /* RENAME conflict policy is supported for one file entry. The callback
     * writes an absolute canonical, currently missing path into output. */
    int (*choose_renamed_destination)(void* context, const char* source_path,
                                      const char* destination_path,
                                      char* output, uint32_t output_capacity);
    uint64_t reserved[2];
} RinRuntimeFileOperationBackendV1;

typedef struct RinRuntimeFileOperationV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    RinRuntimeFileOperationBackendV1 backend;
    RinRuntimeFileOperationEntryV1* entries;
    uint32_t entry_count;
    uint32_t entry_index;
    uint32_t conflict_policy;
    uint32_t active;
    uint32_t cancel_requested;
    uint32_t file_open;
    uint32_t temporary_created;
    uint32_t sparse_file_enabled;
    uint32_t sparse_output_sized;
    uintptr_t source_handle;
    uintptr_t temporary_handle;
    char temporary_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    uint64_t total_bytes;
    uint64_t completed_bytes;
    uint64_t completed_items;
    uint64_t temporary_sequence;
    uint64_t sparse_data_end;
    uint8_t copy_buffer[RINRUNTIME_FILE_OPERATION_COPY_CHUNK_SIZE];
} RinRuntimeFileOperationV1;

void rinruntime_file_operation_init(RinRuntimeFileOperationV1* operation);
int rinruntime_file_operation_path_valid(const char* path);
RinRuntimeFileOperationResult rinruntime_file_operation_start(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationKind kind,
    RinRuntimeFileOperationConflictPolicy conflict_policy,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count);
RinRuntimeFileOperationResult rinruntime_file_operation_pump(
    RinRuntimeFileOperationV1* operation);
RinRuntimeFileOperationResult rinruntime_file_operation_cancel(
    RinRuntimeFileOperationV1* operation);
uint32_t rinruntime_file_operation_percent(
    const RinRuntimeFileOperationV1* operation);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FILE_OPERATION_H */
