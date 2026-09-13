/* SPDX-License-Identifier: MIT */

#include <rinruntime/safe_save.h>

#include <stddef.h>
#include <string.h>

static int safe_save_backend_valid(const RinRuntimeSafeSaveBackendV1* backend)
{
    return backend != NULL &&
           backend->struct_size == sizeof(*backend) &&
           backend->version == RINRUNTIME_SAFE_SAVE_VERSION &&
           backend->reserved0 == 0u && backend->open_temporary != NULL &&
           backend->write != NULL && backend->sync_file != NULL &&
           backend->close != NULL && backend->publish_replace != NULL &&
           backend->remove_temporary != NULL && backend->sync_directory != NULL &&
           backend->reserved[0] == 0u && backend->reserved[1] == 0u &&
           backend->reserved[2] == 0u;
}

static int safe_save_parent(const char* path, char* parent)
{
    size_t length;
    size_t slash;
    if (!rinruntime_file_operation_path_valid(path)) return 0;
    length = strlen(path);
    if (length < 2u) return 0;
    slash = length;
    while (slash > 0u && path[slash - 1u] != '/') --slash;
    if (slash == 0u || slash == length) return 0;
#ifdef _WIN32
    if (slash == 3u && path[1] == ':' && path[2] == '/') {
        parent[0] = path[0];
        parent[1] = ':';
        parent[2] = '/';
        parent[3] = '\0';
        return rinruntime_file_operation_path_valid(parent);
    }
#endif
    if (slash == 1u) {
        parent[0] = '/';
        parent[1] = '\0';
        return 1;
    }
    if (slash >= RINRUNTIME_FILE_OPERATION_PATH_MAX) return 0;
    memcpy(parent, path, slash - 1u);
    parent[slash - 1u] = '\0';
    return rinruntime_file_operation_path_valid(parent);
}

static int safe_save_same_parent(const char* first, const char* second)
{
    char first_parent[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char second_parent[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    return safe_save_parent(first, first_parent) &&
           safe_save_parent(second, second_parent) &&
           strcmp(first_parent, second_parent) == 0;
}

static RinRuntimeSafeSaveResult safe_save_cleanup(
    const RinRuntimeSafeSaveBackendV1* backend, const char* temporary_path,
    const char* parent)
{
    int removed = backend->remove_temporary(backend->context, temporary_path);
    int synchronized = backend->sync_directory(backend->context, parent);
    return removed == 0 && synchronized == 0
               ? RINRUNTIME_SAFE_SAVE_IO_FAILED
               : RINRUNTIME_SAFE_SAVE_CLEANUP_FAILED;
}

RinRuntimeSafeSaveResult rinruntime_safe_save(
    const RinRuntimeSafeSaveBackendV1* backend, const char* target_path,
    const uint8_t* data, uint32_t size)
{
    char temporary_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char parent[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    uintptr_t handle = 0u;
    uint32_t written = 0u;
    uint32_t offset = 0u;
    int close_result;

    if (!safe_save_backend_valid(backend) || !safe_save_parent(target_path, parent) ||
        (size != 0u && data == NULL))
        return RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT;

    memset(temporary_path, 0, sizeof(temporary_path));
    if (backend->open_temporary(backend->context, target_path, temporary_path,
                                sizeof(temporary_path), &handle) != 0)
        return RINRUNTIME_SAFE_SAVE_IO_FAILED;
    if (handle == 0u || !rinruntime_file_operation_path_valid(temporary_path) ||
        strcmp(temporary_path, target_path) == 0 ||
        !safe_save_same_parent(temporary_path, target_path)) {
        (void)backend->close(backend->context, handle);
        return RINRUNTIME_SAFE_SAVE_IO_FAILED;
    }

    while (offset < size) {
        uint32_t remaining = size - offset;
        written = 0u;
        if (backend->write(backend->context, handle, data + offset, remaining,
                           &written) != 0 ||
            written == 0u || written > remaining) {
            (void)backend->close(backend->context, handle);
            return safe_save_cleanup(backend, temporary_path, parent);
        }
        offset += written;
    }

    if (backend->sync_file(backend->context, handle) != 0) {
        (void)backend->close(backend->context, handle);
        return safe_save_cleanup(backend, temporary_path, parent);
    }
    close_result = backend->close(backend->context, handle);
    if (close_result != 0)
        return safe_save_cleanup(backend, temporary_path, parent);

    if (backend->publish_replace(backend->context, temporary_path, target_path) != 0)
        return safe_save_cleanup(backend, temporary_path, parent);
    if (backend->sync_directory(backend->context, parent) != 0)
        return RINRUNTIME_SAFE_SAVE_COMMITTED_UNSYNCED;
    return RINRUNTIME_SAFE_SAVE_COMPLETED;
}


