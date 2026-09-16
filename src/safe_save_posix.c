/* SPDX-License-Identifier: MIT */

#include <rinruntime/safe_save_posix.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <windows.h>
#define fsync _commit
#define getpid _getpid
#ifndef O_BINARY
#define O_BINARY 0x8000
#endif
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define RINRUNTIME_SAFE_SAVE_POSIX_ATTEMPTS 32u

typedef struct RinRuntimeSafeSavePosixContext {
    unsigned int next_attempt;
} RinRuntimeSafeSavePosixContext;

static int posix_handle_to_fd(uintptr_t handle, int* descriptor_out)
{
    if (descriptor_out == NULL || handle == 0u || handle - 1u > (uintptr_t)INT_MAX)
        return -1;
    *descriptor_out = (int)(handle - 1u);
    return 0;
}

static int posix_open_temporary(void* context, const char* target_path,
                                char* temporary_path_out,
                                uint32_t temporary_path_capacity,
                                uintptr_t* handle_out)
{
    RinRuntimeSafeSavePosixContext* state =
        (RinRuntimeSafeSavePosixContext*)context;
    if (state == NULL || target_path == NULL || temporary_path_out == NULL ||
        temporary_path_capacity == 0u || handle_out == NULL) {
        return -1;
    }
    *handle_out = 0u;
    temporary_path_out[0] = '\0';
    for (; state->next_attempt < RINRUNTIME_SAFE_SAVE_POSIX_ATTEMPTS;
         ++state->next_attempt) {
        int descriptor;
        int count = snprintf(temporary_path_out, temporary_path_capacity,
                             "%s.rinos-save-%ld-%u.tmp", target_path,
                             (long)getpid(), state->next_attempt);
        if (count < 0 || (uint32_t)count >= temporary_path_capacity) {
            temporary_path_out[0] = '\0';
            return -1;
        }
        descriptor = open(temporary_path_out,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW |
                              O_BINARY,
                          0600);
        if (descriptor >= 0) {
            *handle_out = (uintptr_t)descriptor + 1u;
            ++state->next_attempt;
            return 0;
        }
        if (errno != EEXIST) {
            temporary_path_out[0] = '\0';
            return -1;
        }
    }
    temporary_path_out[0] = '\0';
    return -1;
}

static int posix_write(void* context, uintptr_t handle, const uint8_t* bytes,
                       uint32_t size, uint32_t* bytes_written_out)
{
    int descriptor;
    ssize_t written;
    (void)context;
    if (bytes_written_out == NULL || (size != 0u && bytes == NULL) ||
        posix_handle_to_fd(handle, &descriptor) != 0) {
        return -1;
    }
    *bytes_written_out = 0u;
    do {
        written = write(descriptor, bytes, size);
    } while (written < 0 && errno == EINTR);
    if (written <= 0 || (uintmax_t)written > size) return -1;
    *bytes_written_out = (uint32_t)written;
    return 0;
}

static int posix_sync_file(void* context, uintptr_t handle)
{
    int descriptor;
    (void)context;
    return posix_handle_to_fd(handle, &descriptor) == 0 && fsync(descriptor) == 0
               ? 0 : -1;
}

static int posix_close(void* context, uintptr_t handle)
{
    int descriptor;
    (void)context;
    return posix_handle_to_fd(handle, &descriptor) == 0 && close(descriptor) == 0
               ? 0 : -1;
}

static int posix_publish_replace(void* context, const char* temporary_path,
                                 const char* target_path)
{
    (void)context;
#ifdef _WIN32
    return temporary_path != NULL && target_path != NULL &&
                   MoveFileExA(temporary_path, target_path,
                               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
               ? 0 : -1;
#else
    return temporary_path != NULL && target_path != NULL &&
                   rename(temporary_path, target_path) == 0 ? 0 : -1;
#endif
}

static int posix_remove_temporary(void* context, const char* temporary_path)
{
    (void)context;
    return temporary_path != NULL && unlink(temporary_path) == 0 ? 0 : -1;
}

static int posix_sync_directory(void* context, const char* directory_path)
{
#ifdef _WIN32
    (void)context;
    return directory_path != NULL ? 0 : -1;
#else
    int descriptor;
    int sync_result;
    int close_result;
    (void)context;
    if (directory_path == NULL) return -1;
    descriptor = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                                        O_NOFOLLOW);
    if (descriptor < 0) return -1;
    sync_result = fsync(descriptor);
    close_result = close(descriptor);
    return sync_result == 0 && close_result == 0 ? 0 : -1;
#endif
}

RinRuntimeSafeSaveResult rinruntime_safe_save_posix(
    const char* target_path, const uint8_t* data, uint32_t size)
{
    RinRuntimeSafeSavePosixContext context;
    RinRuntimeSafeSaveBackendV1 backend;
#ifdef _WIN32
    char normalized_target[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    size_t target_size;
#endif

    memset(&context, 0, sizeof(context));
    memset(&backend, 0, sizeof(backend));
    backend.struct_size = sizeof(backend);
    backend.version = RINRUNTIME_SAFE_SAVE_VERSION;
    backend.context = &context;
    backend.open_temporary = posix_open_temporary;
    backend.write = posix_write;
    backend.sync_file = posix_sync_file;
    backend.close = posix_close;
    backend.publish_replace = posix_publish_replace;
    backend.remove_temporary = posix_remove_temporary;
    backend.sync_directory = posix_sync_directory;
#ifdef _WIN32
    if (target_path == NULL) return RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT;
    target_size = 0u;
    while (target_size < sizeof(normalized_target) &&
           target_path[target_size] != '\0')
        ++target_size;
    if (target_size >= sizeof(normalized_target))
        return RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT;
    for (size_t index = 0u; index <= target_size; ++index) {
        normalized_target[index] = target_path[index] == '\\' ? '/'
                                                                 : target_path[index];
    }
    target_path = normalized_target;
#endif
    return rinruntime_safe_save(&backend, target_path, data, size);
}

