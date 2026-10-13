/* SPDX-License-Identifier: MIT */

#include <rinruntime/safe_save_posix.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define RINRUNTIME_SAFE_SAVE_WRITE_INTERRUPTION_LIMIT 32u

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

#ifndef O_BINARY
#define O_BINARY 0
#endif
#ifdef _WIN32
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif
#else
#if !defined(O_CLOEXEC) || !defined(O_NOFOLLOW) || !defined(O_DIRECTORY)
#error "POSIX safe-save requires O_CLOEXEC, O_NOFOLLOW, and O_DIRECTORY"
#endif
#endif

#define RINRUNTIME_SAFE_SAVE_POSIX_ATTEMPTS 32u

typedef struct RinRuntimeSafeSavePosixContext {
    unsigned int next_attempt;
#ifndef _WIN32
    int parent_descriptor;
#endif
    char parent_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char target_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char target_name[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char temporary_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char temporary_name[RINRUNTIME_FILE_OPERATION_PATH_MAX];
} RinRuntimeSafeSavePosixContext;

static int posix_split_target_path(const char* target_path, char* parent_path,
                                   char* target_name)
{
    size_t length;
    size_t slash;
    size_t name_length;
    if (target_path == NULL || parent_path == NULL || target_name == NULL ||
        !rinruntime_file_operation_path_valid(target_path))
        return -1;
    length = strlen(target_path);
    slash = length;
    while (slash > 0u && target_path[slash - 1u] != '/') --slash;
    if (slash == 0u || slash == length) return -1;
    name_length = length - slash;
    if (name_length == 0u ||
        name_length >= RINRUNTIME_FILE_OPERATION_PATH_MAX)
        return -1;
#ifdef _WIN32
    if (slash == 3u && target_path[1] == ':' && target_path[2] == '/') {
        parent_path[0] = target_path[0];
        parent_path[1] = ':';
        parent_path[2] = '/';
        parent_path[3] = '\0';
    } else
#endif
    if (slash == 1u) {
        parent_path[0] = '/';
        parent_path[1] = '\0';
    } else {
        if (slash >= RINRUNTIME_FILE_OPERATION_PATH_MAX) return -1;
        memcpy(parent_path, target_path, slash - 1u);
        parent_path[slash - 1u] = '\0';
    }
    memcpy(target_name, target_path + slash, name_length);
    target_name[name_length] = '\0';
    return rinruntime_file_operation_path_valid(parent_path) ? 0 : -1;
}

#ifndef _WIN32
/* Resolve every parent component from the root while rejecting symlinks.
 * Keeping the final directory descriptor pins subsequent publication to the
 * directory that was validated, even if a pathname component is replaced. */
static int posix_open_parent_directory(const char* parent_path)
{
    int current;
    const char* component;
    if (parent_path == NULL || parent_path[0] != '/' ||
        !rinruntime_file_operation_path_valid(parent_path))
        return -1;
    current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current < 0) return -1;
    component = parent_path + 1u;
    while (*component != '\0') {
        char name[RINRUNTIME_FILE_OPERATION_PATH_MAX];
        const char* end = component;
        size_t length;
        int next;
        while (*end != '\0' && *end != '/') ++end;
        length = (size_t)(end - component);
        if (length == 0u || length >= sizeof(name)) {
            (void)close(current);
            return -1;
        }
        memcpy(name, component, length);
        name[length] = '\0';
        next = openat(current, name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) {
            (void)close(current);
            return -1;
        }
        if (close(current) != 0) {
            (void)close(next);
            return -1;
        }
        current = next;
        component = (*end == '/') ? end + 1u : end;
    }
    return current;
}
#endif

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
    if (strcmp(target_path, state->target_path) != 0) return -1;
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
#ifdef _WIN32
        descriptor = open(temporary_path_out,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW |
                              O_BINARY,
                          0600);
#else
        {
            const char* slash = strrchr(temporary_path_out, '/');
            size_t temporary_name_length;
            if (slash == NULL || slash[1] == '\0') {
                temporary_path_out[0] = '\0';
                return -1;
            }
            temporary_name_length = strlen(slash + 1u);
            if (temporary_name_length >= sizeof(state->temporary_name)) {
                temporary_path_out[0] = '\0';
                return -1;
            }
            memcpy(state->temporary_name, slash + 1u,
                   temporary_name_length + 1u);
            memcpy(state->temporary_path, temporary_path_out,
                   strlen(temporary_path_out) + 1u);
            descriptor = openat(state->parent_descriptor,
                                state->temporary_name,
                                O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC |
                                    O_NOFOLLOW | O_BINARY,
                                0600);
        }
#endif
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
    uint32_t interrupted = 0u;
    (void)context;
    if (bytes_written_out == NULL || (size != 0u && bytes == NULL) ||
        posix_handle_to_fd(handle, &descriptor) != 0) {
        return -1;
    }
    *bytes_written_out = 0u;
    do {
        written = write(descriptor, bytes, size);
        if (written >= 0) break;
        if (errno != EINTR ||
            ++interrupted >= RINRUNTIME_SAFE_SAVE_WRITE_INTERRUPTION_LIMIT)
            break;
    } while (1);
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
    RinRuntimeSafeSavePosixContext* state =
        (RinRuntimeSafeSavePosixContext*)context;
    if (state == NULL || temporary_path == NULL || target_path == NULL ||
        strcmp(target_path, state->target_path) != 0)
        return -1;
#ifdef _WIN32
    return MoveFileExA(temporary_path, target_path,
                               MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
               ? 0 : -1;
#else
    if (state->temporary_name[0] == '\0' ||
        strcmp(temporary_path, state->temporary_path) != 0)
        return -1;
    return renameat(state->parent_descriptor, state->temporary_name,
                    state->parent_descriptor, state->target_name) == 0 ? 0 : -1;
#endif
}

static int posix_remove_temporary(void* context, const char* temporary_path)
{
    RinRuntimeSafeSavePosixContext* state =
        (RinRuntimeSafeSavePosixContext*)context;
    if (state == NULL || temporary_path == NULL) return -1;
#ifdef _WIN32
    return unlink(temporary_path) == 0 ? 0 : -1;
#else
    if (state->temporary_name[0] == '\0' ||
        strcmp(temporary_path, state->temporary_path) != 0)
        return -1;
    return unlinkat(state->parent_descriptor, state->temporary_name, 0) == 0
               ? 0 : -1;
#endif
}

static int posix_sync_directory(void* context, const char* directory_path)
{
#ifdef _WIN32
    (void)context;
    return directory_path != NULL ? 0 : -1;
#else
    RinRuntimeSafeSavePosixContext* state =
        (RinRuntimeSafeSavePosixContext*)context;
    if (state == NULL || directory_path == NULL ||
        state->parent_descriptor < 0 ||
        strcmp(directory_path, state->parent_path) != 0)
        return -1;
    return fsync(state->parent_descriptor) == 0 ? 0 : -1;
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
#ifndef _WIN32
    context.parent_descriptor = -1;
#endif
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
    if (size != 0u && data == NULL)
        return RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT;
    if (posix_split_target_path(target_path, context.parent_path,
                                context.target_name) != 0)
        return RINRUNTIME_SAFE_SAVE_INVALID_ARGUMENT;
    memcpy(context.target_path, target_path, strlen(target_path) + 1u);
#ifndef _WIN32
    context.parent_descriptor = posix_open_parent_directory(context.parent_path);
    if (context.parent_descriptor < 0)
        return RINRUNTIME_SAFE_SAVE_IO_FAILED;
#endif
    {
        RinRuntimeSafeSaveResult result =
            rinruntime_safe_save(&backend, target_path, data, size);
#ifndef _WIN32
        if (close(context.parent_descriptor) != 0 &&
            result == RINRUNTIME_SAFE_SAVE_COMPLETED)
            result = RINRUNTIME_SAFE_SAVE_COMMITTED_UNSYNCED;
        context.parent_descriptor = -1;
#endif
        return result;
    }
}
