/* SPDX-License-Identifier: MIT */

#include <rinruntime/file_operation.h>
#include <rinruntime/cancellation.h>

#include <string.h>

static void file_operation_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    if (bytes == 0) return;
    while (size-- != 0u) *bytes++ = 0u;
}

static int file_operation_bytes_zero(const void* input, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)input;
    uint8_t value = 0u;
    if (input == 0) return 0;
    while (size-- != 0u) value |= *bytes++;
    return value == 0u;
}

static int file_operation_kind_valid(uint32_t kind)
{
    return kind == RINRUNTIME_FILE_OPERATION_ENTRY_FILE ||
           kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY ||
           kind == RINRUNTIME_FILE_OPERATION_ENTRY_SYMLINK ||
           kind == RINRUNTIME_FILE_OPERATION_ENTRY_HARDLINK;
}

static int file_operation_operation_valid(uint16_t operation)
{
    return operation >= RINRUNTIME_FILE_OPERATION_COPY &&
           operation <= RINRUNTIME_FILE_OPERATION_RESTORE;
}

static int file_operation_conflict_valid(uint32_t policy)
{
    return policy >= RINRUNTIME_FILE_OPERATION_CONFLICT_FAIL &&
           policy <= RINRUNTIME_FILE_OPERATION_CONFLICT_RENAME;
}

static RinRuntimeFileOperationResult file_operation_result(int result)
{
    if (result == RINRUNTIME_FILE_OPERATION_BACKEND_NO_SPACE)
        return RINRUNTIME_FILE_OPERATION_NO_SPACE;
    if (result == RINRUNTIME_FILE_OPERATION_BACKEND_DEVICE_REMOVED)
        return RINRUNTIME_FILE_OPERATION_DEVICE_REMOVED;
    if (result == RINRUNTIME_FILE_OPERATION_BACKEND_IDENTITY_MISMATCH)
        return RINRUNTIME_FILE_OPERATION_CONFLICT;
    return RINRUNTIME_FILE_OPERATION_IO_FAILED;
}

static int file_operation_identity_valid(
    const RinRuntimeFileOperationObjectIdentityV1* identity)
{
    return identity != 0 && identity->inode != 0u &&
           identity->generation != 0u;
}

static int file_operation_identity_equal(
    const RinRuntimeFileOperationObjectIdentityV1* left,
    const RinRuntimeFileOperationObjectIdentityV1* right)
{
    return file_operation_identity_valid(left) &&
           file_operation_identity_valid(right) &&
           left->device == right->device && left->inode == right->inode &&
           left->generation == right->generation;
}

static int file_operation_identity_empty(
    const RinRuntimeFileOperationObjectIdentityV1* identity)
{
    return identity != 0 && identity->device == 0u && identity->inode == 0u &&
           identity->generation == 0u;
}

static int file_operation_copy(char* output, uint32_t capacity, const char* input)
{
    uint32_t index = 0u;
    if (output == 0 || input == 0 || capacity == 0u) return 0;
    while (index + 1u < capacity && input[index] != '\0') {
        output[index] = input[index];
        ++index;
    }
    if (input[index] != '\0') return 0;
    output[index] = '\0';
    return 1;
}

static int file_operation_parent(const char* path,
                                 char output[RINRUNTIME_FILE_OPERATION_PATH_MAX])
{
    uint32_t length = 0u;
    uint32_t slash = 0u;
    if (!rinruntime_file_operation_path_valid(path)) return 0;
    while (path[length] != '\0') {
        if (path[length] == '/') slash = length;
        ++length;
    }
    if (slash == 0u) return file_operation_copy(output, RINRUNTIME_FILE_OPERATION_PATH_MAX, "/");
    if (slash >= RINRUNTIME_FILE_OPERATION_PATH_MAX) return 0;
    memcpy(output, path, slash);
    output[slash] = '\0';
    return 1;
}

static int file_operation_descendant(const char* root, const char* path)
{
    uint32_t index = 0u;
    if (root == 0 || path == 0) return 0;
    if (root[0] == '/' && root[1] == '\0') return 1;
    while (root[index] != '\0' && root[index] == path[index]) ++index;
    return root[index] == '\0' && (path[index] == '\0' || path[index] == '/');
}

int rinruntime_file_operation_path_valid(const char* path)
{
    uint32_t index = 0u;
    uint32_t component_start = 1u;
#ifdef _WIN32
    const int drive_absolute = path != 0 &&
        ((path[0] >= 'A' && path[0] <= 'Z') ||
         (path[0] >= 'a' && path[0] <= 'z')) &&
        path[1] == ':' && path[2] == '/';
#endif
    if (path == 0) return 0;
#ifdef _WIN32
    if (path[0] != '/' && !drive_absolute) return 0;
    if (drive_absolute) {
        if (path[3] == '\0') return 1;
        index = 3u;
        component_start = 3u;
    }
#else
    if (path[0] != '/') return 0;
#endif
    if (path[1] == '\0') return 1;
    while (index < RINRUNTIME_FILE_OPERATION_PATH_MAX &&
           path[index] != '\0') {
        char value = path[index];
        if (value == '\\' || (unsigned char)value < 0x20u ||
            (unsigned char)value == 0x7fu ||
            index + 1u >= RINRUNTIME_FILE_OPERATION_PATH_MAX)
            return 0;
#ifdef _WIN32
        /* A colon inside a Win32 component selects an alternate data stream;
         * the only colon allowed is the drive separator in C:/... paths. */
        if ((value == ':' && !(drive_absolute && index == 1u)) ||
            value == '"' || value == '<' || value == '>' || value == '|' ||
            value == '?' || value == '*')
            return 0;
#endif
        if (value == '/') {
            uint32_t component_size = index - component_start;
            if (index != 0u && (component_size == 0u ||
                (component_size == 1u && path[component_start] == '.') ||
                (component_size == 2u && path[component_start] == '.' &&
                 path[component_start + 1u] == '.')))
                return 0;
#ifdef _WIN32
            if (component_size != 0u &&
                (path[index - 1u] == '.' || path[index - 1u] == ' '))
                return 0;
#endif
            component_start = index + 1u;
        }
        ++index;
    }
    if (index >= RINRUNTIME_FILE_OPERATION_PATH_MAX) return 0;
    {
        uint32_t component_size = index - component_start;
        if (component_size == 0u ||
            (component_size == 1u && path[component_start] == '.') ||
            (component_size == 2u && path[component_start] == '.' &&
             path[component_start + 1u] == '.'))
            return 0;
#ifdef _WIN32
        if (path[index - 1u] == '.' || path[index - 1u] == ' ') return 0;
#endif
    }
    return index > 1u && path[index - 1u] != '/';
}

void rinruntime_file_operation_init(RinRuntimeFileOperationV1* operation)
{
    if (operation == 0) return;
    file_operation_zero(operation, sizeof(*operation));
    operation->struct_size = sizeof(*operation);
    operation->version = RINRUNTIME_FILE_OPERATION_VERSION;
}

static int file_operation_backend_valid(const RinRuntimeFileOperationBackendV1* backend,
                                        RinRuntimeFileOperationKind kind)
{
    if (backend == 0 || backend->struct_size != sizeof(*backend) ||
        backend->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        backend->reserved0 != 0u || backend->reserved[0] != 0u ||
        backend->reserved[1] != 0u || backend->path_state == 0 ||
        backend->remove_file == 0 || backend->remove_directory == 0 ||
        backend->sync_directory == 0)
        return 0;
    if ((backend->seek == 0) != (backend->truncate == 0) ||
        (backend->seek == 0) != (backend->file_size == 0)) return 0;
    if (kind == RINRUNTIME_FILE_OPERATION_COPY)
        return backend->open_read != 0 && backend->open_create_exclusive != 0 &&
               backend->read != 0 && backend->write != 0 &&
               backend->sync_file != 0 && backend->close != 0 &&
               backend->mkdir != 0 && backend->publish_no_replace != 0 &&
               backend->path_identity != 0 && backend->handle_identity != 0 &&
               backend->remove_file_expected != 0 &&
               backend->remove_directory_expected != 0;
    return kind == RINRUNTIME_FILE_OPERATION_DELETE ||
           (backend->rename_no_replace != 0 && backend->path_identity != 0 &&
            backend->rename_no_replace_expected != 0);
}

static int file_operation_entry_valid(const RinRuntimeFileOperationEntryV1* entry,
                                      RinRuntimeFileOperationKind kind)
{
    if (entry == 0 || !file_operation_kind_valid(entry->kind) ||
        (entry->flags & ~(RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP |
                          RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED |
                          RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED)) != 0u ||
        entry->cleanup_state >
            RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_SYNC_PENDING ||
        entry->replacement_state >
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_RESTORE_IN_PROGRESS ||
        entry->reserved0 != 0u ||
        !rinruntime_file_operation_path_valid(entry->source_path))
        return 0;
    if (kind != RINRUNTIME_FILE_OPERATION_DELETE &&
        !rinruntime_file_operation_path_valid(entry->destination_path))
        return 0;
    if (entry->replacement_state == RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE) {
        if (!file_operation_bytes_zero(entry->backup_path,
                                       sizeof(entry->backup_path)) ||
            !file_operation_identity_empty(&entry->backup_identity))
            return 0;
    } else if (!rinruntime_file_operation_path_valid(entry->backup_path) ||
               entry->backup_path[0] == '\0' ||
               !file_operation_identity_valid(&entry->backup_identity)) {
        return 0;
    }
    return 1;
}

static RinRuntimeFileOperationResult file_operation_checkpoint(
    RinRuntimeFileOperationV1* operation)
{
    if (operation == 0 || operation->backend.checkpoint == 0)
        return RINRUNTIME_FILE_OPERATION_OK;
    return operation->backend.checkpoint(operation->backend.context,
                                          operation) == 0
        ? RINRUNTIME_FILE_OPERATION_OK : RINRUNTIME_FILE_OPERATION_IO_FAILED;
}

static int file_operation_skipped(const RinRuntimeFileOperationV1* operation,
                                  uint32_t index)
{
    uint32_t previous;
    const RinRuntimeFileOperationEntryV1* entry = &operation->entries[index];
    if ((entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP) != 0u)
        return 1;
    for (previous = 0u; previous < index; ++previous) {
        const RinRuntimeFileOperationEntryV1* root = &operation->entries[previous];
        if ((root->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP) != 0u &&
            root->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY &&
            file_operation_descendant(root->source_path, entry->source_path))
            return 1;
    }
    return 0;
}

static RinRuntimeFileOperationResult file_operation_sync_parent_once(
    RinRuntimeFileOperationV1* operation, const char* path)
{
    char parent[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    int result;
    if (!file_operation_parent(path, parent)) return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    result = operation->backend.sync_directory(operation->backend.context, parent);
    return result == 0 ? RINRUNTIME_FILE_OPERATION_OK : file_operation_result(result);
}

static RinRuntimeFileOperationResult file_operation_copy_metadata(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationEntryV1* entry, const char* destination)
{
    int result;
    if (operation->backend.copy_metadata == 0)
        return RINRUNTIME_FILE_OPERATION_OK;
    result = operation->backend.copy_metadata(operation->backend.context,
                                              entry->source_path, destination,
                                              entry->kind);
    return result == 0 ? RINRUNTIME_FILE_OPERATION_OK
                       : file_operation_result(result);
}

static int file_operation_temporary_path(RinRuntimeFileOperationV1* operation,
                                         const char* destination)
{
    static const char suffix[] = ".rinop-";
    uint32_t length = 0u;
    uint64_t sequence;
    char digits[21];
    uint32_t digit_count = 0u;
    if (!file_operation_copy(operation->temporary_path,
                             sizeof(operation->temporary_path), destination))
        return 0;
    while (operation->temporary_path[length] != '\0') ++length;
    sequence = ++operation->temporary_sequence;
    do {
        digits[digit_count++] = (char)('0' + (sequence % 10u));
        sequence /= 10u;
    } while (sequence != 0u && digit_count < sizeof(digits));
    if (sequence != 0u || length + sizeof(suffix) - 1u + digit_count + 4u >=
                        sizeof(operation->temporary_path))
        return 0;
    memcpy(operation->temporary_path + length, suffix, sizeof(suffix) - 1u);
    length += sizeof(suffix) - 1u;
    while (digit_count != 0u) operation->temporary_path[length++] = digits[--digit_count];
    memcpy(operation->temporary_path + length, ".tmp", 5u);
    return rinruntime_file_operation_path_valid(operation->temporary_path);
}

static int file_operation_close_files(RinRuntimeFileOperationV1* operation)
{
    int success = 1;
    if (operation->source_handle != 0u) {
        if (operation->backend.close(operation->backend.context,
                                     operation->source_handle) != 0) success = 0;
        operation->source_handle = 0u;
    }
    if (operation->temporary_handle != 0u) {
        if (operation->backend.close(operation->backend.context,
                                     operation->temporary_handle) != 0) success = 0;
        operation->temporary_handle = 0u;
    }
    operation->file_open = 0u;
    return success;
}

static int file_operation_cleanup_created_path(
    RinRuntimeFileOperationV1* operation, const char* path, int directory,
    const RinRuntimeFileOperationObjectIdentityV1* identity,
    uint32_t* cleanup_state)
{
    int state;
    int result;
    if (!operation || !path || !identity || !cleanup_state ||
        !file_operation_identity_valid(identity))
        return 0;
    if (*cleanup_state == RINRUNTIME_FILE_OPERATION_CLEANUP_NONE)
        *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_REMOVE_PENDING;
    if (*cleanup_state == RINRUNTIME_FILE_OPERATION_CLEANUP_REMOVE_PENDING ||
        *cleanup_state == RINRUNTIME_FILE_OPERATION_CLEANUP_REMOVE_IN_PROGRESS) {
        state = operation->backend.path_state(operation->backend.context, path);
        if (state == 0) {
            *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return 0;
        } else if (state == 1) {
            *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_REMOVE_IN_PROGRESS;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return 0;
            result = directory
                ? operation->backend.remove_directory_expected(
                      operation->backend.context, path, identity)
                : operation->backend.remove_file_expected(
                      operation->backend.context, path, identity);
            if (result == 0) {
                *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING;
            } else {
                /* Some backends can report an I/O error after the namespace
                 * change. Missing means removal happened; an identity mismatch
                 * means a replacement is present and must remain untouched. */
                state = operation->backend.path_state(operation->backend.context,
                                                      path);
                if (state != 0) return 0;
                *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING;
            }
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return 0;
        } else {
            return 0;
        }
    }
    if (*cleanup_state != RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING)
        return 0;
    if (file_operation_sync_parent_once(operation, path) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return 0;
    *cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
    if (file_operation_checkpoint(operation) != RINRUNTIME_FILE_OPERATION_OK)
        return 0;
    return 1;
}

static int file_operation_restore_replacement(
    RinRuntimeFileOperationV1* operation,
    RinRuntimeFileOperationEntryV1* entry)
{
    int destination_state;
    int backup_state;
    int result;
    RinRuntimeFileOperationObjectIdentityV1 current;
    if (!operation || !entry || entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE ||
        !file_operation_identity_valid(&entry->backup_identity))
        return 0;
    destination_state = operation->backend.path_state(
        operation->backend.context, entry->destination_path);
    backup_state = operation->backend.path_state(
        operation->backend.context, entry->backup_path);
    if (destination_state < 0 || backup_state < 0) return 0;

    /* Reconcile a crash after the backup rename but before its checkpoint. */
    if (entry->replacement_state ==
        RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_IN_PROGRESS) {
        if (backup_state == 0 && destination_state == 1) {
            memset(&current, 0, sizeof(current));
            result = operation->backend.path_identity(
                operation->backend.context, entry->destination_path, &current);
            if (result != 0 || !file_operation_identity_equal(
                    &current, &entry->backup_identity))
                return 0;
            entry->replacement_state = RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE;
            file_operation_zero(entry->backup_path, sizeof(entry->backup_path));
            memset(&entry->backup_identity, 0, sizeof(entry->backup_identity));
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK ||
                file_operation_sync_parent_once(operation,
                                                entry->destination_path) !=
                    RINRUNTIME_FILE_OPERATION_OK)
                return 0;
            return 1;
        }
        if (backup_state != 1 || destination_state != 0) return 0;
        memset(&current, 0, sizeof(current));
        result = operation->backend.path_identity(
            operation->backend.context, entry->backup_path, &current);
        if (result != 0 || !file_operation_identity_equal(
                &current, &entry->backup_identity))
            return 0;
        entry->replacement_state =
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD;
    }

    if (entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_PUBLISH_IN_PROGRESS ||
        entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD)
        entry->replacement_state =
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_RESTORE_IN_PROGRESS;

    if (entry->replacement_state !=
        RINRUNTIME_FILE_OPERATION_REPLACEMENT_RESTORE_IN_PROGRESS)
        return 0;
    if (backup_state == 0 && destination_state == 1) {
        memset(&current, 0, sizeof(current));
        result = operation->backend.path_identity(
            operation->backend.context, entry->destination_path, &current);
        if (result != 0 || !file_operation_identity_equal(
                &current, &entry->backup_identity))
            return 0;
    } else if (backup_state == 1 && destination_state == 0) {
        memset(&current, 0, sizeof(current));
        result = operation->backend.path_identity(
            operation->backend.context, entry->backup_path, &current);
        if (result != 0 || !file_operation_identity_equal(
                &current, &entry->backup_identity))
            return 0;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return 0;
        result = operation->backend.rename_no_replace_expected(
            operation->backend.context, entry->backup_path,
            entry->destination_path, &entry->backup_identity);
        if (result != 0) return 0;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return 0;
    } else {
        return 0;
    }
    if (file_operation_sync_parent_once(operation, entry->destination_path) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return 0;
    entry->replacement_state = RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE;
    file_operation_zero(entry->backup_path, sizeof(entry->backup_path));
    memset(&entry->backup_identity, 0, sizeof(entry->backup_identity));
    if (file_operation_checkpoint(operation) != RINRUNTIME_FILE_OPERATION_OK)
        return 0;
    return 1;
}

/* Performs no more than one namespace recovery action. The service persists
 * the operation checkpoint between calls, so restart recovery cannot lose a
 * successful remove merely because the following directory sync failed. */
static int file_operation_rollback_step(RinRuntimeFileOperationV1* operation)
{
    if (!file_operation_close_files(operation)) return -1;
    if (operation->operation == RINRUNTIME_FILE_OPERATION_COPY &&
        operation->temporary_created != 0u) {
        if (!file_operation_cleanup_created_path(
                operation, operation->temporary_path, 0,
                &operation->temporary_identity,
                &operation->temporary_cleanup_state))
            return -1;
        operation->temporary_created = 0u;
        operation->temporary_path[0] = '\0';
        operation->temporary_cleanup_state =
            RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
        memset(&operation->temporary_identity, 0,
               sizeof(operation->temporary_identity));
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return -1;
        return 1;
    }
    while (operation->rollback_index != 0u) {
        RinRuntimeFileOperationEntryV1* entry =
            &operation->entries[operation->rollback_index - 1u];
        int source_state;
        int destination_state;
        RinRuntimeFileOperationObjectIdentityV1 current_identity;
        int result;
        if ((entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED) != 0u) {
            if (!file_operation_cleanup_created_path(
                    operation, entry->destination_path,
                    entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY,
                    &entry->object_identity, &entry->cleanup_state))
                return -1;
            entry->flags &= ~RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
            entry->cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
            memset(&entry->object_identity, 0, sizeof(entry->object_identity));
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return -1;
            if (entry->replacement_state ==
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE)
                --operation->rollback_index;
            return 1;
        }
        if ((entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED) != 0u) {
            if (!file_operation_identity_valid(&entry->object_identity)) return -1;
            if (entry->cleanup_state == RINRUNTIME_FILE_OPERATION_CLEANUP_NONE)
                entry->cleanup_state =
                    RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_IN_PROGRESS;
            if (entry->cleanup_state ==
                RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_IN_PROGRESS) {
                if (file_operation_checkpoint(operation) !=
                    RINRUNTIME_FILE_OPERATION_OK)
                    return -1;
                source_state = operation->backend.path_state(
                    operation->backend.context, entry->source_path);
                destination_state = operation->backend.path_state(
                    operation->backend.context, entry->destination_path);
                if (source_state < 0 || destination_state < 0) return -1;
                if (source_state == 0 && destination_state == 1) {
                    memset(&current_identity, 0, sizeof(current_identity));
                    result = operation->backend.path_identity(
                        operation->backend.context, entry->destination_path,
                        &current_identity);
                    if (result != 0 || !file_operation_identity_equal(
                            &current_identity, &entry->object_identity))
                        return -1;
                    result = operation->backend.rename_no_replace_expected(
                        operation->backend.context, entry->destination_path,
                        entry->source_path, &entry->object_identity);
                    if (result != 0) return -1;
                } else if (source_state == 1 && destination_state == 0) {
                    memset(&current_identity, 0, sizeof(current_identity));
                    result = operation->backend.path_identity(
                        operation->backend.context, entry->source_path,
                        &current_identity);
                    if (result != 0 || !file_operation_identity_equal(
                            &current_identity, &entry->object_identity))
                        return -1;
                } else {
                    return -1;
                }
                entry->cleanup_state =
                    RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_SYNC_PENDING;
                if (file_operation_checkpoint(operation) !=
                    RINRUNTIME_FILE_OPERATION_OK)
                    return -1;
            }
            if (entry->cleanup_state !=
                RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_SYNC_PENDING ||
                file_operation_sync_parent_once(operation, entry->source_path) !=
                    RINRUNTIME_FILE_OPERATION_OK ||
                file_operation_sync_parent_once(operation,
                                                entry->destination_path) !=
                    RINRUNTIME_FILE_OPERATION_OK)
                return -1;
            entry->flags &= ~RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED;
            entry->cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
            memset(&entry->object_identity, 0, sizeof(entry->object_identity));
            --operation->rollback_index;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return -1;
            return 1;
        }
        if (entry->replacement_state !=
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE) {
            if (!file_operation_restore_replacement(operation, entry)) return -1;
            return 1;
        }
        --operation->rollback_index;
    }
    return 0;
}

static RinRuntimeFileOperationResult file_operation_finish_failure(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationResult result,
    int rollback)
{
    int rollback_step;
    operation->pending_result = result;
    if (rollback && operation->operation != RINRUNTIME_FILE_OPERATION_DELETE) {
        operation->rollback_active = 1u;
        operation->rollback_index = operation->entry_count;
        operation->active = 1u;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK) {
            operation->active = 0u;
            operation->recovery_required = 1u;
            return RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED;
        }
        rollback_step = file_operation_rollback_step(operation);
        if (rollback_step < 0) {
            operation->active = 0u;
            operation->recovery_required = 1u;
            return RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED;
        }
        if (rollback_step > 0) return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        operation->rollback_active = 0u;
    }
    operation->active = 0u;
    operation->recovery_required = 0u;
    return result;
}

static RinRuntimeFileOperationResult file_operation_conflict(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationEntryV1* entry)
{
    char renamed_destination[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    int state = operation->backend.path_state(operation->backend.context,
                                              entry->destination_path);
    if (state == 0) return RINRUNTIME_FILE_OPERATION_OK;
    if (state != 1) return file_operation_result(state);
    if (operation->conflict_policy == RINRUNTIME_FILE_OPERATION_CONFLICT_FAIL)
        return RINRUNTIME_FILE_OPERATION_CONFLICT;
    if (operation->conflict_policy == RINRUNTIME_FILE_OPERATION_CONFLICT_SKIP) {
        entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP;
        return RINRUNTIME_FILE_OPERATION_OK;
    }
    if (operation->conflict_policy == RINRUNTIME_FILE_OPERATION_CONFLICT_REPLACE) {
        char backup_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
        RinRuntimeFileOperationObjectIdentityV1 identity;
        int result;
        if (operation->operation != RINRUNTIME_FILE_OPERATION_COPY ||
            operation->backend.replacement_backup_path == 0 ||
            operation->backend.rename_no_replace_expected == 0 ||
            operation->backend.checkpoint == 0)
            return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
        if (entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE) {
            memset(&identity, 0, sizeof(identity));
            result = operation->backend.path_identity(
                operation->backend.context, entry->destination_path, &identity);
            if (result != 0 || !file_operation_identity_valid(&identity))
                return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                                   : file_operation_result(result);
            file_operation_zero(backup_path, sizeof(backup_path));
            if (operation->backend.replacement_backup_path(
                    operation->backend.context, entry->destination_path,
                    &identity, backup_path, sizeof(backup_path)) != 0 ||
                !rinruntime_file_operation_path_valid(backup_path) ||
                backup_path[0] == '\0' ||
                strcmp(backup_path, entry->destination_path) == 0 ||
                strcmp(backup_path, entry->source_path) == 0 ||
                operation->backend.path_state(operation->backend.context,
                                               backup_path) != 0)
                return RINRUNTIME_FILE_OPERATION_CONFLICT;
            if (!file_operation_copy(entry->backup_path,
                                     sizeof(entry->backup_path), backup_path))
                return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
            entry->backup_identity = identity;
            entry->replacement_state =
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_IN_PROGRESS;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
            result = operation->backend.rename_no_replace_expected(
                operation->backend.context, entry->destination_path,
                entry->backup_path, &entry->backup_identity);
            if (result != 0) return file_operation_result(result);
            result = file_operation_sync_parent_once(
                operation, entry->destination_path);
            if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
            entry->replacement_state =
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        }
        if (entry->replacement_state !=
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD)
            return RINRUNTIME_FILE_OPERATION_CONFLICT;
        state = operation->backend.path_state(operation->backend.context,
                                              entry->destination_path);
        return state == 0 ? RINRUNTIME_FILE_OPERATION_OK
                          : state == 1 ? RINRUNTIME_FILE_OPERATION_CONFLICT
                                       : file_operation_result(state);
    }
    if (entry->kind != RINRUNTIME_FILE_OPERATION_ENTRY_FILE ||
        operation->entry_count != 1u ||
        operation->backend.choose_renamed_destination == 0)
        return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
    if (!file_operation_copy(renamed_destination,
                             sizeof(renamed_destination),
                             entry->destination_path))
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    if (operation->backend.choose_renamed_destination(
            operation->backend.context, entry->source_path, entry->destination_path,
            renamed_destination, sizeof(renamed_destination)) != 0 ||
        !rinruntime_file_operation_path_valid(renamed_destination))
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    state = operation->backend.path_state(operation->backend.context,
                                          renamed_destination);
    if (state == 0) {
        if (!file_operation_copy(entry->destination_path,
                                 sizeof(entry->destination_path),
                                 renamed_destination))
            return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
        return RINRUNTIME_FILE_OPERATION_OK;
    }
    return state == 1 ? RINRUNTIME_FILE_OPERATION_CONFLICT
                      : file_operation_result(state);
}

RinRuntimeFileOperationResult rinruntime_file_operation_start(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationKind kind,
    RinRuntimeFileOperationConflictPolicy conflict_policy,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count)
{
    uint32_t index;
    uint32_t has_symlink = 0u;
    uint32_t has_hardlink = 0u;
    uint64_t total = 0u;
    if (operation == 0 || operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        operation->active != 0u || operation->recovery_required != 0u ||
        entries == 0 || entry_count == 0u ||
        entry_count > RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT ||
        !file_operation_operation_valid((uint16_t)kind) ||
        !file_operation_conflict_valid((uint32_t)conflict_policy) ||
        !file_operation_backend_valid(backend, kind))
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    if (conflict_policy == RINRUNTIME_FILE_OPERATION_CONFLICT_REPLACE &&
        (kind != RINRUNTIME_FILE_OPERATION_COPY ||
         backend->replacement_backup_path == 0 ||
         backend->rename_no_replace_expected == 0 ||
         backend->checkpoint == 0))
        return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
    for (index = 0u; index < entry_count; ++index) {
        RinRuntimeFileOperationEntryV1* entry = &entries[index];
        if (!file_operation_entry_valid(entry, kind))
            return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
        if ((entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED) != 0u ||
            (entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED) != 0u ||
            entry->cleanup_state != RINRUNTIME_FILE_OPERATION_CLEANUP_NONE ||
            entry->object_identity.device != 0u ||
            entry->object_identity.inode != 0u ||
            entry->object_identity.generation != 0u ||
            entry->replacement_state !=
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE ||
            entry->reserved0 != 0u ||
            !file_operation_bytes_zero(entry->backup_path,
                                       sizeof(entry->backup_path)) ||
            !file_operation_identity_empty(&entry->backup_identity))
            return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
        if (kind == RINRUNTIME_FILE_OPERATION_COPY &&
            entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY &&
            file_operation_descendant(entry->source_path, entry->destination_path))
            return RINRUNTIME_FILE_OPERATION_CONFLICT;
        if (kind == RINRUNTIME_FILE_OPERATION_COPY &&
            entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_FILE) {
            if ((~(uint64_t)0) - total < entry->size_bytes)
                return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
            total += entry->size_bytes;
        }
        if (kind == RINRUNTIME_FILE_OPERATION_COPY &&
            entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_SYMLINK)
            has_symlink = 1u;
        if (kind == RINRUNTIME_FILE_OPERATION_COPY &&
            entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_HARDLINK) {
            const RinRuntimeFileOperationEntryV1* source;
            if (entry->link_source_index >= index)
                return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
            source = &entries[entry->link_source_index];
            if (source->kind != RINRUNTIME_FILE_OPERATION_ENTRY_FILE &&
                source->kind != RINRUNTIME_FILE_OPERATION_ENTRY_HARDLINK)
                return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
            has_hardlink = 1u;
        }
    }
    if ((has_symlink != 0u && (backend->read_symlink == 0 ||
                               backend->create_symlink == 0)) ||
        (has_hardlink != 0u && backend->link_no_replace == 0))
        return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
    for (index = 0u; index < entry_count; ++index)
        entries[index].flags &= ~RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP;
    operation->backend = *backend;
    operation->entries = entries;
    operation->entry_count = entry_count;
    operation->entry_index = 0u;
    operation->operation = (uint16_t)kind;
    operation->conflict_policy = (uint32_t)conflict_policy;
    operation->total_bytes = total;
    operation->completed_bytes = 0u;
    operation->completed_items = 0u;
    rinruntime_cancellation_reset(&operation->cancel_requested);
    operation->file_open = 0u;
    operation->temporary_created = 0u;
    operation->sparse_file_enabled = 0u;
    operation->sparse_output_sized = 0u;
    operation->source_handle = 0u;
    operation->temporary_handle = 0u;
    operation->temporary_path[0] = '\0';
    operation->sparse_data_end = 0u;
    operation->recovery_required = 0u;
    operation->replace_undo_active = 0u;
    operation->temporary_cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
    operation->pending_result = RINRUNTIME_FILE_OPERATION_OK;
    operation->rollback_index = entry_count;
    memset(&operation->temporary_identity, 0,
           sizeof(operation->temporary_identity));
    for (index = 0u; index < entry_count; ++index) {
        entries[index].cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
        memset(&entries[index].object_identity, 0,
               sizeof(entries[index].object_identity));
    }
    operation->active = 1u;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

static int file_operation_recovery_restore_internal(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count,
    const RinRuntimeFileOperationRecoveryV1* recovery,
    int require_interrupted_state);

RinRuntimeFileOperationResult rinruntime_file_operation_start_replace_undo(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count,
    const RinRuntimeFileOperationRecoveryV1* recovery)
{
    if (!operation || !backend || !entries || !recovery ||
        operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        operation->active != 0u || operation->recovery_required != 0u ||
        recovery->operation != RINRUNTIME_FILE_OPERATION_COPY ||
        recovery->recovery_required != 0u || recovery->rollback_active != 0u ||
        recovery->replace_undo_active != 0u ||
        file_operation_recovery_restore_internal(
            operation, backend, entries, entry_count, recovery, 0) != 0)
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    if (recovery->entry_index != entry_count)
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    operation->entry_index = entry_count;
    operation->rollback_index = 0u;
    operation->active = 1u;
    operation->recovery_required = 0u;
    operation->rollback_active = 0u;
    operation->replace_undo_active = 1u;
    operation->pending_result = RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

static RinRuntimeFileOperationResult file_operation_open_copy(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationEntryV1* entry)
{
    int result;
    uint64_t source_size = 0u;
    if (!file_operation_temporary_path(operation, entry->destination_path))
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    result = operation->backend.open_read(operation->backend.context,
                                          entry->source_path,
                                          &operation->source_handle);
    if (result != 0 || operation->source_handle == 0u)
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    if (operation->backend.file_size != 0) {
        result = operation->backend.file_size(operation->backend.context,
                                              operation->source_handle,
                                              &source_size);
        if (result != 0 || source_size != entry->size_bytes) {
            (void)file_operation_close_files(operation);
            return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                               : file_operation_result(result);
        }
    }
    result = operation->backend.open_create_exclusive(operation->backend.context,
                                                       operation->temporary_path,
                                                       &operation->temporary_handle);
    if (result != 0 || operation->temporary_handle == 0u) {
        (void)file_operation_close_files(operation);
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    }
    operation->file_open = 1u;
    operation->temporary_created = 1u;
    result = operation->backend.handle_identity(
        operation->backend.context, operation->temporary_handle,
        &operation->temporary_identity);
    if (result != 0 || !file_operation_identity_valid(
                           &operation->temporary_identity))
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    result = file_operation_checkpoint(operation);
    if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
    operation->sparse_file_enabled = operation->backend.seek != 0 ? 1u : 0u;
    operation->sparse_output_sized = 0u;
    operation->sparse_data_end = 0u;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

static RinRuntimeFileOperationResult file_operation_entry_completed(
    const RinRuntimeFileOperationV1* operation, uint64_t* completed_out)
{
    uint32_t index;
    uint64_t completed;
    if (operation == 0 || completed_out == 0) return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    completed = operation->completed_bytes;
    for (index = 0u; index < operation->entry_index; ++index) {
        const RinRuntimeFileOperationEntryV1* prior = &operation->entries[index];
        if (prior->kind != RINRUNTIME_FILE_OPERATION_ENTRY_FILE) continue;
        if (completed < prior->size_bytes) return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        completed -= prior->size_bytes;
    }
    *completed_out = completed;
    return RINRUNTIME_FILE_OPERATION_OK;
}

static RinRuntimeFileOperationResult file_operation_sparse_size_output(
    RinRuntimeFileOperationV1* operation, const RinRuntimeFileOperationEntryV1* entry)
{
    int result;
    if (operation->sparse_output_sized != 0u) return RINRUNTIME_FILE_OPERATION_OK;
    result = operation->backend.truncate(operation->backend.context,
                                         operation->temporary_handle,
                                         entry->size_bytes);
    if (result != 0) return file_operation_result(result);
    operation->sparse_output_sized = 1u;
    return RINRUNTIME_FILE_OPERATION_OK;
}

/* Position only allocated source extents. The backend preserves a dense-copy
 * fallback for filesystems that cannot expose DATA/HOLE; all successful sparse
 * probes are checked against the immutable planned logical size. */
static RinRuntimeFileOperationResult file_operation_prepare_sparse_extent(
    RinRuntimeFileOperationV1* operation, const RinRuntimeFileOperationEntryV1* entry,
    uint64_t* entry_completed)
{
    uint64_t data_start = 0u;
    uint64_t data_end = 0u;
    uint64_t positioned = 0u;
    int result;
    RinRuntimeFileOperationResult core_result;
    if (operation->sparse_file_enabled == 0u) return RINRUNTIME_FILE_OPERATION_OK;
    if (entry_completed == 0) return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    if (*entry_completed >= entry->size_bytes) return *entry_completed == entry->size_bytes
        ? RINRUNTIME_FILE_OPERATION_OK : RINRUNTIME_FILE_OPERATION_IO_FAILED;

    result = operation->backend.seek(operation->backend.context,
        operation->source_handle, *entry_completed,
        RINRUNTIME_FILE_OPERATION_SEEK_DATA, &data_start);
    if (result == RINRUNTIME_FILE_OPERATION_BACKEND_SPARSE_UNSUPPORTED) {
        operation->sparse_file_enabled = 0u;
        operation->sparse_data_end = 0u;
        return RINRUNTIME_FILE_OPERATION_OK;
    }
    core_result = file_operation_sparse_size_output(operation, entry);
    if (core_result != RINRUNTIME_FILE_OPERATION_OK) return core_result;
    if (result == RINRUNTIME_FILE_OPERATION_BACKEND_NO_DATA) {
        uint64_t hole_bytes = entry->size_bytes - *entry_completed;
        if ((~(uint64_t)0) - operation->completed_bytes < hole_bytes)
            return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        operation->completed_bytes += hole_bytes;
        *entry_completed = entry->size_bytes;
        operation->sparse_data_end = 0u;
        return RINRUNTIME_FILE_OPERATION_OK;
    }
    if (result != 0) return file_operation_result(result);
    if (data_start < *entry_completed || data_start >= entry->size_bytes)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;

    result = operation->backend.seek(operation->backend.context,
        operation->source_handle, data_start,
        RINRUNTIME_FILE_OPERATION_SEEK_HOLE, &data_end);
    if (result != 0) return file_operation_result(result);
    if (data_end <= data_start || data_end > entry->size_bytes)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;

    result = operation->backend.seek(operation->backend.context,
        operation->source_handle, data_start,
        RINRUNTIME_FILE_OPERATION_SEEK_SET, &positioned);
    if (result != 0 || positioned != data_start)
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    result = operation->backend.seek(operation->backend.context,
        operation->temporary_handle, data_start,
        RINRUNTIME_FILE_OPERATION_SEEK_SET, &positioned);
    if (result != 0 || positioned != data_start)
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    if ((~(uint64_t)0) - operation->completed_bytes < data_start - *entry_completed)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    operation->completed_bytes += data_start - *entry_completed;
    *entry_completed = data_start;
    operation->sparse_data_end = data_end;
    return RINRUNTIME_FILE_OPERATION_OK;
}

static RinRuntimeFileOperationResult file_operation_finish_copy(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationEntryV1* entry)
{
    int result;
    RinRuntimeFileOperationResult sync_result;
    sync_result = file_operation_copy_metadata(operation, entry,
                                                operation->temporary_path);
    if (sync_result != RINRUNTIME_FILE_OPERATION_OK) return sync_result;
    result = operation->backend.sync_file(operation->backend.context,
                                          operation->temporary_handle);
    if (result != 0) return file_operation_result(result);
    if (!file_operation_close_files(operation)) return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
    entry->object_identity = operation->temporary_identity;
    if (entry->replacement_state ==
        RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD)
        entry->replacement_state =
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_PUBLISH_IN_PROGRESS;
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    result = operation->backend.publish_no_replace(operation->backend.context,
                                                    operation->temporary_path,
                                                    entry->destination_path);
    if (result != 0) return file_operation_result(result);
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    result = operation->backend.path_identity(
        operation->backend.context, entry->destination_path,
        &operation->temporary_identity);
    if (result != 0 || !file_operation_identity_valid(&entry->object_identity))
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    if (!file_operation_identity_equal(&operation->temporary_identity,
                                       &entry->object_identity))
        return RINRUNTIME_FILE_OPERATION_CONFLICT;
    if (entry->replacement_state ==
        RINRUNTIME_FILE_OPERATION_REPLACEMENT_PUBLISH_IN_PROGRESS)
        entry->replacement_state =
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD;
    sync_result = file_operation_sync_parent_once(operation, entry->destination_path);
    if (sync_result != RINRUNTIME_FILE_OPERATION_OK) return sync_result;
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    if (!file_operation_cleanup_created_path(
            operation, operation->temporary_path, 0,
            &operation->temporary_identity,
            &operation->temporary_cleanup_state))
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    operation->temporary_created = 0u;
    operation->temporary_path[0] = '\0';
    memset(&operation->temporary_identity, 0,
           sizeof(operation->temporary_identity));
    return RINRUNTIME_FILE_OPERATION_OK;
}

static int file_operation_symlink_target_valid(const char* target, uint32_t size)
{
    uint32_t index;
    if (target == 0 || size == 0u || size >= RINRUNTIME_FILE_OPERATION_PATH_MAX)
        return 0;
    for (index = 0u; index < size; ++index)
        if (target[index] == '\0') return 0;
    return 1;
}

static RinRuntimeFileOperationResult file_operation_create_symlink(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationEntryV1* entry)
{
    char target[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    uint32_t target_size = 0u;
    int result;
    RinRuntimeFileOperationResult sync_result;
    if (operation->backend.read_symlink == 0 ||
        operation->backend.create_symlink == 0)
        return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
    file_operation_zero(target, sizeof(target));
    result = operation->backend.read_symlink(operation->backend.context,
        entry->source_path, target, sizeof(target), &target_size);
    if (result != 0) return file_operation_result(result);
    if (!file_operation_symlink_target_valid(target, target_size))
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    target[target_size] = '\0';
    result = operation->backend.create_symlink(operation->backend.context,
        target, entry->destination_path);
    if (result != 0) return file_operation_result(result);
    entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
    result = operation->backend.path_identity(
        operation->backend.context, entry->destination_path,
        &entry->object_identity);
    if (result != 0 || !file_operation_identity_valid(&entry->object_identity))
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    sync_result = file_operation_copy_metadata(operation, entry,
                                                entry->destination_path);
    if (sync_result != RINRUNTIME_FILE_OPERATION_OK) return sync_result;
    sync_result = file_operation_sync_parent_once(operation, entry->destination_path);
    return sync_result;
}

static RinRuntimeFileOperationResult file_operation_create_hardlink(
    RinRuntimeFileOperationV1* operation, RinRuntimeFileOperationEntryV1* entry)
{
    const RinRuntimeFileOperationEntryV1* source;
    int result;
    RinRuntimeFileOperationResult sync_result;
    if (operation->backend.link_no_replace == 0 ||
        entry->link_source_index >= operation->entry_index)
        return RINRUNTIME_FILE_OPERATION_UNSUPPORTED;
    source = &operation->entries[entry->link_source_index];
    result = operation->backend.link_no_replace(operation->backend.context,
        source->destination_path, entry->destination_path);
    if (result != 0) return file_operation_result(result);
    entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
    result = operation->backend.path_identity(
        operation->backend.context, entry->destination_path,
        &entry->object_identity);
    if (result != 0 || !file_operation_identity_valid(&entry->object_identity))
        return result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                           : file_operation_result(result);
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    sync_result = file_operation_sync_parent_once(operation, entry->destination_path);
    return sync_result;
}

static RinRuntimeFileOperationResult file_operation_finish_directories(
    RinRuntimeFileOperationV1* operation)
{
    uint32_t index;
    for (index = operation->entry_count; index > 0u; --index) {
        RinRuntimeFileOperationEntryV1* entry = &operation->entries[index - 1u];
        RinRuntimeFileOperationResult result;
        int sync_result;
        if (entry->kind != RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY ||
            (entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED) == 0u)
            continue;
        result = file_operation_copy_metadata(operation, entry,
                                              entry->destination_path);
        if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
        sync_result = operation->backend.sync_directory(operation->backend.context,
                                                        entry->destination_path);
        if (sync_result != 0) return file_operation_result(sync_result);
        result = file_operation_sync_parent_once(operation, entry->destination_path);
        if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
    }
    return RINRUNTIME_FILE_OPERATION_OK;
}

static RinRuntimeFileOperationResult file_operation_pump_copy(
    RinRuntimeFileOperationV1* operation)
{
    RinRuntimeFileOperationEntryV1* entry;
    RinRuntimeFileOperationResult result;
    uint64_t entry_completed = 0u;
    uint32_t count = 0u;
    uint32_t offset = 0u;
    uint32_t read_capacity = sizeof(operation->copy_buffer);
    if (operation->entry_index >= operation->entry_count) {
        result = file_operation_finish_directories(operation);
        if (result != RINRUNTIME_FILE_OPERATION_OK)
            return file_operation_finish_failure(operation, result, 1);
        operation->active = 0u;
        return RINRUNTIME_FILE_OPERATION_COMPLETED;
    }
    entry = &operation->entries[operation->entry_index];
    if (file_operation_skipped(operation, operation->entry_index)) {
        if (entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_FILE) {
            if ((~(uint64_t)0) - operation->completed_bytes < entry->size_bytes)
                return file_operation_finish_failure(operation,
                    RINRUNTIME_FILE_OPERATION_IO_FAILED, 1);
            operation->completed_bytes += entry->size_bytes;
        }
        ++operation->entry_index;
        ++operation->completed_items;
        return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    }
    if (rinruntime_cancellation_requested(&operation->cancel_requested))
        return file_operation_finish_failure(operation,
                                             RINRUNTIME_FILE_OPERATION_CANCELLED, 1);
    if (operation->file_open == 0u) {
        result = file_operation_conflict(operation, entry);
        if (result != RINRUNTIME_FILE_OPERATION_OK)
            return file_operation_finish_failure(operation, result, 1);
        if (file_operation_skipped(operation, operation->entry_index))
            return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        if (entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY) {
            int mkdir_result = operation->backend.mkdir(operation->backend.context,
                                                        entry->destination_path);
            if (mkdir_result != 0)
                return file_operation_finish_failure(operation,
                    file_operation_result(mkdir_result), 1);
            entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
            mkdir_result = operation->backend.path_identity(
                operation->backend.context, entry->destination_path,
                &entry->object_identity);
            if (mkdir_result != 0 ||
                !file_operation_identity_valid(&entry->object_identity))
                return file_operation_finish_failure(operation,
                    mkdir_result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                                      : file_operation_result(mkdir_result), 1);
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return file_operation_finish_failure(operation,
                    RINRUNTIME_FILE_OPERATION_IO_FAILED, 1);
            result = operation->backend.sync_directory(operation->backend.context,
                                                       entry->destination_path);
            if (result != 0)
                return file_operation_finish_failure(operation,
                    file_operation_result(result), 1);
            result = file_operation_sync_parent_once(operation, entry->destination_path);
            if (result != RINRUNTIME_FILE_OPERATION_OK)
                return file_operation_finish_failure(operation, result, 1);
            ++operation->entry_index;
            ++operation->completed_items;
            return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        }
        if (entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_SYMLINK) {
            result = file_operation_create_symlink(operation, entry);
            if (result != RINRUNTIME_FILE_OPERATION_OK)
                return file_operation_finish_failure(operation, result, 1);
            ++operation->entry_index;
            ++operation->completed_items;
            return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        }
        if (entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_HARDLINK) {
            result = file_operation_create_hardlink(operation, entry);
            if (result != RINRUNTIME_FILE_OPERATION_OK)
                return file_operation_finish_failure(operation, result, 1);
            ++operation->entry_index;
            ++operation->completed_items;
            return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        }
        result = file_operation_open_copy(operation, entry);
        if (result != RINRUNTIME_FILE_OPERATION_IN_PROGRESS)
            return file_operation_finish_failure(operation, result, 1);
    }
    result = file_operation_entry_completed(operation, &entry_completed);
    if (result != RINRUNTIME_FILE_OPERATION_OK || entry_completed > entry->size_bytes)
        return file_operation_finish_failure(operation,
            result == RINRUNTIME_FILE_OPERATION_OK
                ? RINRUNTIME_FILE_OPERATION_IO_FAILED : result, 1);
    result = file_operation_prepare_sparse_extent(operation, entry, &entry_completed);
    if (result != RINRUNTIME_FILE_OPERATION_OK)
        return file_operation_finish_failure(operation, result, 1);
    if (entry_completed == entry->size_bytes) {
        result = file_operation_finish_copy(operation, entry);
        if (result != RINRUNTIME_FILE_OPERATION_OK)
            return file_operation_finish_failure(operation, result, 1);
        ++operation->entry_index;
        ++operation->completed_items;
        return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    }
    if (operation->sparse_file_enabled != 0u) {
        uint64_t remaining;
        if (operation->sparse_data_end <= entry_completed)
            return file_operation_finish_failure(operation,
                RINRUNTIME_FILE_OPERATION_IO_FAILED, 1);
        remaining = operation->sparse_data_end - entry_completed;
        if (remaining < read_capacity) read_capacity = (uint32_t)remaining;
    }
    {
        int read_result = operation->backend.read(operation->backend.context,
            operation->source_handle, operation->copy_buffer,
            read_capacity, &count);
        if (read_result != 0 || count > read_capacity)
            return file_operation_finish_failure(operation,
                read_result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED :
                                   file_operation_result(read_result), 1);
    }
    if (count == 0u) {
        if (entry_completed != entry->size_bytes)
            return file_operation_finish_failure(operation,
                RINRUNTIME_FILE_OPERATION_IO_FAILED, 1);
        result = file_operation_finish_copy(operation, entry);
        if (result != RINRUNTIME_FILE_OPERATION_OK)
            return file_operation_finish_failure(operation, result, 1);
        ++operation->entry_index;
        ++operation->completed_items;
        return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    }
    if ((uint64_t)count > entry->size_bytes - entry_completed)
        return file_operation_finish_failure(operation,
            RINRUNTIME_FILE_OPERATION_IO_FAILED, 1);
    while (offset < count) {
        uint32_t written = 0u;
        int write_result = operation->backend.write(operation->backend.context,
            operation->temporary_handle, operation->copy_buffer + offset,
            count - offset, &written);
        if (write_result != 0 || written == 0u || written > count - offset)
            return file_operation_finish_failure(operation,
                write_result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED :
                                    file_operation_result(write_result), 1);
        offset += written;
    }
    operation->completed_bytes += count;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

static RinRuntimeFileOperationResult file_operation_pump_namespace(
    RinRuntimeFileOperationV1* operation)
{
    RinRuntimeFileOperationEntryV1* entry;
    RinRuntimeFileOperationResult result;
    int action_result;
    if (operation->entry_index >= operation->entry_count) {
        operation->active = 0u;
        return RINRUNTIME_FILE_OPERATION_COMPLETED;
    }
    entry = &operation->entries[operation->entry_index];
    if (rinruntime_cancellation_requested(&operation->cancel_requested)) {
        result = RINRUNTIME_FILE_OPERATION_CANCELLED;
        goto namespace_failure;
    }
    if (operation->operation != RINRUNTIME_FILE_OPERATION_DELETE) {
        result = file_operation_conflict(operation, entry);
        if (result != RINRUNTIME_FILE_OPERATION_OK) goto namespace_failure;
        if (file_operation_skipped(operation, operation->entry_index)) {
            ++operation->entry_index;
            ++operation->completed_items;
            return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        }
        action_result = operation->backend.path_identity(
            operation->backend.context, entry->source_path,
            &entry->object_identity);
        if (action_result != 0 ||
            !file_operation_identity_valid(&entry->object_identity)) {
            result = action_result == 0 ? RINRUNTIME_FILE_OPERATION_IO_FAILED
                                        : file_operation_result(action_result);
            goto namespace_failure;
        }
        entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED;
        entry->cleanup_state =
            RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_IN_PROGRESS;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK) {
            result = RINRUNTIME_FILE_OPERATION_IO_FAILED;
            goto namespace_failure;
        }
        action_result = operation->backend.rename_no_replace_expected(
            operation->backend.context, entry->source_path,
            entry->destination_path, &entry->object_identity);
        if (action_result != 0) {
            result = file_operation_result(action_result);
            goto namespace_failure;
        }
        entry->cleanup_state =
            RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_SYNC_PENDING;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK) {
            result = RINRUNTIME_FILE_OPERATION_IO_FAILED;
            goto namespace_failure;
        }
        result = file_operation_sync_parent_once(operation, entry->destination_path);
        if (result == RINRUNTIME_FILE_OPERATION_OK &&
            !file_operation_descendant(entry->destination_path, entry->source_path))
            result = file_operation_sync_parent_once(operation, entry->source_path);
        if (result != RINRUNTIME_FILE_OPERATION_OK) goto namespace_failure;
        entry->cleanup_state = RINRUNTIME_FILE_OPERATION_CLEANUP_NONE;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK) {
            result = RINRUNTIME_FILE_OPERATION_IO_FAILED;
            goto namespace_failure;
        }
    } else {
        action_result = entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY
            ? operation->backend.remove_directory(operation->backend.context, entry->source_path)
            : operation->backend.remove_file(operation->backend.context, entry->source_path);
        if (action_result != 0) {
            operation->active = 0u;
            return file_operation_result(action_result);
        }
        entry->flags |= RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED;
        result = file_operation_sync_parent_once(operation, entry->source_path);
        if (result != RINRUNTIME_FILE_OPERATION_OK) {
            operation->active = 0u;
            return result;
        }
    }
    ++operation->entry_index;
    ++operation->completed_items;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;

namespace_failure:
    if (operation->operation == RINRUNTIME_FILE_OPERATION_DELETE) {
        operation->active = 0u;
        operation->pending_result = result;
        return result;
    }
    return file_operation_finish_failure(operation, result, 1);
}

static RinRuntimeFileOperationResult file_operation_pump_replace_undo(
    RinRuntimeFileOperationV1* operation)
{
    RinRuntimeFileOperationEntryV1* entry;
    RinRuntimeFileOperationObjectIdentityV1 current;
    int destination_state;
    int backup_state;
    int result;
    if (operation->entry_index == 0u) {
        operation->active = 0u;
        operation->replace_undo_active = 0u;
        return RINRUNTIME_FILE_OPERATION_COMPLETED;
    }
    entry = &operation->entries[operation->entry_index - 1u];
    if ((entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP) != 0u ||
        (entry->flags & RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED) == 0u) {
        --operation->entry_index;
        return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    }
    destination_state = operation->backend.path_state(
        operation->backend.context, entry->destination_path);
    if (destination_state < 0) return RINRUNTIME_FILE_OPERATION_IO_FAILED;

    if (entry->replacement_state == RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE) {
        if (destination_state == 1) {
            memset(&current, 0, sizeof(current));
            result = operation->backend.path_identity(
                operation->backend.context, entry->destination_path, &current);
            if (result != 0 || !file_operation_identity_equal(
                    &current, &entry->object_identity))
                return RINRUNTIME_FILE_OPERATION_CONFLICT;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
            result = entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY
                ? operation->backend.remove_directory_expected(
                      operation->backend.context, entry->destination_path,
                      &entry->object_identity)
                : operation->backend.remove_file_expected(
                      operation->backend.context, entry->destination_path,
                      &entry->object_identity);
            if (result != 0) return file_operation_result(result);
            result = file_operation_sync_parent_once(
                operation, entry->destination_path);
            if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        }
        entry->flags &= ~RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
        memset(&entry->object_identity, 0, sizeof(entry->object_identity));
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        --operation->entry_index;
        return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    }

    if (entry->replacement_state !=
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD &&
        entry->replacement_state !=
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_REMOVE_IN_PROGRESS &&
        entry->replacement_state !=
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_RESTORE_IN_PROGRESS)
        return RINRUNTIME_FILE_OPERATION_CONFLICT;

    if (entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_BACKUP_HELD ||
        entry->replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_REMOVE_IN_PROGRESS) {
        if (destination_state == 1) {
            memset(&current, 0, sizeof(current));
            result = operation->backend.path_identity(
                operation->backend.context, entry->destination_path, &current);
            if (result != 0 || !file_operation_identity_equal(
                    &current, &entry->object_identity))
                return RINRUNTIME_FILE_OPERATION_CONFLICT;
            entry->replacement_state =
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_REMOVE_IN_PROGRESS;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
            result = entry->kind == RINRUNTIME_FILE_OPERATION_ENTRY_DIRECTORY
                ? operation->backend.remove_directory_expected(
                      operation->backend.context, entry->destination_path,
                      &entry->object_identity)
                : operation->backend.remove_file_expected(
                      operation->backend.context, entry->destination_path,
                      &entry->object_identity);
            if (result != 0) return file_operation_result(result);
            result = file_operation_sync_parent_once(
                operation, entry->destination_path);
            if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
            if (file_operation_checkpoint(operation) !=
                RINRUNTIME_FILE_OPERATION_OK)
                return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        }
        entry->replacement_state =
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_RESTORE_IN_PROGRESS;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    }

    backup_state = operation->backend.path_state(
        operation->backend.context, entry->backup_path);
    destination_state = operation->backend.path_state(
        operation->backend.context, entry->destination_path);
    if (backup_state < 0 || destination_state < 0)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    if (backup_state == 1 && destination_state == 0) {
        memset(&current, 0, sizeof(current));
        result = operation->backend.path_identity(
            operation->backend.context, entry->backup_path, &current);
        if (result != 0 || !file_operation_identity_equal(
                &current, &entry->backup_identity))
            return RINRUNTIME_FILE_OPERATION_CONFLICT;
        if (file_operation_checkpoint(operation) !=
            RINRUNTIME_FILE_OPERATION_OK)
            return RINRUNTIME_FILE_OPERATION_IO_FAILED;
        result = operation->backend.rename_no_replace_expected(
            operation->backend.context, entry->backup_path,
            entry->destination_path, &entry->backup_identity);
        if (result != 0) return file_operation_result(result);
    } else if (backup_state == 0 && destination_state == 1) {
        memset(&current, 0, sizeof(current));
        result = operation->backend.path_identity(
            operation->backend.context, entry->destination_path, &current);
        if (result != 0 || !file_operation_identity_equal(
                &current, &entry->backup_identity))
            return RINRUNTIME_FILE_OPERATION_CONFLICT;
    } else {
        return RINRUNTIME_FILE_OPERATION_CONFLICT;
    }
    result = file_operation_sync_parent_once(operation, entry->destination_path);
    if (result != RINRUNTIME_FILE_OPERATION_OK) return result;
    entry->replacement_state = RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE;
    file_operation_zero(entry->backup_path, sizeof(entry->backup_path));
    memset(&entry->backup_identity, 0, sizeof(entry->backup_identity));
    entry->flags &= ~RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED;
    memset(&entry->object_identity, 0, sizeof(entry->object_identity));
    if (file_operation_checkpoint(operation) !=
        RINRUNTIME_FILE_OPERATION_OK)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    --operation->entry_index;
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

RinRuntimeFileOperationResult rinruntime_file_operation_pump(
    RinRuntimeFileOperationV1* operation)
{
    int rollback_step;
    if (operation == 0 || operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        !file_operation_operation_valid(operation->operation) ||
        operation->active == 0u)
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    if (operation->rollback_active != 0u) {
        rollback_step = file_operation_rollback_step(operation);
        if (rollback_step < 0) {
            operation->active = 0u;
            operation->recovery_required = 1u;
            return RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED;
        }
        if (rollback_step > 0) return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
        operation->rollback_active = 0u;
        operation->active = 0u;
        operation->recovery_required = 0u;
        return (RinRuntimeFileOperationResult)operation->pending_result;
    }
    if (operation->replace_undo_active != 0u) {
        RinRuntimeFileOperationResult undo_result =
            file_operation_pump_replace_undo(operation);
        if (undo_result < 0) {
            operation->pending_result = undo_result;
            operation->active = 0u;
            operation->recovery_required = 1u;
            return RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED;
        }
        return undo_result;
    }
    return operation->operation == RINRUNTIME_FILE_OPERATION_COPY
               ? file_operation_pump_copy(operation)
               : file_operation_pump_namespace(operation);
}

RinRuntimeFileOperationResult rinruntime_file_operation_cancel(
    RinRuntimeFileOperationV1* operation)
{
    if (operation == 0 || operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION || operation->active == 0u)
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    (void)rinruntime_cancellation_request(&operation->cancel_requested);
    return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
}

RinRuntimeFileOperationResult rinruntime_file_operation_retry_recovery(
    RinRuntimeFileOperationV1* operation)
{
    int rollback_step;
    if (operation == 0 || operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        operation->active != 0u || operation->recovery_required == 0u ||
        !file_operation_operation_valid(operation->operation) ||
        operation->entries == 0 || operation->entry_count == 0u ||
        !file_operation_backend_valid(
            &operation->backend,
            (RinRuntimeFileOperationKind)operation->operation))
        return RINRUNTIME_FILE_OPERATION_INVALID_ARGUMENT;
    operation->active = 1u;
    operation->rollback_active = 1u;
    if (operation->rollback_index > operation->entry_count)
        operation->rollback_index = operation->entry_count;
    rollback_step = file_operation_rollback_step(operation);
    if (rollback_step < 0) {
        operation->active = 0u;
        operation->recovery_required = 1u;
        return RINRUNTIME_FILE_OPERATION_ROLLBACK_FAILED;
    }
    if (rollback_step > 0) return RINRUNTIME_FILE_OPERATION_IN_PROGRESS;
    operation->active = 0u;
    operation->rollback_active = 0u;
    operation->recovery_required = 0u;
    if (operation->pending_result == RINRUNTIME_FILE_OPERATION_OK ||
        operation->pending_result == RINRUNTIME_FILE_OPERATION_IN_PROGRESS ||
        operation->pending_result == RINRUNTIME_FILE_OPERATION_COMPLETED)
        return RINRUNTIME_FILE_OPERATION_IO_FAILED;
    return (RinRuntimeFileOperationResult)operation->pending_result;
}

int rinruntime_file_operation_recovery_save(
    const RinRuntimeFileOperationV1* operation,
    RinRuntimeFileOperationRecoveryV1* recovery_out)
{
    uint32_t index;
    if (!operation || !recovery_out ||
        operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        !file_operation_operation_valid(operation->operation) ||
        operation->entries == 0 || operation->entry_count == 0u ||
        operation->entry_count > RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT ||
        operation->recovery_required > 1u || operation->rollback_active > 1u ||
        operation->temporary_created > 1u ||
        operation->temporary_cleanup_state >
            RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING ||
        operation->replace_undo_active > 1u ||
        operation->entry_index > operation->entry_count ||
        (operation->temporary_created != 0u &&
         !rinruntime_file_operation_path_valid(operation->temporary_path)))
        return -1;
    file_operation_zero(recovery_out, sizeof(*recovery_out));
    recovery_out->struct_size = sizeof(*recovery_out);
    recovery_out->version = RINRUNTIME_FILE_OPERATION_RECOVERY_VERSION;
    recovery_out->operation = operation->operation;
    recovery_out->entry_count = operation->entry_count;
    recovery_out->conflict_policy = operation->conflict_policy;
    recovery_out->temporary_created = operation->temporary_created;
    recovery_out->temporary_cleanup_state = operation->temporary_cleanup_state;
    recovery_out->recovery_required =
        operation->recovery_required != 0u || operation->active != 0u;
    recovery_out->rollback_active = operation->rollback_active;
    recovery_out->pending_result = operation->pending_result;
    recovery_out->rollback_index = operation->rollback_index;
    recovery_out->entry_index = operation->entry_index;
    recovery_out->replace_undo_active = operation->replace_undo_active;
    if (operation->temporary_created != 0u) {
        if (!file_operation_copy(recovery_out->temporary_path,
                                 sizeof(recovery_out->temporary_path),
                                 operation->temporary_path))
            return -1;
        recovery_out->temporary_identity = operation->temporary_identity;
    }
    for (index = 0u; index < operation->entry_count; ++index) {
        const RinRuntimeFileOperationEntryV1* source = &operation->entries[index];
        RinRuntimeFileOperationRecoveryEntryV1* destination =
            &recovery_out->entries[index];
        if (!file_operation_entry_valid(
                source, (RinRuntimeFileOperationKind)operation->operation))
            return -1;
        destination->flags = source->flags;
        destination->cleanup_state = source->cleanup_state;
        destination->object_identity = source->object_identity;
        destination->replacement_state = source->replacement_state;
        destination->reserved0 = source->reserved0;
        memcpy(destination->backup_path, source->backup_path,
               sizeof(destination->backup_path));
        destination->backup_identity = source->backup_identity;
    }
    return 0;
}

static int file_operation_recovery_restore_internal(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count,
    const RinRuntimeFileOperationRecoveryV1* recovery,
    int require_interrupted_state)
{
    uint32_t index;
    RinRuntimeFileOperationResult pending_result;
    if (!operation || !backend || !entries || !recovery ||
        operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION ||
        operation->active != 0u || operation->recovery_required != 0u ||
        recovery->struct_size != sizeof(*recovery) ||
        recovery->version != RINRUNTIME_FILE_OPERATION_RECOVERY_VERSION ||
        !file_operation_operation_valid(recovery->operation) ||
        entry_count == 0u || entry_count != recovery->entry_count ||
        entry_count > RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT ||
        !file_operation_conflict_valid(recovery->conflict_policy) ||
        recovery->temporary_created > 1u || recovery->recovery_required > 1u ||
        (require_interrupted_state != 0 &&
         recovery->recovery_required != 1u) ||
        recovery->rollback_active > 1u ||
        recovery->replace_undo_active > 1u ||
        recovery->entry_index > entry_count ||
        recovery->temporary_cleanup_state >
            RINRUNTIME_FILE_OPERATION_CLEANUP_SYNC_PENDING ||
        !file_operation_backend_valid(
            backend, (RinRuntimeFileOperationKind)recovery->operation) ||
        (recovery->temporary_created != 0u &&
         (!rinruntime_file_operation_path_valid(recovery->temporary_path) ||
          recovery->temporary_path[0] == '\0')) ||
        (recovery->temporary_created == 0u &&
         (recovery->temporary_path[0] != '\0' ||
          recovery->temporary_cleanup_state !=
              RINRUNTIME_FILE_OPERATION_CLEANUP_NONE)))
        return -1;
    if (recovery->temporary_created == 0u &&
        (recovery->temporary_identity.device != 0u ||
         recovery->temporary_identity.inode != 0u ||
         recovery->temporary_identity.generation != 0u))
        return -1;
    if (!file_operation_bytes_zero(
            &recovery->entries[entry_count],
            (RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT - entry_count) *
                sizeof(recovery->entries[0])))
        return -1;
    for (index = 0u; index < entry_count; ++index) {
        if (!file_operation_entry_valid(
                &entries[index], (RinRuntimeFileOperationKind)recovery->operation) ||
            (recovery->entries[index].flags &
             ~(RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_SKIP |
               RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_CREATED |
               RINRUNTIME_FILE_OPERATION_ENTRY_FLAG_APPLIED)) != 0u ||
            recovery->entries[index].cleanup_state >
                RINRUNTIME_FILE_OPERATION_CLEANUP_RENAME_SYNC_PENDING ||
            recovery->entries[index].replacement_state >
                RINRUNTIME_FILE_OPERATION_REPLACEMENT_UNDO_RESTORE_IN_PROGRESS ||
            recovery->entries[index].reserved0 != 0u)
            return -1;
        if (recovery->entries[index].replacement_state ==
            RINRUNTIME_FILE_OPERATION_REPLACEMENT_NONE) {
            if (!file_operation_bytes_zero(
                    recovery->entries[index].backup_path,
                    sizeof(recovery->entries[index].backup_path)) ||
                !file_operation_identity_empty(
                    &recovery->entries[index].backup_identity))
                return -1;
        } else if (!rinruntime_file_operation_path_valid(
                       recovery->entries[index].backup_path) ||
                   recovery->entries[index].backup_path[0] == '\0' ||
                   !file_operation_identity_valid(
                       &recovery->entries[index].backup_identity)) {
            return -1;
        }
    }
    rinruntime_file_operation_init(operation);
    operation->backend = *backend;
    operation->entries = entries;
    operation->entry_count = entry_count;
    operation->operation = recovery->operation;
    operation->conflict_policy = recovery->conflict_policy;
    operation->temporary_created = recovery->temporary_created;
    operation->temporary_cleanup_state = recovery->temporary_cleanup_state;
    operation->temporary_identity = recovery->temporary_identity;
    if (operation->temporary_created != 0u &&
        !file_operation_copy(operation->temporary_path,
                             sizeof(operation->temporary_path),
                             recovery->temporary_path))
        return -1;
    for (index = 0u; index < entry_count; ++index) {
        entries[index].flags = recovery->entries[index].flags;
        entries[index].cleanup_state = recovery->entries[index].cleanup_state;
        entries[index].object_identity =
            recovery->entries[index].object_identity;
        entries[index].replacement_state =
            recovery->entries[index].replacement_state;
        entries[index].reserved0 = recovery->entries[index].reserved0;
        memcpy(entries[index].backup_path,
               recovery->entries[index].backup_path,
               sizeof(entries[index].backup_path));
        entries[index].backup_identity =
            recovery->entries[index].backup_identity;
    }
    pending_result = (RinRuntimeFileOperationResult)recovery->pending_result;
    if (pending_result == RINRUNTIME_FILE_OPERATION_OK ||
        pending_result == RINRUNTIME_FILE_OPERATION_IN_PROGRESS ||
        pending_result == RINRUNTIME_FILE_OPERATION_COMPLETED)
        pending_result = RINRUNTIME_FILE_OPERATION_IO_FAILED;
    operation->pending_result = pending_result;
    operation->rollback_index = entry_count;
    operation->entry_index = recovery->entry_index;
    operation->replace_undo_active = recovery->replace_undo_active;
    operation->active = 0u;
    operation->rollback_active = 0u;
    operation->recovery_required = 1u;
    return 0;
}

int rinruntime_file_operation_recovery_restore(
    RinRuntimeFileOperationV1* operation,
    const RinRuntimeFileOperationBackendV1* backend,
    RinRuntimeFileOperationEntryV1* entries, uint32_t entry_count,
    const RinRuntimeFileOperationRecoveryV1* recovery)
{
    return file_operation_recovery_restore_internal(
        operation, backend, entries, entry_count, recovery, 1);
}

uint32_t rinruntime_file_operation_percent(const RinRuntimeFileOperationV1* operation)
{
    uint64_t completed;
    if (operation == 0 || operation->struct_size != sizeof(*operation) ||
        operation->version != RINRUNTIME_FILE_OPERATION_VERSION) return 0u;
    if (operation->total_bytes == 0u)
        return operation->active != 0u ? 0u : 100u;
    completed = operation->completed_bytes;
    if (completed > operation->total_bytes) completed = operation->total_bytes;
    return (uint32_t)((completed * 100u) / operation->total_bytes);
}
