/* SPDX-License-Identifier: MIT */
#include <rinruntime/backup_restore.h>
#include <rinruntime/file_operation.h>
#include <rinruntime/known_folders.h>
#include <rinruntime/crash.h>
#include <rinruntime/portal.h>

#include <string.h>

static int backup_round_trip(void)
{
    RinRuntimeBackupItemV1 item = {0};
    RinRuntimeBackupManifestV1 manifest = {0};
    RinRuntimeBackupIdentityV1 identity = {0};
    RinRuntimeBackupManifestInfoV1 info = {0};
    uint8_t encoded[RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX] = {0};
    size_t encoded_size = 0u;
    identity.struct_size = sizeof(identity);
    identity.version = RINRUNTIME_BACKUP_VERSION;
    identity.application_id[0] = 'r';
    identity.package_digest[0] = 1u;
    identity.package_generation = 4u;
    item.struct_size = sizeof(item);
    item.version = RINRUNTIME_BACKUP_VERSION;
    item.storage_class = RINRUNTIME_BACKUP_STORAGE_DATA;
    item.item_id[0] = 'd';
    item.item_id[1] = 'a';
    item.item_id[2] = 't';
    item.item_id[3] = 'a';
    item.schema_version = 1u;
    item.flags = RINRUNTIME_BACKUP_ITEM_INCLUDE;
    manifest.struct_size = sizeof(manifest);
    manifest.version = RINRUNTIME_BACKUP_VERSION;
    manifest.identity = identity;
    manifest.manifest_generation = 1u;
    manifest.created_at_ns = 2u;
    manifest.items = &item;
    manifest.item_count = 1u;
    if (rinruntime_backup_manifest_encode(&manifest, encoded, sizeof(encoded),
                                         &encoded_size) != RINRUNTIME_BACKUP_OK)
        return 0;
    if (rinruntime_backup_manifest_inspect(encoded, encoded_size, &info) !=
        RINRUNTIME_BACKUP_OK || info.eligible_item_count != 1u)
        return 0;
    encoded[encoded_size - 1u] ^= 1u;
    return rinruntime_backup_manifest_inspect(encoded, encoded_size, &info) ==
           RINRUNTIME_BACKUP_INTEGRITY_FAILED;
}

int main(void)
{
    char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX];
    RinRuntimeFileOperationV1 operation;
    if (rinruntime_known_folder_resolve("/home/test",
                                        RINRUNTIME_KNOWN_FOLDER_DOCUMENTS,
                                        path, sizeof(path)) !=
            RINRUNTIME_KNOWN_FOLDER_OK || strcmp(path, "/home/test/docs") != 0)
        return 1;
    if (rinruntime_known_folder_resolve("/home/../test",
                                        RINRUNTIME_KNOWN_FOLDER_HOME,
                                        path, sizeof(path)) ==
        RINRUNTIME_KNOWN_FOLDER_OK)
        return 1;
    if (!rinruntime_file_operation_path_valid("/home/test/file") ||
        rinruntime_file_operation_path_valid("/home/test/../file"))
        return 1;
    rinruntime_file_operation_init(&operation);
    if (operation.version != RINRUNTIME_FILE_OPERATION_VERSION ||
        operation.struct_size != sizeof(operation))
        return 1;
    RinRuntimePortalRequestV1 request = {0};
    RinRuntimeCrashSummaryV1 summary = {0};
    request.struct_size = sizeof(request);
    request.version = RINRUNTIME_PORTAL_IPC_PROTOCOL_VERSION;
    request.operation = 1u;
    request.token.struct_size = sizeof(request.token);
    request.token.version = RINRUNTIME_PORTAL_TOKEN_VERSION;
    request.token.owner_id = 7u;
    request.token.generation = 3u;
    request.token.rights = RINRUNTIME_PORTAL_RIGHT_READ;
    request.token.opaque[0] = 1u;
    request.requested_rights = RINRUNTIME_PORTAL_RIGHT_READ;
    request.request_id = 9u;
    request.timeout_ns = 1000000u;
    if (rinruntime_portal_request_validate(&request, 7u, 3u) !=
        RINRUNTIME_PORTAL_OK)
        return 1;
    summary.struct_size = sizeof(summary);
    summary.version = RINRUNTIME_CRASH_API_VERSION;
    summary.kind = RINRUNTIME_CRASH_USER_FAILURE;
    summary.message_size = 4u;
    memcpy(summary.message, "oops", 4u);
    if (!rinruntime_crash_summary_validate(&summary)) return 1;
    return backup_round_trip() ? 0 : 1;
}
