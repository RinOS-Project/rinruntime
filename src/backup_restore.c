/* SPDX-License-Identifier: MIT */

#include <rinruntime/backup_restore.h>

#include <string.h>

#define RINRUNTIME_BACKUP_MAGIC UINT32_C(0x314b4252) /* RBK1 */

typedef struct __attribute__((packed)) RinRuntimeBackupWireHeaderV1 {
    uint32_t magic;
    uint16_t version;
    uint16_t header_size;
    uint32_t total_size;
    uint32_t item_count;
    uint64_t manifest_generation;
    uint64_t created_at_ns;
    uint8_t application_id[RINRUNTIME_BACKUP_APPLICATION_ID_SIZE];
    uint8_t package_digest[RINRUNTIME_BACKUP_PACKAGE_DIGEST_SIZE];
    uint64_t package_generation;
    uint32_t integrity;
    uint32_t reserved0;
} RinRuntimeBackupWireHeaderV1;

typedef struct __attribute__((packed)) RinRuntimeBackupWireItemV1 {
    uint8_t item_id[RINRUNTIME_BACKUP_ITEM_ID_SIZE];
    uint16_t storage_class;
    uint16_t flags;
    uint64_t schema_version;
    uint32_t reserved0;
} RinRuntimeBackupWireItemV1;

static int backup_nonzero(const uint8_t* bytes, size_t size)
{
    uint8_t value = 0u;
    size_t index;
    if (bytes == NULL) return 0;
    for (index = 0u; index < size; ++index) value |= bytes[index];
    return value != 0u;
}

static uint32_t backup_crc32(uint32_t value, const uint8_t* bytes,
                             size_t size)
{
    size_t index;
    if (bytes == NULL && size != 0u) return 0u;
    for (index = 0u; index < size; ++index) {
        unsigned int bit;
        value ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit)
            value = (value >> 1u) ^
                (UINT32_C(0xedb88320) & (uint32_t)-(int32_t)(value & 1u));
    }
    return value;
}

static uint32_t backup_integrity(const RinRuntimeBackupWireHeaderV1* header,
                                 const uint8_t* item_bytes,
                                 size_t item_bytes_size)
{
    uint32_t value = UINT32_C(0xffffffff);
    value = backup_crc32(value, (const uint8_t*)header, sizeof(*header));
    value = backup_crc32(value, item_bytes, item_bytes_size);
    return value ^ UINT32_C(0xffffffff);
}

static int backup_storage_class_valid(uint16_t storage_class)
{
    return storage_class >= RINRUNTIME_BACKUP_STORAGE_CONFIG &&
           storage_class <= RINRUNTIME_BACKUP_STORAGE_SECRET_KEYRING;
}

static int backup_storage_class_is_forced_excluded(uint16_t storage_class)
{
    return storage_class == RINRUNTIME_BACKUP_STORAGE_CACHE ||
           storage_class == RINRUNTIME_BACKUP_STORAGE_RECENT_ITEMS ||
           storage_class == RINRUNTIME_BACKUP_STORAGE_SECRET_KEYRING;
}

static int backup_item_id_valid(
    const uint8_t item_id[RINRUNTIME_BACKUP_ITEM_ID_SIZE])
{
    size_t index;
    size_t terminator = RINRUNTIME_BACKUP_ITEM_ID_SIZE;
    if (item_id == NULL) return 0;
    for (index = 0u; index < RINRUNTIME_BACKUP_ITEM_ID_SIZE; ++index) {
        unsigned char character = item_id[index];
        int allowed;
        if (character == '\0') {
            terminator = index;
            break;
        }
        allowed = (character >= 'a' && character <= 'z') ||
                  (character >= 'A' && character <= 'Z') ||
                  (character >= '0' && character <= '9') ||
                  character == '.' || character == '_' || character == '-';
        if (!allowed) return 0;
    }
    if (terminator == 0u || terminator == RINRUNTIME_BACKUP_ITEM_ID_SIZE ||
        (terminator == 1u && item_id[0] == '.'))
        return 0;
    for (index = terminator + 1u; index < RINRUNTIME_BACKUP_ITEM_ID_SIZE;
         ++index) {
        if (item_id[index] != '\0') return 0;
    }
    return !(terminator == 2u && item_id[0] == '.' && item_id[1] == '.');
}

int rinruntime_backup_identity_valid(const RinRuntimeBackupIdentityV1* identity)
{
    return identity != NULL && identity->struct_size == sizeof(*identity) &&
           identity->version == RINRUNTIME_BACKUP_VERSION &&
           identity->reserved0 == 0u && identity->package_generation != 0u &&
           backup_nonzero(identity->application_id,
                          sizeof(identity->application_id)) &&
           backup_nonzero(identity->package_digest,
                          sizeof(identity->package_digest)) &&
           identity->reserved[0] == 0u && identity->reserved[1] == 0u;
}

static RinRuntimeBackupResult backup_item_validate(
    const RinRuntimeBackupItemV1* item)
{
    uint16_t selection;
    if (item == NULL || item->struct_size != sizeof(*item) ||
        item->version != RINRUNTIME_BACKUP_VERSION ||
        !backup_storage_class_valid(item->storage_class) ||
        !backup_item_id_valid(item->item_id) || item->schema_version == 0u ||
        item->reserved0 != 0u || item->reserved[0] != 0u ||
        item->reserved[1] != 0u)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    selection = (uint16_t)(item->flags &
                           (RINRUNTIME_BACKUP_ITEM_INCLUDE |
                            RINRUNTIME_BACKUP_ITEM_EXCLUDE));
    if (selection != RINRUNTIME_BACKUP_ITEM_INCLUDE &&
        selection != RINRUNTIME_BACKUP_ITEM_EXCLUDE)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    if ((item->flags & ~(RINRUNTIME_BACKUP_ITEM_INCLUDE |
                         RINRUNTIME_BACKUP_ITEM_EXCLUDE)) != 0u)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    if (backup_storage_class_is_forced_excluded(item->storage_class) &&
        selection == RINRUNTIME_BACKUP_ITEM_INCLUDE)
        return RINRUNTIME_BACKUP_INELIGIBLE;
    return RINRUNTIME_BACKUP_OK;
}

int rinruntime_backup_item_is_eligible(const RinRuntimeBackupItemV1* item)
{
    return backup_item_validate(item) == RINRUNTIME_BACKUP_OK &&
           item->flags == RINRUNTIME_BACKUP_ITEM_INCLUDE;
}

static int backup_items_strictly_ordered(const RinRuntimeBackupItemV1* items,
                                         uint32_t count)
{
    uint32_t index;
    for (index = 1u; index < count; ++index) {
        if (memcmp(items[index - 1u].item_id, items[index].item_id,
                   RINRUNTIME_BACKUP_ITEM_ID_SIZE) >= 0)
            return 0;
    }
    return 1;
}

static RinRuntimeBackupResult backup_manifest_validate(
    const RinRuntimeBackupManifestV1* manifest)
{
    uint32_t index;
    if (manifest == NULL || manifest->struct_size != sizeof(*manifest) ||
        manifest->version != RINRUNTIME_BACKUP_VERSION ||
        manifest->reserved0 != 0u ||
        !rinruntime_backup_identity_valid(&manifest->identity) ||
        manifest->manifest_generation == 0u || manifest->created_at_ns == 0u ||
        manifest->item_count > RINRUNTIME_BACKUP_MAX_ITEMS ||
        (manifest->item_count != 0u && manifest->items == NULL) ||
        manifest->reserved1 != 0u || manifest->reserved[0] != 0u ||
        manifest->reserved[1] != 0u)
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    for (index = 0u; index < manifest->item_count; ++index) {
        RinRuntimeBackupResult result = backup_item_validate(&manifest->items[index]);
        if (result != RINRUNTIME_BACKUP_OK) return result;
    }
    if (!backup_items_strictly_ordered(manifest->items, manifest->item_count))
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    return RINRUNTIME_BACKUP_OK;
}

static void backup_item_to_wire(const RinRuntimeBackupItemV1* item,
                                RinRuntimeBackupWireItemV1* wire)
{
    memset(wire, 0, sizeof(*wire));
    memcpy(wire->item_id, item->item_id, sizeof(wire->item_id));
    wire->storage_class = item->storage_class;
    wire->flags = item->flags;
    wire->schema_version = item->schema_version;
}

static RinRuntimeBackupResult backup_item_from_wire(
    const RinRuntimeBackupWireItemV1* wire, RinRuntimeBackupItemV1* item)
{
    RinRuntimeBackupResult result;
    if (wire == NULL || item == NULL || wire->reserved0 != 0u)
        return RINRUNTIME_BACKUP_MALFORMED;
    memset(item, 0, sizeof(*item));
    item->struct_size = sizeof(*item);
    item->version = RINRUNTIME_BACKUP_VERSION;
    item->storage_class = wire->storage_class;
    memcpy(item->item_id, wire->item_id, sizeof(item->item_id));
    item->schema_version = wire->schema_version;
    item->flags = wire->flags;
    result = backup_item_validate(item);
    return result == RINRUNTIME_BACKUP_INVALID_ARGUMENT
               ? RINRUNTIME_BACKUP_MALFORMED
               : result;
}

RinRuntimeBackupResult rinruntime_backup_manifest_encode(
    const RinRuntimeBackupManifestV1* manifest, uint8_t* bytes_out,
    size_t bytes_capacity, size_t* bytes_size_out)
{
    RinRuntimeBackupWireHeaderV1 header;
    RinRuntimeBackupWireItemV1 wire_item;
    RinRuntimeBackupResult result;
    size_t item_bytes_size;
    size_t total_size;
    uint32_t index;
    if (bytes_size_out != NULL) *bytes_size_out = 0u;
    result = backup_manifest_validate(manifest);
    if (result != RINRUNTIME_BACKUP_OK || bytes_out == NULL ||
        bytes_size_out == NULL)
        return result == RINRUNTIME_BACKUP_OK
                   ? RINRUNTIME_BACKUP_INVALID_ARGUMENT
                   : result;
    item_bytes_size = (size_t)manifest->item_count * sizeof(wire_item);
    total_size = sizeof(header) + item_bytes_size;
    if (total_size > bytes_capacity ||
        total_size > RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX)
        return RINRUNTIME_BACKUP_LIMIT;
    memset(&header, 0, sizeof(header));
    header.magic = RINRUNTIME_BACKUP_MAGIC;
    header.version = RINRUNTIME_BACKUP_VERSION;
    header.header_size = sizeof(header);
    header.total_size = (uint32_t)total_size;
    header.item_count = manifest->item_count;
    header.manifest_generation = manifest->manifest_generation;
    header.created_at_ns = manifest->created_at_ns;
    memcpy(header.application_id, manifest->identity.application_id,
           sizeof(header.application_id));
    memcpy(header.package_digest, manifest->identity.package_digest,
           sizeof(header.package_digest));
    header.package_generation = manifest->identity.package_generation;
    memcpy(bytes_out, &header, sizeof(header));
    for (index = 0u; index < manifest->item_count; ++index) {
        backup_item_to_wire(&manifest->items[index], &wire_item);
        memcpy(bytes_out + sizeof(header) + (size_t)index * sizeof(wire_item),
               &wire_item, sizeof(wire_item));
    }
    header.integrity = backup_integrity(
        &header, bytes_out + sizeof(header), item_bytes_size);
    memcpy(bytes_out, &header, sizeof(header));
    *bytes_size_out = total_size;
    return RINRUNTIME_BACKUP_OK;
}

static RinRuntimeBackupResult backup_wire_validate(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeBackupWireHeaderV1* header_out,
    RinRuntimeBackupManifestInfoV1* info_out)
{
    RinRuntimeBackupWireHeaderV1 header;
    RinRuntimeBackupWireHeaderV1 integrity_header;
    RinRuntimeBackupIdentityV1 identity;
    RinRuntimeBackupItemV1 prior_item;
    RinRuntimeBackupItemV1 item;
    size_t item_bytes_size;
    size_t expected_size;
    uint32_t index;
    uint32_t eligible_count = 0u;
    uint32_t excluded_count = 0u;
    if (bytes == NULL || bytes_size < sizeof(header))
        return RINRUNTIME_BACKUP_MALFORMED;
    memcpy(&header, bytes, sizeof(header));
    if (header.magic != RINRUNTIME_BACKUP_MAGIC ||
        header.version != RINRUNTIME_BACKUP_VERSION ||
        header.header_size != sizeof(header) || header.reserved0 != 0u ||
        header.item_count > RINRUNTIME_BACKUP_MAX_ITEMS)
        return RINRUNTIME_BACKUP_MALFORMED;
    item_bytes_size = (size_t)header.item_count *
                      sizeof(RinRuntimeBackupWireItemV1);
    expected_size = sizeof(header) + item_bytes_size;
    if (header.total_size != expected_size || bytes_size != expected_size ||
        expected_size > RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX)
        return RINRUNTIME_BACKUP_MALFORMED;
    integrity_header = header;
    integrity_header.integrity = 0u;
    if (header.integrity != backup_integrity(
                                &integrity_header, bytes + sizeof(header),
                                item_bytes_size))
        return RINRUNTIME_BACKUP_INTEGRITY_FAILED;
    memset(&identity, 0, sizeof(identity));
    identity.struct_size = sizeof(identity);
    identity.version = RINRUNTIME_BACKUP_VERSION;
    memcpy(identity.application_id, header.application_id,
           sizeof(identity.application_id));
    memcpy(identity.package_digest, header.package_digest,
           sizeof(identity.package_digest));
    identity.package_generation = header.package_generation;
    if (header.manifest_generation == 0u || header.created_at_ns == 0u ||
        !rinruntime_backup_identity_valid(&identity))
        return RINRUNTIME_BACKUP_MALFORMED;
    memset(&prior_item, 0, sizeof(prior_item));
    for (index = 0u; index < header.item_count; ++index) {
        RinRuntimeBackupWireItemV1 wire_item;
        RinRuntimeBackupResult item_result;
        memcpy(&wire_item, bytes + sizeof(header) +
                              (size_t)index * sizeof(wire_item),
               sizeof(wire_item));
        item_result = backup_item_from_wire(&wire_item, &item);
        if (item_result != RINRUNTIME_BACKUP_OK)
            return item_result == RINRUNTIME_BACKUP_INELIGIBLE
                       ? RINRUNTIME_BACKUP_INELIGIBLE
                       : RINRUNTIME_BACKUP_MALFORMED;
        if (index != 0u &&
            memcmp(prior_item.item_id, item.item_id,
                   RINRUNTIME_BACKUP_ITEM_ID_SIZE) >= 0)
            return RINRUNTIME_BACKUP_MALFORMED;
        if (rinruntime_backup_item_is_eligible(&item))
            ++eligible_count;
        else
            ++excluded_count;
        prior_item = item;
    }
    if (header_out != NULL) *header_out = header;
    if (info_out != NULL) {
        memset(info_out, 0, sizeof(*info_out));
        info_out->struct_size = sizeof(*info_out);
        info_out->version = RINRUNTIME_BACKUP_VERSION;
        info_out->identity = identity;
        info_out->manifest_generation = header.manifest_generation;
        info_out->created_at_ns = header.created_at_ns;
        info_out->item_count = header.item_count;
        info_out->eligible_item_count = eligible_count;
        info_out->excluded_item_count = excluded_count;
        info_out->manifest_size = header.total_size;
        info_out->integrity = header.integrity;
    }
    return RINRUNTIME_BACKUP_OK;
}

RinRuntimeBackupResult rinruntime_backup_manifest_inspect(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeBackupManifestInfoV1* info_out)
{
    if (info_out == NULL) return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    memset(info_out, 0, sizeof(*info_out));
    return backup_wire_validate(bytes, bytes_size, NULL, info_out);
}

RinRuntimeBackupResult rinruntime_backup_manifest_entry_at(
    const uint8_t* bytes, size_t bytes_size, uint32_t entry_index,
    RinRuntimeBackupItemV1* item_out)
{
    RinRuntimeBackupWireHeaderV1 header;
    RinRuntimeBackupWireItemV1 wire_item;
    RinRuntimeBackupResult result;
    if (item_out == NULL) return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    memset(item_out, 0, sizeof(*item_out));
    result = backup_wire_validate(bytes, bytes_size, &header, NULL);
    if (result != RINRUNTIME_BACKUP_OK) return result;
    if (entry_index >= header.item_count) return RINRUNTIME_BACKUP_LIMIT;
    memcpy(&wire_item, bytes + sizeof(header) +
                          (size_t)entry_index * sizeof(wire_item),
           sizeof(wire_item));
    return backup_item_from_wire(&wire_item, item_out);
}

static void backup_status_initialize(RinRuntimeBackupStatusV1* status_out)
{
    memset(status_out, 0, sizeof(*status_out));
    status_out->struct_size = sizeof(*status_out);
    status_out->version = RINRUNTIME_BACKUP_VERSION;
    status_out->flags = RINRUNTIME_BACKUP_STATUS_FRAMEWORK_AVAILABLE |
                        RINRUNTIME_BACKUP_STATUS_RESTORE_REQUIRES_APP_CONFIRMATION |
                        RINRUNTIME_BACKUP_STATUS_SENSITIVE_DATA_EXCLUDED;
}

RinRuntimeBackupResult rinruntime_backup_status_unconfigured(
    RinRuntimeBackupStatusV1* status_out)
{
    if (status_out == NULL) return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    backup_status_initialize(status_out);
    return RINRUNTIME_BACKUP_OK;
}

RinRuntimeBackupResult rinruntime_backup_status_from_manifest(
    const uint8_t* bytes, size_t bytes_size,
    RinRuntimeBackupStatusV1* status_out)
{
    RinRuntimeBackupResult result;
    if (status_out == NULL) return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    backup_status_initialize(status_out);
    result = rinruntime_backup_manifest_inspect(bytes, bytes_size,
                                                &status_out->manifest);
    if (result != RINRUNTIME_BACKUP_OK) {
        backup_status_initialize(status_out);
        return result;
    }
    status_out->flags |= RINRUNTIME_BACKUP_STATUS_MANIFEST_DECLARED;
    return RINRUNTIME_BACKUP_OK;
}

static int backup_identity_equal(const RinRuntimeBackupIdentityV1* left,
                                 const RinRuntimeBackupIdentityV1* right)
{
    return memcmp(left->application_id, right->application_id,
                  sizeof(left->application_id)) == 0 &&
           memcmp(left->package_digest, right->package_digest,
                  sizeof(left->package_digest)) == 0 &&
           left->package_generation == right->package_generation;
}

RinRuntimeBackupResult rinruntime_backup_restore_item(
    const uint8_t* source_manifest_bytes, size_t source_manifest_size,
    uint32_t item_index, const RinRuntimeBackupIdentityV1* target_identity,
    uint64_t target_schema_version,
    RinRuntimeBackupIdentityAuthorizerFn authorize_identity,
    void* authorize_context, RinRuntimeBackupMigrationFn migrate,
    void* migrate_context, const uint8_t* archived_bytes,
    uint32_t archived_size, uint8_t* restored_out,
    uint32_t restored_capacity, uint32_t* restored_size_out)
{
    RinRuntimeBackupManifestInfoV1 source_manifest;
    RinRuntimeBackupItemV1 item;
    RinRuntimeBackupResult item_result;
    if (restored_size_out != NULL) *restored_size_out = 0u;
    if (!rinruntime_backup_identity_valid(target_identity) ||
        restored_size_out == NULL || target_schema_version == 0u ||
        (archived_size != 0u && archived_bytes == NULL) ||
        (archived_size != 0u && restored_out == NULL))
        return RINRUNTIME_BACKUP_INVALID_ARGUMENT;
    item_result = rinruntime_backup_manifest_inspect(
        source_manifest_bytes, source_manifest_size, &source_manifest);
    if (item_result != RINRUNTIME_BACKUP_OK) return item_result;
    item_result = rinruntime_backup_manifest_entry_at(
        source_manifest_bytes, source_manifest_size, item_index, &item);
    if (item_result != RINRUNTIME_BACKUP_OK) return item_result;
    if (!rinruntime_backup_item_is_eligible(&item))
        return RINRUNTIME_BACKUP_INELIGIBLE;
    if (!backup_identity_equal(&source_manifest.identity, target_identity)) {
        if (authorize_identity == NULL)
            return RINRUNTIME_BACKUP_IDENTITY_MISMATCH;
        if (authorize_identity(authorize_context, &source_manifest.identity,
                               target_identity) != 1)
            return RINRUNTIME_BACKUP_IDENTITY_NOT_AUTHORIZED;
    }
    if (item.schema_version == target_schema_version) {
        if (restored_capacity < archived_size) return RINRUNTIME_BACKUP_LIMIT;
        if (archived_size != 0u)
            memmove(restored_out, archived_bytes, archived_size);
        *restored_size_out = archived_size;
        return RINRUNTIME_BACKUP_OK;
    }
    if (migrate == NULL) return RINRUNTIME_BACKUP_MIGRATION_REQUIRED;
    if (migrate(migrate_context, &item, item.schema_version,
                target_schema_version, archived_bytes, archived_size,
                restored_out, restored_capacity, restored_size_out) != 0 ||
        *restored_size_out > restored_capacity) {
        *restored_size_out = 0u;
        return RINRUNTIME_BACKUP_MIGRATION_FAILED;
    }
    return RINRUNTIME_BACKUP_OK;
}

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinRuntimeBackupWireHeaderV1) == 112u,
               "RinRuntimeBackupWireHeaderV1 ABI drift");
_Static_assert(sizeof(RinRuntimeBackupWireItemV1) == 64u,
               "RinRuntimeBackupWireItemV1 ABI drift");
_Static_assert(sizeof(RinRuntimeBackupIdentityV1) == 96u,
               "RinRuntimeBackupIdentityV1 ABI drift");
#endif
