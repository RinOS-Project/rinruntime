/* SPDX-License-Identifier: MIT */

#include "../include/rinruntime/backup_archive.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

static RinRuntimeBackupIdentityV1 makeIdentity(std::uint8_t seed)
{
    RinRuntimeBackupIdentityV1 identity{};
    identity.struct_size = sizeof(identity);
    identity.version = RINRUNTIME_BACKUP_VERSION;
    identity.package_generation = 7u;
    for (std::size_t index = 0u;
         index < RINRUNTIME_BACKUP_APPLICATION_ID_SIZE; ++index)
        identity.application_id[index] =
            static_cast<std::uint8_t>(seed + index + 1u);
    for (std::size_t index = 0u;
         index < RINRUNTIME_BACKUP_PACKAGE_DIGEST_SIZE; ++index)
        identity.package_digest[index] =
            static_cast<std::uint8_t>(seed + index + 33u);
    return identity;
}

static RinRuntimeBackupItemV1 makeItem(const char* itemId,
                                       std::uint16_t storageClass,
                                       std::uint16_t flags,
                                       std::uint64_t schemaVersion)
{
    RinRuntimeBackupItemV1 item{};
    item.struct_size = sizeof(item);
    item.version = RINRUNTIME_BACKUP_VERSION;
    item.storage_class = storageClass;
    std::memcpy(item.item_id, itemId, std::strlen(itemId));
    item.schema_version = schemaVersion;
    item.flags = flags;
    return item;
}

static std::vector<std::uint8_t> encodeManifest(
    const RinRuntimeBackupIdentityV1& identity,
    RinRuntimeBackupItemV1* items, std::uint32_t itemCount)
{
    RinRuntimeBackupManifestV1 manifest{};
    manifest.struct_size = sizeof(manifest);
    manifest.version = RINRUNTIME_BACKUP_VERSION;
    manifest.identity = identity;
    manifest.manifest_generation = 11u;
    manifest.created_at_ns = 22u;
    manifest.items = items;
    manifest.item_count = itemCount;

    std::vector<std::uint8_t> bytes(
        RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX, 0u);
    std::size_t size = 0u;
    assert(rinruntime_backup_manifest_encode(
               &manifest, bytes.data(), bytes.size(), &size) ==
           RINRUNTIME_BACKUP_OK);
    bytes.resize(size);
    return bytes;
}

static std::vector<std::uint8_t> makeArchive(
    const std::vector<std::uint8_t>& manifest, bool includeConfig,
    bool includeData, bool includeExcluded, bool includeUnknown)
{
    RinRuntime::ArchiveZipWriter writer;
    assert(writer.addStored("manifest.rbk1", manifest.data(), manifest.size()) ==
           RinRuntime::ArchiveZipResult::Ok);
    const char config[] = "configuration bytes";
    const char data[] = "document payload";
    if (includeConfig)
        assert(writer.addDeflated(
                   "payload/config", reinterpret_cast<const std::uint8_t*>(
                                          config), sizeof(config) - 1u) ==
               RinRuntime::ArchiveZipResult::Ok);
    if (includeData)
        assert(writer.addStored(
                   "payload/data", reinterpret_cast<const std::uint8_t*>(data),
                   sizeof(data) - 1u) == RinRuntime::ArchiveZipResult::Ok);
    if (includeExcluded)
        assert(writer.addStored(
                   "payload/cache", reinterpret_cast<const std::uint8_t*>(data),
                   sizeof(data) - 1u) == RinRuntime::ArchiveZipResult::Ok);
    if (includeUnknown)
        assert(writer.addStored(
                   "payload/unknown", reinterpret_cast<const std::uint8_t*>(data),
                   sizeof(data) - 1u) == RinRuntime::ArchiveZipResult::Ok);

    std::vector<std::uint8_t> archive;
    assert(writer.finish(archive) == RinRuntime::ArchiveZipResult::Ok);
    return archive;
}

static bool cancelNow(void* context)
{
    return context != nullptr && *static_cast<const std::uint32_t*>(context) != 0u;
}

int main()
{
    const RinRuntimeBackupIdentityV1 identity = makeIdentity(0x10u);
    RinRuntimeBackupItemV1 items[] = {
        makeItem("cache", RINRUNTIME_BACKUP_STORAGE_CACHE,
                 RINRUNTIME_BACKUP_ITEM_EXCLUDE, 1u),
        makeItem("config", RINRUNTIME_BACKUP_STORAGE_CONFIG,
                 RINRUNTIME_BACKUP_ITEM_INCLUDE, 1u),
        makeItem("data", RINRUNTIME_BACKUP_STORAGE_DATA,
                 RINRUNTIME_BACKUP_ITEM_INCLUDE, 1u),
    };
    const std::vector<std::uint8_t> manifest =
        encodeManifest(identity, items, 3u);
    const std::vector<std::uint8_t> archive =
        makeArchive(manifest, true, true, false, false);

    RinRuntime::BackupArchiveReader reader;
    assert(reader.parse(archive.data(), archive.size()) ==
           RinRuntime::BackupArchiveResult::Ok);
    assert(reader.parsed());
    assert(reader.manifestInfo().item_count == 3u);
    assert(reader.manifestInfo().eligible_item_count == 2u);
    assert(reader.manifestInfo().excluded_item_count == 1u);

    std::uint8_t restored[64];
    std::memset(restored, 0xa5, sizeof(restored));
    std::uint32_t restoredSize = 0u;
    assert(reader.readItem(
               1u, &identity, 1u, nullptr, nullptr, nullptr, nullptr,
               restored, sizeof(restored), &restoredSize) ==
           RinRuntime::BackupArchiveResult::Ok);
    const char expectedConfig[] = "configuration bytes";
    assert(restoredSize == sizeof(expectedConfig) - 1u &&
           std::memcmp(restored, expectedConfig, restoredSize) == 0);

    std::memset(restored, 0xa5, sizeof(restored));
    restoredSize = 99u;
    assert(reader.readItem(0u, &identity, 1u, nullptr, nullptr, nullptr,
                           nullptr, restored, sizeof(restored),
                           &restoredSize) ==
           RinRuntime::BackupArchiveResult::Ineligible);
    assert(restoredSize == 0u);
    for (std::uint8_t byte : restored) assert(byte == 0u);

    RinRuntimeBackupIdentityV1 otherIdentity = makeIdentity(0x40u);
    std::memset(restored, 0xa5, sizeof(restored));
    restoredSize = 99u;
    assert(reader.readItem(1u, &otherIdentity, 1u, nullptr, nullptr, nullptr,
                           nullptr, restored, sizeof(restored),
                           &restoredSize) ==
           RinRuntime::BackupArchiveResult::IdentityMismatch);
    assert(restoredSize == 0u);
    for (std::uint8_t byte : restored) assert(byte == 0u);

    std::memset(restored, 0xa5, sizeof(restored));
    restoredSize = 99u;
    assert(reader.readItem(1u, &identity, 1u, nullptr, nullptr, nullptr,
                           nullptr, restored, 1u,
                           &restoredSize) == RinRuntime::BackupArchiveResult::Limit);
    assert(restoredSize == 0u);
    assert(restored[0] == 0u);
    for (std::size_t index = 1u; index < sizeof(restored); ++index)
        assert(restored[index] == 0xa5u);

    std::uint32_t cancellation = 1u;
    std::memset(restored, 0xa5, sizeof(restored));
    restoredSize = 99u;
    assert(reader.readItem(1u, &identity, 1u, nullptr, nullptr, nullptr,
                           nullptr, restored, sizeof(restored), &restoredSize,
                           &cancelNow, &cancellation) ==
           RinRuntime::BackupArchiveResult::Cancelled);
    assert(restoredSize == 0u);
    for (std::uint8_t byte : restored) assert(byte == 0u);

    const std::vector<std::uint8_t> missingData =
        makeArchive(manifest, true, false, false, false);
    assert(reader.parse(missingData.data(), missingData.size()) ==
           RinRuntime::BackupArchiveResult::Malformed);
    assert(!reader.parsed() && reader.manifestInfo().item_count == 0u);

    const std::vector<std::uint8_t> excludedPayload =
        makeArchive(manifest, true, true, true, false);
    assert(reader.parse(excludedPayload.data(), excludedPayload.size()) ==
           RinRuntime::BackupArchiveResult::Malformed);

    const std::vector<std::uint8_t> unknownPayload =
        makeArchive(manifest, true, true, false, true);
    assert(reader.parse(unknownPayload.data(), unknownPayload.size()) ==
           RinRuntime::BackupArchiveResult::Malformed);

    std::vector<std::uint8_t> corrupted = archive;
    corrupted[corrupted.size() - 1u] ^= 0x01u;
    assert(reader.parse(corrupted.data(), corrupted.size()) ==
           RinRuntime::BackupArchiveResult::Malformed);
    return 0;
}
