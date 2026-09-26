/* SPDX-License-Identifier: MIT */
/* Public, memory-only RBK1 ZIP archive consumer. */

#ifndef RINRUNTIME_BACKUP_ARCHIVE_HPP
#define RINRUNTIME_BACKUP_ARCHIVE_HPP

#include "archive_zip.hpp"
#include "backup_restore.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace RinRuntime {

enum class BackupArchiveResult : int {
    Ok = RINRUNTIME_BACKUP_OK,
    InvalidArgument = RINRUNTIME_BACKUP_INVALID_ARGUMENT,
    Limit = RINRUNTIME_BACKUP_LIMIT,
    Malformed = RINRUNTIME_BACKUP_MALFORMED,
    IntegrityFailed = RINRUNTIME_BACKUP_INTEGRITY_FAILED,
    Ineligible = RINRUNTIME_BACKUP_INELIGIBLE,
    IdentityMismatch = RINRUNTIME_BACKUP_IDENTITY_MISMATCH,
    IdentityNotAuthorized = RINRUNTIME_BACKUP_IDENTITY_NOT_AUTHORIZED,
    MigrationRequired = RINRUNTIME_BACKUP_MIGRATION_REQUIRED,
    MigrationFailed = RINRUNTIME_BACKUP_MIGRATION_FAILED,
    TransportFailed = RINRUNTIME_BACKUP_TRANSPORT_FAILED,
    Cancelled = -11,
};

/*
 * Consume the public RBK1 backup layout from a caller-owned ZIP image:
 *
 *   manifest.rbk1
 *   payload/<logical item id>  (one entry for each included item)
 *
 * The reader never opens a path, resolves a known folder, authenticates a
 * package, or publishes restored bytes.  The caller supplies the target
 * identity and the authenticated launcher callbacks to readItem(), while a
 * private archive/File Portal owner remains responsible for transport and
 * publication.
 */
class BackupArchiveReader final {
public:
    BackupArchiveReader() = default;

    BackupArchiveResult parse(const std::uint8_t* bytes, std::size_t size)
    {
        clear();
        const ArchiveZipResult archiveResult = zip_.parse(bytes, size);
        if (archiveResult != ArchiveZipResult::Ok)
            return fail(fromArchiveResult(archiveResult));

        std::size_t manifestIndex = npos;
        const std::vector<ArchiveZipEntry>& entries = zip_.entries();
        for (std::size_t index = 0u; index < entries.size(); ++index) {
            const ArchiveZipEntry& entry = entries[index];
            if (entry.directory)
                return fail(BackupArchiveResult::Malformed);
            if (entry.name == "manifest.rbk1") {
                if (manifestIndex != npos)
                    return fail(BackupArchiveResult::Malformed);
                manifestIndex = index;
                continue;
            }
            if (entry.name.size() <= payloadPrefixSize() ||
                entry.name.compare(0u, payloadPrefixSize(), "payload/") != 0)
                return fail(BackupArchiveResult::Malformed);
        }
        if (manifestIndex == npos)
            return fail(BackupArchiveResult::Malformed);

        const ArchiveZipEntry& manifestEntry = entries[manifestIndex];
        if (manifestEntry.uncompressedSize >
            RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX)
            return fail(BackupArchiveResult::Limit);
        std::string manifestBytes;
        const ArchiveZipResult manifestRead =
            zip_.readEntry(manifestIndex, manifestBytes);
        if (manifestRead != ArchiveZipResult::Ok)
            return fail(fromArchiveResult(manifestRead));
        if (manifestBytes.size() > RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX)
            return fail(BackupArchiveResult::Limit);

        RinRuntimeBackupManifestInfoV1 info{};
        const RinRuntimeBackupResult inspectResult =
            rinruntime_backup_manifest_inspect(
                reinterpret_cast<const std::uint8_t*>(manifestBytes.data()),
                manifestBytes.size(), &info);
        if (inspectResult != RINRUNTIME_BACKUP_OK)
            return fail(fromBackupResult(inspectResult));

        manifestBytes_ = std::move(manifestBytes);
        info_ = info;
        payloadIndices_.assign(info_.item_count, npos);

        for (std::size_t index = 0u; index < entries.size(); ++index) {
            const ArchiveZipEntry& entry = entries[index];
            if (entry.name == "manifest.rbk1")
                continue;
            bool matched = false;
            for (std::uint32_t itemIndex = 0u;
                 itemIndex < info_.item_count; ++itemIndex) {
                RinRuntimeBackupItemV1 item{};
                const RinRuntimeBackupResult itemResult =
                    rinruntime_backup_manifest_entry_at(
                        reinterpret_cast<const std::uint8_t*>(
                            manifestBytes_.data()),
                        manifestBytes_.size(), itemIndex, &item);
                if (itemResult != RINRUNTIME_BACKUP_OK)
                    return fail(fromBackupResult(itemResult));
                if (!payloadNameMatches(entry, item.item_id))
                    continue;
                if (!rinruntime_backup_item_is_eligible(&item))
                    return fail(BackupArchiveResult::Malformed);
                if (payloadIndices_[itemIndex] != npos)
                    return fail(BackupArchiveResult::Malformed);
                payloadIndices_[itemIndex] = index;
                matched = true;
                break;
            }
            if (!matched)
                return fail(BackupArchiveResult::Malformed);
        }

        for (std::uint32_t itemIndex = 0u; itemIndex < info_.item_count;
             ++itemIndex) {
            RinRuntimeBackupItemV1 item{};
            const RinRuntimeBackupResult itemResult =
                rinruntime_backup_manifest_entry_at(
                    reinterpret_cast<const std::uint8_t*>(manifestBytes_.data()),
                    manifestBytes_.size(), itemIndex, &item);
            if (itemResult != RINRUNTIME_BACKUP_OK)
                return fail(fromBackupResult(itemResult));
            if (rinruntime_backup_item_is_eligible(&item) &&
                payloadIndices_[itemIndex] == npos)
                return fail(BackupArchiveResult::Malformed);
        }

        parsed_ = true;
        return BackupArchiveResult::Ok;
    }

    void clear()
    {
        zip_.clear();
        manifestBytes_.clear();
        info_ = RinRuntimeBackupManifestInfoV1{};
        payloadIndices_.clear();
        parsed_ = false;
    }

    bool parsed() const { return parsed_; }

    const RinRuntimeBackupManifestInfoV1& manifestInfo() const { return info_; }

    BackupArchiveResult readItem(
        std::uint32_t itemIndex,
        const RinRuntimeBackupIdentityV1* targetIdentity,
        std::uint64_t targetSchemaVersion,
        RinRuntimeBackupIdentityAuthorizerFn authorizeIdentity,
        void* authorizeContext, RinRuntimeBackupMigrationFn migrate,
        void* migrateContext, std::uint8_t* restoredOut,
        std::uint32_t restoredCapacity, std::uint32_t* restoredSizeOut,
        ArchiveDeflateCancellationFunction cancellation = nullptr,
        void* cancellationContext = nullptr) const
    {
        clearRestoreOutput(restoredOut, restoredCapacity, restoredSizeOut);
        if (!parsed_ || targetIdentity == nullptr ||
            !rinruntime_backup_identity_valid(targetIdentity) ||
            targetSchemaVersion == 0u || restoredSizeOut == nullptr ||
            itemIndex >= payloadIndices_.size())
            return BackupArchiveResult::InvalidArgument;
        if (payloadIndices_[itemIndex] == npos)
            return BackupArchiveResult::Ineligible;

        std::string archivedBytes;
        const ArchiveZipResult readResult = zip_.readEntry(
            payloadIndices_[itemIndex], archivedBytes, cancellation,
            cancellationContext);
        if (readResult != ArchiveZipResult::Ok)
            return fromArchiveResult(readResult);
        if (archivedBytes.size() > std::numeric_limits<std::uint32_t>::max())
            return BackupArchiveResult::Limit;

        const std::uint8_t* archived =
            archivedBytes.empty()
                ? nullptr
                : reinterpret_cast<const std::uint8_t*>(archivedBytes.data());
        return fromBackupResult(rinruntime_backup_restore_item(
            reinterpret_cast<const std::uint8_t*>(manifestBytes_.data()),
            manifestBytes_.size(), itemIndex, targetIdentity,
            targetSchemaVersion, authorizeIdentity, authorizeContext, migrate,
            migrateContext, archived,
            static_cast<std::uint32_t>(archivedBytes.size()), restoredOut,
            restoredCapacity, restoredSizeOut));
    }

private:
    static constexpr std::size_t npos = std::numeric_limits<std::size_t>::max();

    static constexpr std::size_t payloadPrefixSize() { return 8u; }

    static std::size_t itemIdLength(
        const std::uint8_t itemId[RINRUNTIME_BACKUP_ITEM_ID_SIZE])
    {
        for (std::size_t index = 0u; index < RINRUNTIME_BACKUP_ITEM_ID_SIZE;
             ++index)
            if (itemId[index] == 0u)
                return index;
        return 0u;
    }

    static bool payloadNameMatches(
        const ArchiveZipEntry& entry,
        const std::uint8_t itemId[RINRUNTIME_BACKUP_ITEM_ID_SIZE])
    {
        if (entry.name.size() <= payloadPrefixSize() ||
            entry.name.compare(0u, payloadPrefixSize(), "payload/") != 0)
            return false;
        const std::size_t idLength = itemIdLength(itemId);
        const std::size_t nameIdLength = entry.name.size() - payloadPrefixSize();
        return idLength != 0u && idLength == nameIdLength &&
               std::memcmp(entry.name.data() + payloadPrefixSize(), itemId,
                           idLength) == 0;
    }

    static void clearRestoreOutput(std::uint8_t* restoredOut,
                                   std::uint32_t restoredCapacity,
                                   std::uint32_t* restoredSizeOut)
    {
        if (restoredOut != nullptr && restoredCapacity != 0u)
            std::memset(restoredOut, 0, restoredCapacity);
        if (restoredSizeOut != nullptr)
            *restoredSizeOut = 0u;
    }

    static BackupArchiveResult fromArchiveResult(ArchiveZipResult result)
    {
        switch (result) {
        case ArchiveZipResult::Ok:
            return BackupArchiveResult::Ok;
        case ArchiveZipResult::InvalidArgument:
            return BackupArchiveResult::InvalidArgument;
        case ArchiveZipResult::Limit:
            return BackupArchiveResult::Limit;
        case ArchiveZipResult::Cancelled:
            return BackupArchiveResult::Cancelled;
        case ArchiveZipResult::Malformed:
        default:
            return BackupArchiveResult::Malformed;
        }
    }

    static BackupArchiveResult fromBackupResult(RinRuntimeBackupResult result)
    {
        return static_cast<BackupArchiveResult>(result);
    }

    BackupArchiveResult fail(BackupArchiveResult result)
    {
        clear();
        return result;
    }

    ArchiveZipReader zip_;
    std::string manifestBytes_;
    RinRuntimeBackupManifestInfoV1 info_{};
    std::vector<std::size_t> payloadIndices_;
    bool parsed_ = false;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_BACKUP_ARCHIVE_HPP */
