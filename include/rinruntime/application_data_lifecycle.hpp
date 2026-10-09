/* SPDX-License-Identifier: MIT */
/* Identity-bound application data uninstall and restore lifecycle. */

#ifndef RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP
#define RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP

#include "application_data.hpp"
#include "backup_archive.hpp"
#include "backup_restore.h"
#include "known_folders.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
#    include <new>
#endif
#include <string>
#include <utility>

namespace RinRuntime {

enum class ApplicationDataLifecycleResult : int {
    Ok = 0,
    InvalidArgument = -1,
    KnownFolderUnavailable = -2,
    IdentityMismatch = -3,
    ArchivePathUnavailable = -4,
    RestoreNotAuthorized = -5,
    MigrationRequired = -6,
    MigrationFailed = -7,
    PublishFailed = -8,
    AllocationFailed = -9,
    InvalidArchive = -10,
    RestoreTransactionFailed = -11,
    RestoreRollbackFailed = -12,
    RestoreScratchTooSmall = -13,
};

/* The application id is the same authenticated logical id used by the
 * package launcher.  It is never interpreted as a path.  backupIdentity is
 * copied from the signed launcher handoff and is checked against this
 * profile before any Known Folder path is exposed to an owner. */
struct ApplicationDataProfile final {
    ApplicationDataIdentity owner{};
    std::string applicationId;
    RinRuntimeBackupIdentityV1 backupIdentity{};
    std::uint64_t dataSchemaVersion = 0u;
};

/* Product launchers provide this owner for lifecycle mutations.  The
 * callback is an authority boundary: it resolves a root only for the exact
 * authenticated user/application identity supplied by the launcher.  The
 * returned value is a canonical directory label, not a capability by
 * itself; the filesystem owner must still enforce access on open/mutate. */
using ApplicationDataKnownFolderResolveFn = int (*)(
    void* context, const ApplicationDataIdentity* owner,
    const char* applicationId, RinRuntimeApplicationDirectory directory,
    char* pathOut, std::size_t pathCapacity);

struct ApplicationDataKnownFolderOwner final {
    ApplicationDataIdentity identity{};
    ApplicationDataKnownFolderResolveFn resolve = nullptr;
    void* context = nullptr;

    bool validFor(const ApplicationDataIdentity& expected) const {
        return resolve != nullptr &&
               identity.userId == expected.userId &&
               identity.applicationTag == expected.applicationTag &&
               identity.packageGeneration == expected.packageGeneration;
    }
};

struct ApplicationDataLifecyclePlan final {
    ApplicationDataIdentity owner{};
    std::string applicationId;
    std::string dataRoot;
    std::string cacheRoot;
    std::string stateRoot;
    std::string backupRoot;
    std::string archiveRoot;
    ApplicationDataUninstallAction dataAction =
        ApplicationDataUninstallAction::RemoveUserData;
    ApplicationDataUninstallAction cacheAction =
        ApplicationDataUninstallAction::RemoveTransientCache;
    std::uint64_t archiveGeneration = 0u;
    bool preserveUserData = false;
    /* True only when all roots came from the authenticated owner callback. */
    bool ownerBound = false;
};

/* The publisher is called only after RBK1 identity, item eligibility and
 * schema migration have completed into caller-owned isolated storage.  It
 * receives the validated Known Folder plan and a logical item id, never an
 * untrusted source path.  A non-zero result keeps the bytes unpublished. */
using ApplicationDataRestorePublishFn = int (*)(
    void* context, const ApplicationDataLifecyclePlan* plan,
    const RinRuntimeBackupItemV1* item, const std::uint8_t* bytes,
    std::uint32_t size);

/* A product owner implements these callbacks with one private staging area.
 * begin() must reserve an unpublished transaction, stageItem() must copy the
 * supplied bytes before returning, commit() must publish every staged item
 * atomically, and rollback() must remove the unpublished transaction. A
 * callback failure or exception never means that partially published data is
 * accepted by this common layer. */
using ApplicationDataRestoreBeginFn = int (*)(
    void* context, const ApplicationDataLifecyclePlan* plan,
    const RinRuntimeBackupManifestInfoV1* manifest);
using ApplicationDataRestoreStageItemFn = int (*)(
    void* context, const ApplicationDataLifecyclePlan* plan,
    const RinRuntimeBackupItemV1* item, const std::uint8_t* bytes,
    std::uint32_t size);
using ApplicationDataRestoreCommitFn = int (*)(
    void* context, const ApplicationDataLifecyclePlan* plan,
    std::uint32_t stagedItemCount);
using ApplicationDataRestoreRollbackFn = int (*)(
    void* context, const ApplicationDataLifecyclePlan* plan);

struct ApplicationDataRestoreTransactionOwner final {
    ApplicationDataRestoreBeginFn begin = nullptr;
    ApplicationDataRestoreStageItemFn stageItem = nullptr;
    ApplicationDataRestoreCommitFn commit = nullptr;
    ApplicationDataRestoreRollbackFn rollback = nullptr;
    void* context = nullptr;

    bool valid() const {
        return begin != nullptr && stageItem != nullptr &&
               commit != nullptr && rollback != nullptr;
    }
};

/* Optional launcher authorization for restoring data across a package
 * digest/generation change.  The callback must be owned by the authenticated
 * launcher; an application callback must not be used to self-authorize. */
using ApplicationDataIdentityAuthorizerFn =
    RinRuntimeBackupIdentityAuthorizerFn;
using ApplicationDataMigrationFn = RinRuntimeBackupMigrationFn;

class ApplicationDataLifecycle final {
    static bool profileIdentityMatches(
        const ApplicationDataProfile& profile) {
        if (!ApplicationDataPolicy::validIdentity(profile.owner) ||
            !ApplicationDataPolicy::validApplicationId(profile.applicationId) ||
            profile.applicationId.size() >=
                RINRUNTIME_BACKUP_APPLICATION_ID_SIZE ||
            profile.dataSchemaVersion == 0u ||
            !rinruntime_backup_identity_valid(&profile.backupIdentity) ||
            profile.owner.packageGeneration !=
                profile.backupIdentity.package_generation)
            return false;
        for (std::size_t index = 0u;
             index < RINRUNTIME_BACKUP_APPLICATION_ID_SIZE; ++index) {
            const std::uint8_t expected =
                index < profile.applicationId.size()
                    ? static_cast<std::uint8_t>(profile.applicationId[index])
                    : 0u;
            if (profile.backupIdentity.application_id[index] != expected)
                return false;
        }
        return true;
    }

    static bool appendGeneration(std::string& path,
                                 std::uint64_t generation) {
        char digits[20] = {};
        std::size_t count = 0u;
        if (generation == 0u || path.empty()) return false;
        do {
            digits[count++] = static_cast<char>('0' + generation % 10u);
            generation /= 10u;
        } while (generation != 0u && count < sizeof(digits));
        if (generation != 0u || path.size() + 1u + count >=
                                    RINRUNTIME_KNOWN_FOLDER_PATH_MAX)
            return false;
        path.push_back('/');
        while (count != 0u) path.push_back(digits[--count]);
        return true;
    }

    static ApplicationDataLifecycleResult resolveDirectory(
        RinRuntimeApplicationDirectory directory,
        const std::string& applicationId, std::string& output) {
        char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX] = {};
        if (rinruntime_application_directory_current(
                directory, applicationId.c_str(), path, sizeof(path)) !=
            RINRUNTIME_KNOWN_FOLDER_OK)
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;
        output.assign(path);
        return output.empty() ? ApplicationDataLifecycleResult::KnownFolderUnavailable
                              : ApplicationDataLifecycleResult::Ok;
    }

    static bool resolvedRootValid(const std::string& path,
                                  const std::string& applicationId) {
        if (path.empty() || path.size() >= RINRUNTIME_KNOWN_FOLDER_PATH_MAX ||
            path.front() != '/' || path.back() == '/' ||
            !ApplicationDataPolicy::validApplicationId(applicationId))
            return false;
        std::size_t componentStart = 1u;
        for (std::size_t index = 1u; index <= path.size(); ++index) {
            if (index != path.size() && path[index] != '/') {
                const unsigned char byte =
                    static_cast<unsigned char>(path[index]);
                if (byte < 0x20u || byte == 0x7fu || byte == '\\')
                    return false;
                continue;
            }
            const std::size_t componentLength = index - componentStart;
            if (componentLength == 0u ||
                (componentLength == 1u && path[componentStart] == '.') ||
                (componentLength == 2u && path[componentStart] == '.' &&
                 path[componentStart + 1u] == '.'))
                return false;
            componentStart = index + 1u;
        }
        const std::string suffix = "/" + applicationId;
        return path.size() > suffix.size() &&
               path.compare(path.size() - suffix.size(), suffix.size(),
                            suffix) == 0;
    }

    static ApplicationDataLifecycleResult resolveOwnedDirectory(
        const ApplicationDataProfile& profile,
        const ApplicationDataKnownFolderOwner& owner,
        RinRuntimeApplicationDirectory directory, std::string& output) {
        char path[RINRUNTIME_KNOWN_FOLDER_PATH_MAX] = {};
        int resolveResult = -1;
        output.clear();
        if (!profileIdentityMatches(profile) ||
            !owner.validFor(profile.owner))
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            resolveResult = owner.resolve(
                owner.context, &profile.owner, profile.applicationId.c_str(),
                directory, path, sizeof(path));
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            output.clear();
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;
        }
#endif
        if (resolveResult != 0 ||
            std::memchr(path, '\0', sizeof(path)) == nullptr)
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;
        output.assign(path);
        return resolvedRootValid(output, profile.applicationId)
                   ? ApplicationDataLifecycleResult::Ok
                   : ApplicationDataLifecycleResult::KnownFolderUnavailable;
    }

    static ApplicationDataLifecycleResult mapRestoreResult(
        RinRuntimeBackupResult result) {
        switch (result) {
        case RINRUNTIME_BACKUP_OK:
            return ApplicationDataLifecycleResult::Ok;
        case RINRUNTIME_BACKUP_IDENTITY_MISMATCH:
        case RINRUNTIME_BACKUP_IDENTITY_NOT_AUTHORIZED:
            return result == RINRUNTIME_BACKUP_IDENTITY_MISMATCH
                ? ApplicationDataLifecycleResult::IdentityMismatch
                : ApplicationDataLifecycleResult::RestoreNotAuthorized;
        case RINRUNTIME_BACKUP_MIGRATION_REQUIRED:
            return ApplicationDataLifecycleResult::MigrationRequired;
        case RINRUNTIME_BACKUP_MIGRATION_FAILED:
            return ApplicationDataLifecycleResult::MigrationFailed;
        default:
            return ApplicationDataLifecycleResult::InvalidArgument;
        }
    }

    static bool itemIdLength(const RinRuntimeBackupItemV1& item,
                             std::size_t& length) {
        length = 0u;
        while (length < RINRUNTIME_BACKUP_ITEM_ID_SIZE &&
               item.item_id[length] != 0u)
            ++length;
        if (length == 0u || length == RINRUNTIME_BACKUP_ITEM_ID_SIZE)
            return false;
        return ApplicationDataPolicy::validLogicalKey(
            std::string(reinterpret_cast<const char*>(item.item_id), length));
    }

    static ApplicationDataLifecycleResult restoreItemFromPlan(
        const ApplicationDataProfile& profile,
        const ApplicationDataLifecyclePlan& plan,
        const std::uint8_t* sourceManifestBytes,
        std::size_t sourceManifestSize, std::uint32_t itemIndex,
        ApplicationDataIdentityAuthorizerFn authorizeIdentity,
        void* authorizeContext, ApplicationDataMigrationFn migrate,
        void* migrateContext, const std::uint8_t* archivedBytes,
        std::uint32_t archivedSize, std::uint8_t* restoredOut,
        std::uint32_t restoredCapacity, std::uint32_t* restoredSizeOut,
        ApplicationDataRestorePublishFn publish, void* publishContext) {
        const auto clearRestoreOutput = [&]() noexcept {
            if (restoredOut != nullptr && restoredCapacity != 0u)
                std::memset(restoredOut, 0, restoredCapacity);
            if (restoredSizeOut != nullptr) *restoredSizeOut = 0u;
        };
        RinRuntimeBackupItemV1 item{};
        std::size_t itemLength = 0u;
        if (restoredSizeOut != nullptr) *restoredSizeOut = 0u;
        if (restoredOut != nullptr && restoredCapacity != 0u)
            std::memset(restoredOut, 0, restoredCapacity);
        if (restoredSizeOut == nullptr || publish == nullptr ||
            (archivedSize != 0u &&
             (archivedBytes == nullptr || restoredOut == nullptr)))
            return ApplicationDataLifecycleResult::InvalidArgument;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
        RinRuntimeBackupResult result = rinruntime_backup_manifest_entry_at(
            sourceManifestBytes, sourceManifestSize, itemIndex, &item);
        if (result != RINRUNTIME_BACKUP_OK || !itemIdLength(item, itemLength))
            return mapRestoreResult(result == RINRUNTIME_BACKUP_OK
                                         ? RINRUNTIME_BACKUP_INVALID_ARGUMENT
                                         : result);
        result = rinruntime_backup_restore_item(
            sourceManifestBytes, sourceManifestSize, itemIndex,
            &profile.backupIdentity, profile.dataSchemaVersion,
            authorizeIdentity, authorizeContext, migrate, migrateContext,
            archivedBytes, archivedSize, restoredOut, restoredCapacity,
            restoredSizeOut);
        if (result != RINRUNTIME_BACKUP_OK)
            return mapRestoreResult(result);
        int publishResult = 0;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            publishResult = publish(publishContext, &plan, &item, restoredOut,
                                    *restoredSizeOut);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            clearRestoreOutput();
            return ApplicationDataLifecycleResult::AllocationFailed;
        } catch (...) {
            clearRestoreOutput();
            return ApplicationDataLifecycleResult::PublishFailed;
        }
#endif
        if (publishResult != 0) {
            clearRestoreOutput();
            return ApplicationDataLifecycleResult::PublishFailed;
        }
        return ApplicationDataLifecycleResult::Ok;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            clearRestoreOutput();
            return ApplicationDataLifecycleResult::AllocationFailed;
        }
#endif
    }

public:
    static bool validProfile(const ApplicationDataProfile& profile) {
        return profileIdentityMatches(profile);
    }

    /* Resolve all current per-user roots in one snapshot.  Relocation is
     * read on every call by the C provider; no caller-supplied home path is
     * accepted.  The archive root is generation-bound and outside Data. */
    static ApplicationDataLifecycleResult buildUninstallPlan(
        const ApplicationDataProfile& profile, bool preserveUserData,
        ApplicationDataLifecyclePlan& output) {
        output = ApplicationDataLifecyclePlan{};
        if (!profileIdentityMatches(profile))
            return ApplicationDataLifecycleResult::InvalidArgument;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            ApplicationDataLifecyclePlan candidate;
            candidate.owner = profile.owner;
            candidate.applicationId = profile.applicationId;
            candidate.archiveGeneration = profile.owner.packageGeneration;
            candidate.preserveUserData = preserveUserData;
            candidate.dataAction = ApplicationDataPolicy::uninstallAction(
                ApplicationDataKind::Data, false, preserveUserData);
            candidate.cacheAction = ApplicationDataPolicy::uninstallAction(
                ApplicationDataKind::Cache, false, false);
            if (resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_DATA,
                                 profile.applicationId, candidate.dataRoot) !=
                    ApplicationDataLifecycleResult::Ok ||
                resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_CACHE,
                                 profile.applicationId, candidate.cacheRoot) !=
                    ApplicationDataLifecycleResult::Ok ||
                resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_STATE,
                                 profile.applicationId, candidate.stateRoot) !=
                    ApplicationDataLifecycleResult::Ok ||
                resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_BACKUP,
                                 profile.applicationId, candidate.backupRoot) !=
                    ApplicationDataLifecycleResult::Ok)
                return ApplicationDataLifecycleResult::KnownFolderUnavailable;
            if (preserveUserData) {
                candidate.archiveRoot = candidate.backupRoot + "/uninstall";
                if (!appendGeneration(candidate.archiveRoot,
                                      candidate.archiveGeneration))
                    return ApplicationDataLifecycleResult::ArchivePathUnavailable;
            }
            output = std::move(candidate);
            return ApplicationDataLifecycleResult::Ok;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            output = ApplicationDataLifecyclePlan{};
            return ApplicationDataLifecycleResult::AllocationFailed;
        }
#endif
    }

    /* Product lifecycle entry point.  Unlike the compatibility overload
     * above, this path never consults ambient environment variables and
     * cannot use a resolver registered for another user or package
     * generation. */
    static ApplicationDataLifecycleResult buildUninstallPlan(
        const ApplicationDataProfile& profile, bool preserveUserData,
        const ApplicationDataKnownFolderOwner& owner,
        ApplicationDataLifecyclePlan& output) {
        output = ApplicationDataLifecyclePlan{};
        if (!profileIdentityMatches(profile) || !owner.validFor(profile.owner))
            return ApplicationDataLifecycleResult::InvalidArgument;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
        std::string dataRoot;
        std::string cacheRoot;
        std::string stateRoot;
        std::string backupRoot;
        if (resolveOwnedDirectory(profile, owner,
                                  RINRUNTIME_APPLICATION_DIRECTORY_DATA,
                                  dataRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveOwnedDirectory(profile, owner,
                                  RINRUNTIME_APPLICATION_DIRECTORY_CACHE,
                                  cacheRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveOwnedDirectory(profile, owner,
                                  RINRUNTIME_APPLICATION_DIRECTORY_STATE,
                                  stateRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveOwnedDirectory(profile, owner,
                                  RINRUNTIME_APPLICATION_DIRECTORY_BACKUP,
                                  backupRoot) !=
                ApplicationDataLifecycleResult::Ok)
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;

        ApplicationDataLifecyclePlan candidate;
        candidate.owner = profile.owner;
        candidate.applicationId = profile.applicationId;
        candidate.dataRoot = std::move(dataRoot);
        candidate.cacheRoot = std::move(cacheRoot);
        candidate.stateRoot = std::move(stateRoot);
        candidate.backupRoot = std::move(backupRoot);
        candidate.archiveGeneration = profile.owner.packageGeneration;
        candidate.preserveUserData = preserveUserData;
        candidate.ownerBound = true;
        candidate.dataAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Data, false, preserveUserData);
        candidate.cacheAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Cache, false, false);
        if (preserveUserData) {
            candidate.archiveRoot = candidate.backupRoot + "/uninstall";
            if (!appendGeneration(candidate.archiveRoot,
                                  candidate.archiveGeneration))
                return ApplicationDataLifecycleResult::ArchivePathUnavailable;
        }
        output = std::move(candidate);
        return ApplicationDataLifecycleResult::Ok;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (const std::bad_alloc&) {
            output = ApplicationDataLifecyclePlan{};
            return ApplicationDataLifecycleResult::AllocationFailed;
        }
#endif
    }

    /* Restore one logical item from a retained RBK1 archive.  The source
     * package may differ only when the authenticated launcher authorizer
     * explicitly approves the handoff; a newer target schema requires the
     * supplied migration callback. */
    static ApplicationDataLifecycleResult restoreItem(
        const ApplicationDataProfile& profile,
        const std::uint8_t* sourceManifestBytes,
        std::size_t sourceManifestSize, std::uint32_t itemIndex,
        ApplicationDataIdentityAuthorizerFn authorizeIdentity,
        void* authorizeContext, ApplicationDataMigrationFn migrate,
        void* migrateContext, const std::uint8_t* archivedBytes,
        std::uint32_t archivedSize, std::uint8_t* restoredOut,
        std::uint32_t restoredCapacity, std::uint32_t* restoredSizeOut,
        ApplicationDataRestorePublishFn publish, void* publishContext) {
        ApplicationDataLifecyclePlan plan;
        const ApplicationDataLifecycleResult planResult = buildUninstallPlan(
            profile, true, plan);
        if (planResult != ApplicationDataLifecycleResult::Ok)
            return planResult;
        return restoreItemFromPlan(
            profile, plan, sourceManifestBytes, sourceManifestSize, itemIndex,
            authorizeIdentity, authorizeContext, migrate, migrateContext,
            archivedBytes, archivedSize, restoredOut, restoredCapacity,
            restoredSizeOut, publish, publishContext);
    }

    /* Product restore entry point.  The same authenticated Known Folder
     * owner used for uninstall planning must also own the restore publish
     * plan; accepting an ambient resolver here would allow a different
     * profile to receive the restored bytes. */
    static ApplicationDataLifecycleResult restoreItem(
        const ApplicationDataProfile& profile,
        const ApplicationDataKnownFolderOwner& owner,
        const std::uint8_t* sourceManifestBytes,
        std::size_t sourceManifestSize, std::uint32_t itemIndex,
        ApplicationDataIdentityAuthorizerFn authorizeIdentity,
        void* authorizeContext, ApplicationDataMigrationFn migrate,
        void* migrateContext, const std::uint8_t* archivedBytes,
        std::uint32_t archivedSize, std::uint8_t* restoredOut,
        std::uint32_t restoredCapacity, std::uint32_t* restoredSizeOut,
        ApplicationDataRestorePublishFn publish, void* publishContext) {
        ApplicationDataLifecyclePlan plan;
        const ApplicationDataLifecycleResult planResult = buildUninstallPlan(
            profile, true, owner, plan);
        if (planResult != ApplicationDataLifecycleResult::Ok) {
            if (restoredSizeOut != nullptr) *restoredSizeOut = 0u;
            return planResult;
        }
        return restoreItemFromPlan(
            profile, plan, sourceManifestBytes, sourceManifestSize, itemIndex,
            authorizeIdentity, authorizeContext, migrate, migrateContext,
            archivedBytes, archivedSize, restoredOut, restoredCapacity,
            restoredSizeOut, publish, publishContext);
    }

    /* Restore every included declaration as one owner transaction. The
     * archive reader validates ZIP/member shape before entry, this preflight
     * checks the complete declaration set before begin(), and each payload is
     * identity/schema checked before it reaches the private staging owner.
     * scratch is caller-owned, bounded storage for one restored item and is
     * zeroed on entry, between items, and on every exit. */
    static ApplicationDataLifecycleResult restoreArchive(
        const ApplicationDataProfile& profile,
        const ApplicationDataKnownFolderOwner& knownFolderOwner,
        const BackupArchiveReader& archive,
        ApplicationDataIdentityAuthorizerFn authorizeIdentity,
        void* authorizeContext, ApplicationDataMigrationFn migrate,
        void* migrateContext, std::uint8_t* scratch,
        std::uint32_t scratchCapacity,
        const ApplicationDataRestoreTransactionOwner& transaction) {
        const auto clearScratch = [&]() noexcept {
            if (scratch != nullptr && scratchCapacity != 0u)
                std::memset(scratch, 0, scratchCapacity);
        };
        clearScratch();
        if (!archive.parsed() || !transaction.valid() ||
            (scratchCapacity != 0u && scratch == nullptr))
            return ApplicationDataLifecycleResult::InvalidArgument;

        ApplicationDataLifecyclePlan plan;
        const ApplicationDataLifecycleResult planResult = buildUninstallPlan(
            profile, true, knownFolderOwner, plan);
        if (planResult != ApplicationDataLifecycleResult::Ok)
            return planResult;
        if (!plan.ownerBound)
            return ApplicationDataLifecycleResult::RestoreNotAuthorized;

        const RinRuntimeBackupManifestInfoV1& manifest =
            archive.manifestInfo();
        if (manifest.struct_size != sizeof(manifest) ||
            manifest.version != RINRUNTIME_BACKUP_VERSION ||
            manifest.item_count == 0u ||
            manifest.item_count > RINRUNTIME_BACKUP_MAX_ITEMS ||
            !rinruntime_backup_identity_valid(&manifest.identity))
            return ApplicationDataLifecycleResult::InvalidArchive;

        std::uint32_t includedCount = 0u;
        for (std::uint32_t index = 0u; index < manifest.item_count; ++index) {
            RinRuntimeBackupItemV1 item{};
            if (archive.itemAt(index, item) != BackupArchiveResult::Ok)
                return ApplicationDataLifecycleResult::InvalidArchive;
            if (item.flags == RINRUNTIME_BACKUP_ITEM_EXCLUDE) continue;
            if (item.flags != RINRUNTIME_BACKUP_ITEM_INCLUDE ||
                !rinruntime_backup_item_is_eligible(&item))
                return ApplicationDataLifecycleResult::InvalidArchive;
            ++includedCount;
        }
        if (includedCount == 0u ||
            includedCount != manifest.eligible_item_count)
            return ApplicationDataLifecycleResult::InvalidArchive;

        bool transactionStarted = false;
        const auto rollback = [&]() noexcept {
            clearScratch();
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            try {
                return transaction.rollback(transaction.context, &plan) == 0;
            } catch (...) {
                return false;
            }
#else
            return transaction.rollback(transaction.context, &plan) == 0;
#endif
        };
        const auto failTransaction = [&](
            ApplicationDataLifecycleResult failure) noexcept {
            clearScratch();
            if (!transactionStarted) return failure;
            if (!rollback())
                return ApplicationDataLifecycleResult::RestoreRollbackFailed;
            transactionStarted = false;
            return failure;
        };
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        try {
#endif
            std::uint32_t stagedCount = 0u;
            for (std::uint32_t index = 0u; index < manifest.item_count;
                 ++index) {
                RinRuntimeBackupItemV1 item{};
                if (archive.itemAt(index, item) != BackupArchiveResult::Ok) {
                    return failTransaction(
                        ApplicationDataLifecycleResult::InvalidArchive);
                }
                if (item.flags == RINRUNTIME_BACKUP_ITEM_EXCLUDE) continue;

                std::uint32_t restoredSize = 0u;
                const BackupArchiveResult readResult = archive.readItem(
                    index, &profile.backupIdentity, profile.dataSchemaVersion,
                    authorizeIdentity, authorizeContext, migrate, migrateContext,
                    scratch, scratchCapacity, &restoredSize);
                if (readResult != BackupArchiveResult::Ok) {
                    clearScratch();
                    const ApplicationDataLifecycleResult failure =
                        readResult == BackupArchiveResult::IdentityMismatch
                            ? ApplicationDataLifecycleResult::IdentityMismatch
                        : readResult == BackupArchiveResult::IdentityNotAuthorized
                            ? ApplicationDataLifecycleResult::RestoreNotAuthorized
                        : readResult == BackupArchiveResult::MigrationRequired
                            ? ApplicationDataLifecycleResult::MigrationRequired
                        : readResult == BackupArchiveResult::MigrationFailed
                            ? ApplicationDataLifecycleResult::MigrationFailed
                        : readResult == BackupArchiveResult::Limit
                            ? ApplicationDataLifecycleResult::RestoreScratchTooSmall
                        : ApplicationDataLifecycleResult::InvalidArchive;
                    return failTransaction(failure);
                }

                if (!transactionStarted) {
                    /* Authenticate/decode the first item before reserving
                     * private staging resources for an untrusted archive. */
                    transactionStarted = true;
                    if (transaction.begin(transaction.context, &plan,
                                          &manifest) != 0)
                        return failTransaction(
                            ApplicationDataLifecycleResult::RestoreTransactionFailed);
                }

                int stageResult = -1;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
                try {
#endif
                    stageResult = transaction.stageItem(
                        transaction.context, &plan, &item,
                        restoredSize == 0u ? nullptr : scratch, restoredSize);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
                } catch (...) {
                    clearScratch();
                    return failTransaction(
                        ApplicationDataLifecycleResult::RestoreTransactionFailed);
                }
#endif
                clearScratch();
                if (stageResult != 0)
                    return failTransaction(
                        ApplicationDataLifecycleResult::RestoreTransactionFailed);
                ++stagedCount;
            }

            int commitResult = -1;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            try {
#endif
                commitResult = transaction.commit(transaction.context, &plan,
                                                  stagedCount);
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
            } catch (...) {
                commitResult = -1;
            }
#endif
            if (commitResult != 0)
                return failTransaction(
                    ApplicationDataLifecycleResult::RestoreTransactionFailed);

            transactionStarted = false;
            clearScratch();
            return ApplicationDataLifecycleResult::Ok;
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS) || defined(_CPPUNWIND)
        } catch (...) {
            if (transactionStarted && !rollback())
                return ApplicationDataLifecycleResult::RestoreRollbackFailed;
            return ApplicationDataLifecycleResult::RestoreTransactionFailed;
        }
#endif
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP */
