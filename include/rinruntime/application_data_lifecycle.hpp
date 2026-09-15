/* SPDX-License-Identifier: MIT */
/* Identity-bound application data uninstall and restore lifecycle. */

#ifndef RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP
#define RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP

#include "application_data.hpp"
#include "backup_restore.h"
#include "known_folders.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
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
        output.clear();
        if (!profileIdentityMatches(profile) || !owner.validFor(profile.owner) ||
            owner.resolve(owner.context, &profile.owner,
                          profile.applicationId.c_str(), directory, path,
                          sizeof(path)) != 0 ||
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
        output.owner = profile.owner;
        output.applicationId = profile.applicationId;
        output.archiveGeneration = profile.owner.packageGeneration;
        output.preserveUserData = preserveUserData;
        output.dataAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Data, false, preserveUserData);
        output.cacheAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Cache, false, false);
        if (resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_DATA,
                             profile.applicationId, output.dataRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_CACHE,
                             profile.applicationId, output.cacheRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_STATE,
                             profile.applicationId, output.stateRoot) !=
                ApplicationDataLifecycleResult::Ok ||
            resolveDirectory(RINRUNTIME_APPLICATION_DIRECTORY_BACKUP,
                             profile.applicationId, output.backupRoot) !=
                ApplicationDataLifecycleResult::Ok)
            return ApplicationDataLifecycleResult::KnownFolderUnavailable;
        if (preserveUserData) {
            output.archiveRoot = output.backupRoot + "/uninstall";
            if (!appendGeneration(output.archiveRoot,
                                  output.archiveGeneration)) {
                output = ApplicationDataLifecyclePlan{};
                return ApplicationDataLifecycleResult::ArchivePathUnavailable;
            }
        }
        return ApplicationDataLifecycleResult::Ok;
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

        output.owner = profile.owner;
        output.applicationId = profile.applicationId;
        output.dataRoot = std::move(dataRoot);
        output.cacheRoot = std::move(cacheRoot);
        output.stateRoot = std::move(stateRoot);
        output.backupRoot = std::move(backupRoot);
        output.archiveGeneration = profile.owner.packageGeneration;
        output.preserveUserData = preserveUserData;
        output.ownerBound = true;
        output.dataAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Data, false, preserveUserData);
        output.cacheAction = ApplicationDataPolicy::uninstallAction(
            ApplicationDataKind::Cache, false, false);
        if (preserveUserData) {
            output.archiveRoot = output.backupRoot + "/uninstall";
            if (!appendGeneration(output.archiveRoot,
                                  output.archiveGeneration)) {
                output = ApplicationDataLifecyclePlan{};
                return ApplicationDataLifecycleResult::ArchivePathUnavailable;
            }
        }
        return ApplicationDataLifecycleResult::Ok;
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
        RinRuntimeBackupItemV1 item{};
        std::size_t itemLength = 0u;
        if (restoredSizeOut != nullptr) *restoredSizeOut = 0u;
        if (restoredSizeOut == nullptr || publish == nullptr ||
            (archivedSize != 0u &&
             (archivedBytes == nullptr || restoredOut == nullptr)))
            return ApplicationDataLifecycleResult::InvalidArgument;
        const ApplicationDataLifecycleResult planResult = buildUninstallPlan(
            profile, true, plan);
        if (planResult != ApplicationDataLifecycleResult::Ok)
            return planResult;
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
        if (publish(publishContext, &plan, &item, restoredOut,
                    *restoredSizeOut) != 0) {
            if (restoredOut != nullptr && restoredCapacity != 0u)
                std::memset(restoredOut, 0, restoredCapacity);
            *restoredSizeOut = 0u;
            return ApplicationDataLifecycleResult::PublishFailed;
        }
        return ApplicationDataLifecycleResult::Ok;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_DATA_LIFECYCLE_HPP */
