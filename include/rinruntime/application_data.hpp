/* SPDX-License-Identifier: MIT */
/* Bounded, renderer-independent application data classification policy. */

#ifndef RINRUNTIME_APPLICATION_DATA_HPP
#define RINRUNTIME_APPLICATION_DATA_HPP

#include "accessibility.hpp"

namespace RinRuntime {

enum class ApplicationDataKind : uint8_t {
    Config = 0,
    Data = 1,
    Cache = 2,
    State = 3,
    Backup = 4
};

enum class ApplicationDataSchemaAction : uint8_t {
    Same = 0,
    MigrateForward = 1,
    RejectDowngrade = 2
};

enum class ApplicationDataUninstallAction : uint8_t {
    PreserveUserData = 0,
    RemoveTransientCache = 1,
    RetainImmutablePayload = 2
};

/* Application data roots are private to one authenticated user and one
 * signed application identity.  These values are opaque identifiers supplied
 * by the launcher; this model never derives authority from a path or name. */
struct ApplicationDataIdentity final {
    uint64_t userId = 0;
    uint64_t applicationTag = 0;
    uint64_t packageGeneration = 0;
};

class ApplicationDataPolicy final {
    static bool asciiIdentifierByte(uint8_t value) {
        return (value >= static_cast<uint8_t>('a') &&
                value <= static_cast<uint8_t>('z')) ||
               (value >= static_cast<uint8_t>('A') &&
                value <= static_cast<uint8_t>('Z')) ||
               (value >= static_cast<uint8_t>('0') &&
                value <= static_cast<uint8_t>('9')) ||
               value == static_cast<uint8_t>('.') ||
               value == static_cast<uint8_t>('-') ||
               value == static_cast<uint8_t>('_');
    }

public:
    static constexpr size_t kMaxApplicationIdBytes = 64u;
    static constexpr size_t kMaxLogicalKeyBytes = 255u;

    static constexpr uint32_t kPrivateDirectoryMode = 0700u;
    static constexpr uint32_t kPrivateFileMode = 0600u;

    static bool validIdentity(const ApplicationDataIdentity& identity) {
        return identity.userId != 0u && identity.applicationTag != 0u &&
               identity.packageGeneration != 0u;
    }

    /* Application reads/writes require an exact authenticated identity. */
    static bool accessAllowed(ApplicationDataKind kind,
                              const ApplicationDataIdentity& owner,
                              const ApplicationDataIdentity& requester) {
        (void)kind;
        return validIdentity(owner) && validIdentity(requester) &&
               owner.userId == requester.userId &&
               owner.applicationTag == requester.applicationTag &&
               owner.packageGeneration == requester.packageGeneration;
    }

    /* A storage-pressure service may remove cache entries only when the
     * broker has granted the explicit maintenance capability.  It cannot
     * use that capability for config/data/state/backup or secret material. */
    static bool cacheCleanupAllowed(
        ApplicationDataKind kind, const ApplicationDataIdentity& owner,
        const ApplicationDataIdentity& requester, bool maintenanceCapability) {
        return kind == ApplicationDataKind::Cache && maintenanceCapability &&
               validIdentity(owner) && validIdentity(requester) &&
               owner.userId == requester.userId;
    }

    /* Application IDs are logical package identifiers, never paths. */
    static bool validApplicationId(const std::string& value) {
        if (value.empty() || value.size() > kMaxApplicationIdBytes ||
            value.front() == '.' || value.back() == '.')
            return false;
        for (size_t index = 0u; index < value.size(); ++index) {
            const uint8_t byte = static_cast<uint8_t>(value[index]);
            if (!asciiIdentifierByte(byte)) return false;
        }
        return value.find("..") == std::string::npos;
    }

    /* Logical keys are one flat identifier.  A storage adapter must join it
     * below the selected Known Folder root; callers never supply separators. */
    static bool validLogicalKey(const std::string& value) {
        if (value.empty() || value.size() > kMaxLogicalKeyBytes ||
            value == "." || value == ".." || value.front() == '.' ||
            value.back() == '.')
            return false;
        for (size_t index = 0u; index < value.size(); ++index) {
            const uint8_t byte = static_cast<uint8_t>(value[index]);
            if (byte < 0x20u || byte == 0x7fu || byte == '/' || byte == '\\')
                return false;
        }
        return true;
    }

    static bool isTransient(ApplicationDataKind kind) {
        return kind == ApplicationDataKind::Cache;
    }

    static bool backupEligible(ApplicationDataKind kind, bool secret) {
        if (secret || kind == ApplicationDataKind::Cache)
            return false;
        return kind == ApplicationDataKind::Config ||
               kind == ApplicationDataKind::Data ||
               kind == ApplicationDataKind::State ||
               kind == ApplicationDataKind::Backup;
    }

    static bool purgeAllowed(ApplicationDataKind kind) {
        return kind == ApplicationDataKind::Cache;
    }

    static ApplicationDataUninstallAction uninstallAction(
        ApplicationDataKind kind, bool immutablePayload) {
        if (immutablePayload)
            return ApplicationDataUninstallAction::RetainImmutablePayload;
        if (kind == ApplicationDataKind::Cache)
            return ApplicationDataUninstallAction::RemoveTransientCache;
        return ApplicationDataUninstallAction::PreserveUserData;
    }

    /* Schema bytes are never copied on downgrade.  Forward changes must use
     * one isolated migration callback before publication. */
    static ApplicationDataSchemaAction schemaAction(uint64_t stored,
                                                    uint64_t target) {
        if (stored == 0u || target == 0u) return ApplicationDataSchemaAction::RejectDowngrade;
        if (stored == target) return ApplicationDataSchemaAction::Same;
        return stored < target ? ApplicationDataSchemaAction::MigrateForward
                               : ApplicationDataSchemaAction::RejectDowngrade;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_DATA_HPP */
