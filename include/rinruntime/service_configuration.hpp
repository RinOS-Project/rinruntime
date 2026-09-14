/* SPDX-License-Identifier: MIT */
/* Backend-independent service configuration model for public consumers. */
#ifndef RINRUNTIME_SERVICE_CONFIGURATION_HPP
#define RINRUNTIME_SERVICE_CONFIGURATION_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

static constexpr std::size_t kServiceConfigurationMaxIdBytes = 63u;
static constexpr std::size_t kServiceConfigurationMaxDependencies = 16u;
static constexpr std::uint32_t kServiceConfigurationMaxInstances = 64u;
static constexpr std::uint32_t kServiceConfigurationMaxTimeoutSeconds = 3600u;
static constexpr std::uint64_t kServiceConfigurationMaxMemoryBytes =
    1ull << 40;

enum class ServiceRestartPolicy : std::uint8_t {
    Disabled = 1u,
    OnFailure = 2u,
    Always = 3u,
};

struct ServiceConfiguration {
    std::string serviceId;
    std::string displayName;
    ServiceRestartPolicy restartPolicy = ServiceRestartPolicy::OnFailure;
    std::uint32_t maxInstances = 1u;
    std::uint64_t memoryLimitBytes = 0u;
    std::uint32_t startupTimeoutSeconds = 0u;
    std::uint32_t stopTimeoutSeconds = 0u;
    bool enabledByDefault = true;
    std::vector<std::string> dependencies;
    std::vector<std::string> optionalDependencies;

    static bool validIdentifier(const std::string& value) {
        if (value.empty() || value.size() > kServiceConfigurationMaxIdBytes)
            return false;
        for (const unsigned char byte : value) {
            if (byte < 0x21u || byte == 0x7fu || byte == '/' ||
                byte == '\\' || byte == ':')
                return false;
        }
        return true;
    }

    static bool sortedUnique(const std::vector<std::string>& values,
                             const std::string& owner) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!validIdentifier(values[index]) || values[index] == owner ||
                (index != 0u && values[index - 1u] >= values[index]))
                return false;
        }
        return true;
    }

    bool valid() const {
        if (!validIdentifier(serviceId) || displayName.empty() ||
            displayName.size() > 127u || maxInstances == 0u ||
            maxInstances > kServiceConfigurationMaxInstances ||
            memoryLimitBytes > kServiceConfigurationMaxMemoryBytes ||
            startupTimeoutSeconds > kServiceConfigurationMaxTimeoutSeconds ||
            stopTimeoutSeconds > kServiceConfigurationMaxTimeoutSeconds ||
            dependencies.size() > kServiceConfigurationMaxDependencies ||
            optionalDependencies.size() > kServiceConfigurationMaxDependencies ||
            dependencies.size() + optionalDependencies.size() >
                kServiceConfigurationMaxDependencies ||
            (restartPolicy != ServiceRestartPolicy::Disabled &&
             restartPolicy != ServiceRestartPolicy::OnFailure &&
             restartPolicy != ServiceRestartPolicy::Always) ||
            !sortedUnique(dependencies, serviceId) ||
            !sortedUnique(optionalDependencies, serviceId))
            return false;
        for (const unsigned char byte : displayName)
            if (byte < 0x20u || byte == 0x7fu) return false;
        for (const std::string& dependency : dependencies)
            for (const std::string& optional : optionalDependencies)
                if (dependency == optional) return false;
        return true;
    }

    bool dependsOn(const std::string& dependencyId) const {
        for (const std::string& dependency : dependencies)
            if (dependency == dependencyId) return true;
        return false;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_SERVICE_CONFIGURATION_HPP */
