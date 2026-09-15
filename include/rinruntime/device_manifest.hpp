/* SPDX-License-Identifier: MIT */
/* Backend-independent device inventory manifest for public consumers. */
#ifndef RINRUNTIME_DEVICE_MANIFEST_HPP
#define RINRUNTIME_DEVICE_MANIFEST_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

static constexpr std::size_t kDeviceManifestMaxIdBytes = 95u;
static constexpr std::size_t kDeviceManifestMaxNameBytes = 127u;
static constexpr std::size_t kDeviceManifestMaxCapabilities = 32u;
static constexpr std::size_t kDeviceManifestMaxDevices = 128u;

enum class DeviceManifestClass : std::uint8_t {
    Input = 1u,
    Audio = 2u,
    Network = 3u,
    Storage = 4u,
    Display = 5u,
    Usb = 6u,
    Pci = 7u,
    Bluetooth = 8u,
    Sensor = 9u,
    Camera = 10u,
    Printer = 11u,
    Other = 12u,
};

enum class DeviceManifestTransport : std::uint8_t {
    Pci = 1u,
    Usb = 2u,
    I2c = 3u,
    Hda = 4u,
    Ac97 = 5u,
    Bluetooth = 6u,
    Network = 7u,
    Virtual = 8u,
    Platform = 9u,
    Other = 10u,
};

struct DeviceManifestDevice {
    std::string id;
    std::string displayName;
    std::string parentId;
    DeviceManifestClass deviceClass = DeviceManifestClass::Other;
    DeviceManifestTransport transport = DeviceManifestTransport::Other;
    std::uint16_t vendorId = 0u;
    std::uint16_t productId = 0u;
    std::uint32_t revision = 0u;
    std::uint64_t generation = 0u;
    bool present = false;
    std::vector<std::string> capabilities;

    static bool validIdentifier(const std::string& value,
                                std::size_t maximum) {
        if (value.empty() || value.size() > maximum) return false;
        for (const unsigned char byte : value) {
            if (byte < 0x21u || byte == 0x7fu || byte == '/' ||
                byte == '\\')
                return false;
        }
        return true;
    }

    static bool validText(const std::string& value, std::size_t maximum,
                          bool allowEmpty) {
        if (value.size() > maximum || (!allowEmpty && value.empty()))
            return false;
        for (const unsigned char byte : value)
            if (byte < 0x20u || byte == 0x7fu) return false;
        return true;
    }

    static bool sortedUniqueCapabilities(
        const std::vector<std::string>& values) {
        if (values.size() > kDeviceManifestMaxCapabilities) return false;
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!validIdentifier(values[index], kDeviceManifestMaxIdBytes) ||
                (index != 0u && values[index - 1u] >= values[index]))
                return false;
        }
        return true;
    }

    bool valid() const {
        return validIdentifier(id, kDeviceManifestMaxIdBytes) &&
               validText(displayName, kDeviceManifestMaxNameBytes, false) &&
               (parentId.empty() ||
                validIdentifier(parentId, kDeviceManifestMaxIdBytes)) &&
               deviceClass >= DeviceManifestClass::Input &&
               deviceClass <= DeviceManifestClass::Other &&
               transport >= DeviceManifestTransport::Pci &&
               transport <= DeviceManifestTransport::Other && generation != 0u &&
               sortedUniqueCapabilities(capabilities) && parentId != id;
    }
};

struct DeviceManifest {
    std::uint16_t versionMajor = 0u;
    std::uint16_t versionMinor = 0u;
    std::string manifestId;
    std::uint64_t generation = 0u;
    std::vector<DeviceManifestDevice> devices;

    static bool validIdentifier(const std::string& value) {
        return DeviceManifestDevice::validIdentifier(
            value, kDeviceManifestMaxIdBytes);
    }

    bool valid() const {
        if (versionMajor == 0u || !validIdentifier(manifestId) ||
            generation == 0u || devices.size() > kDeviceManifestMaxDevices)
            return false;
        for (std::size_t index = 0u; index < devices.size(); ++index) {
            const DeviceManifestDevice& device = devices[index];
            if (!device.valid() ||
                (index != 0u && devices[index - 1u].id >= device.id))
                return false;
            if (!device.parentId.empty()) {
                bool parentFound = false;
                for (std::size_t parent = 0u; parent < index; ++parent)
                    if (devices[parent].id == device.parentId) {
                        parentFound = true;
                        break;
                    }
                if (!parentFound) return false;
            }
        }
        return true;
    }

    const DeviceManifestDevice* find(const std::string& deviceId) const {
        for (const DeviceManifestDevice& device : devices)
            if (device.id == deviceId) return &device;
        return nullptr;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_DEVICE_MANIFEST_HPP */
