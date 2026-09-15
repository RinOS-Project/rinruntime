/* SPDX-License-Identifier: MIT */
/* Bounded JSON adapter for the public device inventory manifest model. */
#ifndef RINRUNTIME_DEVICE_MANIFEST_JSON_HPP
#define RINRUNTIME_DEVICE_MANIFEST_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

#include <rinjson/json.hpp>

#include "device_manifest.hpp"

namespace RinRuntime {

class DeviceManifestJson final {
public:
    static constexpr std::size_t kMaximumBytes = 64u * 1024u;
    static constexpr std::size_t kMaximumStringBytes =
        kDeviceManifestMaxNameBytes;
    static constexpr std::size_t kMaximumObjectMembers = 16u;
    static constexpr std::size_t kMaximumArrayElements =
        kDeviceManifestMaxDevices;
    static constexpr std::size_t kMaximumNodes = 4096u;
    static constexpr std::size_t kMaximumAllocationBytes = 512u * 1024u;

private:
    using Value = rinjson::Value;

    static const Value* field(const Value::Object& object,
                              std::string_view name) {
        const auto found = object.find(name);
        return found == object.end() ? nullptr : &found->second;
    }

    static bool readString(const Value* value, std::size_t maximum,
                           std::string& output) {
        if (value == nullptr || !value->isString() ||
            value->asString().size() > maximum)
            return false;
        output = value->asString();
        return true;
    }

    static bool readUnsigned(const Value* value, std::uint64_t maximum,
                             std::uint64_t& output) {
        if (value == nullptr || !value->isInteger()) return false;
        if (value->isSignedInteger()) {
            const std::int64_t parsed = value->asInteger();
            if (parsed < 0) return false;
            output = static_cast<std::uint64_t>(parsed);
        } else {
            output = value->asUnsignedInteger();
        }
        return output <= maximum;
    }

    static bool readBool(const Value* value, bool& output) {
        if (value == nullptr || !value->isBool()) return false;
        output = value->asBool();
        return true;
    }

    static bool readClass(const Value::Object& object,
                          DeviceManifestClass& output) {
        std::string text;
        if (!readString(field(object, "class"), kDeviceManifestMaxIdBytes,
                        text))
            return false;
        if (text == "input") output = DeviceManifestClass::Input;
        else if (text == "audio") output = DeviceManifestClass::Audio;
        else if (text == "network") output = DeviceManifestClass::Network;
        else if (text == "storage") output = DeviceManifestClass::Storage;
        else if (text == "display") output = DeviceManifestClass::Display;
        else if (text == "usb") output = DeviceManifestClass::Usb;
        else if (text == "pci") output = DeviceManifestClass::Pci;
        else if (text == "bluetooth") output = DeviceManifestClass::Bluetooth;
        else if (text == "sensor") output = DeviceManifestClass::Sensor;
        else if (text == "camera") output = DeviceManifestClass::Camera;
        else if (text == "printer") output = DeviceManifestClass::Printer;
        else if (text == "other") output = DeviceManifestClass::Other;
        else return false;
        return true;
    }

    static bool readTransport(const Value::Object& object,
                              DeviceManifestTransport& output) {
        std::string text;
        if (!readString(field(object, "transport"),
                        kDeviceManifestMaxIdBytes, text))
            return false;
        if (text == "pci") output = DeviceManifestTransport::Pci;
        else if (text == "usb") output = DeviceManifestTransport::Usb;
        else if (text == "i2c") output = DeviceManifestTransport::I2c;
        else if (text == "hda") output = DeviceManifestTransport::Hda;
        else if (text == "ac97") output = DeviceManifestTransport::Ac97;
        else if (text == "bluetooth")
            output = DeviceManifestTransport::Bluetooth;
        else if (text == "network") output = DeviceManifestTransport::Network;
        else if (text == "virtual") output = DeviceManifestTransport::Virtual;
        else if (text == "platform") output = DeviceManifestTransport::Platform;
        else if (text == "other") output = DeviceManifestTransport::Other;
        else return false;
        return true;
    }

    static bool readCapabilities(const Value::Object& object,
                                 std::vector<std::string>& output) {
        const Value* value = field(object, "capabilities");
        if (value == nullptr) return true;
        if (!value->isArray() ||
            value->asArray().size() > kDeviceManifestMaxCapabilities)
            return false;
        std::vector<std::string> candidate;
        candidate.reserve(value->asArray().size());
        for (const Value& item : value->asArray()) {
            std::string capability;
            if (!readString(&item, kDeviceManifestMaxIdBytes, capability))
                return false;
            candidate.push_back(std::move(capability));
        }
        output = std::move(candidate);
        return true;
    }

    static bool readDevice(const Value& value,
                           DeviceManifestDevice& output) {
        if (!value.isObject()) return false;
        const Value::Object& object = value.asObject();
        std::uint64_t number = 0u;
        if (!readString(field(object, "id"), kDeviceManifestMaxIdBytes,
                        output.id) ||
            !readString(field(object, "display_name"),
                        kDeviceManifestMaxNameBytes, output.displayName) ||
            !readClass(object, output.deviceClass) ||
            !readTransport(object, output.transport) ||
            !readUnsigned(field(object, "generation"), UINT64_MAX,
                          output.generation) ||
            !readBool(field(object, "present"), output.present) ||
            !readCapabilities(object, output.capabilities))
            return false;
        const Value* parent = field(object, "parent_id");
        if (parent != nullptr &&
            !readString(parent, kDeviceManifestMaxIdBytes, output.parentId))
            return false;
        if (field(object, "vendor_id") != nullptr &&
            !readUnsigned(field(object, "vendor_id"), UINT16_MAX, number))
            return false;
        output.vendorId = static_cast<std::uint16_t>(number);
        number = 0u;
        if (field(object, "product_id") != nullptr &&
            !readUnsigned(field(object, "product_id"), UINT16_MAX, number))
            return false;
        output.productId = static_cast<std::uint16_t>(number);
        number = 0u;
        if (field(object, "revision") != nullptr &&
            !readUnsigned(field(object, "revision"), UINT32_MAX, number))
            return false;
        output.revision = static_cast<std::uint32_t>(number);
        return true;
    }

public:
    /* output is cleared before parsing and remains empty on every failure. */
    static bool parse(std::string_view input, DeviceManifest& output,
                      std::string& error) {
        DeviceManifest candidate = {};
        output = {};
        error.clear();
        if (input.empty() || input.size() > kMaximumBytes) {
            error = "device manifest size";
            return false;
        }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        try {
#endif
            rinjson::Limits limits;
            limits.maxBytes = kMaximumBytes;
            limits.maxDepth = 16u;
            limits.maxStringBytes = kMaximumStringBytes;
            limits.maxArrayElements = kMaximumArrayElements;
            limits.maxObjectMembers = kMaximumObjectMembers;
            limits.maxTotalNodes = kMaximumNodes;
            limits.maxAllocationBytes = kMaximumAllocationBytes;
            const Value document = rinjson::parse(input, limits);
            if (!document.isObject()) {
                error = "device manifest object";
                return false;
            }
            const Value::Object& object = document.asObject();
            std::uint64_t number = 0u;
            if (!readString(field(object, "manifest_id"),
                            kDeviceManifestMaxIdBytes, candidate.manifestId) ||
                !readUnsigned(field(object, "version_major"), UINT16_MAX,
                              number)) {
                error = "device manifest field type";
                return false;
            }
            candidate.versionMajor = static_cast<std::uint16_t>(number);
            number = 0u;
            if (field(object, "version_minor") != nullptr &&
                !readUnsigned(field(object, "version_minor"), UINT16_MAX,
                              number)) {
                error = "device manifest field type";
                return false;
            }
            candidate.versionMinor = static_cast<std::uint16_t>(number);
            number = 0u;
            if (!readUnsigned(field(object, "generation"), UINT64_MAX,
                              number)) {
                error = "device manifest field type";
                return false;
            }
            candidate.generation = number;
            const Value* devices = field(object, "devices");
            if (devices == nullptr || !devices->isArray() ||
                devices->asArray().size() > kDeviceManifestMaxDevices) {
                error = "device manifest devices";
                return false;
            }
            candidate.devices.reserve(devices->asArray().size());
            for (const Value& value : devices->asArray()) {
                DeviceManifestDevice device;
                if (!readDevice(value, device)) {
                    error = "device manifest field type";
                    return false;
                }
                candidate.devices.push_back(std::move(device));
            }
            if (!candidate.valid()) {
                error = "device manifest validation";
                return false;
            }
#if defined(__cpp_exceptions) || defined(__EXCEPTIONS)
        } catch (const rinjson::Error& exception) {
            error = "device manifest JSON: ";
            error += exception.what();
            return false;
        }
#endif
        output = std::move(candidate);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_DEVICE_MANIFEST_JSON_HPP */
