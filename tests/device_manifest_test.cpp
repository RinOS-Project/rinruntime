/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/device_manifest.hpp"

using RinRuntime::DeviceManifest;
using RinRuntime::DeviceManifestClass;
using RinRuntime::DeviceManifestDevice;
using RinRuntime::DeviceManifestTransport;

static DeviceManifestDevice validDevice(const char* id) {
    DeviceManifestDevice device;
    device.id = id;
    device.displayName = "Rin device";
    device.deviceClass = DeviceManifestClass::Input;
    device.transport = DeviceManifestTransport::Usb;
    device.generation = 1u;
    device.present = true;
    device.capabilities = {"input.keyboard", "input.pointer"};
    return device;
}

int main() {
    DeviceManifest manifest;
    manifest.versionMajor = 1u;
    manifest.manifestId = "desktop.devices";
    manifest.generation = 4u;
    manifest.devices.push_back(validDevice("usb.001"));
    assert(manifest.valid());
    assert(manifest.find("usb.001") != nullptr);

    manifest.devices.front().capabilities[1] = "input.keyboard";
    assert(!manifest.valid());

    manifest.devices.front().capabilities = {"input.keyboard"};
    manifest.devices.front().parentId = "usb.001";
    assert(!manifest.valid());

    manifest.devices.front().parentId.clear();
    manifest.devices.front().id = "bad/id";
    assert(!manifest.valid());
    return 0;
}
