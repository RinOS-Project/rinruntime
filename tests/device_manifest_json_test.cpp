/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <string>

#include "../include/rinruntime/device_manifest_json.hpp"

int main() {
    RinRuntime::DeviceManifest output;
    std::string error;
    const std::string valid =
        "{\"manifest_id\":\"desktop.devices\","
        "\"version_major\":1,\"version_minor\":2,\"generation\":9,"
        "\"devices\":["
        "{\"id\":\"pci.0000.00.1f.3\",\"display_name\":\"Audio\","
        "\"class\":\"audio\",\"transport\":\"pci\","
        "\"vendor_id\":32902,\"product_id\":4660,\"revision\":1,"
        "\"generation\":9,\"present\":true,"
        "\"capabilities\":[\"audio.capture\",\"audio.playback\"]},"
        "{\"id\":\"usb.001\",\"display_name\":\"Keyboard\","
        "\"parent_id\":\"pci.0000.00.1f.3\",\"class\":\"input\","
        "\"transport\":\"usb\",\"generation\":9,\"present\":true,"
        "\"capabilities\":[\"input.keyboard\"]}]}";
    assert(RinRuntime::DeviceManifestJson::parse(valid, output, error));
    assert(error.empty());
    assert(output.valid());
    assert(output.versionMinor == 2u);
    assert(output.devices.size() == 2u);
    assert(output.devices[1].parentId == "pci.0000.00.1f.3");
    assert(output.devices[0].vendorId == 32902u);

    assert(!RinRuntime::DeviceManifestJson::parse(
        "{\"manifest_id\":\"desktop.devices\",\"version_major\":1,"
        "\"generation\":9,\"devices\":[{\"id\":\"usb.001\","
        "\"display_name\":\"Keyboard\",\"class\":\"input\","
        "\"transport\":\"usb\",\"generation\":9,"
        "\"present\":true},{\"id\":\"usb.001\","
        "\"display_name\":\"Duplicate\",\"class\":\"input\","
        "\"transport\":\"usb\",\"generation\":9,"
        "\"present\":true}]}\n",
        output, error));
    assert(error == "device manifest validation");
    assert(output.manifestId.empty());

    assert(!RinRuntime::DeviceManifestJson::parse(
        "{\"manifest_id\":\"desktop.devices\",\"version_major\":1,"
        "\"generation\":9,\"devices\":[{\"id\":\"usb.001\","
        "\"display_name\":\"Keyboard\",\"class\":\"input\","
        "\"transport\":\"usb\",\"generation\":9,"
        "\"present\":true,\"parent_id\":\"missing\"}]}\n",
        output, error));
    assert(error == "device manifest validation");
    assert(output.devices.empty());

    assert(!RinRuntime::DeviceManifestJson::parse(
        "{\"manifest_id\":\"desktop.devices\",\"version_major\":1,"
        "\"generation\":9,\"devices\":[{\"id\":\"usb.001\","
        "\"display_name\":\"Keyboard\",\"class\":\"input\","
        "\"transport\":\"unknown\",\"generation\":9,"
        "\"present\":true}]}\n",
        output, error));
    assert(error == "device manifest field type");
    assert(output.manifestId.empty());
    return 0;
}
