/* SPDX-License-Identifier: MIT */
#include <rinruntime/rinruntime.hpp>

int main() {
    RinRuntime::Button windowTitle("RinOS Hello Window");
    return windowTitle.accessibilityDefaultName() == "RinOS Hello Window" ? 0 : 1;
}
