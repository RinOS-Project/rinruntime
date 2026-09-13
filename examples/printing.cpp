/* SPDX-License-Identifier: MIT */
#include <rinruntime/rin_app_printing.hpp>
int main() {
    Rin::PrintSettings settings;
    settings.duplex = true;
    return settings.valid() ? 0 : 1;
}
