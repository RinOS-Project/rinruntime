/* SPDX-License-Identifier: MIT */
#include <cassert>
#include <cstddef>
#include <cstdint>

#include "../include/rinruntime/theme.hpp"

int main() {
    std::uint32_t palette[RinRuntime::kThemeColorCount] = {};
    for (std::size_t index = 0u; index < RinRuntime::kThemeColorCount; ++index)
        palette[index] = 0xff000000u | static_cast<std::uint32_t>(index);

    RinRuntime::ThemeProfile profile;
    assert(!RinRuntime::ThemeProfile::fromPalette(
        static_cast<std::uint32_t>(RinRuntime::ThemeId::Aqua), 0u, nullptr,
        profile));
    assert(!profile.valid());

    assert(RinRuntime::ThemeProfile::fromPalette(
        static_cast<std::uint32_t>(RinRuntime::ThemeId::Midnight),
        RinRuntime::kThemeFlagDark, palette, profile));
    assert(profile.valid());
    assert(profile.dark());
    assert(profile.color(RinRuntime::ThemeColor::Primary) == 0xff000000u);
    assert(profile.color(RinRuntime::ThemeColor::Selected) == 0xff000013u);

    assert(!RinRuntime::ThemeProfile::fromPalette(99u, 0u, palette, profile));
    assert(!profile.valid());
    assert(!RinRuntime::ThemeProfile::fromPalette(
        static_cast<std::uint32_t>(RinRuntime::ThemeId::Aqua), 0x80u, palette,
        profile));
    assert(!profile.valid());
    return 0;
}
