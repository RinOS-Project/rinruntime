/* SPDX-License-Identifier: MIT */
/* Backend-independent theme profile for public consumers. */
#ifndef RINRUNTIME_THEME_HPP
#define RINRUNTIME_THEME_HPP

#include <array>
#include <cstddef>
#include <cstdint>

namespace RinRuntime {

enum class ThemeId : std::uint32_t {
    Aqua = 0u,
    Pink = 1u,
    Lavender = 2u,
    Sakura = 3u,
    Ocean = 4u,
    Mint = 5u,
    Peach = 6u,
    Dark = 7u,
    Midnight = 8u,
};

enum class ThemeColor : std::uint8_t {
    Primary = 0u,
    PrimaryLight = 1u,
    PrimaryDark = 2u,
    OnPrimary = 3u,
    Secondary = 4u,
    Surface = 5u,
    Background = 6u,
    Text = 7u,
    TextSecondary = 8u,
    TextDim = 9u,
    Border = 10u,
    Shadow = 11u,
    Success = 12u,
    SuccessLight = 13u,
    Warning = 14u,
    WarningLight = 15u,
    Error = 16u,
    ErrorLight = 17u,
    Hover = 18u,
    Selected = 19u,
};

static constexpr std::size_t kThemeColorCount = 20u;
static constexpr std::uint32_t kThemeFlagDark = 0x00000001u;
static constexpr std::uint32_t kThemeKnownFlags = kThemeFlagDark;

/*
 * A ThemeProfile contains only semantic ARGB values and bounded identity.
 * It deliberately has no palette generator, filesystem path, native handle,
 * allocator, or compositor ownership.  A product may populate it from a
 * private theme service or palette producer and hand the validated value to
 * any ordinary application or external toolkit.
 */
struct ThemeProfile final {
    /* UINT32_MAX is the cleared/invalid state used on rejected input. */
    std::uint32_t id = UINT32_MAX;
    std::uint32_t flags = 0u;
    std::array<std::uint32_t, kThemeColorCount> colors = {};

    static constexpr bool validId(std::uint32_t value) {
        return value <= static_cast<std::uint32_t>(ThemeId::Midnight);
    }

    static constexpr bool validColor(std::uint32_t value) {
        return value < kThemeColorCount;
    }

    bool valid() const {
        return validId(id) && (flags & ~kThemeKnownFlags) == 0u;
    }

    std::uint32_t color(ThemeColor slot) const {
        const auto index = static_cast<std::uint32_t>(slot);
        return validColor(index) ? colors[index] : 0u;
    }

    bool dark() const { return (flags & kThemeFlagDark) != 0u; }

    /* Failure-atomic conversion from a private producer's caller-owned array. */
    static bool fromPalette(std::uint32_t themeId, std::uint32_t themeFlags,
                            const std::uint32_t* palette,
                            ThemeProfile& output) {
        output = {};
        if (!validId(themeId) ||
            (themeFlags & ~kThemeKnownFlags) != 0u || palette == nullptr)
            return false;

        ThemeProfile candidate;
        candidate.id = themeId;
        candidate.flags = themeFlags;
        for (std::size_t index = 0u; index < kThemeColorCount; ++index)
            candidate.colors[index] = palette[index];
        output = candidate;
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_THEME_HPP */
