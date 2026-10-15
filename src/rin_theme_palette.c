// SPDX-License-Identifier: MIT

#include <rinruntime/rin_theme_palette.h>

static void palette_zero(uint32_t* colors) {
    uint32_t index;
    if (!colors) return;
    for (index = 0u; index < RIN_THEME_PALETTE_COLOR_COUNT; ++index)
        colors[index] = 0u;
}

static void palette_base(uint32_t* colors) {
    colors[RIN_THEME_PALETTE_PRIMARY] = 0xff7fdbffu;
    colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xffb0e0e6u;
    colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xff5fbdcfu;
    colors[RIN_THEME_PALETTE_ON_PRIMARY] = 0xffffffffu;
    colors[RIN_THEME_PALETTE_SECONDARY] = 0xffffb6c1u;
    colors[RIN_THEME_PALETTE_SURFACE] = 0xffffffffu;
    colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfff0ffffu;
    colors[RIN_THEME_PALETTE_TEXT] = 0xff333333u;
    colors[RIN_THEME_PALETTE_TEXT_SECONDARY] = 0xff666666u;
    colors[RIN_THEME_PALETTE_TEXT_DIM] = 0xff999999u;
    colors[RIN_THEME_PALETTE_BORDER] = 0xffddddddu;
    colors[RIN_THEME_PALETTE_SHADOW] = 0x20000000u;
    colors[RIN_THEME_PALETTE_SUCCESS] = 0xff4caf50u;
    colors[RIN_THEME_PALETTE_SUCCESS_LIGHT] = 0xffc8e6c9u;
    colors[RIN_THEME_PALETTE_WARNING] = 0xffff9800u;
    colors[RIN_THEME_PALETTE_WARNING_LIGHT] = 0xffffe0b2u;
    colors[RIN_THEME_PALETTE_ERROR] = 0xfff44336u;
    colors[RIN_THEME_PALETTE_ERROR_LIGHT] = 0xffffcdd2u;
    colors[RIN_THEME_PALETTE_HOVER] = 0x10000000u;
    colors[RIN_THEME_PALETTE_SELECTED] = 0x20000000u;
}

int rin_theme_palette_build(
    uint32_t theme_id,
    uint32_t out_colors[RIN_THEME_PALETTE_COLOR_COUNT],
    uint32_t* out_flags) {
    palette_zero(out_colors);
    if (out_flags) *out_flags = 0u;
    if (!out_colors || !out_flags || theme_id > RIN_THEME_MIDNIGHT)
        return -1;
    palette_base(out_colors);
    switch (theme_id) {
        case RIN_THEME_AQUA:
            break;
        case RIN_THEME_PINK:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xffffb6c1u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xffffd9e0u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xffe894a2u;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfffff0f5u;
            break;
        case RIN_THEME_LAVENDER:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xffdda0ddu;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xffeee0eeu;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xffba7dbau;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfff8f8ffu;
            break;
        case RIN_THEME_SAKURA:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xffffb7c5u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xffffdce3u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xffff7994u;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfffff5eeu;
            break;
        case RIN_THEME_OCEAN:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xff00ced1u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xff8fe5e7u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xff009a9du;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfff0ffffu;
            break;
        case RIN_THEME_MINT:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xff6ee7b7u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xffa7f3d0u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xff34b985u;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfff0fdf4u;
            break;
        case RIN_THEME_PEACH:
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xfffdba74u;
            out_colors[RIN_THEME_PALETTE_PRIMARY_LIGHT] = 0xfffed7aau;
            out_colors[RIN_THEME_PALETTE_PRIMARY_DARK] = 0xffe78b3au;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xfffffbebu;
            break;
        case RIN_THEME_DARK:
            *out_flags = RIN_THEME_PALETTE_DARK;
            out_colors[RIN_THEME_PALETTE_SURFACE] = 0xff2d2d2du;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xff1e1e1eu;
            out_colors[RIN_THEME_PALETTE_TEXT] = 0xffeeeeeeu;
            out_colors[RIN_THEME_PALETTE_TEXT_SECONDARY] = 0xffccccccu;
            out_colors[RIN_THEME_PALETTE_TEXT_DIM] = 0xff999999u;
            out_colors[RIN_THEME_PALETTE_BORDER] = 0xff555555u;
            break;
        case RIN_THEME_MIDNIGHT:
            *out_flags = RIN_THEME_PALETTE_DARK;
            out_colors[RIN_THEME_PALETTE_PRIMARY] = 0xffffb6c1u;
            out_colors[RIN_THEME_PALETTE_SURFACE] = 0xff1e1e1eu;
            out_colors[RIN_THEME_PALETTE_BACKGROUND] = 0xff121212u;
            out_colors[RIN_THEME_PALETTE_TEXT] = 0xffeeeeeeu;
            out_colors[RIN_THEME_PALETTE_TEXT_SECONDARY] = 0xffc8c8c8u;
            out_colors[RIN_THEME_PALETTE_TEXT_DIM] = 0xff8f8f8fu;
            out_colors[RIN_THEME_PALETTE_BORDER] = 0xff444444u;
            break;
        default:
            palette_zero(out_colors);
            *out_flags = 0u;
            return -1;
    }
    return 0;
}
